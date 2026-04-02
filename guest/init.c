// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <linux/reboot.h>
#include <unistd.h>

#define STACK_SIZE (64 * 1024)
#define REPORT_SHIFT 25
#define REPORT_MASK ((1 << REPORT_SHIFT) - 1)
#define EXIT_SHIFT 29
#define THREAD_COUNT 2
#define INITIAL_HASH 0xdeadbeef

struct thread_arg {
	int id;
	uint64_t counter;
	uint32_t hash;
	struct thread_arg *other;
};

static inline uint64_t rdtsc(void)
{
	uint32_t lo, hi;
	asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
	return ((uint64_t)hi << 32) | lo;
}

/* Mix bits from the other thread's hash into our own. This is a data dependency
   that crosses threads at every preemption boundary: the final hash encodes not
   just how many iterations each thread ran, but the exact sequence of scheduling
   decisions that determined which values were visible at each step. */
static inline uint32_t mix(uint32_t h, uint32_t other)
{
	h ^= other;
	h *= 0x9e3779b9; /* golden ratio hash constant */
	h ^= h >> 16;
	return h;
}

/* Format into a local buffer and emit with a single write(2). The threads are
   raw clone() tasks sharing the FILE table; musl's stdio lock is a no-op for
   non-pthread tasks, so going through printf would let writes interleave or
   double up. A single write() syscall per line is kernel-atomic for our
   virtio-console output path. */
static int thread_fn(void *arg)
{
	struct thread_arg *t = arg;
	char buf[128];

	/* clock_gettime() goes through the vDSO, which executes rdtsc in
	   userspace and triggers a VMEXIT on every call. Avoid it. */
	sched_yield();

	for (;;) {
		t->counter++;
		t->hash = mix(t->hash, t->other->hash);

		if ((t->counter  & REPORT_MASK) == 0) {
			int n = snprintf(buf, sizeof buf,
				"thread %d: n=%lu hash=%08x\n",
				t->id, t->counter, t->hash);
			write(1, buf, n);
			if (t->counter >> EXIT_SHIFT != 0)
				break;
		}
	}

	return 0;
}

int main(void)
{
	setbuf(stdout, NULL);

	pid_t pid = getpid();
	uint64_t boot_tsc = 0;

	if (pid == 1) {
		boot_tsc = rdtsc();
	}

	/* Pin to CPU 0 so both threads compete for the same core, forcing
	   preemption. Without this, each thread may run on its own core
	   and never observe the other's intermediate state. */
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(0, &cpuset);
	sched_setaffinity(0, sizeof(cpuset), &cpuset);

	if (pid == 1) {
		printf("Boot: %lu instructions to reach /init\n", boot_tsc);
	}

	int urand = open("/dev/urandom", O_RDONLY);
	if (urand >= 0) {
		uint8_t buf[32];
		if (read(urand, buf, sizeof(buf)) == sizeof(buf)) {
			printf("urandom: ");
			for (int i = 0; i < 32; i++)
				printf("%02x", buf[i]);
			printf("\n");
		}
		close(urand);
	}

	printf("Spawning %d threads...\n", THREAD_COUNT);

	struct thread_arg args[THREAD_COUNT];
	uint32_t hash = INITIAL_HASH;
	for (int i = 0; i < THREAD_COUNT; i++) {
		args[i] = (struct thread_arg){ 
			.id = i,
			.counter = i,
			.hash = hash,
			.other = &args[(i + THREAD_COUNT - 1) % THREAD_COUNT]
		};
		hash = mix(hash, i);
	}
      
	pid_t pids[THREAD_COUNT];
	for (int i = 0; i < THREAD_COUNT; i++) {
		void *stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
				   MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
		if (stack == MAP_FAILED) {
			perror("mmap");
			return 1;
		}

		pids[i] = clone(thread_fn, (char *)stack + STACK_SIZE,
				CLONE_VM | CLONE_FS | CLONE_FILES | SIGCHLD,
				&args[i]);
		if (pids[i] < 0) {
			perror("clone");
			return 1;
		}
	}

	for (int i = 0; i < THREAD_COUNT; i++) {
		int status;
		waitpid(pids[i], &status, 0);
		printf("thread %d: final n=%lu hash=%08x\n",
			args[i].id, args[i].counter, args[i].hash);
	}

	if (pid == 1) {
		uint64_t final_tsc = rdtsc();
		printf("Final: %lu instructions (%lu since boot)\n",
			final_tsc, final_tsc - boot_tsc);
	}

	reboot(LINUX_REBOOT_CMD_RESTART);
	return 0;
}
