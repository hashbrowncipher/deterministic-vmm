# Deterministic VMM

A toy KVM-based virtual machine monitor that boots unmodified Linux kernels
(v6.19) with fully deterministic execution. Produces identical execution every
time against an adversarial workload.

## How it works

The VMM controls every known source of non-determinism in the guest:

- **TSC (time stamp counter)**: intercepted via a custom KVM patch; returns the
  number of retired instructions instead of wall-clock time.

- **LAPIC timer**: emulated entirely in userspace with a crystal-clock model.
  The timer counts at 1 GHz (crystal rate) with a 8x TSC multiplier, giving a
virtual TSC of 8 GHz. Timer interrupts are delivered at exactly the right
instruction via PMU-driven preemption with single-step precision landing.

- **All other I/O**: minimal emulation of a serial console, IOAPIC, and legacy
  port stubs. No PCI, no networking, no disk — the guest runs from an
initramfs.

## Requirements

- Linux host kernel with the KVM patch from the `linux` submodule
  (`KVM_CAP_X86_ENABLE_EXITS` for RDTSC/RDRAND interception)
- `perf_event_paranoid <= 1` (the VMM uses hardware performance counters)
- Rust toolchain (for building the VMM)
- make

The Makefile downloads a Bootlin toolchain and validates its sha256 hash
against a known value in the Makefile. We use this to compile a Linux kernel
and our bundled test workload. Because the compiler is the same, you should
have the same bytes as I do for both the kernel and test workload. Same bytes
=> same behavior.

## Quick start

```
git submodule update --init

# Check that perf counters are accessible
make check-paranoid

# Build everything
make             # builds VMM; runs twice; verifies determinism of output

# Run
make run
```

## What you'll see

The guest boots a minimal Linux kernel, spawns two threads that hash and mix
data with a data dependent race between threads. Each one does this for 2^29
iterations, and then exits:

```
thread 0: n=335544320 hash=49efdbf8
thread 1: n=335544320 hash=3b28ccd4
thread 1: n=369098752 hash=674af5d0
thread 0: n=369098752 hash=9ce45be2
thread 0: n=402653184 hash=d705e30e
thread 1: n=402653184 hash=4794e760
thread 0: n=436207616 hash=8450e203
thread 1: n=436207616 hash=a7f7cf77
thread 0: n=469762048 hash=da227ad8
thread 1: n=469762048 hash=f84a95b6
thread 0: n=503316480 hash=1a5c4cb0
thread 1: n=503316480 hash=d20570b4
thread 0: n=536870912 hash=d4497dc8
thread 1: n=536870912 hash=c5fe8f86
thread 0: final n=536870912 hash=d4497dc8
thread 1: final n=536870912 hash=c5fe8f86
Final: 13505164472 instructions (12885930001 since boot)
```

## Project structure

```
src/main.rs           VMM core: KVM setup, VMEXIT loop, I/O emulation, preemption
src/lapic.rs          Userspace LAPIC timer with crystal-clock model
src/virtio_console.rs Minimal virtio-console (MMIO transport) for guest output
cpu.toml              CPUID definition for the virtual CPU
guest/init.c          Guest workload (statically linked /init)
guest/kernel.config   Kernel config fragment (applied on top of tinyconfig)
tools/mkcpio/         Deterministic cpio (newc) writer used to build the initramfs
linux/                Linux submodule with KVM patches
Makefile              Build and run targets
```

## Linux patches

The `linux` submodule carries two patches on top of v6.19:

1. **KVM: RDTSC/RDRAND interception** (host) — adds `KVM_CAP_X86_ENABLE_EXITS`
so the VMM can intercept these instructions and return deterministic values.
This patch is needed for the _host_ kernel, not the system being emulated.

2. **clockevents: ceiling division** (guest) — the kernel's ns-to-tick
conversion truncates, which can cause timers to fire up to one APIC tick early.
Under precise emulation the tick handler observes `ktime_get() < expires` and
programs a spurious catch-up timer, doubling the interrupt rate, which is very
expensive under single-step emulation. Ceiling division ensures that timers
always fire at or after the requested time. The guest patch is purely optional:
it speeds up the virtualization, but virtualization functions just fine without
it.

3. **unselect objtool** (build) — removes dependency on objtool during build:
our musl buildroot doesn't have it.
