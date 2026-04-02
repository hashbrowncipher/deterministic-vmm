// SPDX-License-Identifier: Apache-2.0
// Deterministic KVM VMM for booting unmodified Linux.
//
// Boots a bzImage + initramfs in a single-vCPU VM with controlled hardware inputs so that
// execution is fully deterministic: same kernel + same initramfs + same VMM config produces
// identical execution, instruction for instruction.
//
// Usage: deterministic-vmm <bzimage> <initramfs> <cpuid-toml>

mod lapic;
mod virtio_console;

use std::io::{self, Write};
use std::os::unix::io::AsRawFd;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};

use kvm_bindings::{
    kvm_cpuid_entry2, kvm_enable_cap, kvm_guest_debug, kvm_guest_debug_arch,
    kvm_msr_entry, kvm_regs, kvm_segment, kvm_userspace_memory_region, Msrs,
    KVM_CAP_X86_DISABLE_EXITS, KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_SINGLESTEP,
};
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use serde::Deserialize;
use linux_loader::loader::{self, bootparam::boot_e820_entry, KernelLoader};
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Safe wrapper for libc::ioctl that returns errno on failure.
fn ioctl(fd: libc::c_int, request: libc::c_ulong, arg: libc::c_ulong) -> std::io::Result<libc::c_int> {
    let ret = unsafe { libc::ioctl(fd, request, arg) };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

const GUEST_MEM_SIZE: u64 = 256 * 1024 * 1024; // 256 MiB

// Memory layout constants
const BOOT_PARAMS_ADDR: u64 = 0x7000;
const CMDLINE_ADDR: u64 = 0x20000;
const RNG_SEED_ADDR: u64 = 0x21000; // setup_data node for RNG seed
const KERNEL_ADDR: u64 = 0x100000; // 1 MiB — standard bzImage load address
const MPTABLE_ADDR: u64 = 0xF0000; // MP floating pointer + config table (BIOS area)

// KVM address space setup (must not overlap guest RAM)
const TSS_ADDR: u64 = 0xfffb_d000;
const IDENTITY_MAP_ADDR: u64 = 0xfffb_c000;

// Standard IOAPIC MMIO base address
const IOAPIC_ADDR: u32 = 0xFEC0_0000;
// Standard LAPIC MMIO base address
const LAPIC_ADDR: u32 = 0xFEE0_0000;

// Custom KVM capability for RDTSC/RDRAND exit interception (from our kernel patch)
const KVM_CAP_X86_ENABLE_EXITS: u32 = 248;
const KVM_X86_ENABLE_EXITS_RDTSC: u64 = 1 << 0;
const KVM_X86_ENABLE_EXITS_RDRAND: u64 = 1 << 1;
const KVM_EXIT_RDTSC: u32 = 45;
const KVM_EXIT_RDRAND: u32 = 46;
const KVM_EXIT_X86_RDMSR: u32 = 29;
const KVM_EXIT_X86_WRMSR: u32 = 30;

// MSR indices
const MSR_IA32_TSC_DEADLINE: u32 = 0x6E0;

// KVM_CAP_X86_USER_SPACE_MSR: exit to userspace on MSR accesses that KVM doesn't handle.
const KVM_CAP_X86_USER_SPACE_MSR: u32 = 188;

const KERNEL_CMDLINE: &str =
    "clocksource=tsc tsc=reliable console=hvc0 reboot=t unknown_nmi_panic=1 nmi_watchdog=0 loglevel=7 virtio_mmio.device=0x1000@0xd0000000:5";

// E820 memory type
const E820_RAM: u32 = 1;

// Serial UART (16550) I/O ports and registers
const SERIAL_PORT_BASE: u16 = 0x3F8;
const SERIAL_PORT_END: u16 = 0x3FF;
const SERIAL_THR: u16 = 0x3F8; // Transmitter Holding Register (write) / Receive Buffer (read)
const SERIAL_IER: u16 = 0x3F9; // Interrupt Enable Register
const SERIAL_IIR: u16 = 0x3FA; // Interrupt Identification Register (read)
const SERIAL_LCR: u16 = 0x3FB; // Line Control Register
const SERIAL_MCR: u16 = 0x3FC; // Modem Control Register
const SERIAL_LSR: u16 = 0x3FD; // Line Status Register
const SERIAL_MSR: u16 = 0x3FE; // Modem Status Register
const SERIAL_IRQ: u32 = 4;     // COM1 IRQ line

// Virtio console MMIO transport
const VIRTIO_MMIO_BASE: u64 = 0xd000_0000;
const VIRTIO_IRQ: u32 = 5;

// Virtio block MMIO transport


// Virtual TSC frequency model.
//
// The deterministic TSC ticks once per retired instruction. On a real CPU at 5 GHz with IPC 4–6,
// that's 20–30 billion retired instructions/sec, so 100 GHz is a plausible effective frequency.
// We express it as crystal × ratio, since a u32 can't hold 100 GHz directly.
//
// On real Intel hardware, the LAPIC timer is clocked by the crystal oscillator, not the TSC.
// The kernel uses CPUID leaf 0x15 to learn the crystal frequency and derives
// lapic_timer_period from it (crystal_khz * 1000 / HZ). Our VMM must be consistent: the
// LAPIC timer must count at crystal rate, and TSC ticks pass ratio× faster.
const CRYSTAL_HZ: u64 = 1_000_000_000;     // 1 GHz crystal
const TSC_TO_CRYSTAL_RATIO: u64 = 8;
const TSC_BASE_MHZ: u32 = ((CRYSTAL_HZ * TSC_TO_CRYSTAL_RATIO) / 1_000_000) as u32;
const BUS_MHZ: u32 = 100;                  // bus/reference frequency

/// Minimal 16550 UART emulation — just enough for console I/O.
struct Serial {
    ier: u8,         // Interrupt Enable Register
    lcr: u8,         // Line Control Register
    mcr: u8,         // Modem Control Register
    scr: u8,         // Scratch Register
    thr_empty: bool, // THR is empty (ready for next byte)
}

impl Serial {
    fn new() -> Self {
        Serial {
            ier: 0,
            lcr: 0,
            mcr: 0,
            scr: 0,
            thr_empty: true,
        }
    }

    /// Handle a write to a serial port. Returns true if IRQ state may have changed.
    fn handle_out(&mut self, port: u16, data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        let val = data[0];

        // When DLAB (LCR bit 7) is set, ports 0x3F8/0x3F9 are divisor latch low/high
        if self.lcr & 0x80 != 0 && (port == SERIAL_THR || port == SERIAL_IER) {
            return false; // ignore divisor latch writes
        }

        match port {
            SERIAL_THR => {
                let stdout = io::stdout();
                let mut handle = stdout.lock();
                let _ = handle.write_all(data);
                let _ = handle.flush();
                self.thr_empty = true; // we consume instantly
                return self.ier & 0x02 != 0; // IRQ state changed if TX interrupt enabled
            }
            SERIAL_IER => {
                let old = self.ier;
                self.ier = val & 0x0F;
                return self.ier != old;
            }
            0x3FA => {} // FCR (write) — ignore FIFO control
            SERIAL_LCR => { self.lcr = val; }
            SERIAL_MCR => { self.mcr = val; }
            0x3FF => { self.scr = val; } // Scratch register
            _ => {}
        }
        false
    }

    /// Handle a read from a serial port.
    fn handle_in(&self, port: u16, data: &mut [u8]) {
        if data.is_empty() {
            return;
        }

        // DLAB reads
        if self.lcr & 0x80 != 0 && (port == SERIAL_THR || port == SERIAL_IER) {
            data[0] = 0; // divisor latch: return 0
            return;
        }

        data[0] = match port {
            SERIAL_THR => 0,    // no input available
            SERIAL_IER => self.ier,
            SERIAL_IIR => {
                if self.ier & 0x02 != 0 && self.thr_empty {
                    0x02 // TX holding register empty interrupt pending
                } else {
                    0x01 // no interrupt pending
                }
            }
            SERIAL_LCR => self.lcr,
            SERIAL_MCR => self.mcr,
            SERIAL_LSR => {
                let mut lsr = 0x60; // THRE + TEMT (transmitter empty)
                if false { lsr |= 0x01; } // DR: data ready (no input for now)
                lsr
            }
            SERIAL_MSR => 0, // no modem signals
            0x3FF => self.scr,
            _ => 0,
        };
    }

    /// Returns true if an interrupt should be asserted.
    fn irq_pending(&self) -> bool {
        // TX empty interrupt: IER bit 1 set and THR is empty
        self.ier & 0x02 != 0 && self.thr_empty
    }
}

const NUM_IOAPIC_PINS: usize = 24;

/// Userspace IOAPIC emulation for split irqchip mode. The guest programs redirect entries via
/// MMIO at 0xFEC00000. We translate those entries into KVM GSI routing (MSI) entries so that
/// set_irq_line() delivers interrupts through the in-kernel LAPIC.
struct Ioapic {
    id: u32,
    ioregsel: u32,
    redirect_table: [u64; NUM_IOAPIC_PINS],
}

impl Ioapic {
    fn new() -> Self {
        // All redirect entries start masked (bit 16 set)
        let mut redirect_table = [0u64; NUM_IOAPIC_PINS];
        for entry in &mut redirect_table {
            *entry = 1 << 16; // masked
        }
        Ioapic {
            id: 2, // matches MP table
            ioregsel: 0,
            redirect_table,
        }
    }

    fn read_register(&self, reg: u32) -> u32 {
        match reg {
            0x00 => self.id << 24,
            0x01 => ((NUM_IOAPIC_PINS as u32 - 1) << 16) | 0x17, // version 0x17, max redir
            0x02 => self.id << 24, // arbitration ID
            _ if reg >= 0x10 && reg < 0x10 + (NUM_IOAPIC_PINS as u32) * 2 => {
                let pin = ((reg - 0x10) / 2) as usize;
                let entry = self.redirect_table[pin];
                if reg & 1 == 0 {
                    entry as u32 // low 32 bits
                } else {
                    (entry >> 32) as u32 // high 32 bits
                }
            }
            _ => 0,
        }
    }

    /// Write a register. Returns Some(pin) if a redirect entry changed and routing needs update.
    fn write_register(&mut self, reg: u32, val: u32) -> Option<usize> {
        match reg {
            0x00 => { self.id = (val >> 24) & 0xF; None }
            _ if reg >= 0x10 && reg < 0x10 + (NUM_IOAPIC_PINS as u32) * 2 => {
                let pin = ((reg - 0x10) / 2) as usize;
                let entry = &mut self.redirect_table[pin];
                if reg & 1 == 0 {
                    *entry = (*entry & 0xFFFF_FFFF_0000_0000) | val as u64;
                } else {
                    *entry = (*entry & 0x0000_0000_FFFF_FFFF) | ((val as u64) << 32);
                }
                Some(pin)
            }
            _ => None,
        }
    }

    fn handle_mmio_write(&mut self, offset: u64, data: &[u8]) -> Option<usize> {
        let val = match data.len() {
            4 => u32::from_le_bytes(data.try_into().unwrap()),
            _ => return None,
        };
        match offset {
            0x00 => { self.ioregsel = val; None }
            0x10 => self.write_register(self.ioregsel, val),
            _ => None,
        }
    }

    fn handle_mmio_read(&self, offset: u64, data: &mut [u8]) {
        let val = match offset {
            0x00 => self.ioregsel,
            0x10 => self.read_register(self.ioregsel),
            _ => 0,
        };
        if data.len() == 4 {
            data.copy_from_slice(&val.to_le_bytes());
        }
    }
}

use lapic::Lapic;


/// Inject an external interrupt via KVM_SET_VCPU_EVENTS. Only injects when the guest
/// is interruptible (IF=1, no interrupt shadow).
fn inject_interrupt(vcpu: &VcpuFd, vector: u8) -> Result<bool> {
    // Check if guest is interruptible (IF flag in RFLAGS)
    let regs = vcpu.get_regs()?;
    if regs.rflags & (1 << 9) == 0 {
        return Ok(false); // IF=0, guest has interrupts disabled
    }

    let mut events = vcpu.get_vcpu_events()?;
    if events.interrupt.injected != 0 || events.interrupt.shadow != 0 {
        return Ok(false); // already have a pending interrupt or in shadow
    }
    events.interrupt.injected = 1;
    events.interrupt.nr = vector;
    events.interrupt.soft = 0;
    events.interrupt.shadow = 0;
    vcpu.set_vcpu_events(&events)?;
    Ok(true)
}

/// Budget for single-step normalization. The PMU overflow fires SKID_BUDGET
/// instructions before the LAPIC timer deadline, then we single-step to land
/// at the exact deadline. Must exceed the worst-case PMI skid (~100–300 on Intel).
const SKID_BUDGET: u64 = 100;

/// Preemption state machine. The target is the LAPIC timer deadline (absolute TSC).
#[derive(Debug)]
enum PreemptState {
    /// Guest is running freely. PMU overflow will fire at approximately
    /// deadline - SKID_BUDGET instructions.
    Running,
    /// PMU overflow fired. Single-stepping one instruction at a time toward
    /// the exact LAPIC timer deadline.
    SingleStepping { target_tsc: u64 },
}

/// Open a single perf counter for instructions retired that serves BOTH as the TSC source
/// (read for instruction count) and the preemption trigger (overflow generates SIGIO).
/// Using one counter eliminates drift between two separate counters.
fn open_insn_counter() -> Result<std::os::unix::io::RawFd> {
    let mut attr = [0u8; 136];

    // type = PERF_TYPE_HARDWARE (0), size = 136, config = PERF_COUNT_HW_INSTRUCTIONS (1)
    attr[0..4].copy_from_slice(&0u32.to_ne_bytes());
    attr[4..8].copy_from_slice(&136u32.to_ne_bytes());
    attr[8..16].copy_from_slice(&1u64.to_ne_bytes());

    // sample_period at offset 16. Initial period is huge — no LAPIC timer is armed yet.
    // reprogram_counter() sets the real period when the guest programs the LAPIC timer.
    let initial_period: u64 = 1 << 60;
    attr[16..24].copy_from_slice(&initial_period.to_ne_bytes());

    let flags_guest_only: u64 = (1 << 0) | (1 << 19); // disabled + exclude_host
    let flags_all: u64 = 1 << 0; // disabled only

    let mut last_err = None;
    for (label, flags) in [("exclude_host", flags_guest_only), ("all", flags_all)] {
        attr[40..48].copy_from_slice(&flags.to_ne_bytes());

        let fd = unsafe {
            libc::syscall(libc::SYS_perf_event_open,
                attr.as_ptr(), 0i32, -1i32, -1i32, 0u64)
        } as i32;

        if fd >= 0 {
            // Configure async signal delivery: overflow → SIGIO → interrupts KVM_RUN
            unsafe {
                const F_SETSIG: libc::c_int = 10;
                libc::fcntl(fd, libc::F_SETOWN, libc::getpid());
                libc::fcntl(fd, libc::F_SETFL, libc::O_ASYNC);
                libc::fcntl(fd, F_SETSIG, libc::SIGIO);
            }

            const PERF_EVENT_IOC_RESET: libc::c_ulong = 0x2403;
            const PERF_EVENT_IOC_ENABLE: libc::c_ulong = 0x2400;
            let _ = ioctl(fd, PERF_EVENT_IOC_RESET, 0);
            let _ = ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
            eprintln!("pmu: instruction counter enabled (mode={}, fd={}, skid_budget={})",
                label, fd, SKID_BUDGET);
            return Ok(fd);
        }
        last_err = Some(std::io::Error::last_os_error());
    }

    Err(format!("perf_event_open failed: {} — PMU instruction counting is required",
        last_err.expect("loop ran at least once, so last_err is set on failure")).into())
}

fn read_insn_counter(fd: std::os::unix::io::RawFd) -> u64 {
    let mut buf = [0u8; 8];
    let ret = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 8) };
    if ret != 8 {
        return 0;
    }
    u64::from_ne_bytes(buf)
}

/// Deterministic hardware state — controls what the guest sees for TSC.
struct DeterministicHw {
    tsc: u64,
    insn_counter_fd: std::os::unix::io::RawFd,
    last_insn_count: u64,
    /// Set true the first time the guest executes an intercepted instruction
    /// (currently rdtsc) from CPL=3. Used to stamp the "time to reach userspace
    /// /init" point on the host side, independent of any guest cooperation.
    user_reached: bool,
}

impl DeterministicHw {
    fn new(insn_counter_fd: std::os::unix::io::RawFd) -> Self {
        let last_insn_count = read_insn_counter(insn_counter_fd);
        DeterministicHw {
            tsc: 0,
            insn_counter_fd,
            last_insn_count,
            user_reached: false,
        }
    }

    /// Advance TSC by the number of guest instructions retired since the last call.
    fn advance_tsc(&mut self) -> u64 {
        let now = read_insn_counter(self.insn_counter_fd);
        let delta = now.wrapping_sub(self.last_insn_count);
        self.last_insn_count = now;
        self.tsc += delta;
        delta
    }

    /// Return the current deterministic TSC value. TSC is advanced by advance_tsc()
    /// after each KVM_RUN, so this just returns the current accumulated count.
    fn rdtsc(&self) -> u64 {
        self.tsc
    }

    /// Reset the perf counter for a clean next overflow period. Uses rr's proven
    /// DISABLE → RESET → PERIOD → ENABLE sequence. RESET zeros the read() value
    /// (keeping our TSC delta math correct), PERIOD reprograms the overflow countdown.
    fn reprogram_counter(&mut self, next_period: u64) {
        const PERF_EVENT_IOC_DISABLE: libc::c_ulong = 0x2401;
        const PERF_EVENT_IOC_RESET: libc::c_ulong = 0x2403;
        const PERF_EVENT_IOC_PERIOD: libc::c_ulong = 0x40082404;
        const PERF_EVENT_IOC_ENABLE: libc::c_ulong = 0x2400;
        let _ = ioctl(self.insn_counter_fd, PERF_EVENT_IOC_DISABLE, 0);
        let _ = ioctl(self.insn_counter_fd, PERF_EVENT_IOC_RESET, 0);
        let _ = ioctl(self.insn_counter_fd, PERF_EVENT_IOC_PERIOD,
            &next_period as *const u64 as libc::c_ulong);
        let _ = ioctl(self.insn_counter_fd, PERF_EVENT_IOC_ENABLE, 0);
        self.last_insn_count = 0;
    }
}

fn parse_args() -> Result<(String, String, String)> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: {} <bzimage> <cpuid-toml> <initramfs.cpio>", args[0]);
        eprintln!("  set VMM_QUIET=1 to suppress non-deterministic host-side diagnostics");
        process::exit(1);
    }
    Ok((args[1].clone(), args[2].clone(), args[3].clone()))
}

/// True when `VMM_QUIET=1` is set in the environment. Suppresses host-side
/// diagnostics that are not bit-for-bit reproducible across runs (wall-clock
/// elapsed time, host-side exit counters such as Debug exits driven by perf
/// skid, etc.). Guest output and guest-instruction-counted diagnostics are
/// always printed.
fn quiet() -> bool {
    use std::sync::OnceLock;
    static Q: OnceLock<bool> = OnceLock::new();
    *Q.get_or_init(|| std::env::var("VMM_QUIET").map(|v| v == "1").unwrap_or(false))
}

fn open_kvm() -> Result<Kvm> {
    let kvm = Kvm::new()?;
    let api_version = kvm.get_api_version();
    if api_version != 12 {
        return Err(format!("KVM API version {} (expected 12)", api_version).into());
    }
    Ok(kvm)
}

fn create_vm(kvm: &Kvm) -> Result<VmFd> {
    let vm = kvm.create_vm()?;

    // TSS and identity map addresses are required for x86 VMs
    vm.set_tss_address(TSS_ADDR as usize)?;
    vm.set_identity_map_address(IDENTITY_MAP_ADDR)?;

    // No KVM_CREATE_IRQCHIP or KVM_CAP_SPLIT_IRQCHIP — all interrupt control is in userspace.
    // This means lapic_in_kernel() returns false, so HLT exits to userspace and we control
    // all timer and interrupt delivery deterministically.
    eprintln!("irqchip: none (fully userspace LAPIC/IOAPIC)");
    Ok(vm)
}

fn allocate_guest_memory(vm: &VmFd) -> Result<GuestMemoryMmap> {
    let guest_mem =
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0), GUEST_MEM_SIZE as usize)])?;

    let host_addr = guest_mem
        .get_host_address(GuestAddress(0))
        .map_err(|e| format!("failed to get host address for guest memory: {}", e))?;

    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: GUEST_MEM_SIZE,
        userspace_addr: host_addr as u64,
        flags: 0,
    };
    // SAFETY: host_addr points to a valid mmap'd region of GUEST_MEM_SIZE bytes that will live
    // as long as guest_mem.
    unsafe { vm.set_user_memory_region(mem_region)? };

    Ok(guest_mem)
}

fn load_kernel(
    guest_mem: &GuestMemoryMmap,
    bzimage_path: &str,
) -> Result<loader::KernelLoaderResult> {
    let mut kernel_file = std::fs::File::open(bzimage_path)
        .map_err(|e| format!("failed to open bzImage '{}': {}", bzimage_path, e))?;

    let result = loader::bzimage::BzImage::load(
        guest_mem,
        Some(GuestAddress(KERNEL_ADDR)),
        &mut kernel_file,
        Some(GuestAddress(0)),
    )?;

    eprintln!(
        "kernel: loaded at {:#x}, end at {:#x}, setup_header present: {}",
        result.kernel_load.raw_value(),
        result.kernel_end,
        result.setup_header.is_some(),
    );
    if let Some(ref hdr) = result.setup_header {
        let version = { hdr.version };
        let loadflags = { hdr.loadflags };
        let code32_start = { hdr.code32_start };
        eprintln!(
            "kernel: protocol {:#06x}, loadflags {:#04x}, code32_start {:#x}",
            version, loadflags, code32_start,
        );
    }
    Ok(result)
}

/// Load the initramfs cpio archive into guest memory. Place it just below the top of RAM,
/// page-aligned downward, to maximize the gap between kernel and initrd.
fn load_initramfs(guest_mem: &GuestMemoryMmap, initramfs_path: &str) -> Result<(u64, u64)> {
    let initramfs_data = std::fs::read(initramfs_path)
        .map_err(|e| format!("failed to read initramfs '{}': {}", initramfs_path, e))?;

    let initramfs_size = initramfs_data.len() as u64;
    // Align the initramfs start address down to a page boundary
    let initramfs_addr = (GUEST_MEM_SIZE - initramfs_size) & !0xFFF;

    guest_mem
        .write_slice(&initramfs_data, GuestAddress(initramfs_addr))
        .map_err(|e| format!("failed to write initramfs to guest memory: {}", e))?;

    eprintln!(
        "initramfs: loaded at {:#x}, size {:#x} ({} bytes)",
        initramfs_addr, initramfs_size, initramfs_size
    );
    Ok((initramfs_addr, initramfs_size))
}

/// Write the kernel command line to guest memory and return its GPA.
/// Write a minimal Intel MP table so the kernel discovers the IOAPIC and can route interrupts.
/// Without this, the kernel says "ACPI MADT or MP tables are not detected" and IRQs don't work.
///
/// Layout at MPTABLE_ADDR:
///   +0x00: MP Floating Pointer (16 bytes) — points to config table at +0x10
///   +0x10: MP Config Table header (44 bytes)
///   +0x3C: CPU entry (20 bytes)
///   +0x50: Bus entry (8 bytes) — ISA bus
///   +0x58: IOAPIC entry (8 bytes)
///   +0x60: Interrupt source entries (8 bytes each) — ISA IRQs 0–15
fn write_mptable(guest_mem: &GuestMemoryMmap) -> Result<()> {
    let config_addr = MPTABLE_ADDR + 0x10;
    let mut buf: Vec<u8> = Vec::new();

    // --- MP Config Table entries (appended after the 44-byte header) ---
    let mut entries: Vec<u8> = Vec::new();

    // CPU entry (type 0, 20 bytes)
    let mut cpu = [0u8; 20];
    cpu[0] = 0; // type = MP_PROCESSOR
    cpu[1] = 0; // APIC ID 0
    cpu[2] = 0x14; // APIC version (arbitrary modern value)
    cpu[3] = 0x03; // CPU_ENABLED | CPU_BOOTPROCESSOR
    // cpufeature (bytes 4-7): family 6, model 0x5E, stepping 3 → same as CPUID leaf 1 EAX
    let sig: u32 = 0x000506E3;
    cpu[4..8].copy_from_slice(&sig.to_le_bytes());
    // featureflag (bytes 8-11): copy from CPUID leaf 1 EDX
    let features: u32 = 0x078BEBFD;
    cpu[8..12].copy_from_slice(&features.to_le_bytes());
    entries.extend_from_slice(&cpu);

    // Bus entry (type 1, 8 bytes) — ISA bus, ID 0
    let mut bus = [0u8; 8];
    bus[0] = 1; // type = MP_BUS
    bus[1] = 0; // bus ID
    bus[2..8].copy_from_slice(b"ISA   ");
    entries.extend_from_slice(&bus);

    // IOAPIC entry (type 2, 8 bytes)
    let mut ioapic = [0u8; 8];
    ioapic[0] = 2; // type = MP_IOAPIC
    ioapic[1] = 2; // APIC ID 2 (different from CPU's 0)
    ioapic[2] = 0x20; // version (32 entries)
    ioapic[3] = 0x01; // MPC_APIC_USABLE
    ioapic[4..8].copy_from_slice(&IOAPIC_ADDR.to_le_bytes());
    entries.extend_from_slice(&ioapic);

    // Interrupt source entries: map ISA IRQs 0–15 to IOAPIC pins 0–15
    for irq in 0u8..16 {
        let mut intsrc = [0u8; 8];
        intsrc[0] = 3; // type = MP_INTSRC
        intsrc[1] = 0; // irqtype = mp_INT
        intsrc[2] = 0; // irqflag low byte: default polarity/trigger
        intsrc[3] = 0; // irqflag high byte
        intsrc[4] = 0; // srcbus = ISA bus 0
        intsrc[5] = irq; // srcbusirq
        intsrc[6] = 2; // dstapic = IOAPIC ID 2
        intsrc[7] = irq; // dstirq = pin N
        entries.extend_from_slice(&intsrc);
    }

    // --- MP Config Table header (44 bytes) ---
    let table_len = (44 + entries.len()) as u16;
    let mut header = [0u8; 44];
    header[0..4].copy_from_slice(b"PCMP");
    header[4..6].copy_from_slice(&table_len.to_le_bytes());
    header[6] = 0x04; // spec revision 1.4
    // header[7] = checksum (filled below)
    header[8..16].copy_from_slice(b"BUILDVMM");
    header[16..28].copy_from_slice(b"DETERM-VM   ");
    // oemptr (28-31): 0
    // oemsize (32-33): 0
    let entry_count = (1 + 1 + 1 + 16) as u16; // 1 cpu + 1 bus + 1 ioapic + 16 intsrc
    header[34..36].copy_from_slice(&entry_count.to_le_bytes());
    header[36..40].copy_from_slice(&LAPIC_ADDR.to_le_bytes());
    // reserved (40-43): 0

    // Compute config table checksum
    let mut cksum: u8 = 0;
    for &b in &header { cksum = cksum.wrapping_add(b); }
    for &b in &entries { cksum = cksum.wrapping_add(b); }
    header[7] = 0u8.wrapping_sub(cksum);

    buf.extend_from_slice(&header);
    buf.extend_from_slice(&entries);

    // Write config table at config_addr
    guest_mem.write_slice(&buf, GuestAddress(config_addr))?;

    // --- MP Floating Pointer (16 bytes at MPTABLE_ADDR) ---
    let mut mpf = [0u8; 16];
    mpf[0..4].copy_from_slice(b"_MP_");
    mpf[4..8].copy_from_slice(&(config_addr as u32).to_le_bytes());
    mpf[8] = 1; // length in 16-byte paragraphs
    mpf[9] = 4; // MP spec version 1.4
    // mpf[10] = checksum (filled below)
    // feature bytes: all 0 (use config table, not default config)

    let mut cksum: u8 = 0;
    for &b in &mpf { cksum = cksum.wrapping_add(b); }
    mpf[10] = 0u8.wrapping_sub(cksum);

    guest_mem.write_slice(&mpf, GuestAddress(MPTABLE_ADDR))?;

    eprintln!(
        "mptable: written at {:#x}, config at {:#x}, {} entries",
        MPTABLE_ADDR, config_addr, entry_count
    );
    Ok(())
}

fn write_cmdline(guest_mem: &GuestMemoryMmap) -> Result<u64> {
    let cmdline_bytes = KERNEL_CMDLINE.as_bytes();
    guest_mem.write_slice(cmdline_bytes, GuestAddress(CMDLINE_ADDR))?;
    // Null-terminate
    guest_mem.write_slice(&[0u8], GuestAddress(CMDLINE_ADDR + cmdline_bytes.len() as u64))?;
    Ok(CMDLINE_ADDR)
}

/// Set up the Linux boot parameters ("zero page") at BOOT_PARAMS_ADDR. This includes the setup
/// header from the bzImage, the kernel command line pointer, initrd location, and the e820 memory
/// map.
fn write_boot_params(
    guest_mem: &GuestMemoryMmap,
    kernel_result: &loader::KernelLoaderResult,
    initramfs_addr: u64,
    initramfs_size: u64,
    cmdline_addr: u64,
) -> Result<()> {
    use linux_loader::loader::bootparam::boot_params;

    let mut params = boot_params::default();

    // Copy setup header from the loaded bzImage
    if let Some(ref hdr) = kernel_result.setup_header {
        params.hdr = *hdr;
    }

    // Boot protocol magic
    params.hdr.boot_flag = 0xAA55;
    params.hdr.header = 0x5372_6448; // "HdrS"
    params.hdr.type_of_loader = 0xFF; // undefined loader
    params.hdr.loadflags |= 0x01; // LOADED_HIGH

    // Command line
    params.hdr.cmd_line_ptr = cmdline_addr as u32;

    // Initramfs
    params.hdr.ramdisk_image = initramfs_addr as u32;
    params.hdr.ramdisk_size = initramfs_size as u32;
    // For addresses above 4 GiB, the ext_ fields would be needed, but our 256 MiB guest fits
    // in 32 bits.

    // E820 memory map:
    //   0x00000000 – 0x0009FFFF: usable RAM (640 KiB conventional)
    //   0x000F0000 – 0x000FFFFF: reserved (BIOS area — MP table lives here)
    //   0x00100000 – top of RAM:  usable RAM (extended memory)
    params.e820_entries = 3;
    params.e820_table[0] = boot_e820_entry {
        addr: 0,
        size: 0xA0000,
        type_: E820_RAM,
    };
    params.e820_table[1] = boot_e820_entry {
        addr: 0xF0000,
        size: 0x10000,
        type_: 2, // E820_RESERVED
    };
    params.e820_table[2] = boot_e820_entry {
        addr: 0x100000,
        size: GUEST_MEM_SIZE - 0x100000,
        type_: E820_RAM,
    };

    // Write a setup_data node with a deterministic RNG seed so the kernel's CRNG
    // initializes immediately. The seed is fixed — determinism is the point.
    //
    // struct setup_data { u64 next; u32 type; u32 len; u8 data[32]; }
    const SETUP_RNG_SEED: u32 = 9;
    let mut setup_data = [0u8; 8 + 4 + 4 + 32]; // next + type + len + 32 bytes of seed
    // next = 0 (end of list)
    setup_data[8..12].copy_from_slice(&SETUP_RNG_SEED.to_le_bytes());
    setup_data[12..16].copy_from_slice(&32u32.to_le_bytes());
    // Deterministic seed: SHA-256("deterministic-vmm") truncated, or any fixed bytes.
    setup_data[16..48].copy_from_slice(
        b"\xd1\x2a\x8b\x3f\x47\x6e\x91\x05\xbc\x4d\xe2\x73\xa0\x58\x1f\xc6\
          \x9e\x7b\x24\xd8\x63\xf0\x15\x4a\x87\xcc\x3e\x59\xb1\x06\x2d\x7f"
    );
    guest_mem.write_slice(&setup_data, GuestAddress(RNG_SEED_ADDR))?;
    params.hdr.setup_data = RNG_SEED_ADDR;

    // Write the boot_params struct to guest memory
    guest_mem.write_obj(params, GuestAddress(BOOT_PARAMS_ADDR))?;

    eprintln!(
        "boot_params: written at {:#x}, cmdline at {:#x}, initrd at {:#x}",
        BOOT_PARAMS_ADDR, cmdline_addr, initramfs_addr
    );
    Ok(())
}


/// CPUID leaf entry as deserialized from the standard-cpu TOML file.
#[derive(Deserialize)]
struct CpuidLeaf {
    leaf: u32,
    subleaf: u32,
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
}

#[derive(Deserialize)]
struct CpuidFile {
    cpuid: Vec<CpuidLeaf>,
}

fn load_cpuid_file(path: &str) -> Result<Vec<CpuidLeaf>> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read CPUID file '{}': {}", path, e))?;
    let file: CpuidFile = toml::from_str(&contents)
        .map_err(|e| format!("failed to parse CPUID file '{}': {}", path, e))?;
    Ok(file.cpuid)
}

/// Build the vCPU's CPUID table from the TOML file, plus VMM-synthesized leaves for TSC/LAPIC
/// timer frequency (0x15, 0x16). These are generated here rather than in the TOML because
/// they're tightly coupled to the VMM's LAPIC timer implementation.
fn configure_cpuid(vcpu: &VcpuFd, cpuid_leaves: &[CpuidLeaf]) -> Result<()> {
    let mut entries: Vec<kvm_cpuid_entry2> = cpuid_leaves
        .iter()
        .map(|leaf| kvm_cpuid_entry2 {
            function: leaf.leaf,
            index: leaf.subleaf,
            // KVM_CPUID_FLAG_SIGNIFICANT_INDEX: tell KVM this entry is subleaf-specific.
            // Leaves 0x04, 0x07, 0x0B, 0x0D, 0x12, 0x14, 0x17, 0x18 use subleaves.
            flags: match leaf.leaf {
                0x04 | 0x07 | 0x0B | 0x0D | 0x12 | 0x14 | 0x17 | 0x18 => 1,
                _ => 0,
            },
            eax: leaf.eax,
            ebx: leaf.ebx,
            ecx: leaf.ecx,
            edx: leaf.edx,
            padding: [0; 3],
        })
        .collect();

    let synth_base = kvm_cpuid_entry2 {
        function: 0, index: 0, flags: 0,
        eax: 0, ebx: 0, ecx: 0, edx: 0, padding: [0; 3],
    };

    // Leaf 0x15: TSC / Core Crystal Clock. The kernel uses this to derive tsc_khz (skipping
    // runtime calibration) and lapic_timer_period (= crystal_khz * 1000 / HZ).
    entries.push(kvm_cpuid_entry2 {
        function: 0x15,
        eax: 1,                                         // denominator
        ebx: TSC_TO_CRYSTAL_RATIO as u32,               // numerator
        ecx: CRYSTAL_HZ as u32,                         // crystal frequency in Hz
        ..synth_base
    });

    // Leaf 0x16: Processor Frequency Information (MHz). Informational only — the kernel
    // prefers leaf 0x15 for calibration, but logs these values.
    entries.push(kvm_cpuid_entry2 {
        function: 0x16,
        eax: TSC_BASE_MHZ,  // base frequency
        ebx: TSC_BASE_MHZ,  // max frequency
        ecx: BUS_MHZ,       // bus/reference frequency
        ..synth_base
    });

    let cpuid = kvm_bindings::CpuId::from_entries(&entries)
        .map_err(|e| format!("failed to build CpuId: {:?}", e))?;
    vcpu.set_cpuid2(&cpuid)?;
    eprintln!("cpuid: loaded {} entries from file, 2 synthesized (0x15, 0x16)", cpuid_leaves.len());
    Ok(())
}

/// Set up 32-bit protected mode with flat segments. The Linux boot protocol enters at
/// code32_start in protected mode — the kernel handles the transition to long mode itself.
fn configure_sregs(vcpu: &VcpuFd) -> Result<()> {
    let mut sregs = vcpu.get_sregs()?;

    // CR0: Protection Enable only. No paging — the kernel sets that up.
    sregs.cr0 = 1 << 0; // PE
    sregs.cr4 = 0;
    sregs.cr3 = 0;
    sregs.efer = 0;

    // APIC base: enable APIC, mark as BSP, set base address to 0xFEE00000
    sregs.apic_base = (LAPIC_ADDR as u64) | (1 << 11) | (1 << 8); // enable + BSP

    // Flat 32-bit code segment, ring 0
    sregs.cs = kvm_segment {
        base: 0,
        limit: 0xFFFF_FFFF,
        selector: 0x10, // GDT entry 2
        type_: 0xB,     // execute/read, accessed
        present: 1,
        dpl: 0,
        db: 1,  // 32-bit
        s: 1,   // code/data segment
        l: 0,   // not 64-bit
        g: 1,   // 4K granularity
        avl: 0,
        unusable: 0,
        padding: 0,
    };

    // Flat 32-bit data segment, ring 0
    let data_seg = kvm_segment {
        base: 0,
        limit: 0xFFFF_FFFF,
        selector: 0x18, // GDT entry 3
        type_: 0x3,     // read/write, accessed
        present: 1,
        dpl: 0,
        db: 1,  // 32-bit
        s: 1,
        l: 0,
        g: 1,
        avl: 0,
        unusable: 0,
        padding: 0,
    };
    sregs.ds = data_seg;
    sregs.es = data_seg;
    sregs.fs = data_seg;
    sregs.gs = data_seg;
    sregs.ss = data_seg;

    vcpu.set_sregs(&sregs)?;
    Ok(())
}

fn configure_regs(vcpu: &VcpuFd, kernel_entry: u64) -> Result<()> {
    let regs = kvm_regs {
        rip: kernel_entry,
        rsi: BOOT_PARAMS_ADDR, // Linux boot protocol: RSI = pointer to boot_params
        rflags: 0x2,           // reserved bit must be 1
        rsp: 0,
        ..Default::default()
    };
    vcpu.set_regs(&regs)?;
    Ok(())
}

/// Set MSR values so the kernel doesn't complain about old microcode or disabled features.
fn configure_msrs(vcpu: &VcpuFd) -> Result<()> {
    let msrs = Msrs::from_entries(&[
        kvm_msr_entry {
            index: 0x1A0, // IA32_MISC_ENABLE: enable fast string operations (bit 0)
            data: 1,
            ..Default::default()
        },
        kvm_msr_entry {
            index: 0x10A, // IA32_ARCH_CAPABILITIES: declare "not vulnerable" to everything
            data: (1 << 0)  // RDCL_NO (no Meltdown)
                | (1 << 4)  // SSB_NO (no Speculative Store Bypass)
                | (1 << 5)  // MDS_NO
                | (1 << 6)  // PSCHANGE_MC_NO (no ITLB_MULTIHIT)
                | (1 << 8)  // TAA_NO
                | (1 << 13) // SBDR_SSDP_NO
                | (1 << 14) // FBSDP_NO
                | (1 << 15) // PSDP_NO
                | (1 << 20) // BHI_NO
                | (1 << 24) // PBRSB_NO
                | (1 << 26) // GDS_NO
                | (1 << 27) // RFDS_NO
                | (1u64 << 62), // ITS_NO
            ..Default::default()
        },
    ]).map_err(|e| format!("failed to create MSR entries: {:?}", e))?;
    vcpu.set_msrs(&msrs)?;
    Ok(())
}

fn configure_exit_controls(kvm: &Kvm, vm: &VmFd) -> Result<()> {
    // Ensure KVM doesn't optimize away exits for MWAIT, HLT, PAUSE, CSTATE
    let supported = kvm.check_extension_raw(KVM_CAP_X86_DISABLE_EXITS as u64);
    if supported > 0 {
        let cap = kvm_enable_cap {
            cap: KVM_CAP_X86_DISABLE_EXITS,
            args: [0, 0, 0, 0],
            ..Default::default()
        };
        vm.enable_cap(&cap)?;
    }

    // Enable RDTSC and RDRAND exits via our custom kernel patch
    let supported = kvm.check_extension_raw(KVM_CAP_X86_ENABLE_EXITS as u64);
    if supported > 0 {
        let flags = KVM_X86_ENABLE_EXITS_RDTSC | KVM_X86_ENABLE_EXITS_RDRAND;
        let cap = kvm_enable_cap {
            cap: KVM_CAP_X86_ENABLE_EXITS,
            args: [flags, 0, 0, 0],
            ..Default::default()
        };
        vm.enable_cap(&cap)?;
        eprintln!("exits: RDTSC and RDRAND interception enabled");
    } else {
        return Err("KVM_CAP_X86_ENABLE_EXITS not supported — need patched kernel".into());
    }

    // Enable userspace MSR handling so that filtered MSR accesses exit to userspace
    // instead of injecting #GP. We then set up a filter to deny (= intercept) writes
    // to IA32_TSC_DEADLINE, since KVM handles it internally but we need it in userspace
    // for our deterministic LAPIC timer.
    let supported = kvm.check_extension_raw(KVM_CAP_X86_USER_SPACE_MSR as u64);
    if supported > 0 {
        const KVM_MSR_EXIT_REASON_UNKNOWN: u64 = 1 << 1;
        const KVM_MSR_EXIT_REASON_FILTER: u64 = 1 << 2;
        let cap = kvm_enable_cap {
            cap: KVM_CAP_X86_USER_SPACE_MSR,
            args: [KVM_MSR_EXIT_REASON_UNKNOWN | KVM_MSR_EXIT_REASON_FILTER, 0, 0, 0],
            ..Default::default()
        };
        vm.enable_cap(&cap)?;
        eprintln!("exits: userspace MSR handling enabled");
    }

    Ok(())
}

/// Set up a KVM MSR filter to intercept reads and writes to IA32_TSC_DEADLINE (0x6E0).
/// Without this, KVM handles it internally (even without an in-kernel LAPIC), silently
/// eating the writes. The filter denies access, which — combined with
/// KVM_MSR_EXIT_REASON_FILTER — makes KVM exit to userspace so we can handle it.
fn configure_msr_filter(vm: &VmFd) -> Result<()> {
    // The MSR filter bitmap: one bit per MSR starting at `base`. We only need one MSR
    // (0x6E0), so the bitmap covers 8 MSRs starting at 0x6E0, with bit 0 clear (deny).
    // In KVM_MSR_FILTER_DEFAULT_ALLOW mode, a 0 bit means "deny" (exit to userspace).
    // Deny all MSRs in [0x6E0, 0x6E0+8). A zero bit = denied in DEFAULT_ALLOW mode.
    // The kernel reads BITS_TO_LONGS(nmsrs) * sizeof(long) bytes = 8 bytes for nmsrs=8.
    let bitmap: [u8; 8] = [0x00; 8];

    #[repr(C)]
    #[derive(Default)]
    struct KvmMsrFilterRange {
        flags: u32,
        nmsrs: u32,
        base: u32,
        _pad: u32,
        bitmap: u64, // pointer
    }

    #[repr(C)]
    struct KvmMsrFilter {
        flags: u32,
        _pad: u32,
        ranges: [KvmMsrFilterRange; 16],
    }

    const KVM_MSR_FILTER_READ: u32 = 1 << 0;
    const KVM_MSR_FILTER_WRITE: u32 = 1 << 1;
    const KVM_MSR_FILTER_DEFAULT_ALLOW: u32 = 0;
    const KVMIO: u64 = 0xAE;
    // KVM_X86_SET_MSR_FILTER = _IOW(KVMIO, 0xc6, struct kvm_msr_filter)
    // Size of KvmMsrFilter = 8 + 16*24 = 392
    const KVM_X86_SET_MSR_FILTER: libc::c_ulong =
        (1 << 30) | ((392 & 0x3FFF) << 16) | (KVMIO << 8) | 0xc6;

    let mut filter = KvmMsrFilter {
        flags: KVM_MSR_FILTER_DEFAULT_ALLOW,
        _pad: 0,
        ranges: Default::default(),
    };

    filter.ranges[0] = KvmMsrFilterRange {
        flags: KVM_MSR_FILTER_READ | KVM_MSR_FILTER_WRITE,
        nmsrs: 8, // bitmap covers 8 MSRs (minimum granularity)
        base: MSR_IA32_TSC_DEADLINE,
        _pad: 0,
        bitmap: bitmap.as_ptr() as u64,
    };

    let ret = ioctl(
        vm.as_raw_fd(),
        KVM_X86_SET_MSR_FILTER,
        &filter as *const KvmMsrFilter as libc::c_ulong,
    )?;
    if ret < 0 {
        return Err("KVM_X86_SET_MSR_FILTER failed".into());
    }
    eprintln!("exits: MSR filter installed for IA32_TSC_DEADLINE");
    Ok(())
}

/// Result of handling an I/O OUT.
enum IoOutResult {
    None,
    SerialOutput,   // serial THR was written (data sent to stdout)
    SerialIrqChange, // serial IRQ state may have changed
}

/// Handle an I/O OUT.
fn handle_io_out(serial: &mut Serial, port: u16, data: &[u8]) -> IoOutResult {
    match port {
        SERIAL_PORT_BASE..=SERIAL_PORT_END => {
            let is_thr = port == SERIAL_THR && (serial.lcr & 0x80 == 0);
            let irq_changed = serial.handle_out(port, data);
            if irq_changed {
                IoOutResult::SerialIrqChange
            } else if is_thr {
                IoOutResult::SerialOutput
            } else {
                IoOutResult::None
            }
        }
        // Everything else: silently ignore writes.
        // PIT (0x40-0x43), PIC (0x20-0x21, 0xa0-0xa1), CMOS (0x70-0x71),
        // system control (0x61), PCI config (0xcf8-0xcff), POST (0x80, 0xed)
        0x40..=0x43 | 0x20 | 0x21 | 0xA0 | 0xA1 | 0x70 | 0x71
        | 0x61 | 0xCF8..=0xCFF | 0x80 | 0xED
        | 0x2E8..=0x2EF   // COM4
        | 0x2F8..=0x2FF   // COM2
        | 0x3E8..=0x3EF   // COM3
        => IoOutResult::None,
        _ => {
            eprintln!("io: unhandled OUT port={:#06x} data={:02x?}", port, data);
            IoOutResult::None
        }
    }
}

/// Handle an I/O IN.
fn handle_io_in(serial: &Serial, port: u16, data: &mut [u8]) {
    match port {
        SERIAL_PORT_BASE..=SERIAL_PORT_END => serial.handle_in(port, data),

        // CMOS/RTC data: return 0 (0xFF makes the kernel spin reading the clock)
        0x71 => { data[0] = 0; }
        // PIC: return 0 (no pending interrupts)
        0x20 | 0x21 | 0xA0 | 0xA1 => { data[0] = 0; }
        // System control port: NMI reason register (port 0x61). Return 0 so that NMIs
        // injected via KVM_NMI are classified as "unknown" and trigger unknown_nmi_panic.
        // Returning 0xFF here would set NMI_REASON_SERR/IOCHK bits, causing the kernel to
        // handle the NMI as a PCI error instead of panicking.
        0x61 => { data[0] = 0; }

        // Everything else: 0xFF (floating bus)
        _ => {
            if !matches!(port, 0x80 | 0xED | 0x70 | 0x40..=0x43
                | 0x2E8..=0x2EF   // COM4
                | 0x2F8..=0x2FF   // COM2
                | 0x3E8..=0x3EF   // COM3
            ) {
                eprintln!("io: unhandled IN port={:#06x} len={}", port, data.len());
            }
            for b in data.iter_mut() {
                *b = 0xFF;
            }
        }
    }
}

/// After each VMEXIT, classify what happened so we can act on it without holding a borrow on
/// the VcpuFd (which `VcpuExit<'_>` borrows).
#[derive(Debug)]
enum ExitAction {
    Io,        // IO in/out handled (non-serial)
    Mmio,      // MMIO read/write handled
    Intr,      // host signal interrupted KVM_RUN
    SerialOutput, // serial THR was written — data went to stdout
    CheckIrq,  // serial IRQ state may have changed → route through IOAPIC → LAPIC
    Rdtsc,
    Rdrand,
    Wrmsr,
    Rdmsr,
    VirtioKick,    // virtio console transmit queue kicked
    Halted,
    Debug,
    Shutdown,
    FailEntry(u64, u32),
    InternalError,
    UnhandledExit(String),
}

struct ExitCounts {
    started: std::time::Instant,
    io: u64,
    mmio: u64,
    intr: u64,
    serial_output: u64,
    check_irq: u64,
    rdtsc: u64,
    rdrand: u64,
    wrmsr: u64,
    rdmsr: u64,
    virtio_kick: u64,
    halted: u64,
    debug: u64,
    shutdown: u64,
    fail_entry: u64,
    internal_error: u64,
    unhandled: u64,
}

impl ExitCounts {
    fn new() -> Self {
        Self {
            started: std::time::Instant::now(),
            io: 0, mmio: 0, intr: 0, serial_output: 0, check_irq: 0,
            rdtsc: 0, rdrand: 0, wrmsr: 0, rdmsr: 0,
            virtio_kick: 0,
            halted: 0, debug: 0, shutdown: 0,
            fail_entry: 0, internal_error: 0, unhandled: 0,
        }
    }

    fn record(&mut self, action: &ExitAction) {
        match action {
            ExitAction::Io => self.io += 1,
            ExitAction::Mmio => self.mmio += 1,
            ExitAction::Intr => self.intr += 1,
            ExitAction::SerialOutput => self.serial_output += 1,
            ExitAction::CheckIrq => self.check_irq += 1,
            ExitAction::Rdtsc => self.rdtsc += 1,
            ExitAction::Rdrand => self.rdrand += 1,
            ExitAction::Wrmsr => self.wrmsr += 1,
            ExitAction::Rdmsr => self.rdmsr += 1,
            ExitAction::VirtioKick => self.virtio_kick += 1,
            ExitAction::Halted => self.halted += 1,
            ExitAction::Debug => self.debug += 1,
            ExitAction::Shutdown => self.shutdown += 1,
            ExitAction::FailEntry(..) => self.fail_entry += 1,
            ExitAction::InternalError => self.internal_error += 1,
            ExitAction::UnhandledExit(_) => self.unhandled += 1,
        }
    }

    fn print_and_reset(&mut self, label: &str) {
        self.print_summary_with_label(label);
        *self = Self::new();
    }

    fn print_summary(&self) {
        self.print_summary_with_label("vm: exit counts by type:");
    }

    fn print_summary_with_label(&self, label: &str) {
        if quiet() {
            return;
        }
        let elapsed = self.started.elapsed();
        eprintln!("{} ({:.3}s)", label, elapsed.as_secs_f64());
        let entries: &[(&str, u64)] = &[
            ("IO", self.io),
            ("MMIO", self.mmio),
            ("Intr", self.intr),
            ("SerialOutput", self.serial_output),
            ("CheckIrq", self.check_irq),
            ("RDTSC", self.rdtsc),
            ("RDRAND", self.rdrand),
            ("WRMSR", self.wrmsr),
            ("RDMSR", self.rdmsr),
            ("VirtioKick", self.virtio_kick),
            ("Halted", self.halted),
            ("Debug", self.debug),
            ("Shutdown", self.shutdown),
            ("FailEntry", self.fail_entry),
            ("InternalError", self.internal_error),
            ("Unhandled", self.unhandled),
        ];
        for (name, count) in entries {
            if *count > 0 {
                eprintln!("  {:>14}: {}", name, count);
            }
        }
    }
}

/// Reason the VM run loop terminated.
#[derive(Debug)]
enum VmExit {
    Halted,
    Shutdown { rip: u64 },
    FailEntry { reason: u64 },
    InternalError { rip: u64 },
    UnhandledExit { description: String, rip: u64 },
    NmiComplete,
}

fn classify_exit(
    exit: VcpuExit<'_>,
    serial: &mut Serial,
    ioapic: &mut Ioapic,
    lapic: &mut Lapic,
    hw: &DeterministicHw,
    virtio: &mut virtio_console::VirtioConsole,
    guest_mem: &GuestMemoryMmap,
) -> ExitAction {
    match exit {
        VcpuExit::IoOut(port, data) => {
            match handle_io_out(serial, port, data) {
                IoOutResult::SerialIrqChange => ExitAction::CheckIrq,
                IoOutResult::SerialOutput => ExitAction::SerialOutput,
                IoOutResult::None => ExitAction::Io,
            }
        }
        VcpuExit::IoIn(port, data) => {
            handle_io_in(serial, port, data);
            ExitAction::Io
        }
        VcpuExit::Hlt => ExitAction::Halted,
        VcpuExit::Shutdown => ExitAction::Shutdown,
        VcpuExit::FailEntry(reason, cpu) => ExitAction::FailEntry(reason, cpu),
        VcpuExit::InternalError => ExitAction::InternalError,
        VcpuExit::MmioRead(addr, data) => {
            let lapic_base = LAPIC_ADDR as u64;
            let ioapic_base = IOAPIC_ADDR as u64;
            if addr >= lapic_base && addr < lapic_base + 0x1000 {
                lapic.handle_mmio_read(addr - lapic_base, data, hw.tsc);
            } else if addr >= ioapic_base && addr < ioapic_base + 0x20 {
                ioapic.handle_mmio_read(addr - ioapic_base, data);
            } else if addr >= VIRTIO_MMIO_BASE && addr < VIRTIO_MMIO_BASE + virtio_console::VIRTIO_MMIO_SIZE {
                virtio.mmio_read(addr - VIRTIO_MMIO_BASE, data);
            } else {
                for b in data.iter_mut() {
                    *b = 0xFF;
                }
            }
            ExitAction::Mmio
        }
        VcpuExit::MmioWrite(addr, data) => {
            let lapic_base = LAPIC_ADDR as u64;
            let ioapic_base = IOAPIC_ADDR as u64;
            if addr >= lapic_base && addr < lapic_base + 0x1000 {
                lapic.handle_mmio_write(addr - lapic_base, data, hw.tsc);
            } else if addr >= ioapic_base && addr < ioapic_base + 0x20 {
                ioapic.handle_mmio_write(addr - ioapic_base, data);
            } else if addr >= VIRTIO_MMIO_BASE && addr < VIRTIO_MMIO_BASE + virtio_console::VIRTIO_MMIO_SIZE {
                if virtio.mmio_write(addr - VIRTIO_MMIO_BASE, data) {
                    virtio.drain_tx(guest_mem);
                    return ExitAction::VirtioKick;
                }
            }
            ExitAction::Mmio
        }
        VcpuExit::Intr => ExitAction::Intr,
        VcpuExit::Debug(_) => ExitAction::Debug,
        VcpuExit::Unsupported(reason) if reason == KVM_EXIT_RDTSC => ExitAction::Rdtsc,
        VcpuExit::Unsupported(reason) if reason == KVM_EXIT_RDRAND => ExitAction::Rdrand,
        VcpuExit::Unsupported(reason) if reason == KVM_EXIT_X86_WRMSR => ExitAction::Wrmsr,
        VcpuExit::Unsupported(reason) if reason == KVM_EXIT_X86_RDMSR => ExitAction::Rdmsr,
        VcpuExit::X86Wrmsr(exit) => {
            match exit.index {
                MSR_IA32_TSC_DEADLINE => {
                    lapic.handle_tsc_deadline_write(exit.data);
                    *exit.error = 0;
                }
                _ => {
                    *exit.error = 0;
                }
            }
            ExitAction::Wrmsr
        }
        VcpuExit::X86Rdmsr(exit) => {
            match exit.index {
                MSR_IA32_TSC_DEADLINE => {
                    *exit.data = lapic.read_tsc_deadline();
                    *exit.error = 0;
                }
                _ => {
                    *exit.data = 0;
                    *exit.error = 0; // return 0 for unknown MSRs
                }
            }
            ExitAction::Rdmsr
        }
        other => ExitAction::UnhandledExit(format!("{:?}", other)),
    }
}

/// Route a serial IRQ through the IOAPIC → LAPIC path. Looks up the vector from the
/// IOAPIC redirect entry for the serial pin and sets it in the LAPIC's IRR.
fn route_serial_irq(serial: &Serial, ioapic: &Ioapic, lapic: &mut Lapic) {
    if !serial.irq_pending() || !lapic.enabled() {
        return;
    }
    let pin = SERIAL_IRQ as usize;
    let redir = ioapic.redirect_table[pin];
    if redir & (1 << 16) != 0 {
        return; // masked in IOAPIC
    }
    let vector = (redir & 0xFF) as u8;
    if vector >= 16 {
        lapic.set_irr(vector);
    }
}

/// Route a virtio IRQ through the IOAPIC → LAPIC path after processing used buffers.
fn route_virtio_irq(virtio: &mut virtio_console::VirtioConsole, ioapic: &Ioapic, lapic: &mut Lapic) {
    if !virtio.irq_pending() || !lapic.enabled() {
        return;
    }
    let pin = VIRTIO_IRQ as usize;
    let redir = ioapic.redirect_table[pin];
    if redir & (1 << 16) != 0 {
        return; // masked in IOAPIC
    }
    let vector = (redir & 0xFF) as u8;
    if vector >= 16 {
        lapic.set_irr(vector);
    }
}

/// Try to deliver the highest-priority pending interrupt from the LAPIC to the vCPU.
fn deliver_pending_interrupt(vcpu: &VcpuFd, lapic: &mut Lapic) -> Result<()> {
    if !lapic.enabled() {
        return Ok(());
    }
    if let Some(vector) = lapic.pending_vector() {
        if inject_interrupt(vcpu, vector)? {
            lapic.accept_interrupt(vector);
        }
    }
    Ok(())
}

/// Handle RDTSC exit: write deterministic TSC value to EDX:EAX, advance RIP past the
/// 2-byte instruction (0F 31).
///
/// Also detect the first rdtsc from CPL=3 and stamp `hw.user_reached`. The
/// run loop is responsible for printing the boot-phase exit summary when it
/// observes the transition. Cheap on the steady-state path (single boolean
/// check) because the sregs ioctl only fires once.
fn handle_rdtsc(vcpu: &VcpuFd, hw: &mut DeterministicHw) -> Result<()> {
    let tsc = hw.rdtsc();
    if !hw.user_reached {
        let sregs = vcpu.get_sregs()?;
        if (sregs.cs.selector & 3) == 3 {
            hw.user_reached = true;
            eprintln!("vm: reached userspace at {} retired instructions", tsc);
        }
    }
    let mut regs = vcpu.get_regs()?;
    regs.rax = tsc & 0xFFFF_FFFF;
    regs.rdx = tsc >> 32;
    regs.rip += 2; // RDTSC = 0F 31
    vcpu.set_regs(&regs)?;
    Ok(())
}

/// Handle RDRAND exit: inject #UD. RDRAND is not advertised in CPUID, so any use is a bug
/// in the guest. We intercept it (rather than letting the real CPU execute it) to enforce
/// determinism — without interception, the instruction would succeed on hardware that
/// supports it, silently returning non-deterministic values.
fn handle_rdrand(vcpu: &VcpuFd) -> Result<()> {
    let mut events = vcpu.get_vcpu_events()?;
    events.exception.injected = 1;
    events.exception.nr = 6; // #UD (Invalid Opcode)
    events.exception.has_error_code = 0;
    vcpu.set_vcpu_events(&events)?;
    Ok(())
}

/// Handle WRMSR exit: read the MSR index and data from kvm_run, dispatch to the
/// appropriate handler. For IA32_TSC_DEADLINE, pass to the LAPIC. For unknown MSRs,
/// set the error flag so KVM injects #GP.
fn handle_wrmsr(vcpu: &mut VcpuFd, lapic: &mut Lapic) {
    let run = vcpu.get_kvm_run();
    // SAFETY: exit_reason is KVM_EXIT_X86_WRMSR, so the msr union field is valid.
    let msr = unsafe { &mut run.__bindgen_anon_1.msr };
    match msr.index {
        MSR_IA32_TSC_DEADLINE => {
            lapic.handle_tsc_deadline_write(msr.data);
            msr.error = 0;
        }
        _ => {
            msr.error = 1; // inject #GP for unhandled MSRs
        }
    }
}

/// Handle RDMSR exit: read the MSR index from kvm_run, return the value.
fn handle_rdmsr(vcpu: &mut VcpuFd, lapic: &Lapic) {
    let run = vcpu.get_kvm_run();
    let msr = unsafe { &mut run.__bindgen_anon_1.msr };
    match msr.index {
        MSR_IA32_TSC_DEADLINE => {
            msr.data = lapic.read_tsc_deadline();
            msr.error = 0;
        }
        _ => {
            msr.error = 1;
        }
    }
}

/// KVM_GUESTDBG_BLOCKIRQ: prevent KVM from injecting interrupts during single-stepping.
/// Without this, injected interrupts push TF-tainted RFLAGS onto the guest stack, and
/// the guest's IRET restores TF — causing a #DB that leaks into the guest kernel.
/// QEMU's GDB stub uses this for the same reason.
const KVM_GUESTDBG_BLOCKIRQ: u32 = 0x00100000;

fn enter_singlestep(vcpu: &VcpuFd) -> Result<()> {
    vcpu.set_guest_debug(&kvm_guest_debug {
        control: KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP | KVM_GUESTDBG_BLOCKIRQ,
        pad: 0,
        arch: kvm_guest_debug_arch { debugreg: [0; 8] },
    })?;
    Ok(())
}

fn leave_singlestep(vcpu: &VcpuFd) -> Result<()> {
    vcpu.set_guest_debug(&kvm_guest_debug {
        control: 0,
        pad: 0,
        arch: kvm_guest_debug_arch { debugreg: [0; 8] },
    })?;
    Ok(())
}

/// Program the PMU to fire SKID_BUDGET instructions before a LAPIC timer deadline.
/// If the deadline is already close (within SKID_BUDGET), returns true to indicate
/// the caller should enter single-stepping immediately.
fn program_pmu_for_deadline(hw: &mut DeterministicHw, deadline: u64) -> bool {
    let remaining = deadline.saturating_sub(hw.tsc);
    if remaining <= SKID_BUDGET {
        return true; // already close enough — single-step immediately
    }
    hw.reprogram_counter(remaining - SKID_BUDGET);
    false
}

fn run_vm(vcpu: &mut VcpuFd, hw: &mut DeterministicHw, serial: &mut Serial, ioapic: &mut Ioapic, lapic: &mut Lapic, virtio: &mut virtio_console::VirtioConsole, guest_mem: &GuestMemoryMmap, _preempt_fd: std::os::unix::io::RawFd) -> Result<VmExit> {
    let mut exit_count: u64 = 0;
    let mut trace_file = std::env::var("VMM_TRACE").ok().map(|path| {
        std::fs::File::create(&path).expect("failed to create trace file")
    });
    let mut timer_fires: u64 = 0;
    let mut preempt_count: u64 = 0;
    let mut nmi_injected = false;
    let mut post_nmi_exits: u64 = 0;
    let mut exits_since_last_serial: u64 = 0;
    let mut exit_counts = ExitCounts::new();
    let mut boot_phase_reported = false;
    const POST_NMI_QUIET_THRESHOLD: u64 = 10_000;

    let mut preempt_state = PreemptState::Running;
    // The LAPIC deadline we last programmed the PMU for. When the LAPIC deadline
    // changes (guest reprograms timer), we detect the mismatch and reprogram.
    let mut pmu_armed_for: Option<u64> = None;

    loop {
        if !nmi_injected && SIGINT_RECEIVED.swap(false, Ordering::SeqCst) {
            let regs = vcpu.get_regs()?;
            eprintln!("vm: signal at exit {} RIP={:#x} RSP={:#x} RFLAGS={:#x} TSC={}",
                exit_count, regs.rip, regs.rsp, regs.rflags, hw.tsc);
            let ret = ioctl(vcpu.as_raw_fd(), KVM_NMI, 0);
            match ret {
                Ok(_) => eprintln!("vm: NMI injected, continuing for guest panic output"),
                Err(e) => eprintln!("vm: failed to inject NMI: {}", e),
            }
            nmi_injected = true;
        }

        // If the LAPIC timer deadline changed (guest reprogrammed the timer),
        // reprogram the PMU to target the new deadline.
        let current_deadline = lapic.interrupt_deadline();
        if current_deadline != pmu_armed_for {
            // Cancel any in-progress single-stepping — the old target is stale
            if let PreemptState::SingleStepping { .. } = preempt_state {
                leave_singlestep(vcpu)?;
                preempt_state = PreemptState::Running;
            }
            if let Some(deadline) = current_deadline {
                if program_pmu_for_deadline(hw, deadline) {
                    enter_singlestep(vcpu)?;
                    preempt_state = PreemptState::SingleStepping { target_tsc: deadline };
                }
            }
            pmu_armed_for = current_deadline;
        }

        // Deliver pending interrupts before VMENTRY — but NOT during single-stepping.
        // BLOCKIRQ prevents KVM's internal injection, but our manual injection via
        // set_vcpu_events would bypass it, pushing TF-tainted RFLAGS onto the guest
        // stack and causing a #DB leak on IRET.
        if !matches!(preempt_state, PreemptState::SingleStepping { .. }) {
            if let Err(e) = deliver_pending_interrupt(vcpu, lapic) {
                eprintln!("warn: interrupt delivery failed at exit {}: {}", exit_count, e);
            }
        }

        let action = match vcpu.run() {
            Ok(exit) => {
                let tsc_delta = hw.advance_tsc();
                // Timer check is NOT done here — timer fires only at the exact
                // landing point (deterministic) or at HLT (guest is idle).
                let action = classify_exit(exit, serial, ioapic, lapic, hw, virtio, guest_mem);
                // During single-stepping, delta=0 means the guest is halted (no
                // instruction retired). With BLOCKIRQ, no interrupt can wake it.
                // Handle it like HLT: leave stepping, advance TSC to the timer
                // deadline, and fire the timer so the guest can be woken.
                if tsc_delta == 0 {
                    if let PreemptState::SingleStepping { .. } = preempt_state {
                        leave_singlestep(vcpu)?;
                        preempt_state = PreemptState::Running;
                        if let Some(deadline) = lapic.timer_deadline_tsc {
                            if deadline > hw.tsc {
                                hw.tsc = deadline;
                            }
                            if lapic.check_and_fire_timer(hw.tsc) {
                                timer_fires += 1;
                            }
                            pmu_armed_for = None;
                        }
                    }
                }
                if let PreemptState::SingleStepping { target_tsc } = preempt_state {
                    if hw.tsc >= target_tsc {
                        leave_singlestep(vcpu)?;
                        preempt_count += 1;
                        let overshoot = hw.tsc - target_tsc;
                        if overshoot > 0 {
                            panic!("preempt[{}]: overshoot={} at tsc={} (target={}). \
                                    Determinism violated — timer delivered late.",
                                preempt_count, overshoot, hw.tsc, target_tsc);
                        }
                        // Fire the timer now — we've landed at exactly the deadline
                        if lapic.check_and_fire_timer(hw.tsc) {
                            timer_fires += 1;
                        }
                        // check_and_fire_timer re-arms for periodic mode, so
                        // pmu_armed_for will mismatch on the next iteration and
                        // we'll reprogram the PMU for the new deadline.
                        pmu_armed_for = None;
                        preempt_state = PreemptState::Running;
                    }
                }
                if let Some(ref mut trace) = trace_file {
                    use std::io::Write;
                    let _ = writeln!(trace, "{} {:?}", exit_count, action);
                }
                action
            }
            Err(e) => {
                if e.errno() == libc::EINTR {
                    hw.advance_tsc();
                    // PMU overflow: we're near the deadline. Enter single-stepping.
                    if let PreemptState::Running = preempt_state {
                        if let Some(deadline) = lapic.interrupt_deadline() {
                            let remaining = deadline.saturating_sub(hw.tsc);
                            if remaining <= SKID_BUDGET * 2 {
                                enter_singlestep(vcpu)?;
                                            preempt_state = PreemptState::SingleStepping {
                                    target_tsc: deadline,
                                };
                            }
                            // else: stale overflow from before a reprogram — ignore
                        }
                    }
                    exit_counts.intr += 1;
                    exit_count += 1;
                    continue;
                }
                return Err(format!("KVM_RUN failed: {}", e).into());
            }
        };

        exit_counts.record(&action);

        if nmi_injected {
            post_nmi_exits += 1;
            match action {
                ExitAction::SerialOutput | ExitAction::CheckIrq => {
                    exits_since_last_serial = 0;
                }
                _ => {
                    exits_since_last_serial += 1;
                    if exits_since_last_serial >= POST_NMI_QUIET_THRESHOLD {
                        eprintln!("vm: panic trace complete ({} exits, {} post-NMI)",
                            exit_count, post_nmi_exits);
                        exit_counts.print_summary();
                        return Ok(VmExit::NmiComplete);
                    }
                }
            }
        }
        match action {
            ExitAction::Io | ExitAction::Mmio | ExitAction::Intr | ExitAction::SerialOutput => {}
            ExitAction::VirtioKick => {
                route_virtio_irq(virtio, ioapic, lapic);
            }
            ExitAction::CheckIrq => {
                route_serial_irq(serial, ioapic, lapic);
            }
            ExitAction::Rdtsc => {
                handle_rdtsc(vcpu, hw)?;
                if hw.user_reached && !boot_phase_reported {
                    exit_counts.print_and_reset("vm: boot phase exit counts:");
                    boot_phase_reported = true;
                }
            }
            ExitAction::Rdrand => {
                handle_rdrand(vcpu)?;
            }
            ExitAction::Wrmsr => {
                handle_wrmsr(vcpu, lapic);
            }
            ExitAction::Rdmsr => {
                handle_rdmsr(vcpu, lapic);
            }
            ExitAction::Debug => {}
            ExitAction::Halted => {
                // Guest is idle — no instructions execute. If a timer deadline
                // exists, advance TSC so time progresses and fire the timer.
                if let Some(deadline) = lapic.timer_deadline_tsc {
                    if deadline > hw.tsc {
                        hw.tsc = deadline;
                    }
                    if lapic.check_and_fire_timer(hw.tsc) {
                        timer_fires += 1;
                    }
                    pmu_armed_for = None;
                    if let PreemptState::SingleStepping { .. } = preempt_state {
                        leave_singlestep(vcpu)?;
                        preempt_state = PreemptState::Running;
                    }
                }
                // After timer handling (if any), check what can wake the guest.
                // A masked timer fires without setting IRR, so we must not assume
                // that a fired timer always produces a pending interrupt.
                if lapic.pending_vector().is_some() {
                    // Interrupt pending — will deliver at top of loop and re-enter
                } else if serial.irq_pending() {
                    route_serial_irq(serial, ioapic, lapic);
                } else if nmi_injected {
                    eprintln!("vm: guest halted after NMI panic after {} exits", exit_count);
                    exit_counts.print_summary();
                    return Ok(VmExit::NmiComplete);
                } else {
                    eprintln!("vm: guest halted with no pending work after {} exits", exit_count);
                    exit_counts.print_summary();
                    return Ok(VmExit::Halted);
                }
            }
            ExitAction::Shutdown => {
                let regs = vcpu.get_regs()?;
                if !quiet() {
                    eprintln!(
                        "vm: shutdown/triple-fault at RIP={:#x} after {} exits ({} preemptions, {} timer fires)",
                        regs.rip, exit_count, preempt_count, timer_fires
                    );
                }
                exit_counts.print_summary();
                return Ok(VmExit::Shutdown { rip: regs.rip });
            }
            ExitAction::FailEntry(reason, cpu) => {
                eprintln!(
                    "KVM_EXIT_FAIL_ENTRY: hardware_entry_failure_reason={:#x}, cpu={}",
                    reason, cpu
                );
                exit_counts.print_summary();
                return Ok(VmExit::FailEntry { reason });
            }
            ExitAction::InternalError => {
                let regs = vcpu.get_regs()?;
                eprintln!(
                    "KVM internal error at RIP={:#x} after {} exits",
                    regs.rip, exit_count
                );
                exit_counts.print_summary();
                return Ok(VmExit::InternalError { rip: regs.rip });
            }
            ExitAction::UnhandledExit(desc) => {
                let regs = vcpu.get_regs()?;
                eprintln!(
                    "unhandled VMEXIT: {} at RIP={:#x} after {} exits",
                    desc, regs.rip, exit_count
                );
                exit_counts.print_summary();
                return Ok(VmExit::UnhandledExit { description: desc, rip: regs.rip });
            }
        }

        // Re-arm single-stepping after any non-Debug exit. Intercepted exits
        // (MMIO, IO, RDTSC) consume the MTF — without re-arming, the next KVM_RUN
        // would free-run.
        if let PreemptState::SingleStepping { .. } = preempt_state {
            if !matches!(action, ExitAction::Debug) {
                enter_singlestep(vcpu)?;
            }
        }

        exit_count += 1;
    }
}

static SIGINT_RECEIVED: AtomicBool = AtomicBool::new(false);

extern "C" fn sigint_handler(_sig: libc::c_int) {
    SIGINT_RECEIVED.store(true, Ordering::SeqCst);
}

extern "C" fn noop_handler(_sig: libc::c_int) {}


/// KVM_NMI ioctl: _IO(0xAE, 0x9a)
const KVM_NMI: libc::c_ulong = 0xAE9A;

fn main() -> Result<()> {
    unsafe {
        libc::signal(libc::SIGINT, sigint_handler as *const () as libc::sighandler_t);
        libc::signal(libc::SIGIO, noop_handler as *const () as libc::sighandler_t);
    }

    let (bzimage_path, cpuid_path, initramfs_path) = parse_args()?;
    let cpuid_leaves = load_cpuid_file(&cpuid_path)?;

    let kvm = open_kvm()?;
    let vm = create_vm(&kvm)?;

    configure_exit_controls(&kvm, &vm)?;

    let guest_mem = allocate_guest_memory(&vm)?;

    write_mptable(&guest_mem)?;
    let kernel_result = load_kernel(&guest_mem, &bzimage_path)?;
    let (initramfs_addr, initramfs_size) = load_initramfs(&guest_mem, &initramfs_path)?;
    let cmdline_addr = write_cmdline(&guest_mem)?;
    write_boot_params(
        &guest_mem,
        &kernel_result,
        initramfs_addr,
        initramfs_size,
        cmdline_addr,
    )?;

    let mut vcpu = vm.create_vcpu(0).map_err(|e| format!("create_vcpu: {}", e))?;
    eprintln!("vcpu: created");

    // MSR filter must be set AFTER vCPU creation: KVM_REQ_RECALC_INTERCEPTS
    // updates the MSR permission bitmap on existing vCPUs.
    configure_msr_filter(&vm)?;

    configure_cpuid(&vcpu, &cpuid_leaves).map_err(|e| format!("configure_cpuid: {}", e))?;
    eprintln!("vcpu: cpuid configured");

    configure_sregs(&vcpu).map_err(|e| format!("configure_sregs: {}", e))?;
    configure_msrs(&vcpu).map_err(|e| format!("configure_msrs: {}", e))?;
    eprintln!("vcpu: sregs/msrs configured");

    // Determine the kernel entry point. For bzImage loaded with linux-loader, the 64-bit entry
    // point is at the kernel load address.
    let entry_point = kernel_result.kernel_load.raw_value();
    configure_regs(&vcpu, entry_point).map_err(|e| format!("configure_regs: {}", e))?;

    eprintln!("vm: starting guest, entry at {:#x}", entry_point);

    let insn_fd = open_insn_counter()?;
    let mut hw = DeterministicHw::new(insn_fd);
    let mut serial = Serial::new();
    let mut ioapic = Ioapic::new();
    let mut lapic = Lapic::new(TSC_TO_CRYSTAL_RATIO);
    let mut virtio = virtio_console::VirtioConsole::new();
    let exit = run_vm(&mut vcpu, &mut hw, &mut serial, &mut ioapic, &mut lapic, &mut virtio, &guest_mem, insn_fd)?;

    match exit {
        VmExit::Halted | VmExit::NmiComplete => process::exit(0),
        VmExit::Shutdown { rip } => {
            eprintln!("vm: shutdown at rip={:#x}", rip);
            process::exit(0)
        }
        VmExit::FailEntry { reason } => {
            eprintln!("vm: fail entry, reason={:#x}", reason);
            process::exit(1)
        }
        VmExit::InternalError { rip } => {
            eprintln!("vm: internal error at rip={:#x}", rip);
            process::exit(1)
        }
        VmExit::UnhandledExit { description, rip } => {
            eprintln!("vm: unhandled exit at rip={:#x}: {}", rip, description);
            process::exit(1)
        }
    }
}

#[cfg(test)]
mod testvm {
    use super::*;

    /// Assemble Intel-syntax x86-32 code into a flat binary via GNU as + objcopy.
    fn asm(source: &str) -> Vec<u8> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("vmm-test-{}-{}", std::process::id(), id));
        std::fs::create_dir_all(&dir).expect("failed to create temp dir");
        let asm_path = dir.join("guest.S");
        let obj_path = dir.join("guest.o");
        let bin_path = dir.join("guest.bin");

        std::fs::write(&asm_path, format!(".intel_syntax noprefix\n{}", source))
            .expect("failed to write asm");

        let as_out = std::process::Command::new("as")
            .args(["--32", "-o"])
            .arg(&obj_path)
            .arg(&asm_path)
            .output()
            .expect("failed to run as");
        assert!(as_out.status.success(), "as failed: {}",
            String::from_utf8_lossy(&as_out.stderr));

        let objcopy_out = std::process::Command::new("objcopy")
            .args(["-O", "binary"])
            .arg(&obj_path)
            .arg(&bin_path)
            .output()
            .expect("failed to run objcopy");
        assert!(objcopy_out.status.success(), "objcopy failed: {}",
            String::from_utf8_lossy(&objcopy_out.stderr));

        let bytes = std::fs::read(&bin_path).expect("failed to read binary");
        let _ = std::fs::remove_dir_all(&dir);
        bytes
    }

    /// Create a minimal KVM VM with a flat 32-bit binary loaded at GPA 0x1000.
    ///
    /// The guest runs in 32-bit protected mode with flat segments (no paging), giving it
    /// direct access to the full 4 GiB address space. MMIO accesses to the LAPIC region
    /// (0xFEE00000) cause KVM exits that the run loop routes to our Lapic struct.
    ///
    /// No irqchip, no CPUID, no MSRs, no boot protocol — just raw code execution.
    struct TestVm {
        vcpu: VcpuFd,
        hw: DeterministicHw,
        serial: Serial,
        ioapic: Ioapic,
        lapic: Lapic,
        virtio: virtio_console::VirtioConsole,
        insn_fd: std::os::unix::io::RawFd,
        // Keep these alive so KVM's memory mapping remains valid.
        _vm: VmFd,
        guest_mem: GuestMemoryMmap,
    }

    impl TestVm {
        fn new(code: &[u8]) -> Result<Self> {
            let kvm = open_kvm()?;
            let vm = create_vm(&kvm)?;
            let guest_mem = allocate_guest_memory(&vm)?;

            guest_mem.write_slice(code, GuestAddress(0x1000))
                .map_err(|e| format!("failed to write guest code: {}", e))?;

            let vcpu = vm.create_vcpu(0)
                .map_err(|e| format!("create_vcpu: {}", e))?;
            configure_sregs(&vcpu)?;
            configure_regs(&vcpu, 0x1000)?;

            let insn_fd = open_insn_counter()?;
            let hw = DeterministicHw::new(insn_fd);

            Ok(TestVm {
                vcpu,
                hw,
                serial: Serial::new(),
                ioapic: Ioapic::new(),
                lapic: Lapic::new(TSC_TO_CRYSTAL_RATIO),
                virtio: virtio_console::VirtioConsole::new(),
                insn_fd,
                _vm: vm,
                guest_mem,
            })
        }

        fn run(&mut self) -> Result<VmExit> {
            run_vm(
                &mut self.vcpu, &mut self.hw, &mut self.serial,
                &mut self.ioapic, &mut self.lapic, &mut self.virtio,
                &self.guest_mem, self.insn_fd,
            )
        }

        fn regs(&self) -> Result<kvm_regs> {
            self.vcpu.get_regs().map_err(|e| e.into())
        }
    }

    fn require_kvm() -> bool {
        std::path::Path::new("/dev/kvm").exists()
    }

    #[test]
    fn lapic_id() {
        if !require_kvm() { return; }
        let code = asm("mov eax, [0xFEE00020]; hlt");
        let mut vm = TestVm::new(&code).expect("TestVm::new");
        let exit = vm.run().expect("run");
        assert!(matches!(exit, VmExit::Halted), "expected Halted, got {:?}", exit);
        let regs = vm.regs().expect("get_regs");
        assert_eq!(regs.rax, 0, "LAPIC ID should be 0 for BSP");
    }

    #[test]
    fn lapic_version() {
        if !require_kvm() { return; }
        let code = asm("mov eax, [0xFEE00030]; hlt");
        let mut vm = TestVm::new(&code).expect("TestVm::new");
        let exit = vm.run().expect("run");
        assert!(matches!(exit, VmExit::Halted), "expected Halted, got {:?}", exit);
        let regs = vm.regs().expect("get_regs");
        let expected = (5u64 << 16) | 0x14;
        assert_eq!(regs.rax, expected, "LAPIC version mismatch");
    }

    #[test]
    fn svr_write_readback() {
        if !require_kvm() { return; }
        let code = asm("\
            mov eax, 0x1FF;
            mov [0xFEE000F0], eax;
            mov eax, [0xFEE000F0];
            hlt");
        let mut vm = TestVm::new(&code).expect("TestVm::new");
        let exit = vm.run().expect("run");
        assert!(matches!(exit, VmExit::Halted), "expected Halted, got {:?}", exit);
        let regs = vm.regs().expect("get_regs");
        assert_eq!(regs.rax, 0x1FF, "SVR readback should match written value");
    }

    #[test]
    fn timer_initial_equals_current() {
        if !require_kvm() { return; }
        // Set divide-by-1, write initial count = 1000, read current count.
        // With only a few TSC ticks elapsed (one per instruction, ratio=100),
        // the truncated APIC count should still equal the initial value.
        let code = asm("\
            mov eax, 0x0B;
            mov [0xFEE003E0], eax;
            mov eax, 1000;
            mov [0xFEE00380], eax;
            mov eax, [0xFEE00390];
            hlt");
        let mut vm = TestVm::new(&code).expect("TestVm::new");
        let exit = vm.run().expect("run");
        assert!(matches!(exit, VmExit::Halted), "expected Halted, got {:?}", exit);
        let regs = vm.regs().expect("get_regs");
        assert_eq!(regs.rax, 1000, "current count should equal initial count (few insns elapsed)");
    }
}
