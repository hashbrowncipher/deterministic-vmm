// SPDX-License-Identifier: Apache-2.0
/// Userspace LAPIC — minimal emulation for single-vCPU deterministic execution.
///
/// With no in-kernel irqchip, HLT exits to userspace, giving us full control over
/// interrupt timing and timer advancement.
///
/// The LAPIC timer counts at the crystal clock rate, not the TSC rate. The TSC runs
/// `tsc_to_crystal_ratio` times faster (e.g., 100× for a 100 GHz virtual TSC with
/// a 1 GHz crystal). Timer deadlines are stored in TSC ticks for direct comparison
/// with the deterministic TSC counter, but the initial count and current count
/// registers operate in crystal-rate ticks (divided by the programmable divisor).


// If Linux asks for a timer in X cycles, we deliver it after X * SCHEDULER_FUDGE cycles
const SCHEDULER_FUDGE: u64 = 1;

/// Round `value` up to the next multiple of `step` (fixed-point ceiling).
fn round_up(value: u64, step: u64) -> u64 {
    value.div_ceil(step) * step
}

pub struct Lapic {
    // Registers
    svr: u32,               // Spurious Vector Register (0xF0)
    tpr: u32,               // Task Priority Register (0x80)
    lvt_timer: u32,         // LVT Timer (0x320) — vector + mode + mask
    timer_initial: u32,     // Initial Count (0x380)
    timer_divide: u32,      // Divide Configuration (0x3E0)

    // Timer state
    pub timer_deadline_tsc: Option<u64>,  // TSC value at which timer should fire

    // The LAPIC timer counts at crystal rate, but deadlines are in TSC ticks (which
    // run ratio× faster). This multiplier converts APIC timer ticks to TSC ticks.
    tsc_to_crystal_ratio: u64,

    // Interrupt state — 256-bit registers as arrays of 8 u32s
    irr: [u32; 8],          // Interrupt Request Register
    isr: [u32; 8],          // In-Service Register
}

impl Lapic {
    pub fn new(tsc_to_crystal_ratio: u64) -> Self {
        Lapic {
            svr: 0xFF,       // APIC starts disabled (bit 8 = 0), spurious vector 0xFF
            tpr: 0,
            lvt_timer: 1 << 16,  // masked
            timer_initial: 0,
            timer_divide: 0,
            timer_deadline_tsc: None,
            tsc_to_crystal_ratio,
            irr: [0; 8],
            isr: [0; 8],
        }
    }

    pub fn handle_mmio_read(&self, offset: u64, data: &mut [u8], current_tsc: u64) {
        let val: u32 = match offset {
            0x20 => 0,                 // APIC ID (0 for BSP)
            0x30 => (5 << 16) | 0x14,  // Version: max LVT=5, version=0x14
            0x80 => self.tpr,
            0xD0 => 1 << 24,           // Logical Destination: cluster 0, ID 1
            0xE0 => 0x0FFF_FFFF,       // Destination Format: flat model
            0xF0 => self.svr,
            o @ 0x100..=0x170 => {
                let idx = ((o - 0x100) / 0x10) as usize;
                if idx < 8 { self.isr[idx] } else { 0 }
            }
            0x180..=0x1F0 => 0,  // TMR: all edge-triggered
            o @ 0x200..=0x270 => {
                let idx = ((o - 0x200) / 0x10) as usize;
                if idx < 8 { self.irr[idx] } else { 0 }
            }
            0x320 => self.lvt_timer,
            0x380 => self.timer_initial,
            0x390 => self.read_current_count(current_tsc),
            0x3E0 => self.timer_divide,
            _ => 0,
        };
        if data.len() == 4 {
            data.copy_from_slice(&val.to_le_bytes());
        }
    }

    /// Handle MMIO write. Returns true if timer configuration changed.
    pub fn handle_mmio_write(&mut self, offset: u64, data: &[u8], current_tsc: u64) -> bool {
        let val = if data.len() == 4 {
            u32::from_le_bytes(data.try_into().unwrap())
        } else {
            return false;
        };
        match offset {
            0x80 => { self.tpr = val & 0xFF; }
            0xB0 => { self.do_eoi(); }
            0xD0 => {} // LDR — ignore for 1 vCPU
            0xE0 => {} // DFR — ignore for 1 vCPU
            0xF0 => { self.svr = val; }
            0x320 => {
                let old_mode = self.timer_mode();
                self.lvt_timer = val;
                // Switching to TSC-deadline mode disarms any one-shot/periodic timer.
                // Switching away from TSC-deadline mode clears the deadline.
                if self.timer_mode() == 2 && old_mode != 2 {
                    self.timer_deadline_tsc = None;
                    self.timer_initial = 0;
                } else if self.timer_mode() != 2 && old_mode == 2 {
                    self.timer_deadline_tsc = None;
                }
                return true;
            }
            0x380 => {
                // Writing the initial count register in TSC-deadline mode is ignored.
                if self.timer_mode() == 2 {
                    return false;
                }
                self.timer_initial = val;
                self.arm_timer(current_tsc);
                return true;
            }
            0x3E0 => {
                self.timer_divide = val;
            }
            _ => {}
        }
        false
    }

    /// Handle a write to the IA32_TSC_DEADLINE MSR (0x6E0). The guest writes a raw TSC
    /// value; the timer fires when the TSC reaches it. Only effective in TSC-deadline mode
    /// (LVT timer mode bits = 0b10). Writing 0 disarms the timer.
    pub fn handle_tsc_deadline_write(&mut self, value: u64) {
        if self.timer_mode() != 2 {
            return;
        }
        if value == 0 {
            self.timer_deadline_tsc = None;
        } else {
            self.timer_deadline_tsc = Some(value);
        }
    }

    /// Read the IA32_TSC_DEADLINE MSR. Returns the current deadline, or 0 if not armed
    /// or not in TSC-deadline mode.
    pub fn read_tsc_deadline(&self) -> u64 {
        if self.timer_mode() != 2 {
            return 0;
        }
        self.timer_deadline_tsc.unwrap_or(0)
    }

    /// Decode the divide configuration register into a shift count.
    ///
    /// The divide register's bits [3,1,0] encode a power-of-two divisor applied to the
    /// crystal clock before it drives the timer counter:
    ///   0b000 → ÷2  (shift 1)    0b100 → ÷16 (shift 4)
    ///   0b001 → ÷4  (shift 2)    0b101 → ÷32 (shift 5)
    ///   0b010 → ÷8  (shift 3)    0b110 → ÷64 (shift 6)
    ///   0b011 → ÷16 (shift 4)    0b111 → ÷1  (shift 0)
    fn divide_shift(&self) -> u32 {
        let div_bits = (self.timer_divide & 0x3) | ((self.timer_divide >> 1) & 0x4);
        if div_bits == 0x7 { 0 } else { div_bits + 1 }
    }

    /// Convert APIC timer ticks (at crystal rate) to TSC ticks.
    ///
    /// The APIC timer counts at `crystal_hz / divisor`. To convert an initial count to
    /// TSC ticks: undo the divisor (shift left), then scale by the TSC:crystal ratio.
    fn apic_ticks_to_tsc(&self, initial_count: u64) -> u64 {
        let shift = self.divide_shift();
        (initial_count << shift) * self.tsc_to_crystal_ratio
    }

    /// Current Count register (offset 0x390): remaining APIC timer ticks.
    ///
    /// The deadline is aligned to the crystal grid by `arm_timer` (via `round_up`), so
    /// floor-dividing the remaining TSC ticks by `tick_size` gives the correct step
    /// behavior: the count holds steady between crystal edges and decrements by 1 at each.
    fn read_current_count(&self, current_tsc: u64) -> u32 {
        match self.timer_deadline_tsc {
            Some(deadline) if deadline > current_tsc => {
                let tick_size = self.tsc_to_crystal_ratio << self.divide_shift();
                ((deadline - current_tsc) / tick_size) as u32
            }
            _ => 0,
        }
    }

    fn arm_timer(&mut self, current_tsc: u64) {
        if self.timer_initial == 0 {
            self.timer_deadline_tsc = None;
            return;
        }
        // The timer counts down regardless of the mask bit — masking only suppresses
        // interrupt delivery, not the countdown. The kernel's APIC calibration relies
        // on this: it masks the timer, starts counting, and polls the current count.
        //
        // The crystal clock is free-running with edges at absolute TSC multiples of
        // tick_size. The deadline is aligned to the crystal grid so the timer always
        // fires on a crystal edge.
        let tsc_ticks = self.apic_ticks_to_tsc(self.timer_initial as u64) * SCHEDULER_FUDGE;
        let tick_size = self.tsc_to_crystal_ratio << self.divide_shift();
        self.timer_deadline_tsc = Some(round_up(current_tsc + tsc_ticks, tick_size));
    }

    /// If the timer deadline has passed, fire it: clear the deadline, set the IRR
    /// (unless masked), and re-arm for periodic mode. Returns true if fired.
    pub fn check_and_fire_timer(&mut self, current_tsc: u64) -> bool {
        let deadline = match self.timer_deadline_tsc {
            Some(d) if current_tsc >= d => d,
            _ => return false,
        };

        self.timer_deadline_tsc = None;
        let mode = self.timer_mode();

        if self.lvt_timer & (1 << 16) == 0 {
            let vector = (self.lvt_timer & 0xFF) as u8;
            if vector >= 16 {
                self.set_irr(vector);
            }
        }

        // Periodic mode: re-arm from the deadline, not from current_tsc, so that
        // drift from interrupt handling latency doesn't accumulate.
        // TSC-deadline mode (mode 2) is always one-shot — no re-arm.
        if mode == 1 {
            let period_tsc = self.apic_ticks_to_tsc(self.timer_initial as u64);
            self.timer_deadline_tsc = Some(deadline + period_tsc);
        }

        true
    }

    /// Set a bit in the IRR for the given vector.
    pub fn set_irr(&mut self, vector: u8) {
        let idx = (vector / 32) as usize;
        let bit = 1u32 << (vector % 32);
        self.irr[idx] |= bit;
    }

    /// Find the highest-priority pending interrupt (highest vector in IRR that's not in ISR
    /// and above TPR). Returns the vector if one should be delivered.
    pub fn pending_vector(&self) -> Option<u8> {
        let tpr_class = (self.tpr >> 4) & 0xF;

        // Scan from highest to lowest priority (vector 255 down to 16)
        for idx in (0..8).rev() {
            let pending = self.irr[idx] & !self.isr[idx];
            if pending == 0 {
                continue;
            }
            let bit = 31 - pending.leading_zeros();
            let vector = (idx as u32) * 32 + bit;
            if vector < 16 {
                continue; // vectors 0-15 are reserved
            }
            if (vector >> 4) <= tpr_class as u32 {
                continue; // below TPR threshold
            }
            return Some(vector as u8);
        }
        None
    }

    /// Move a vector from IRR to ISR (interrupt accepted by the CPU).
    pub fn accept_interrupt(&mut self, vector: u8) {
        let idx = (vector / 32) as usize;
        let bit = 1u32 << (vector % 32);
        self.irr[idx] &= !bit;
        self.isr[idx] |= bit;
    }

    /// EOI: clear the highest-priority bit in ISR.
    fn do_eoi(&mut self) {
        for idx in (0..8).rev() {
            if self.isr[idx] != 0 {
                let bit = 31 - self.isr[idx].leading_zeros();
                self.isr[idx] &= !(1u32 << bit);
                return;
            }
        }
    }

    pub fn enabled(&self) -> bool {
        self.svr & (1 << 8) != 0
    }

    /// Timer mode from LVT timer bits 18:17: 0=one-shot, 1=periodic, 2=TSC-deadline.
    fn timer_mode(&self) -> u32 {
        (self.lvt_timer >> 17) & 0x3
    }

    /// Returns the deadline at which the timer will deliver an interrupt, or None if:
    /// - no timer is armed
    /// - the timer is masked (calibration polling, not interrupt delivery)
    pub fn interrupt_deadline(&self) -> Option<u64> {
        let deadline = self.timer_deadline_tsc?;
        if self.lvt_timer & (1 << 16) != 0 {
            return None; // masked — counting down but won't deliver an interrupt
        }
        Some(deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: write a u32 to an LAPIC register via MMIO.
    fn write_reg(lapic: &mut Lapic, offset: u64, val: u32, tsc: u64) {
        lapic.handle_mmio_write(offset, &val.to_le_bytes(), tsc);
    }

    /// Helper: read a u32 from an LAPIC register via MMIO.
    fn read_reg(lapic: &Lapic, offset: u64, tsc: u64) -> u32 {
        let mut buf = [0u8; 4];
        lapic.handle_mmio_read(offset, &mut buf, tsc);
        u32::from_le_bytes(buf)
    }

    // --- Timer conversion round-trip tests ---
    //
    // The kernel programs the APIC timer by converting a nanosecond delta to an APIC tick
    // count via its clockevent mult/shift. Our VMM converts that APIC tick count to a TSC
    // deadline (apic_ticks_to_tsc), and the current count register converts back
    // (read_current_count). These tests verify the round-trip is consistent: programming
    // an initial count and immediately reading the current count should return the same value.

    #[test]
    fn timer_roundtrip_divide_by_16() {
        let mut lapic = Lapic::new(100);
        // Divide by 16: register value 0x3 → div_bits=0b011 → shift=4
        write_reg(&mut lapic, 0x3E0, 0x3, 0);
        write_reg(&mut lapic, 0x380, 625_000, 0);

        // Read current count immediately (tsc hasn't advanced)
        let count = read_reg(&lapic, 0x390, 0);
        assert_eq!(count, 625_000, "current count should equal initial count at t=0");
    }

    #[test]
    fn timer_roundtrip_divide_by_1() {
        let mut lapic = Lapic::new(100);
        // Divide by 1: register value 0xB → div_bits=0b111 → shift=0
        write_reg(&mut lapic, 0x3E0, 0xB, 0);
        write_reg(&mut lapic, 0x380, 10_000_000, 0);

        let count = read_reg(&lapic, 0x390, 0);
        assert_eq!(count, 10_000_000);
    }

    #[test]
    fn timer_counts_down() {
        let mut lapic = Lapic::new(100);
        write_reg(&mut lapic, 0x3E0, 0x3, 0);  // divide by 16
        write_reg(&mut lapic, 0x380, 625_000, 0);

        // After 1 crystal tick worth of TSC ticks (= 16 * 100 = 1600 TSC ticks),
        // the count should decrease by 1.
        let count = read_reg(&lapic, 0x390, 1600);
        assert_eq!(count, 624_999);
    }

    #[test]
    fn timer_reaches_zero() {
        let mut lapic = Lapic::new(100);
        write_reg(&mut lapic, 0x3E0, 0x3, 0);  // divide by 16
        write_reg(&mut lapic, 0x380, 100, 0);

        // Total TSC ticks for the timer: 100 * 16 * 100 = 160,000
        let count = read_reg(&lapic, 0x390, 160_000);
        assert_eq!(count, 0);
    }

    #[test]
    fn timer_fires_at_deadline() {
        let mut lapic = Lapic::new(100);
        // Unmask the timer, set vector 0xEC
        write_reg(&mut lapic, 0x320, 0xEC, 0);
        write_reg(&mut lapic, 0x3E0, 0x3, 0);  // divide by 16

        // Arm at TSC=1000. tick_size = 100*16 = 1600.
        // raw deadline = 1000 + 625000*1600 = 1,000,001,000
        // round_up(1,000,001,000, 1600) = 1,000,001,600
        write_reg(&mut lapic, 0x380, 625_000, 1000);

        let deadline = lapic.timer_deadline_tsc.unwrap();
        assert_eq!(deadline, 1_000_001_600);

        // Before deadline: should not fire
        assert!(!lapic.check_and_fire_timer(1_000_001_599));
        assert!(lapic.pending_vector().is_none());

        // At deadline: should fire
        assert!(lapic.check_and_fire_timer(1_000_001_600));
        assert_eq!(lapic.pending_vector(), Some(0xEC));
    }

    // --- Round-trip consistency with the kernel's clockevent conversion ---
    //
    // The kernel computes the APIC initial count as:
    //   apic_ticks = delta_ns * ce_mult >> ce_shift
    // where ce_mult/ce_shift convert nanoseconds to APIC timer ticks. For our virtual
    // CPU with crystal=1GHz and divide-by-16:
    //   ce_mult = div_sc(lapic_timer_period / 16, TICK_NSEC, 32)
    //           = div_sc(625000, 10000000, 32)
    //           = (625000 << 32) / 10000000
    //           = 268435456
    //   ce_shift = 32
    //
    // The VMM then converts: tsc_deadline = tsc + apic_ticks * 16 * ratio
    // And the current count converts back: current = remaining_tsc / ratio >> 4
    //
    // Rounding in the kernel's ns→ticks truncation means the APIC initial count is
    // slightly less than the ideal value. This test checks how much error that
    // introduces in the round-trip.

    #[test]
    fn kernel_clockevent_roundtrip() {
        let ratio: u64 = 100;
        let ce_mult: u64 = 268_435_456;  // (625000 << 32) / 10_000_000
        let ce_shift: u32 = 32;

        let mut lapic = Lapic::new(ratio);
        write_reg(&mut lapic, 0x3E0, 0x3, 0);  // divide by 16

        // Simulate the kernel programming a 10ms timer (TICK_NSEC = 10,000,000 ns)
        let delta_ns: u64 = 10_000_000;
        let apic_ticks = ((delta_ns * ce_mult) >> ce_shift) as u32;

        // The kernel would write this to the initial count register
        write_reg(&mut lapic, 0x380, apic_ticks, 0);

        let deadline = lapic.timer_deadline_tsc.unwrap();

        // The ideal deadline is delta_ns * (ratio) = 10,000,000 * 100 = 1,000,000,000
        let ideal_deadline: u64 = delta_ns * ratio;
        let error = (ideal_deadline as i64) - (deadline as i64);

        // The error comes from truncation in the kernel's ns→ticks conversion.
        // It should be small (< 1 crystal tick = ratio TSC ticks = 100).
        assert!(error.unsigned_abs() < ratio,
                "deadline error {} exceeds 1 crystal tick (ratio={}). \
                 ideal={} actual={} apic_ticks={}",
                error, ratio, ideal_deadline, deadline, apic_ticks);
    }

    /// Verify that reading back the current count after the kernel's conversion gives
    /// a value very close to the programmed initial count.
    #[test]
    fn current_count_matches_initial_after_kernel_conversion() {
        let ratio: u64 = 100;
        let ce_mult: u64 = 268_435_456;
        let ce_shift: u32 = 32;

        let mut lapic = Lapic::new(ratio);
        write_reg(&mut lapic, 0x3E0, 0x3, 0);

        let delta_ns: u64 = 10_000_000;
        let apic_ticks = ((delta_ns * ce_mult) >> ce_shift) as u32;
        write_reg(&mut lapic, 0x380, apic_ticks, 0);

        // Read back immediately — should match
        let readback = read_reg(&lapic, 0x390, 0);
        assert_eq!(readback, apic_ticks,
                   "current count readback should equal initial count at t=0");
    }

    /// The counter steps discretely at crystal clock edges (every `tick_size` TSC cycles).
    /// Floor division of remaining TSC ticks means the count drops to 0 during the final
    /// partial tick before the deadline.
    #[test]
    fn current_count_near_expiry() {
        let ratio: u64 = 100;
        let mut lapic = Lapic::new(ratio);
        write_reg(&mut lapic, 0x3E0, 0x3, 0);  // divide by 16
        write_reg(&mut lapic, 0x380, 625_000, 0);

        // Deadline = 625000 * 16 * 100 = 1,000,000,000. Tick size = 1600.

        // Exactly 1 tick remaining (1600 TSC cycles) — count is 1
        let count = read_reg(&lapic, 0x390, 1_000_000_000 - 1600);
        assert_eq!(count, 1);

        // 1599 TSC cycles remaining — less than one full tick, count is 0
        let count = read_reg(&lapic, 0x390, 1_000_000_000 - 1599);
        assert_eq!(count, 0);

        // 1 TSC cycle remaining — still 0, timer hasn't fired yet
        let count = read_reg(&lapic, 0x390, 1_000_000_000 - 1);
        assert_eq!(count, 0);
    }

    // --- Periodic mode ---

    #[test]
    fn periodic_mode_rearms_from_deadline() {
        let ratio: u64 = 100;
        let mut lapic = Lapic::new(ratio);
        // Periodic mode (bit 17), unmasked, vector 0xEC
        write_reg(&mut lapic, 0x320, 0x2_00EC, 0);
        write_reg(&mut lapic, 0x3E0, 0x3, 0);  // divide by 16
        write_reg(&mut lapic, 0x380, 625_000, 0);

        let first_deadline = lapic.timer_deadline_tsc.unwrap();
        assert_eq!(first_deadline, 1_000_000_000);

        // Fire slightly late
        assert!(lapic.check_and_fire_timer(1_000_000_100));

        // Periodic re-arm should be from the deadline, not from current TSC
        let second_deadline = lapic.timer_deadline_tsc.unwrap();
        assert_eq!(second_deadline, 2_000_000_000,
                   "periodic re-arm should be deadline + period, not current_tsc + period");
    }

    // --- Divide register encoding ---

    #[test]
    fn divide_register_encodings() {
        let mut lapic = Lapic::new(1);

        let cases = [
            (0x0, 1),  // ÷2  → shift 1
            (0x1, 2),  // ÷4  → shift 2
            (0x2, 3),  // ÷8  → shift 3
            (0x3, 4),  // ÷16 → shift 4
            (0x8, 5),  // ÷32 → shift 5
            (0x9, 6),  // ÷64 → shift 6
            (0xA, 7),  // ÷128 → shift 7
            (0xB, 0),  // ÷1  → shift 0
        ];

        for (reg_val, expected_shift) in cases {
            lapic.timer_divide = reg_val;
            assert_eq!(lapic.divide_shift(), expected_shift,
                       "divide register {:#x} should give shift {}", reg_val, expected_shift);
        }
    }
}
