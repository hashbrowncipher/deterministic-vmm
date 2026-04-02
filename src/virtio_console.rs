// SPDX-License-Identifier: Apache-2.0
//! Minimal virtio-console device over the MMIO transport (virtio spec v1.2).
//!
//! Only the transmit queue (guest→host) is implemented. The guest writes console
//! output into virtqueue buffers and kicks; we drain them to stdout in a single
//! MMIO exit — one VMEXIT per write() instead of one per byte.

use std::io::Write;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

/// MMIO region size (4 KiB page).
pub const VIRTIO_MMIO_SIZE: u64 = 0x1000;

const VIRTIO_MMIO_MAGIC: u32 = 0x7472_6976; // "virt"
const VIRTIO_MMIO_VERSION: u32 = 2; // modern (non-legacy)
const VIRTIO_DEVICE_CONSOLE: u32 = 3;
const VIRTIO_VENDOR_ID: u32 = 0x554d_4551; // "QEMU" — conventional

// Feature bits
const VIRTIO_F_VERSION_1: u64 = 1 << 32;

// Virtqueue constants
const QUEUE_SIZE: u16 = 256;
const TX_QUEUE: u32 = 1;

// Descriptor flags
const VRING_DESC_F_NEXT: u16 = 1;

pub struct VirtioConsole {
    // Transport state
    device_features_sel: u32,
    driver_features_sel: u32,
    driver_features: [u32; 2],
    queue_sel: u32,
    status: u32,
    interrupt_status: u32,

    // Per-queue state (0 = receiveq, 1 = transmitq)
    queue_num: [u16; 2],
    queue_ready: [bool; 2],
    queue_desc: [u64; 2],
    queue_avail: [u64; 2],
    queue_used: [u64; 2],
    last_avail_idx: [u16; 2],
}

impl VirtioConsole {
    pub fn new() -> Self {
        Self {
            device_features_sel: 0,
            driver_features_sel: 0,
            driver_features: [0; 2],
            queue_sel: 0,
            status: 0,
            interrupt_status: 0,
            queue_num: [QUEUE_SIZE; 2],
            queue_ready: [false; 2],
            queue_desc: [0; 2],
            queue_avail: [0; 2],
            queue_used: [0; 2],
            last_avail_idx: [0; 2],
        }
    }

    pub fn mmio_read(&self, offset: u64, data: &mut [u8]) {
        let val: u32 = match offset {
            0x000 => VIRTIO_MMIO_MAGIC,
            0x004 => VIRTIO_MMIO_VERSION,
            0x008 => VIRTIO_DEVICE_CONSOLE,
            0x00c => VIRTIO_VENDOR_ID,
            0x010 => {
                // DeviceFeatures — selected by DeviceFeaturesSel
                match self.device_features_sel {
                    0 => 0, // no device-specific features
                    1 => (VIRTIO_F_VERSION_1 >> 32) as u32,
                    _ => 0,
                }
            }
            0x034 => QUEUE_SIZE as u32, // QueueNumMax
            0x044 => {
                let q = self.queue_sel as usize;
                if q < 2 { self.queue_ready[q] as u32 } else { 0 }
            }
            0x060 => self.interrupt_status,  // InterruptStatus
            0x070 => self.status,            // Status
            0x0fc => 0,                      // ConfigGeneration
            // Device config space: cols=0, rows=0
            0x100..=0x10f => 0,
            _ => 0,
        };
        let bytes = val.to_le_bytes();
        let len = data.len().min(4);
        data[..len].copy_from_slice(&bytes[..len]);
    }

    /// Handle an MMIO write. Returns true if the transmit queue was kicked
    /// (caller should drain it).
    pub fn mmio_write(&mut self, offset: u64, data: &[u8]) -> bool {
        let val = match data.len() {
            1 => data[0] as u32,
            2 => u16::from_le_bytes([data[0], data[1]]) as u32,
            4 => u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            _ => return false,
        };

        match offset {
            0x014 => self.device_features_sel = val,
            0x020 => {
                self.driver_features[self.driver_features_sel as usize & 1] = val;
            }
            0x024 => self.driver_features_sel = val,
            0x030 => self.queue_sel = val,
            0x038 => {
                let q = self.queue_sel as usize;
                if q < 2 {
                    self.queue_num[q] = val.min(QUEUE_SIZE as u32) as u16;
                }
            }
            0x044 => {
                let q = self.queue_sel as usize;
                if q < 2 {
                    self.queue_ready[q] = val != 0;
                }
            }
            0x050 => {
                // QueueNotify — the guest kicked a queue
                if val == TX_QUEUE {
                    return true;
                }
            }
            0x064 => {
                // InterruptACK
                self.interrupt_status &= !val;
            }
            0x070 => {
                // Status
                if val == 0 {
                    // Device reset
                    *self = Self::new();
                } else {
                    self.status = val;
                }
            }
            0x080 => {
                let q = self.queue_sel as usize;
                if q < 2 {
                    self.queue_desc[q] = (self.queue_desc[q] & !0xFFFF_FFFF) | val as u64;
                }
            }
            0x084 => {
                let q = self.queue_sel as usize;
                if q < 2 {
                    self.queue_desc[q] = (self.queue_desc[q] & 0xFFFF_FFFF) | ((val as u64) << 32);
                }
            }
            0x090 => {
                let q = self.queue_sel as usize;
                if q < 2 {
                    self.queue_avail[q] = (self.queue_avail[q] & !0xFFFF_FFFF) | val as u64;
                }
            }
            0x094 => {
                let q = self.queue_sel as usize;
                if q < 2 {
                    self.queue_avail[q] = (self.queue_avail[q] & 0xFFFF_FFFF) | ((val as u64) << 32);
                }
            }
            0x0a0 => {
                let q = self.queue_sel as usize;
                if q < 2 {
                    self.queue_used[q] = (self.queue_used[q] & !0xFFFF_FFFF) | val as u64;
                }
            }
            0x0a4 => {
                let q = self.queue_sel as usize;
                if q < 2 {
                    self.queue_used[q] = (self.queue_used[q] & 0xFFFF_FFFF) | ((val as u64) << 32);
                }
            }
            _ => {}
        }
        false
    }

    /// Drain the transmit queue: read all pending buffers from guest memory and
    /// write their contents to stdout. Updates the used ring so the guest can
    /// reclaim the buffers.
    pub fn drain_tx(&mut self, guest_mem: &GuestMemoryMmap) {
        let q = TX_QUEUE as usize;
        if !self.queue_ready[q] {
            return;
        }
        let num = self.queue_num[q] as u16;
        if num == 0 {
            return;
        }

        let desc_base = self.queue_desc[q];
        let avail_base = self.queue_avail[q];
        let used_base = self.queue_used[q];

        // Read avail->idx (offset 2 in the avail ring)
        let avail_idx: u16 = guest_mem
            .read_obj(GuestAddress(avail_base + 2))
            .unwrap_or(self.last_avail_idx[q]);

        let stdout = std::io::stdout();
        let mut out = stdout.lock();

        while self.last_avail_idx[q] != avail_idx {
            let ring_idx = (self.last_avail_idx[q] % num) as u64;
            // avail ring entries start at offset 4
            let head: u16 = guest_mem
                .read_obj(GuestAddress(avail_base + 4 + ring_idx * 2))
                .unwrap_or(0);

            let mut written = 0u32;
            let mut desc_idx = head;
            loop {
                let desc_addr = desc_base + (desc_idx as u64) * 16;
                let addr: u64 = guest_mem.read_obj(GuestAddress(desc_addr)).unwrap_or(0);
                let len: u32 = guest_mem.read_obj(GuestAddress(desc_addr + 8)).unwrap_or(0);
                let flags: u16 = guest_mem.read_obj(GuestAddress(desc_addr + 12)).unwrap_or(0);
                let next: u16 = guest_mem.read_obj(GuestAddress(desc_addr + 14)).unwrap_or(0);

                if len > 0 {
                    let mut buf = vec![0u8; len as usize];
                    if guest_mem.read_slice(&mut buf, GuestAddress(addr)).is_ok() {
                        let _ = out.write_all(&buf);
                    }
                    written += len;
                }

                if flags & VRING_DESC_F_NEXT == 0 || next >= num {
                    break;
                }
                desc_idx = next;
            }

            // Add to used ring: used ring entries start at offset 4 (after flags + idx)
            let used_idx: u16 = guest_mem
                .read_obj(GuestAddress(used_base + 2))
                .unwrap_or(0);
            let used_ring_idx = (used_idx % num) as u64;
            // Each used element is 8 bytes: u32 id + u32 len
            let used_elem_addr = used_base + 4 + used_ring_idx * 8;
            let _ = guest_mem.write_obj(head as u32, GuestAddress(used_elem_addr));
            let _ = guest_mem.write_obj(written, GuestAddress(used_elem_addr + 4));
            // Update used->idx
            let _ = guest_mem.write_obj(used_idx.wrapping_add(1), GuestAddress(used_base + 2));

            self.last_avail_idx[q] = self.last_avail_idx[q].wrapping_add(1);
        }

        let _ = out.flush();

        // Signal used buffer notification
        self.interrupt_status |= 1;
    }

    /// Returns true if there's a pending interrupt that hasn't been ACKed.
    pub fn irq_pending(&self) -> bool {
        self.interrupt_status != 0
    }
}
