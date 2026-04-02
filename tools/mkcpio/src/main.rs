// SPDX-License-Identifier: Apache-2.0
//! Deterministic cpio (newc / "070701") writer.
//!
//! Builds a fixed-layout initramfs containing /init and the mountpoint
//! directories the guest expects. Every byte of the output is a function of
//! the input init binary's bytes — no timestamps, uids, inode counters, or
//! filesystem state leak in.
//!
//! Usage: mkcpio <init-binary> <output.cpio>

use std::env;
use std::fs;
use std::io::{self, BufWriter, Write};
use std::process;

const MAGIC: &[u8] = b"070701";
// newc header is the 6-byte magic plus 13 fixed-width 8-char hex fields.
const HEADER_LEN: usize = 6 + 13 * 8;

struct Entry {
    name: &'static str,
    mode: u32,
    nlink: u32,
    data: Vec<u8>,
}

fn write_hex(out: &mut impl Write, val: u32) -> io::Result<()> {
    write!(out, "{:08x}", val)
}

fn pad4(out: &mut impl Write, len: usize) -> io::Result<()> {
    let pad = (4 - (len % 4)) % 4;
    out.write_all(&[0u8; 3][..pad])
}

fn write_entry(out: &mut impl Write, ino: u32, e: &Entry) -> io::Result<()> {
    let name_bytes = e.name.as_bytes();
    let namesize = name_bytes.len() as u32 + 1; // include trailing NUL

    out.write_all(MAGIC)?;
    write_hex(out, ino)?;
    write_hex(out, e.mode)?;
    write_hex(out, 0)?; // uid
    write_hex(out, 0)?; // gid
    write_hex(out, e.nlink)?;
    write_hex(out, 0)?; // mtime
    write_hex(out, e.data.len() as u32)?; // filesize
    write_hex(out, 0)?; // devmajor
    write_hex(out, 0)?; // devminor
    write_hex(out, 0)?; // rdevmajor
    write_hex(out, 0)?; // rdevminor
    write_hex(out, namesize)?;
    write_hex(out, 0)?; // check (unused for newc)

    out.write_all(name_bytes)?;
    out.write_all(&[0])?;
    pad4(out, HEADER_LEN + namesize as usize)?;

    out.write_all(&e.data)?;
    pad4(out, e.data.len())?;
    Ok(())
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: {} <init-binary> <output.cpio>", args[0]);
        process::exit(1);
    }

    let init_data = fs::read(&args[1])?;

    // Fixed entry list. Order is part of the contract: deterministic output
    // requires a deterministic traversal, and hand-listing is simpler than
    // sorting a directory walk for a rootfs this small.
    let entries = [
        Entry { name: ".",    mode: 0o040755, nlink: 2, data: Vec::new() },
        Entry { name: "dev",  mode: 0o040755, nlink: 2, data: Vec::new() },
        Entry { name: "proc", mode: 0o040755, nlink: 2, data: Vec::new() },
        Entry { name: "sys",  mode: 0o040755, nlink: 2, data: Vec::new() },
        Entry { name: "mnt",  mode: 0o040755, nlink: 2, data: Vec::new() },
        Entry { name: "init", mode: 0o100755, nlink: 1, data: init_data },
    ];

    let mut out = BufWriter::new(fs::File::create(&args[2])?);
    for (i, e) in entries.iter().enumerate() {
        write_entry(&mut out, (i + 1) as u32, e)?;
    }
    // Trailer: zero ino, zero mode, nlink=1, name "TRAILER!!!".
    write_entry(
        &mut out,
        0,
        &Entry { name: "TRAILER!!!", mode: 0, nlink: 1, data: Vec::new() },
    )?;
    out.flush()?;
    Ok(())
}
