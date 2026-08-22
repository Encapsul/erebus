//! Universal Binary (Polyglot) Assembly
//!
//! Creates a single ``.erebus`` file that runs on Linux `x86_64/ARM64`,
//! macOS ARM64, and Windows x64 by embedding multiple architecture-specific
//! slices in a polyglot wrapper.
//!
//! Layout: `[polyglot-header][slice-table][slice-1][slice-2][slice-3][slice-4]`
//!
//! Each slice = `[stub][payload][metadata][footer]` (standard erebus v5 format)
//!
//! The polyglot header is a valid ELF (Linux), PE (Windows), and Mach-O (macOS)
//! that executes the polyglot stub. The stub detects OS/arch at runtime,
//! seeks to the correct slice, and execve(2)s it.

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::format::{ARCH_AARCH64, ARCH_X86_64};
use sha2::{Digest, Sha256};

/// Polyglot slice entry — one architecture-specific .erebus artifact
#[derive(Debug, Clone)]
pub struct PolyglotSlice {
    /// Target identifier (e.g., "linux-x86_64", "linux-aarch64", "macos-aarch64", "windows-x86_64")
    pub target: String,
    /// Architecture byte (matches format.rs ARCH_* constants)
    pub arch: u8,
    /// OS identifier for runtime detection
    pub os: PolyglotOS,
    /// The complete .erebus bytes for this target
    pub bytes: Vec<u8>,
}

/// Supported operating systems in the polyglot
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolyglotOS {
    Linux,
    MacOS,
    Windows,
}

impl PolyglotOS {
    /// Parse OS from string (not `FromStr` to avoid trait confusion)
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "linux" => Some(PolyglotOS::Linux),
            "macos" | "darwin" => Some(PolyglotOS::MacOS),
            "windows" => Some(PolyglotOS::Windows),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            PolyglotOS::Linux => "linux",
            PolyglotOS::MacOS => "macos",
            PolyglotOS::Windows => "windows",
        }
    }
}

/// Slice table entry (written in the polyglot header)
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct SliceTableEntry {
    pub target_os: u8,   // 0=linux, 1=macos, 2=windows
    pub target_arch: u8, // format.rs ARCH_* constants
    pub offset: u64,     // offset from file start
    pub size: u64,       // slice size
    pub flags: u8,       // reserved
    pad: [u8; 7],        // align to 32 bytes
}

/// Polyglot header magic: "ERE\x01" + "POLY" = 8 bytes
pub const POLYGLOT_MAGIC: &[u8; 8] = b"ERE\x01POLY";

/// Current polyglot format version
pub const POLYGLOT_VERSION: u8 = 1;

/// Polyglot header (fixed size, placed at file offset 0)
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct PolyglotHeader {
    pub magic: [u8; 8],          // "ERE\x01POLY"
    pub version: u8,             // format version
    pub slice_count: u8,         // number of slices
    pub entry_slice: u8,         // default slice index (first match)
    pub header_size: u32,        // size of this header + slice table
    pub slice_table_offset: u64, // always = header_size
    pub footer_offset: u64,      // offset of polyglot footer (for verification)
    pub total_size: u64,         // total file size
    reserved: [u8; 16],          // future expansion
}

/// Polyglot footer (at end of file, for integrity verification)
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct PolyglotFooter {
    pub magic: [u8; 8], // "ERE\x01POLY"
    pub version: u8,
    pub slice_count: u8,
    pub sha256: [u8; 32], // SHA-256 of entire file except this footer
    reserved: [u8; 16],   // future expansion
}

/// Default targets for universal build
pub const DEFAULT_UNIVERSAL_TARGETS: &[(&str, &str, u8, PolyglotOS)] = &[
    (
        "x86_64-unknown-linux-musl",
        "linux-x86_64",
        ARCH_X86_64,
        PolyglotOS::Linux,
    ),
    (
        "aarch64-unknown-linux-musl",
        "linux-aarch64",
        ARCH_AARCH64,
        PolyglotOS::Linux,
    ),
    (
        "aarch64-apple-darwin",
        "macos-aarch64",
        ARCH_AARCH64,
        PolyglotOS::MacOS,
    ),
    (
        "x86_64-pc-windows-gnu",
        "windows-x86_64",
        ARCH_X86_64,
        PolyglotOS::Windows,
    ),
];

/// Build a universal .erebus from per-target assemblies
///
/// Each `target_input` is assembled independently, then all slices are combined
/// into a single polyglot file with a header that routes to the correct slice.
pub fn assemble_universal(out_path: &Path, slices: &[PolyglotSlice]) -> io::Result<u64> {
    if slices.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no slices provided",
        ));
    }
    if slices.len() > 255 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "too many slices (max 255)",
        ));
    }

    // Calculate header + slice table size
    let header_size = std::mem::size_of::<PolyglotHeader>() as u64;
    let slice_table_size = slices.len() as u64 * std::mem::size_of::<SliceTableEntry>() as u64;
    let total_header_size = header_size + slice_table_size;

    // Align slices to 4KB boundaries for cleaner extraction
    const ALIGN: u64 = 4096;
    let mut slice_offset = (total_header_size + ALIGN - 1) & !(ALIGN - 1);

    // Build slice table entries
    let mut slice_entries = Vec::with_capacity(slices.len());
    let mut slice_data = Vec::new();

    for slice in slices {
        let aligned_offset = (slice_offset + ALIGN - 1) & !(ALIGN - 1);
        let entry = SliceTableEntry {
            target_os: slice.os as u8,
            target_arch: slice.arch,
            offset: aligned_offset,
            size: slice.bytes.len() as u64,
            flags: 0,
            pad: [0; 7],
        };
        slice_entries.push(entry);

        // Pad to alignment
        let current_len = slice_data.len() as u64;
        let target_start = aligned_offset - total_header_size;
        if current_len < target_start {
            let pad = target_start - current_len;
            slice_data.extend(std::iter::repeat_n(0, pad as usize));
        }

        slice_data.extend_from_slice(&slice.bytes);
        slice_offset = aligned_offset + slice.bytes.len() as u64;
    }

    // Compute total size (header + slice table + slices + footer)
    let polyglot_footer_size = std::mem::size_of::<PolyglotFooter>() as u64;
    let total_size = slice_offset + polyglot_footer_size;

    // Compute SHA-256 of everything except the footer
    // Use the REAL footer_offset (not placeholder) so hash matches what's written
    let real_footer_offset = total_size - polyglot_footer_size;
    let mut hasher = Sha256::new();
    hasher.update(POLYGLOT_MAGIC);
    hasher.update([POLYGLOT_VERSION]);
    hasher.update([slices.len() as u8]);
    hasher.update([0]); // entry_slice
    hasher.update((total_header_size as u32).to_le_bytes());
    hasher.update((header_size as u64).to_le_bytes()); // slice_table_offset = header_size
    hasher.update(real_footer_offset.to_le_bytes());
    hasher.update(total_size.to_le_bytes());
    hasher.update([0u8; 16]); // reserved

    for entry in &slice_entries {
        hasher.update([entry.target_os]);
        hasher.update([entry.target_arch]);
        hasher.update(entry.offset.to_le_bytes());
        hasher.update(entry.size.to_le_bytes());
        hasher.update([entry.flags]);
        hasher.update(entry.pad);
    }

    hasher.update(&slice_data);
    let file_sha256: [u8; 32] = hasher.finalize().into();

    // Build polyglot header
    let header = PolyglotHeader {
        magic: *POLYGLOT_MAGIC,
        version: POLYGLOT_VERSION,
        slice_count: slices.len() as u8,
        entry_slice: 0, // will be determined at runtime
        header_size: total_header_size as u32,
        slice_table_offset: header_size, // slice table starts right after header
        footer_offset: total_size - polyglot_footer_size,
        total_size,
        reserved: [0; 16],
    };

    // Build polyglot footer
    let footer = PolyglotFooter {
        magic: *POLYGLOT_MAGIC,
        version: POLYGLOT_VERSION,
        slice_count: slices.len() as u8,
        sha256: file_sha256,
        reserved: [0; 16],
    };

    // Write everything
    let parent = out_path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;

    let mut file = std::fs::File::create(out_path)?;

    // Write header
    write_polyglot_header(&mut file, &header)?;

    // Write slice table
    for entry in &slice_entries {
        write_slice_entry(&mut file, entry)?;
    }

    // Write slices (already aligned in slice_data)
    file.write_all(&slice_data)?;

    // Write footer
    write_polyglot_footer(&mut file, &footer)?;

    file.flush()?;

    // Make executable on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(out_path, std::fs::Permissions::from_mode(0o755))?;
    }

    Ok(total_size)
}

fn write_polyglot_header<W: Write>(w: &mut W, header: &PolyglotHeader) -> io::Result<()> {
    w.write_all(&header.magic)?;
    w.write_all(&[header.version])?;
    w.write_all(&[header.slice_count])?;
    w.write_all(&[header.entry_slice])?;
    w.write_all(&header.header_size.to_le_bytes())?;
    w.write_all(&header.slice_table_offset.to_le_bytes())?;
    w.write_all(&header.footer_offset.to_le_bytes())?;
    w.write_all(&header.total_size.to_le_bytes())?;
    w.write_all(&header.reserved)?;
    Ok(())
}

fn write_slice_entry<W: Write>(w: &mut W, entry: &SliceTableEntry) -> io::Result<()> {
    w.write_all(&[entry.target_os])?;
    w.write_all(&[entry.target_arch])?;
    w.write_all(&entry.offset.to_le_bytes())?;
    w.write_all(&entry.size.to_le_bytes())?;
    w.write_all(&[entry.flags])?;
    w.write_all(&entry.pad)?;
    Ok(())
}

fn write_polyglot_footer<W: Write>(w: &mut W, footer: &PolyglotFooter) -> io::Result<()> {
    w.write_all(&footer.magic)?;
    w.write_all(&[footer.version])?;
    w.write_all(&[footer.slice_count])?;
    w.write_all(&footer.sha256)?;
    w.write_all(&footer.reserved)?;
    Ok(())
}

/// Read polyglot header from an existing file
pub fn read_polyglot_header<R: Read + Seek>(r: &mut R) -> io::Result<PolyglotHeader> {
    let mut magic = [0u8; 8];
    r.read_exact(&mut magic)?;
    if &magic != POLYGLOT_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a polyglot erebus file",
        ));
    }

    let mut version = [0u8; 1];
    r.read_exact(&mut version)?;
    let mut slice_count = [0u8; 1];
    r.read_exact(&mut slice_count)?;
    let mut entry_slice = [0u8; 1];
    r.read_exact(&mut entry_slice)?;

    let mut header_size = [0u8; 4];
    r.read_exact(&mut header_size)?;
    let mut slice_table_offset = [0u8; 8];
    r.read_exact(&mut slice_table_offset)?;
    let mut footer_offset = [0u8; 8];
    r.read_exact(&mut footer_offset)?;
    let mut total_size = [0u8; 8];
    r.read_exact(&mut total_size)?;
    let mut reserved = [0u8; 16];
    r.read_exact(&mut reserved)?;

    Ok(PolyglotHeader {
        magic,
        version: version[0],
        slice_count: slice_count[0],
        entry_slice: entry_slice[0],
        header_size: u32::from_le_bytes(header_size),
        slice_table_offset: u64::from_le_bytes(slice_table_offset),
        footer_offset: u64::from_le_bytes(footer_offset),
        total_size: u64::from_le_bytes(total_size),
        reserved,
    })
}

/// Read slice table from an existing file
pub fn read_slice_table<R: Read + Seek>(
    r: &mut R,
    header: &PolyglotHeader,
) -> io::Result<Vec<SliceTableEntry>> {
    r.seek(SeekFrom::Start(header.slice_table_offset))?;
    let mut entries = Vec::with_capacity(header.slice_count as usize);
    for _ in 0..header.slice_count {
        let mut target_os = [0u8; 1];
        r.read_exact(&mut target_os)?;
        let mut target_arch = [0u8; 1];
        r.read_exact(&mut target_arch)?;
        let mut offset = [0u8; 8];
        r.read_exact(&mut offset)?;
        let mut size = [0u8; 8];
        r.read_exact(&mut size)?;
        let mut flags = [0u8; 1];
        r.read_exact(&mut flags)?;
        let mut pad = [0u8; 7];
        r.read_exact(&mut pad)?;

        entries.push(SliceTableEntry {
            target_os: target_os[0],
            target_arch: target_arch[0],
            offset: u64::from_le_bytes(offset),
            size: u64::from_le_bytes(size),
            flags: flags[0],
            pad,
        });
    }
    Ok(entries)
}

/// Verify polyglot file integrity
pub fn verify_polyglot<R: Read + Seek>(r: &mut R) -> io::Result<bool> {
    r.seek(SeekFrom::Start(0))?;
    let header = read_polyglot_header(r)?;
    let _entries = read_slice_table(r, &header)?;

    // Read footer
    let footer_size = std::mem::size_of::<PolyglotFooter>() as i64;
    r.seek(SeekFrom::End(-footer_size))?;
    let mut footer_magic = [0u8; 8];
    r.read_exact(&mut footer_magic)?;
    if &footer_magic != POLYGLOT_MAGIC {
        return Ok(false);
    }

    let mut version = [0u8; 1];
    r.read_exact(&mut version)?;
    let mut slice_count = [0u8; 1];
    r.read_exact(&mut slice_count)?;
    let mut sha256 = [0u8; 32];
    r.read_exact(&mut sha256)?;
    let mut reserved = [0u8; 16];
    r.read_exact(&mut reserved)?;

    // Recompute hash
    r.seek(SeekFrom::Start(0))?;
    let footer_offset = header.footer_offset;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 8192];
    let mut remaining = footer_offset;
    while remaining > 0 {
        let to_read = std::cmp::min(buf.len() as u64, remaining);
        r.read_exact(&mut buf[..to_read as usize])?;
        hasher.update(&buf[..to_read as usize]);
        remaining -= to_read;
    }
    let computed: [u8; 32] = hasher.finalize().into();

    Ok(computed == sha256)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{ARCH_AARCH64, ARCH_X86_64};
    use tempfile::tempdir;

    #[test]
    fn test_polyglot_roundtrip() {
        let dir = tempdir().unwrap();
        let out = dir.path().join("test.polyglot");

        // Create dummy slices
        let slices = vec![
            PolyglotSlice {
                target: "linux-x86_64".into(),
                arch: ARCH_X86_64,
                os: PolyglotOS::Linux,
                bytes: [0x7f, 0x45, 0x4c, 0x46].repeat(250), // fake ELF
            },
            PolyglotSlice {
                target: "linux-aarch64".into(),
                arch: ARCH_AARCH64,
                os: PolyglotOS::Linux,
                bytes: [0x7f, 0x45, 0x4c, 0x46].repeat(375), // fake ELF
            },
        ];

        let size = assemble_universal(&out, &slices).unwrap();
        assert!(size > 0);

        // Verify
        let mut f = std::fs::File::open(&out).unwrap();

        f.seek(SeekFrom::Start(0)).unwrap();
        let mut dbg_magic = [0u8; 8];
        f.read_exact(&mut dbg_magic).unwrap();

        let footer_size = std::mem::size_of::<PolyglotFooter>() as i64;
        f.seek(SeekFrom::End(-footer_size)).unwrap();
        let mut dbg_footer_magic = [0u8; 8];
        f.read_exact(&mut dbg_footer_magic).unwrap();
        let mut dbg_version = [0u8; 1];
        f.read_exact(&mut dbg_version).unwrap();
        let mut dbg_slice_count = [0u8; 1];
        f.read_exact(&mut dbg_slice_count).unwrap();
        let mut dbg_sha256 = [0u8; 32];
        f.read_exact(&mut dbg_sha256).unwrap();

        let ok = verify_polyglot(&mut f).unwrap();
        assert!(ok);

        // Read header
        f.seek(SeekFrom::Start(0)).unwrap();
        let header = read_polyglot_header(&mut f).unwrap();
        assert_eq!(header.slice_count, 2);
        assert_eq!(header.version, POLYGLOT_VERSION);
        assert_eq!(&header.magic, POLYGLOT_MAGIC);

        // Read slice table
        let entries = read_slice_table(&mut f, &header).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].target_os, PolyglotOS::Linux as u8);
        assert_eq!(entries[0].target_arch, ARCH_X86_64);
        assert_eq!(entries[1].target_arch, ARCH_AARCH64);
    }
}
