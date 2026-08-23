//! Universal Binary (Polyglot) Assembly
//!
//! Creates a single `.erebus` file that runs on Linux `x86_64/ARM64`,
//! macOS ARM64, and Windows x64 by embedding multiple architecture-specific
//! slices in a polyglot wrapper.
//!
//! Layout: `[sh-loader][polyglot-header][slice-table][slice-1]..[slice-N][footer]`
//!
//! Why a shell-script loader? A single file cannot be simultaneously a valid
//! ELF, Mach-O and PE (three different magics at offset 0), and one ELF cannot
//! carry two `e_machine` values — so a native multi-arch stub is impossible
//! without a Cosmopolitan-style toolchain. `/bin/sh`, however, exists on every
//! Unix regardless of architecture, so the kernel's shebang handler becomes
//! our universal launcher: it extracts the slice matching
//! `uname -s`/`uname -m` into a private cache directory and exec(2)s it.
//! Each slice is itself a complete native `.erebus` artifact
//! (`[stub][payload][metadata][footer]`) whose real stub takes over there.

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::format::{ARCH_AARCH64, ARCH_X86_64};
use sha2::{Digest, Sha256};

/// Size of the leading shell-loader region; the polyglot header starts at this
/// offset. 32 KiB leaves room for the script prologue plus up to 255 case arms.
pub const LOADER_REGION_SIZE: u64 = 32 * 1024;

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
    pad: [u8; 7],        // reserved (total entry size: 26 bytes)
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
/// Each slice is a complete native `.erebus` artifact for one OS/arch pair.
/// Slices are combined behind a generated `#!/bin/sh` loader (see module docs)
/// into a single polyglot file; the loader routes to the matching slice at
/// runtime based on `uname -s`/`uname -m`.
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
    // Duplicate platform pairs would generate overlapping sh case arms; the
    // shell would silently pick the first match, hiding a broken slice.
    let mut seen = std::collections::HashSet::new();
    for slice in slices {
        if !seen.insert((slice.os as u8, slice.arch)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "duplicate slice for os={} arch={}",
                    slice.os.as_str(),
                    slice.arch
                ),
            ));
        }
    }

    let header_size = std::mem::size_of::<PolyglotHeader>() as u64;

    // Absolute layout: loader region, header, table, then 4K-aligned slices.
    const ALIGN: u64 = 4096;
    let align_up = |v: u64| (v + ALIGN - 1) & !(ALIGN - 1);
    let table_offset = LOADER_REGION_SIZE + header_size;
    let mut cursor = align_up(table_offset);
    let mut offsets = Vec::with_capacity(slices.len());
    for slice in slices {
        let aligned = align_up(cursor);
        offsets.push(aligned);
        cursor = aligned + slice.bytes.len() as u64;
    }
    let polyglot_footer_size = std::mem::size_of::<PolyglotFooter>() as u64;
    let footer_offset = cursor;
    let total_size = footer_offset + polyglot_footer_size;

    // Generate the sh loader with baked-in slice offsets, then lay out entries.
    let script = generate_loader_script(slices, &offsets)?;
    if (script.len() as u64) > LOADER_REGION_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "loader script too large: {} bytes (region is {})",
                script.len(),
                LOADER_REGION_SIZE
            ),
        ));
    }
    let header = PolyglotHeader {
        magic: *POLYGLOT_MAGIC,
        version: POLYGLOT_VERSION,
        slice_count: slices.len() as u8,
        entry_slice: 0, // informational; routing is decided by uname at runtime
        header_size: header_size as u32,
        slice_table_offset: table_offset,
        footer_offset,
        total_size,
        reserved: [0; 16],
    };
    let entries: Vec<SliceTableEntry> = slices
        .iter()
        .zip(&offsets)
        .map(|(slice, &offset)| SliceTableEntry {
            target_os: slice.os as u8,
            target_arch: slice.arch,
            offset,
            size: slice.bytes.len() as u64,
            flags: 0,
            pad: [0; 7],
        })
        .collect();

    // Write everything except the footer.
    let parent = out_path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;

    let mut file = std::fs::File::create(out_path)?;
    file.write_all(&script)?;
    let pad = LOADER_REGION_SIZE - script.len() as u64;
    if pad > 0 {
        // NUL padding is never parsed: every code path execs or exits first.
        file.write_all(&vec![0u8; pad as usize])?;
    }
    debug_assert_eq!(file.stream_position()?, LOADER_REGION_SIZE);
    write_polyglot_header(&mut file, &header)?;
    for entry in &entries {
        write_slice_entry(&mut file, entry)?;
    }
    let mut pos = file.stream_position()?;
    for (slice, &offset) in slices.iter().zip(&offsets) {
        // Pad based on the REAL stream position, not a tracked counter: the
        // byte layout above (header size + per-entry sizes) must match exactly.
        if offset > pos {
            file.write_all(&vec![0u8; (offset - pos) as usize])?;
            pos = offset;
        }
        file.write_all(&slice.bytes)?;
        pos += slice.bytes.len() as u64;
    }
    file.flush()?;
    drop(file);

    // Hash exactly what was written in [0..footer_offset] so the footer always
    // matches verify_polyglot's streaming recomputation.
    let file_sha256: [u8; 32] = {
        let mut f = std::fs::File::open(out_path)?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 8192];
        let mut remaining = footer_offset;
        while remaining > 0 {
            let to_read =
                usize::try_from(std::cmp::min(buf.len() as u64, remaining)).unwrap_or(buf.len());
            f.read_exact(&mut buf[..to_read])?;
            hasher.update(&buf[..to_read]);
            remaining -= to_read as u64;
        }
        hasher.finalize().into()
    };

    let footer = PolyglotFooter {
        magic: *POLYGLOT_MAGIC,
        version: POLYGLOT_VERSION,
        slice_count: slices.len() as u8,
        sha256: file_sha256,
        reserved: [0; 16],
    };

    let mut file = std::fs::OpenOptions::new().append(true).open(out_path)?;
    write_polyglot_footer(&mut file, &footer)?;
    file.flush()?;
    drop(file);

    // Make executable on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(out_path, std::fs::Permissions::from_mode(0o755))?;
    }

    Ok(total_size)
}

/// uname glob arm selecting a slice of the given platform from the sh loader.
fn loader_arm(os: PolyglotOS, arch: u8) -> Option<&'static str> {
    match (os, arch) {
        (PolyglotOS::Linux, ARCH_X86_64) => Some("Linux:x86_64|Linux:amd64"),
        (PolyglotOS::Linux, ARCH_AARCH64) => Some("Linux:aarch64|Linux:arm64"),
        (PolyglotOS::MacOS, ARCH_AARCH64) => Some("Darwin:arm64"),
        (PolyglotOS::MacOS, ARCH_X86_64) => Some("Darwin:x86_64"),
        // git-bash / MSYS2 / Cygwin can spawn PE binaries directly.
        (PolyglotOS::Windows, ARCH_X86_64) => Some("MINGW*:x86_64|MSYS*:x86_64|CYGWIN_NT*:x86_64"),
        _ => None,
    }
}

/// Generate the embedded `#!/bin/sh` loader for the given slices.
///
/// The loader extracts its platform's slice with `tail|head` into a private
/// per-user cache directory keyed by the whole-file hash, then execs it.
fn generate_loader_script(slices: &[PolyglotSlice], offsets: &[u64]) -> io::Result<Vec<u8>> {
    let mut s = String::with_capacity(4096);
    s.push_str("#!/bin/sh\n");
    s.push_str("# erebus polyglot v1 - universal binary loader\n");
    s.push_str("# Generated by 'erebus build --universal'. Do not edit.\n");
    s.push_str("# Each case arm below extracts one native .erebus slice and execs it.\n");
    s.push_str("set -eu\n");
    s.push_str("ERE_SELF=\"$0\"\n");
    s.push_str("erebus_run() {\n");
    s.push_str("    off=\"$1\"; sz=\"$2\"\n");
    s.push_str("    d=\"${TMPDIR:-/tmp}/erebus-polyglot-$(id -u)\"\n");
    s.push_str("    h=\"$(sha256sum -- \"$ERE_SELF\" 2>/dev/null | cut -d' ' -f1)\"\n");
    s.push_str(
        "    [ -n \"$h\" ] || h=\"$(shasum -a 256 -- \"$ERE_SELF\" 2>/dev/null | cut -d' ' -f1)\"\n",
    );
    s.push_str(
        "    [ -n \"$h\" ] || h=\"$(md5sum -- \"$ERE_SELF\" 2>/dev/null | cut -d' ' -f1)\"\n",
    );
    s.push_str("    [ -n \"$h\" ] || h=nohash\n");
    s.push_str("    o=\"$d/$h-$sz.erebus\"\n");
    s.push_str("    if [ ! -x \"$o\" ]; then\n");
    s.push_str("        mkdir -p \"$d\"\n");
    s.push_str("        chmod 700 \"$d\"\n");
    s.push_str("        tail -c \"+$((off + 1))\" \"$ERE_SELF\" | head -c \"$sz\" > \"$o\"\n");
    s.push_str("        chmod 755 \"$o\"\n");
    s.push_str("    fi\n");
    s.push_str("    exec \"$o\" \"$@\"\n");
    s.push_str("}\n");
    s.push_str("case \"$(uname -s):$(uname -m)\" in\n");
    for (slice, &offset) in slices.iter().zip(offsets) {
        let Some(arm) = loader_arm(slice.os, slice.arch) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("no loader arm for target {}", slice.target),
            ));
        };
        s.push_str(&format!(
            "    {arm}) erebus_run {offset} {} ;;\n",
            slice.bytes.len()
        ));
    }
    s.push_str("esac\n");
    s.push_str("echo \"erebus: no slice for $(uname -s):$(uname -m)\" >&2\n");
    s.push_str("exit 1\n");

    Ok(s.into_bytes())
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
    r.seek(SeekFrom::Start(LOADER_REGION_SIZE))?;
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

        let mut f = std::fs::File::open(&out).unwrap();

        // The file must be directly executable: shebang first.
        let mut head = [0u8; 10];
        f.seek(SeekFrom::Start(0)).unwrap();
        f.read_exact(&mut head).unwrap();
        assert_eq!(&head, b"#!/bin/sh\n");

        // Verify
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

    #[test]
    fn loader_script_routes_every_slice() {
        let slices = vec![
            PolyglotSlice {
                target: "linux-x86_64".into(),
                arch: ARCH_X86_64,
                os: PolyglotOS::Linux,
                bytes: vec![1; 100],
            },
            PolyglotSlice {
                target: "macos-aarch64".into(),
                arch: ARCH_AARCH64,
                os: PolyglotOS::MacOS,
                bytes: vec![2; 200],
            },
            PolyglotSlice {
                target: "windows-x86_64".into(),
                arch: ARCH_X86_64,
                os: PolyglotOS::Windows,
                bytes: vec![3; 300],
            },
        ];
        let offsets = vec![36_864, 40_960, 45_056];
        let script = generate_loader_script(&slices, &offsets).unwrap();
        let text = std::str::from_utf8(&script).unwrap();

        assert!(script.starts_with(b"#!/bin/sh\n"));
        assert!(text.contains("Linux:x86_64|Linux:amd64) erebus_run 36864 100 ;;"));
        assert!(text.contains("Darwin:arm64) erebus_run 40960 200 ;;"));
        assert!(
            text.contains("MINGW*:x86_64|MSYS*:x86_64|CYGWIN_NT*:x86_64) erebus_run 45056 300 ;;")
        );
        // Unsupported platforms must fall through to the error path.
        assert!(text.ends_with("exit 1\n"));
    }

    #[test]
    fn slices_are_recoverable_at_table_offsets() {
        // Mirrors the loader's `tail -c +N | head -c sz` extraction: the bytes
        // at [offset, offset+size) must be exactly the original slice.
        let dir = tempdir().unwrap();
        let out = dir.path().join("test.polyglot");
        let x86 = vec![0xAA; 5000];
        let arm = vec![0xBB; 7000];
        let slices = vec![
            PolyglotSlice {
                target: "linux-x86_64".into(),
                arch: ARCH_X86_64,
                os: PolyglotOS::Linux,
                bytes: x86.clone(),
            },
            PolyglotSlice {
                target: "linux-aarch64".into(),
                arch: ARCH_AARCH64,
                os: PolyglotOS::Linux,
                bytes: arm.clone(),
            },
        ];

        assemble_universal(&out, &slices).unwrap();
        let mut f = std::fs::File::open(&out).unwrap();
        let header = read_polyglot_header(&mut f).unwrap();
        let entries = read_slice_table(&mut f, &header).unwrap();

        for (entry, expected) in entries.iter().zip([&x86, &arm]) {
            f.seek(SeekFrom::Start(entry.offset)).unwrap();
            let mut got = vec![0u8; expected.len()];
            f.read_exact(&mut got).unwrap();
            assert_eq!(&got, expected);
        }
    }

    #[test]
    fn duplicate_platform_slices_are_rejected() {
        // Two Linux/x86_64 slices would generate overlapping case arms — the
        // sh case statement silently picks the first, so assembly must refuse.
        let dir = tempdir().unwrap();
        let out = dir.path().join("dup.polyglot");
        let slices = vec![
            PolyglotSlice {
                target: "linux-x86_64-a".into(),
                arch: ARCH_X86_64,
                os: PolyglotOS::Linux,
                bytes: vec![1; 10],
            },
            PolyglotSlice {
                target: "linux-x86_64-b".into(),
                arch: ARCH_X86_64,
                os: PolyglotOS::Linux,
                bytes: vec![2; 10],
            },
        ];
        assert!(assemble_universal(&out, &slices).is_err());
    }
}

#[cfg(test)]
mod real_slice_tests {
    use super::*;
    use crate::format::{ARCH_AARCH64, ARCH_X86_64};
    use std::fs;
    use std::path::Path;

    #[test]
    #[ignore] // Run with --ignored to test with real slices
    fn test_real_slices() {
        let x86_slice = fs::read("/tmp/polyglot-test/x86_64.erebus").unwrap();
        let arm64_slice = fs::read("/tmp/polyglot-test/aarch64.erebus").unwrap();

        let slices = vec![
            PolyglotSlice {
                target: "linux-x86_64".into(),
                arch: ARCH_X86_64,
                os: PolyglotOS::Linux,
                bytes: x86_slice,
            },
            PolyglotSlice {
                target: "linux-aarch64".into(),
                arch: ARCH_AARCH64,
                os: PolyglotOS::Linux,
                bytes: arm64_slice,
            },
        ];

        let out_path = Path::new("/tmp/polyglot-test/universal.erebus");
        let size = assemble_universal(out_path, &slices).unwrap();

        println!(
            "Universal binary created: {} bytes ({:.1} MB)",
            size,
            size as f64 / 1_048_576.0
        );

        let mut f = fs::File::open(out_path).unwrap();
        let ok = verify_polyglot(&mut f).unwrap();
        assert!(ok, "Verification failed");

        f.seek(std::io::SeekFrom::Start(0)).unwrap();
        let header = read_polyglot_header(&mut f).unwrap();
        let sc = header.slice_count;
        let ver = header.version;
        let ts = header.total_size;
        println!(
            "Header: slice_count={}, version={}, total_size={}",
            sc, ver, ts
        );

        let entries = read_slice_table(&mut f, &header).unwrap();
        for (i, e) in entries.iter().enumerate() {
            let os = e.target_os;
            let arch = e.target_arch;
            let offset = e.offset;
            let size = e.size;
            println!(
                "  Slice {}: os={}, arch={}, offset={}, size={}",
                i, os, arch, offset, size
            );
        }
    }
}
