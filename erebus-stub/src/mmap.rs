//! Zero-copy payload access via `mmap(2)` / `MapViewOfFile` — lazy loading
//! for large payloads.
//!
//! Cold start previously heap-allocated the entire compressed payload before
//! hashing and decompressing it. For multi-GB AI model payloads that meant a
//! multi-GB RSS spike on every first run. Mapping the payload range of the
//! running image instead keeps those pages in kernel page cache: reads are
//! zero-copy and the kernel can evict clean pages under memory pressure.
//!
//! Falls back to a plain heap read when mapping is unavailable, or when
//! `ERE_NO_MMAP=1` is set in the launcher's environment.

use std::fs::File;
use std::io::{self, Read, Seek};
use std::ops::Deref;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;

#[cfg(windows)]
mod ffi {
    type Handle = *mut core::ffi::c_void;

    extern "system" {
        pub fn CreateFileMappingW(
            h_file: Handle,
            lp_attributes: Handle,
            fl_protect: u32,
            dw_maximum_size_high: u32,
            dw_maximum_size_low: u32,
            lp_name: *const u16,
        ) -> Handle;
        pub fn MapViewOfFile(
            h_file_mapping_object: Handle,
            dw_desired_access: u32,
            dw_file_offset_high: u32,
            dw_file_offset_low: u32,
            dw_number_of_bytes_to_map: usize,
        ) -> Handle;
        pub fn UnmapViewOfFile(lp_base_address: Handle) -> i32;
        pub fn CloseHandle(h_object: Handle) -> i32;
    }
}

/// Payload bytes backed by an anonymous heap buffer or an mmap window.
///
/// Dereferences to `&[u8]` so call sites stay byte-source agnostic.
pub enum PayloadBuf {
    Heap(Vec<u8>),
    Mapped(MappedRange),
}

impl Deref for PayloadBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            PayloadBuf::Heap(v) => v,
            PayloadBuf::Mapped(m) => m,
        }
    }
}

impl AsRef<[u8]> for PayloadBuf {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

/// An active read-only file mapping; unmapped exactly once on drop.
#[cfg(unix)]
pub struct MappedRange {
    /// Base address returned by a successful `mmap`; never null (`MAP_FAILED`
    /// is checked at creation) and never reallocated while this value lives.
    ptr: *mut u8,
    len: usize,
    /// Keeps the fd backing the mapping open for the mapping's lifetime;
    /// closing it would be harmless for an existing map, but holding it makes
    /// that invariant local and obvious instead of implicit in the caller.
    _file: File,
}

/// A read-only `MapViewOfFile` window into the payload range.
#[cfg(windows)]
pub struct MappedRange {
    /// View start plus the sub-alignment delta: the requested offset rounded
    /// down to the 64 KiB allocation granularity lives at `view_base`.
    ptr: *mut u8,
    len: usize,
    /// Base address returned by `MapViewOfFile` — what `UnmapViewOfFile`
    /// requires (not `ptr`, which may sit past it inside the first page).
    view_base: *mut core::ffi::c_void,
    /// Section object from `CreateFileMappingW`; closed after unmapping.
    map: *mut core::ffi::c_void,
    /// Keeps the file backing the section open for the mapping's lifetime.
    _file: File,
}

impl Deref for MappedRange {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        // SAFETY: `ptr` points at `len` readable bytes of a live read-only
        // mapping created by `try_mmap` below; no other code mutates or
        // unmaps it during this struct's lifetime (unmapping happens only in
        // Drop).
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl Drop for MappedRange {
    #[cfg(unix)]
    fn drop(&mut self) {
        // SAFETY: paired with the successful `mmap` in `try_mmap`; same ptr
        // and length, called exactly once because `MappedRange` is not Clone.
        unsafe { libc::munmap(self.ptr.cast(), self.len) };
    }

    #[cfg(windows)]
    fn drop(&mut self) {
        // SAFETY: paired with the successful `MapViewOfFile` in `try_mmap`;
        // `view_base` is the exact address the API returned, unmapped once,
        // then the section handle is closed.
        unsafe {
            ffi::UnmapViewOfFile(self.view_base);
            ffi::CloseHandle(self.map);
        }
    }
}

/// Reads `[offset, offset+len)` from `file`, preferring an mmap window.
pub fn read_payload(file: &File, offset: u64, len: usize) -> io::Result<PayloadBuf> {
    if len == 0 || disabled_by_env() {
        return heap_read(file, offset, len);
    }
    match try_mmap(file, offset, len)? {
        Some(mapped) => Ok(PayloadBuf::Mapped(mapped)),
        None => heap_read(file, offset, len),
    }
}

fn disabled_by_env() -> bool {
    matches!(std::env::var_os("ERE_NO_MMAP"), Some(v) if v == "1")
}

fn heap_read(file: &File, offset: u64, len: usize) -> io::Result<PayloadBuf> {
    let mut buf = vec![0u8; len];
    let mut f = file.try_clone()?;
    f.seek(io::SeekFrom::Start(offset))?;
    f.read_exact(&mut buf)?;
    Ok(PayloadBuf::Heap(buf))
}

#[cfg(unix)]
fn try_mmap(file: &File, offset: u64, len: usize) -> io::Result<Option<MappedRange>> {
    if offset > libc::off_t::MAX as u64 {
        return Ok(None);
    }
    let owned = file.try_clone()?;
    // SAFETY: `fd` is a valid open file descriptor; `len > 0` is guaranteed by
    // the caller; `PROT_READ | MAP_PRIVATE` cannot fault on write attempts and
    // never modifies the file. A failed syscall returns MAP_FAILED, which we
    // handle explicitly rather than treating as a valid base address.
    let map = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            file.as_raw_fd(),
            offset as libc::off_t,
        )
    };
    if map == libc::MAP_FAILED {
        return Ok(None);
    }
    Ok(Some(MappedRange {
        ptr: map.cast::<u8>(),
        len,
        _file: owned,
    }))
}

#[cfg(windows)]
fn try_mmap(file: &File, offset: u64, len: usize) -> io::Result<Option<MappedRange>> {
    use std::os::windows::io::AsRawHandle;

    const PAGE_READONLY: u32 = 0x0000_0002;
    const FILE_MAP_READ: u32 = 0x0000_0004;
    /// MapViewOfFile offsets must be a multiple of the system allocation
    /// granularity (always 64 KiB on supported Windows versions).
    const GRANULARITY_MASK: u64 = 0xFFFF;

    let total = len
        .checked_add((offset & GRANULARITY_MASK) as usize)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "payload range overflows"))?;
    let owned = file.try_clone()?;

    // SAFETY: `handle` is a valid open file handle held alive by `owned`;
    // PAGE_READONLY creates a read-only section covering the whole file
    // (zero sizes). Failure returns null, handled below.
    let map = unsafe {
        ffi::CreateFileMappingW(
            file.as_raw_handle(),
            std::ptr::null_mut(),
            PAGE_READONLY,
            0,
            0,
            std::ptr::null(),
        )
    };
    if map.is_null() {
        return Ok(None);
    }

    let aligned = offset & !GRANULARITY_MASK;
    // SAFETY: `[aligned, aligned+total)` lies within the file because the
    // caller validated `offset+len` against the file length; FILE_MAP_READ
    // maps it without copy-on-write access. Failure returns null, handled
    // below together with closing the section handle.
    let view = unsafe {
        ffi::MapViewOfFile(
            map,
            FILE_MAP_READ,
            (aligned >> 32) as u32,
            aligned as u32,
            total,
        )
    };
    if view.is_null() {
        // SAFETY: `map` came from a successful CreateFileMappingW above.
        unsafe { ffi::CloseHandle(map) };
        return Ok(None);
    }

    Ok(Some(MappedRange {
        // SAFETY: `delta <= GRANULARITY_MASK < total`, so the adjusted base
        // stays within the mapped window of `total` bytes.
        ptr: unsafe { view.cast::<u8>().add((offset - aligned) as usize) },
        len,
        view_base: view,
        map,
        _file: owned,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_file(contents: &[u8]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let mut f = File::create(dir.path().join("bin")).unwrap();
        f.write_all(contents).unwrap();
        dir
    }

    #[test]
    fn mmap_reads_expected_range() {
        let payload: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let dir = temp_file(&payload);
        let f = File::open(dir.path().join("bin")).unwrap();

        let buf = read_payload(&f, 4096, 50_000).unwrap();
        assert_eq!(&buf[..], &payload[4096..4096 + 50_000]);
    }

    #[test]
    fn env_kill_switch_forces_heap_path() {
        let dir = temp_file(b"hello-lazy-world");
        let f = File::open(dir.path().join("bin")).unwrap();
        std::env::set_var("ERE_NO_MMAP", "1");
        let buf = read_payload(&f, 6, 5).unwrap();
        std::env::remove_var("ERE_NO_MMAP");
        assert!(matches!(buf, PayloadBuf::Heap(_)));
        assert_eq!(&buf[..], b"lazy-");
    }

    #[test]
    fn zero_length_reads_fall_back_to_heap() {
        let dir = temp_file(b"abc");
        let f = File::open(dir.path().join("bin")).unwrap();
        let buf = read_payload(&f, 0, 0).unwrap();
        assert_eq!(&buf[..], b"");
    }

    #[test]
    fn mapped_and_heap_views_agree() {
        let payload = vec![7u8; 65_536];
        let dir = temp_file(&payload);
        let f = File::open(dir.path().join("bin")).unwrap();
        let m = read_payload(&f, 1, 60_000).unwrap();
        std::env::set_var("ERE_NO_MMAP", "1");
        let h = read_payload(&f, 1, 60_000).unwrap();
        std::env::remove_var("ERE_NO_MMAP");
        assert_eq!(&m[..], &h[..]);
    }

    /// Offsets not aligned to any OS mapping granularity must yield the same
    /// bytes as the heap path (exercises the Windows view-base adjustment).
    #[test]
    fn unaligned_offsets_match_heap_path() {
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 253) as u8).collect();
        let dir = temp_file(&payload);
        let f = File::open(dir.path().join("bin")).unwrap();
        for offset in [65_535u64, 65_537, 131_072, 131_073] {
            let m = read_payload(&f, offset, 10_000).unwrap();
            std::env::set_var("ERE_NO_MMAP", "1");
            let h = read_payload(&f, offset, 10_000).unwrap();
            std::env::remove_var("ERE_NO_MMAP");
            assert_eq!(&m[..], &h[..], "offset {offset}");
        }
    }
}
