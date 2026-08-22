//! Zero-copy payload access via `mmap(2)` — lazy loading for large payloads.
//!
//! Cold start previously heap-allocated the entire compressed payload before
//! hashing and decompressing it. For multi-GB AI model payloads that meant a
//! multi-GB RSS spike on every first run. Mapping the payload range of
//! `/proc/self/exe` instead keeps those pages in kernel page cache: reads are
//! zero-copy and the kernel can evict clean pages under memory pressure.
//!
//! Falls back to a plain heap read when mmap is unavailable, or when
//! `ERE_NO_MMAP=1` is set in the launcher's environment.

use std::fs::File;
use std::io::{self, Read, Seek};
use std::ops::Deref;
use std::os::unix::io::AsRawFd;

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

/// An active `PROT_READ` file mapping; unmapped exactly once on drop.
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

impl Deref for MappedRange {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        // SAFETY: `ptr` is the base of a live PROT_READ mapping of exactly
        // `len` bytes created by `try_mmap` below; no other code mutates or
        // unmaps it during this struct's lifetime (munmap happens only in Drop).
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl Drop for MappedRange {
    fn drop(&mut self) {
        // SAFETY: paired with the successful `mmap` in `try_mmap`; same ptr
        // and length, called exactly once because `MappedRange` is not Clone.
        unsafe { libc::munmap(self.ptr.cast(), self.len) };
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
}
