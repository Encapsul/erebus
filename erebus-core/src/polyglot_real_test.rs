// Run as: cargo test --lib polyglot::tests::test_real_slices -- --nocapture
#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{ARCH_X86_64, ARCH_AARCH64};
    use std::fs;
    use std::path::Path;

    #[test]
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
        
        println!("Universal binary created: {} bytes ({:.1} MB)", size, size as f64 / 1_048_576.0);
        
        let mut f = fs::File::open(out_path).unwrap();
        let ok = verify_polyglot(&mut f).unwrap();
        assert!(ok, "Verification failed");
        
        f.seek(std::io::SeekFrom::Start(0)).unwrap();
        let header = read_polyglot_header(&mut f).unwrap();
        println!("Header: slice_count={}, version={}, total_size={}", header.slice_count, header.version, header.total_size);
        
        let entries = read_slice_table(&mut f, &header).unwrap();
        for (i, e) in entries.iter().enumerate() {
            println!("  Slice {}: os={}, arch={}, offset={}, size={}", i, e.target_os, e.target_arch, e.offset, e.size);
        }
    }
}
