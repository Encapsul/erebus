//! .erebus binary format fuzzing target.

use crate::{FuzzTarget, MutationStrategy};
use anyhow::{anyhow, Context, Result};
use arbitrary::{Arbitrary, Unstructured};
use erebus_core::format::{Footer, FOOTER_MAGIC, FORMAT_VERSION, V3_FOOTER_SIZE, read_at};
use erebus_core::inference::{engine_pack_name, host_pack_key};
use rand::Rng;
use std::io::{Cursor, Read, Seek};
use bincode;

pub struct FormatFuzzTarget;

impl FormatFuzzTarget {
    fn build_binary(&self, footer: Footer, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(payload);
        let footer_bytes = bincode::serialize(&footer).unwrap();
        buf.extend_from_slice(&footer_bytes);
        buf
    }
}

impl FuzzTarget for FormatFuzzTarget {
    fn name(&self) -> &'static str { "format" }
    fn generate_seed(&self, unstructured: &mut Unstructured) -> Result<Vec<u8>> {
        if unstructured.ratio(7, 10)? {
            let payload_size = unstructured.int_in_range(0..=1024)?;
            let payload: Vec<u8> = (0..payload_size).map(|_| unstructured.arbitrary().unwrap_or(0)).collect();
            let footer = Footer { format_version: FORMAT_VERSION, arch: 1, flags: 0, payload_offset: 0, payload_csize: payload.len() as u64, payload_usize: payload.len() as u64, payload_sha256: [0; 32], meta_offset: payload.len() as u64, meta_size: 0, sig_offset: 0 };
            let mut buf = Vec::new(); buf.extend_from_slice(&payload); let footer_bytes = bincode::serialize(&footer).unwrap(); buf.extend_from_slice(&footer_bytes); Ok(buf)
        } else {
            let payload: Vec<u8> = (0..unstructured.int_in_range(0..=512)?).map(|_| unstructured.arbitrary().unwrap_or(0)).collect();
            let footer = Footer { format_version: FORMAT_VERSION, arch: 1, flags: 0, payload_offset: 0, payload_csize: payload.len() as u64, payload_usize: payload.len() as u64, payload_sha256: [0; 32], meta_offset: payload.len() as u64, meta_size: 0, sig_offset: 0 };
            let mut buf = Vec::new(); buf.extend_from_slice(&payload); let footer_bytes = bincode::serialize(&footer).unwrap(); buf.extend_from_slice(&footer_bytes); Ok(buf)
        }
    }
    fn mutate(&self, input: &[u8], unstructured: &mut Unstructured) -> Result<Vec<u8>> {
        let mut out = input.to_vec();
        let strategy = unstructured.choose(&[MutationStrategy::BitFlip, MutationStrategy::ByteInsertDelete])?;
        match strategy {
            MutationStrategy::BitFlip => { for _ in 0..unstructured.int_in_range(1..=4)? { if out.is_empty() { break; } let idx = unstructured.int_in_range(0..=out.len().saturating_sub(1))?; out[idx] ^= 1 << unstructured.int_in_range(0..=7)?; } }
            MutationStrategy::ByteInsertDelete => { if out.len() > 100 && unstructured.ratio(1, 2)? { let idx = unstructured.int_in_range(0..=out.len() - 100)?; let len = unstructured.int_in_range(1..=100.min(out.len() - idx))?; out.drain(idx..idx + len); } else if out.len() < 1_000_000 { let idx = unstructured.int_in_range(0..=out.len())?; let len = unstructured.int_in_range(1..=64)?; let bytes: Vec<u8> = (0..len).map(|_| unstructured.arbitrary().unwrap_or(0)).collect(); out.splice(idx..idx, bytes); } }
            _ => {}
        }
        Ok(out)
    }
    fn execute(&self, input: &[u8]) -> Result<()> {
        use erebus_core::format::V3_FOOTER_SIZE;
        if input.len() < V3_FOOTER_SIZE as usize { return Ok(()); }
        let mut cursor = std::io::Cursor::new(input);
        let file_len = input.len() as u64;
        let footer_size = erebus_core::format::V3_FOOTER_SIZE;
        if file_len < footer_size { return Ok(()); }
        let footer_off = file_len - footer_size;
        let mut footer_buf = vec![0u8; footer_size as usize];
        cursor.seek(std::io::SeekFrom::Start(footer_off))?; cursor.read_exact(&mut footer_buf)?;
        let _footer: erebus_core::format::Footer = bincode::deserialize(&footer_buf).map_err(|e| anyhow!("footer deserialize failed: {}", e))?;
        let _ = erebus_core::format::read_at(&mut cursor, footer_off, V3_FOOTER_SIZE as usize).map_err(|e| anyhow!("read_at failed: {}", e))?;
        let _ = erebus_core::inference::engine_pack_name("llama-server");
        let _ = erebus_core::inference::host_pack_key();
        Ok(())
    }
}

pub struct FormatFuzzTarget;

impl FuzzTarget for FormatFuzzTarget {
    fn name(&self) -> &'static str { "format" }
    fn generate_seed(&self, unstructured: &mut Unstructured) -> Result<Vec<u8>> {
        if unstructured.ratio(7, 10)? {
            let payload_size = unstructured.int_in_range(0..=1024)?;
            let payload: Vec<u8> = (0..payload_size).map(|_| unstructured.arbitrary().unwrap_or(0)).collect();
            let footer = Footer { format_version: FORMAT_VERSION, arch: 1, flags: 0, payload_offset: 0, payload_csize: payload.len() as u64, payload_usize: payload.len() as u64, payload_sha256: [0; 32], meta_offset: payload.len() as u64, meta_size: 0, sig_offset: 0 };
            let mut buf = Vec::new(); buf.extend_from_slice(&payload); let footer_bytes = bincode::serialize(&footer).unwrap(); buf.extend_from_slice(&footer_bytes); Ok(buf)
        } else {
            let payload: Vec<u8> = (0..unstructured.int_in_range(0..=512)?).map(|_| unstructured.arbitrary().unwrap_or(0)).collect();
            let footer = Footer { format_version: FORMAT_VERSION, arch: 1, flags: 0, payload_offset: 0, payload_csize: payload.len() as u64, payload_usize: payload.len() as u64, payload_sha256: [0; 32], meta_offset: payload.len() as u64, meta_size: 0, sig_offset: 0 };
            let mut buf = Vec::new(); buf.extend_from_slice(&payload); let footer_bytes = bincode::serialize(&footer).unwrap(); buf.extend_from_slice(&footer_bytes); Ok(buf)
        }
    }
    fn mutate(&self, input: &[u8], unstructured: &mut Unstructured) -> Result<Vec<u8>> {
        let mut out = input.to_vec();
        let strategy = unstructured.choose(&[MutationStrategy::BitFlip, MutationStrategy::ByteInsertDelete])?;
        match strategy {
            MutationStrategy::BitFlip => { for _ in 0..unstructured.int_in_range(1..=4)? { if out.is_empty() { break; } let idx = unstructured.int_in_range(0..=out.len().saturating_sub(1))?; out[idx] ^= 1 << unstructured.int_in_range(0..=7)?; } }
            MutationStrategy::ByteInsertDelete => { if out.len() > 100 && unstructured.ratio(1, 2)? { let idx = unstructured.int_in_range(0..=out.len() - 100)?; let len = unstructured.int_in_range(1..=100.min(out.len() - idx))?; out.drain(idx..idx + len); } else if out.len() < 1_000_000 { let idx = unstructured.int_in_range(0..=out.len())?; let len = unstructured.int_in_range(1..=64)?; let bytes: Vec<u8> = (0..len).map(|_| unstructured.arbitrary().unwrap_or(0)).collect(); out.splice(idx..idx, bytes); } }
            _ => {}
        }
        Ok(out)
    }
    fn execute(&self, input: &[u8]) -> Result<()> {
        use erebus_core::format::V3_FOOTER_SIZE;
        if input.len() < V3_FOOTER_SIZE as usize { return Ok(()); }
        let mut cursor = std::io::Cursor::new(input);
        let file_len = input.len() as u64;
        let footer_size = erebus_core::format::V3_FOOTER_SIZE;
        if file_len < footer_size { return Ok(()); }
        let footer_off = file_len - footer_size;
        let mut footer_buf = vec![0u8; footer_size as usize];
        cursor.seek(std::io::SeekFrom::Start(footer_off))?; cursor.read_exact(&mut footer_buf)?;
        let _footer: erebus_core::format::Footer = bincode::deserialize(&footer_buf).map_err(|e| anyhow!("footer deserialize failed: {}", e))?;
        let _ = erebus_core::format::read_at(&mut cursor, footer_off, V3_FOOTER_SIZE as usize).map_err(|e| anyhow!("read_at failed: {}", e))?;
        let _ = erebus_core::inference::engine_pack_name("llama-server");
        let _ = erebus_core::inference::host_pack_key();
        Ok(())
    }
}

#[cfg(test)]
mod tests { use super::*; #[test] fn test_format_target_creation() { let target = FormatFuzzTarget; assert_eq!(target.name(), "format"); } }