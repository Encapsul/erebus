//! Stub launcher fuzzing target.

use crate::{FuzzTarget, MutationStrategy};
use anyhow::{anyhow, Context, Result};
use arbitrary::{Arbitrary, Unstructured};
use erebus_core::detect::{detect_runtime, resolve_entrypoint};
use rand::Rng;
use std::path::PathBuf;
use tempfile::TempDir;

pub struct StubFuzzTarget;

impl StubFuzzTarget {
    fn create_test_bundle(&self, _scenario: &ExtractionScenario) -> Result<(TempDir, PathBuf)> {
        let temp = TempDir::new()?;
        let root = temp.path().to_path_buf();
        let app_dir = root.join("app");
        std::fs::create_dir_all(&app_dir)?;
        std::fs::write(app_dir.join("app.py"), b"print('test')")?;
        Ok((temp, root))
    }

    fn mutate_extraction(&self, input: &[u8], unstructured: &mut Unstructured) -> Result<Vec<u8>> {
        let mut out = input.to_vec();
        let strategy = unstructured.choose(&[MutationStrategy::BitFlip, MutationStrategy::ByteInsertDelete])?;
        match strategy {
            MutationStrategy::BitFlip => {
                for _ in 0..unstructured.int_in_range(1..=4)? {
                    if out.is_empty() { break; }
                    let idx = unstructured.int_in_range(0..=out.len().saturating_sub(1))?;
                    out[idx] ^= 1 << unstructured.int_in_range(0..=7)?;
                }
            }
            MutationStrategy::ByteInsertDelete => {
                if out.len() > 50 && unstructured.ratio(1, 2)? {
                    let idx = unstructured.int_in_range(0..=out.len() - 50)?;
                    let len = unstructured.int_in_range(1..=50.min(out.len() - idx))?;
                    out.drain(idx..idx + len);
                } else if out.len() < 5000 {
                    let idx = unstructured.int_in_range(0..=out.len())?;
                    let len = unstructured.int_in_range(1..=32)?;
                    let bytes: Vec<u8> = (0..len).map(|_| unstructured.arbitrary().unwrap_or(0)).collect();
                    out.splice(idx..idx, bytes);
                }
            }
            _ => {}
        }
        Ok(out)
    }
}

#[derive(Debug, Clone, Arbitrary)]
struct ExtractionScenario {
    payload_type: PayloadType,
    entrypoint: String,
}

#[derive(Debug, Clone, Arbitrary, PartialEq, Eq)]
enum PayloadType { Python, Node, GoBinary, RustBinary, Script, Mixed }

pub struct StubFuzzTarget;

impl FuzzTarget for StubFuzzTarget {
    fn name(&self) -> &'static str { "stub" }
    fn generate_seed(&self, unstructured: &mut Unstructured) -> Result<Vec<u8>> {
        let scenario = ExtractionScenario { payload_type: PayloadType::Python, entrypoint: "app.py".into() };
        Ok(serde_json::to_vec(&scenario)?)
    }
    fn mutate(&self, input: &[u8], unstructured: &mut Unstructured) -> Result<Vec<u8>> {
        let mut out = input.to_vec();
        let strategy = unstructured.choose(&[MutationStrategy::BitFlip, MutationStrategy::ByteInsertDelete])?;
        match strategy {
            MutationStrategy::BitFlip => { for _ in 0..unstructured.int_in_range(1..=4)? { if out.is_empty() { break; } let idx = unstructured.int_in_range(0..=out.len().saturating_sub(1))?; out[idx] ^= 1 << unstructured.int_in_range(0..=7)?; } }
            MutationStrategy::ByteInsertDelete => { if out.len() > 50 && unstructured.ratio(1, 2)? { let idx = unstructured.int_in_range(0..=out.len() - 50)?; let len = unstructured.int_in_range(1..=50.min(out.len() - idx))?; out.drain(idx..idx + len); } else if out.len() < 5000 { let idx = unstructured.int_in_range(0..=out.len())?; let len = unstructured.int_in_range(1..=32)?; let bytes: Vec<u8> = (0..len).map(|_| unstructured.arbitrary().unwrap_or(0)).collect(); out.splice(idx..idx, bytes); } }
            _ => {}
        }
        Ok(out)
    }
    fn execute(&self, input: &[u8]) -> Result<()> {
        let _scenario: serde_json::Value = serde_json::from_slice(input)?;
        let temp = tempfile::TempDir::new()?;
        let app_dir = temp.path().join("app");
        std::fs::create_dir_all(&app_dir)?;
        std::fs::write(app_dir.join("app.py"), b"print('test')")?;
        let runtime = erebus_core::detect::detect_runtime(&app_dir).ok_or(anyhow!("detect failed"))?;
        let _entrypoint = erebus_core::detect::resolve_entrypoint(&temp.path(), runtime).ok_or(anyhow!("resolve failed"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests { use super::*; #[test] fn test_stub_target_creation() { let target = StubFuzzTarget; assert_eq!(target.name(), "stub"); } }