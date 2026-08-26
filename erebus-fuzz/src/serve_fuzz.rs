//! Serve fuzzing target.

use crate::{FuzzTarget, MutationStrategy};
use anyhow::{anyhow, Context, Result};
use arbitrary::{Arbitrary, Unstructured};
use erebus_core::gpu::{auto_ngl, detect, total_ram_mb};
use erebus_core::inference::{
    engine_args, engine_pack_name, host_pack_key, ModelFormat,
};
use rand::Rng;
use std::path::PathBuf;
use tempfile::TempDir;

#[derive(Debug, Clone, Arbitrary)]
struct ServeScenario {
    model_format: ModelFormat,
    model_size_mb: u64,
    ctx_size: u32,
    ngl: u32,
    threads: Option<u32>,
    host: String,
    port: u16,
    engine_pack_missing: bool,
}

impl Default for ServeScenario {
    fn default() -> Self {
        Self {
            model_format: ModelFormat::Gguf,
            model_size_mb: 100,
            ctx_size: 2048,
            ngl: 0,
            threads: Some(4),
            host: "127.0.0.1".into(),
            port: 8080,
            engine_pack_missing: true,
        }
    }
}

pub struct ServeFuzzTarget;

impl ServeFuzzTarget {
    fn create_mock_model(&self, scenario: &ServeScenario, temp: &TempDir) -> Result<PathBuf> {
        let model_path = temp
            .path()
            .join(format!("model.{}", scenario.model_format.extension()));
        let size = scenario.model_size_mb as usize * 1024 * 1024;
        let content = match scenario.model_format {
            ModelFormat::Gguf => {
                let mut buf = Vec::new();
                buf.extend_from_slice(b"GGUF");
                buf.extend_from_slice(&1u32.to_le_bytes());
                buf.extend_from_slice(&(0u64).to_le_bytes());
                buf.extend_from_slice(&(0u64).to_le_bytes());
                buf.resize(size, 0);
                buf
            }
            ModelFormat::SafeTensors => {
                let mut buf = Vec::new();
                buf.extend_from_slice(&(0u64).to_le_bytes());
                buf.extend_from_slice(b"{}\n");
                buf.resize(size, 0);
                buf
            }
            _ => vec![0; size],
        };
        std::fs::write(&model_path, content)?;
        Ok(model_path)
    }

    fn mutate_scenario(&self, scenario: &mut ServeScenario, unstructured: &mut Unstructured) {
        let strategy = unstructured
            .choose(&[
                MutationStrategy::BitFlip,
                MutationStrategy::Structured,
                MutationStrategy::Semantic,
            ])
            .unwrap();
        match strategy {
            MutationStrategy::BitFlip => {
                scenario.model_size_mb = scenario
                    .model_size_mb
                    .wrapping_add(unstructured.arbitrary::<u64>().unwrap_or(0) % 1000);
                scenario.ctx_size = scenario
                    .ctx_size
                    .wrapping_add(unstructured.arbitrary::<u32>().unwrap_or(0) % 4096);
                scenario.ngl = scenario
                    .ngl
                    .wrapping_add(unstructured.arbitrary::<u32>().unwrap_or(0) % 100);
            }
            MutationStrategy::Structured => {
                // Manual pick: ModelFormat intentionally carries no Arbitrary
                // impl in core (keeps the derive dep out of the library).
                let fmt = unstructured.int_in_range(0..=1).unwrap_or(0);
                scenario.model_format = if fmt == 0 {
                    ModelFormat::Gguf
                } else {
                    ModelFormat::SafeTensors
                };
                scenario.host = unstructured
                    .arbitrary()
                    .unwrap_or_else(|| "127.0.0.1".into());
                scenario.port = unstructured.arbitrary().unwrap_or(8080);
            }
            MutationStrategy::Semantic => {
                scenario.engine_pack_missing = !scenario.engine_pack_missing;
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_serve_target_creation() {
        let target = ServeFuzzTarget;
        assert_eq!(target.name(), "serve");
    }
}
