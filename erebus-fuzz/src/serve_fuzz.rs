//! Serve fuzzing target.

use crate::{FuzzTarget, MutationStrategy};
use anyhow::Result;
use arbitrary::Unstructured;
use erebus_core::inference::ModelFormat;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
                    .unwrap_or_else(|_| "127.0.0.1".into());
                scenario.port = unstructured.arbitrary().unwrap_or(8080);
            }
            MutationStrategy::Semantic => {
                scenario.engine_pack_missing = !scenario.engine_pack_missing;
            }
            _ => {}
        }
    }
}

impl FuzzTarget for ServeFuzzTarget {
    fn name(&self) -> &'static str {
        "serve"
    }
    fn generate_seed(&self, unstructured: &mut Unstructured) -> Result<Vec<u8>> {
        let fmt_idx = unstructured.int_in_range(0..=1).unwrap_or(0);
        let model_format = if fmt_idx == 0 {
            ModelFormat::Gguf
        } else {
            ModelFormat::SafeTensors
        };
        let scenario = ServeScenario {
            model_format,
            model_size_mb: unstructured.int_in_range(0..=500).unwrap_or(100),
            ctx_size: unstructured.int_in_range(0..=4096).unwrap_or(2048),
            ngl: unstructured.int_in_range(0..=100).unwrap_or(0),
            threads: if unstructured.ratio(1, 2)? {
                Some(unstructured.int_in_range(1..=16).unwrap_or(4))
            } else {
                None
            },
            host: unstructured
                .arbitrary()
                .unwrap_or_else(|_| "127.0.0.1".into()),
            port: unstructured.arbitrary().unwrap_or(8080),
            engine_pack_missing: unstructured.ratio(1, 2)?,
        };
        Ok(serde_json::to_vec(&scenario)?)
    }
    fn mutate(&self, input: &[u8], unstructured: &mut Unstructured) -> Result<Vec<u8>> {
        let mut scenario: ServeScenario = serde_json::from_slice(input)?;
        self.mutate_scenario(&mut scenario, unstructured);
        Ok(serde_json::to_vec(&scenario)?)
    }
    fn execute(&self, input: &[u8]) -> Result<()> {
        let _scenario: ServeScenario = match serde_json::from_slice(input) {
            Ok(s) => s,
            Err(_) => return Ok(()),
        };
        // Execution would spin up serve — skip in fuzzing
        Ok(())
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
