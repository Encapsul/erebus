//! Registry fuzzing target (public API only).

use crate::{FuzzTarget, MutationStrategy};
use anyhow::{Context, Result};
use arbitrary::{Arbitrary, Unstructured};
use tempfile::TempDir;

/// Local copy of LayerKind for fuzzing (core keeps it private).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Arbitrary, serde::Serialize, serde::Deserialize)]
enum LayerKindLocal {
    Runtime,
    Model,
    Tool,
    Config,
    Custom,
}

pub struct RegistryFuzzTarget;

impl RegistryFuzzTarget {
    fn mutate_ops(
        &self,
        ops: &mut Vec<RegistryOp>,
        unstructured: &mut Unstructured,
    ) -> anyhow::Result<()> {
        let strategy =
            unstructured.choose(&[MutationStrategy::BitFlip, MutationStrategy::Structured])?;
        match strategy {
            MutationStrategy::BitFlip => {
                for op in ops {
                    if let RegistryOp::CreateLayer { name, .. } = op {
                        let bytes = unsafe { name.as_bytes_mut() };
                        if !bytes.is_empty() && unstructured.ratio(1, 4)? {
                            let idx =
                                unstructured.int_in_range(0..=bytes.len().saturating_sub(1))?;
                            bytes[idx] ^= 1 << unstructured.int_in_range(0..=7)?;
                        }
                    }
                }
            }
            MutationStrategy::Structured if unstructured.ratio(1, 3)? && ops.len() < 50 => {
                ops.push(RegistryOp::arbitrary(&mut Unstructured::new(&[]))?);
            }
            _ => {}
        }
        Ok(())
    }

    async fn execute_op(&self, op: &RegistryOp) -> anyhow::Result<()> {
        // Create a fresh registry for each operation to avoid borrowing issues.
        let temp_dir = TempDir::new()?;
        let mut reg = erebus_core::registry::LayerRegistry::open(&temp_dir.path().join("layers"))
            .context("opening layer registry")?;
        match op {
            RegistryOp::CreateLayer { name, kind, data } => {
                let core_kind = match kind {
                    LayerKindLocal::Runtime => erebus_core::layer::LayerKind::Runtime,
                    LayerKindLocal::Model => erebus_core::layer::LayerKind::Model,
                    LayerKindLocal::Tool => erebus_core::layer::LayerKind::Tool,
                    LayerKindLocal::Config => erebus_core::layer::LayerKind::Config,
                    LayerKindLocal::Custom => erebus_core::layer::LayerKind::Custom,
                };
                let _ = reg.push(name, core_kind, data)?;
            }
            RegistryOp::MaterializeLayer { name } => {
                let tmp = std::env::temp_dir().join("materialized");
                let _ = reg.materialize(name, &tmp)?;
            }
            RegistryOp::DeleteLayer { name } => {
                let _ = reg.remove(name)?;
            }
            RegistryOp::ListLayers => {
                let _ = reg.list()?;
            }
            RegistryOp::ResolveLayer { name } => {
                let _ = reg.resolve(name)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Arbitrary, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum RegistryOp {
    CreateLayer {
        name: String,
        kind: LayerKindLocal,
        data: Vec<u8>,
    },
    MaterializeLayer {
        name: String,
    },
    DeleteLayer {
        name: String,
    },
    ListLayers,
    ResolveLayer {
        name: String,
    },
}

impl FuzzTarget for RegistryFuzzTarget {
    fn name(&self) -> &'static str {
        "registry"
    }
    fn generate_seed(&self, unstructured: &mut Unstructured) -> Result<Vec<u8>> {
        let ops: Vec<RegistryOp> = (0..unstructured.int_in_range(1..=5)?)
            .map(|_| RegistryOp::arbitrary(unstructured).map_err(anyhow::Error::from))
            .collect::<Result<Vec<_>>>()?;
        Ok(serde_json::to_vec(&ops)?)
    }
    fn mutate(&self, input: &[u8], unstructured: &mut Unstructured) -> Result<Vec<u8>> {
        let mut ops: Vec<RegistryOp> = serde_json::from_slice(input)?;
        self.mutate_ops(&mut ops, unstructured)?;
        Ok(serde_json::to_vec(&ops)?)
    }
    fn execute(&self, input: &[u8]) -> Result<()> {
        let ops: Vec<RegistryOp> = match serde_json::from_slice(input) {
            Ok(o) => o,
            Err(_) => return Ok(()),
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for op in ops {
            // The registry is fail-closed by design: operations on malformed
            // arbitrary data (empty layer names, bad kinds, …) must be refused
            // with an Err, and that is correct behaviour, not a bug. Only
            // panics/timeouts surface as fuzzer failures.
            let _ = rt.block_on(self.execute_op(&op));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_registry_target_creation() {
        let target = RegistryFuzzTarget;
        assert_eq!(target.name(), "registry");
    }
}
