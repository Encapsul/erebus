//! Registry fuzzing target (public API only).

use crate::{FuzzTarget, MutationStrategy};
use anyhow::{anyhow, Context, Result};
use arbitrary::{Arbitrary, Unstructured};
use erebus_core::registry::{LayerRegistry, LayerKind, LayerEntry};
use rand::Rng;
use std::collections::HashMap;
use tempfile::TempDir;
use tokio::sync::Mutex;

pub struct RegistryFuzzTarget {
    temp_dir: TempDir,
    layer_registry: Arc<Mutex<Option<erebus_core::registry::LayerRegistry>>>,
}

impl Default for RegistryFuzzTarget {
    fn default() -> Self {
        let temp_dir = TempDir::new().expect("temp dir");
        Self { temp_dir, layer_registry: Arc::new(Mutex::new(None)) }
    }
}

impl RegistryFuzzTarget {
    async fn get_layer_registry(&self) -> anyhow::Result<Arc<Mutex<erebus_core::registry::LayerRegistry>>> {
        let mut guard = self.layer_registry.lock().await;
        if guard.is_none() {
            let reg = erebus_core::registry::LayerRegistry::open(self.temp_dir.path().join("layers")).context("opening layer registry")?;
            *guard = Some(reg);
        }
        drop(guard);
        Ok(self.layer_registry.clone())
    }

    fn mutate_ops(&self, ops: &mut [RegistryOp], unstructured: &mut Unstructured) -> anyhow::Result<()> {
        let strategy = unstructured.choose(&[MutationStrategy::BitFlip, MutationStrategy::Structured])?;
        match strategy {
            MutationStrategy::BitFlip => {
                for op in ops {
                    if let RegistryOp::CreateLayer { name, .. } = op {
                        let bytes = unsafe { name.as_bytes_mut() };
                        if !bytes.is_empty() && unstructured.ratio(1, 4)? {
                            let idx = unstructured.int_in_range(0..=bytes.len().saturating_sub(1))?;
                            bytes[idx] ^= 1 << unstructured.int_in_range(0..=7)?;
                        }
                    }
                }
            }
            MutationStrategy::Structured => {
                if unstructured.ratio(1, 3)? && ops.len() < 50 {
                    ops.push(RegistryOp::arbitrary(&mut Unstructured::new(&[]))?);
                }
            }
            _ => {}
        }
        Ok(())
    }

    async fn execute_op(&self, op: &RegistryOp) -> anyhow::Result<()> {
        let layer_reg = self.get_layer_registry().await?;
        let mut reg_guard = layer_reg.lock().await;
        match op {
            RegistryOp::CreateLayer { name, kind, data } => { let _ = reg_guard.push(name, kind, data)?; }
            RegistryOp::MaterializeLayer { name } => { let tmp = std::env::temp_dir().join("materialized"); let _ = reg_guard.materialize(name, &tmp)?; }
            RegistryOp::DeleteLayer { name } => { let _ = reg_guard.remove(name)?; }
            RegistryOp::ListLayers => { let _ = reg_guard.list()?; }
            RegistryOp::ResolveLayer { name } => { let _ = reg_guard.resolve(name)?; }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Arbitrary, PartialEq, Eq)]
enum RegistryOp {
    CreateLayer { name: String, kind: erebus_core::layer::LayerKind, data: Vec<u8> },
    MaterializeLayer { name: String },
    DeleteLayer { name: String },
    ListLayers,
    ResolveLayer { name: String },
}

pub struct RegistryFuzzTarget {
    temp_dir: TempDir,
    layer_registry: Arc<Mutex<Option<erebus_core::registry::LayerRegistry>>>,
}

impl Default for RegistryFuzzTarget {
    fn default() -> Self {
        let temp_dir = TempDir::new().expect("temp dir");
        Self { temp_dir, layer_registry: Arc::new(Mutex::new(None)) }
    }
}

impl FuzzTarget for RegistryFuzzTarget {
    fn name(&self) -> &'static str { "registry" }
    fn generate_seed(&self, unstructured: &mut Unstructured) -> Result<Vec<u8>> {
        let ops_count = unstructured.int_in_range(1..=20)?;
        let mut operations = Vec::new();
        for _ in 0..unstructured.int_in_range(1..=20)? { operations.push(RegistryOp::arbitrary(unstructured)?); }
        Ok(serde_json::to_vec(&serde_json::json!({ "operations": operations }))?)
    }
    fn mutate(&self, input: &[u8], unstructured: &mut Unstructured) -> Result<Vec<u8>> {
        let mut ops: Vec<RegistryOp> = serde_json::from_slice(input).map_err(|e| anyhow!("ops parse failed: {}", e))?;
        self.mutate_ops(&mut ops, unstructured)?;
        Ok(serde_json::to_vec(&ops)?)
    }
    fn execute(&self, input: &[u8]) -> Result<()> {
        let ops: Vec<RegistryOp> = serde_json::from_slice(input).map_err(|e| anyhow!("ops parse failed: {}", e))?;
        let rt = tokio::runtime::Handle::current();
        for op in ops { rt.block_on(self.execute_op(&op))?; }
        Ok(())
    }
}

#[cfg(test)]
mod tests { use super::*; #[tokio::test] async fn test_registry_target_creation() { let target = RegistryFuzzTarget::default(); assert_eq!(target.name(), "registry"); } }