//! erebus-fuzz — high-throughput structure-aware fuzzer for the erebus ecosystem.
//!
//! Targets:
//! - .erebus binary format (footer, metadata, payload extraction)
//! - Stub launcher (extraction, exec resolution, path traversal)
//! - CLI argument parsing (all subcommands)
//! - Registry server in-process (multipart, ranges, auth, quotas)
//! - Serve/chat inference pipeline
//!
//! Run: `cargo run -p erebus-fuzz -- [SUBCOMMAND]`

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use arbitrary::{Arbitrary, Unstructured};
use erebus_core::format::{Footer, FOOTER_MAGIC};
use erebus_core::inference::{ModelFormat, FoundModel, LaunchPlan, engine_pack_name, host_pack_key, engine_args};
use erebus_core::registry::{LayerRegistry, LayerKind, LayerEntry};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::sync::Mutex;

pub mod format_fuzz;
pub mod stub_fuzz;
pub mod cli_fuzz;
pub mod registry_fuzz;
pub mod serve_fuzz;
pub mod harness;

pub use harness::{FuzzHarness, FuzzStats, FuzzConfig};

/// Global fuzzing statistics shared across workers.
#[derive(Debug, Default)]
pub struct GlobalStats {
    pub iterations: AtomicU64,
    pub crashes: AtomicU64,
    pub panics: AtomicU64,
    pub timeouts: AtomicU64,
    pub corpus_size: AtomicU64,
    pub unique_crashes: Mutex<HashMap<String, u64>>,
}

impl GlobalStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_iteration(&self) {
        self.iterations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_crash(&self, signature: &str) {
        self.crashes.fetch_add(1, Ordering::Relaxed);
        let mut map = self.unique_crashes.blocking_lock();
        *map.entry(signature.to_string()).or_insert(0) += 1;
    }

    pub fn record_panic(&self) {
        self.panics.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_timeout(&self) {
        self.timeouts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> FuzzStats {
        FuzzStats {
            iterations: self.iterations.load(Ordering::Relaxed),
            crashes: self.crashes.load(Ordering::Relaxed),
            panics: self.panics.load(Ordering::Relaxed),
            timeouts: self.timeouts.load(Ordering::Relaxed),
            corpus_size: self.corpus_size.load(Ordering::Relaxed),
            unique_crashes: self.unique_crashes.blocking_lock().clone(),
        }
    }
}

/// Mutation strategies for structure-aware fuzzing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MutationStrategy {
    BitFlip,
    ByteInsertDelete,
    Structured,
    Crossover,
    Semantic,
    Havoc,
}

impl Default for MutationStrategy {
    fn default() -> Self {
        MutationStrategy::Havoc
    }
}

/// Input corpus entry with metadata.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CorpusEntry {
    pub data: Vec<u8>,
    pub coverage_hash: u64,
    pub execution_time_us: u64,
    pub timestamp: u64,
    pub parent_hash: Option<u64>,
    pub mutation_strategy: MutationStrategy,
}

impl CorpusEntry {
    pub fn new(data: Vec<u8>) -> Self {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        Self {
            data,
            coverage_hash: hasher.finish(),
            execution_time_us: 0,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            parent_hash: None,
            mutation_strategy: MutationStrategy::Havoc,
        }
    }
}

/// Minimized crash reproduction case.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CrashCase {
    pub input: Vec<u8>,
    pub error_message: String,
    pub backtrace: Option<String>,
    pub minimized: bool,
    pub original_size: usize,
}

/// Fuzzing target trait — each target implements its own input generation and validation.
pub trait FuzzTarget: Send + Sync {
    fn name(&self) -> &'static str;

    fn generate_seed(&self, unstructured: &mut Unstructured) -> anyhow::Result<Vec<u8>>;

    fn mutate(&self, input: &[u8], unstructured: &mut Unstructured) -> anyhow::Result<Vec<u8>>;

    fn execute(&self, input: &[u8]) -> anyhow::Result<()>;

    fn minimize(&self, input: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(input.to_vec())
    }

    fn is_valid(&self, input: &[u8]) -> bool {
        !input.is_empty()
    }
}

/// Registry of all fuzzing targets.
pub struct TargetRegistry {
    targets: std::collections::HashMap<&'static str, Box<dyn FuzzTarget>>,
}

impl TargetRegistry {
    pub fn new() -> Self {
        let mut targets = std::collections::HashMap::new();
        targets.insert("format", Box::new(format_fuzz::FormatFuzzTarget) as Box<dyn FuzzTarget>);
        targets.insert("stub", Box::new(stub_fuzz::StubFuzzTarget) as Box<dyn FuzzTarget>);
        targets.insert("cli", Box::new(cli_fuzz::CliFuzzTarget) as Box<dyn FuzzTarget>);
        targets.insert("registry", Box::new(registry_fuzz::RegistryFuzzTarget::default()) as Box<dyn FuzzTarget>);
        targets.insert("serve", Box::new(serve_fuzz::ServeFuzzTarget) as Box<dyn FuzzTarget>);
        Self { targets }
    }

    pub fn get(&self, name: &str) -> Option<&dyn FuzzTarget> {
        self.targets.get(name).map(|b| b.as_ref())
    }

    pub fn all_names(&self) -> Vec<&'static str> {
        self.targets.keys().copied().collect()
    }

    pub fn all_targets(&self) -> Vec<&dyn FuzzTarget> {
        self.targets.values().map(|b| b.as_ref()).collect()
    }
}

impl Default for TargetRegistry {
    fn default() -> Self {
        Self::new()
    }
}