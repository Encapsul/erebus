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

pub mod cli_fuzz;
pub mod format_fuzz;
pub mod harness;
pub mod registry_fuzz;
pub mod serve_fuzz;
pub mod stub_fuzz;

// Single source of truth for shared fuzzing types lives in `harness`;
// historical duplicates here caused trait-mismatch bugs after refactors.
pub use harness::{
    CorpusEntry, CrashCase, FuzzConfig, FuzzHarness, FuzzStats, FuzzTarget, GlobalStats,
    MutationStrategy, TargetRegistry,
};
