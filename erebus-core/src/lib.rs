//! `erebus-core` — core library for the x.bin build tool.
//!
//! Provides format parsing, compression, runtime detection, and package manager
//! detection. Used by the Rust CLI (`erebus-cli`) and the launcher stub
//! (`erebus-stub`).

pub mod assembly;
pub mod attest;
pub mod attest_log;
pub mod audit;
pub mod auth;
pub mod backup;
pub mod cas;
pub mod chunker;
pub mod compress;
pub mod cron;
pub mod cve;
pub mod detect;
pub mod dotenv;
pub mod embed;
pub mod encrypt;
pub mod format;
pub mod gc;
pub mod gguf;
pub mod gpu;
pub mod include;
pub mod inference;
pub mod intoto;
pub mod layer;
pub mod legacy;
pub mod log_proof;
pub mod manifest;
pub mod merkle;
pub mod metadata;
pub mod otel;
pub mod paths;
pub mod persistent;
pub mod pkgmgr;
pub mod polyglot;
pub mod registry;
pub mod rootfs_merkle;
pub mod sisr;
pub mod sisr_header;
pub mod sisr_stage;
pub mod swap;
pub mod tar;
