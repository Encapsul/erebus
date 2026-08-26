//! `erebus-core` — core library for the x.bin build tool.
//!
//! Provides format parsing, compression, runtime detection, and package manager
//! detection. Used by the Rust CLI (`erebus-cli`) and the launcher stub
//! (`erebus-stub`).

pub mod assembly;
pub mod attest;
pub mod audit;
pub mod cas;
pub mod chunker;
pub mod compress;
pub mod cron;
pub mod detect;
pub mod dotenv;
pub mod embed;
pub mod encrypt;
pub mod format;
pub mod gpu;
pub mod include;
pub mod inference;
pub mod layer;
pub mod legacy;
pub mod manifest;
pub mod metadata;
pub mod otel;
pub mod paths;
pub mod persistent;
pub mod pkgmgr;
pub mod polyglot;
pub mod registry;
pub mod sisr;
pub mod sisr_header;
pub mod sisr_stage;
pub mod swap;
pub mod tar;
