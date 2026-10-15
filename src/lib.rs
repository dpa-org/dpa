//! dpa — Data Processing & Analysis, flows as code.
//!
//! Library entry: the CLI binary and the Python binding (feature = "python")
//! share the same engine. CLI and plugin host are excluded on wasm32 targets
//! (Web/WASM: the wasm crate reuses engine/ops/i18n only).

#[cfg(not(target_arch = "wasm32"))]
pub mod cli;
pub mod engine;
pub mod flow;
pub mod i18n;
#[cfg(not(target_arch = "wasm32"))]
pub mod market;
pub mod ops;
#[cfg(not(target_arch = "wasm32"))]
pub mod plugin;
pub mod recipe;
pub mod recipe_map;
pub mod registry;

#[cfg(feature = "python")]
pub mod python;
