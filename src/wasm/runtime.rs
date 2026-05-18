use anyhow::{Context, Result};
use std::env;
use wasmtime::*;

/// Maximum WASM fuel units per execution.
///
/// Prevents a runaway or malicious module from consuming unbounded CPU.
/// One fuel unit ≈ one WASM instruction.  Tune via `OMNIKERNEL_WASM_FUEL`.
const DEFAULT_FUEL_LIMIT: u64 = 1_000_000;

pub async fn start_wasm_runtime() -> Result<()> {
    let fuel_limit: u64 = env::var("OMNIKERNEL_WASM_FUEL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_FUEL_LIMIT);

    let mut config = Config::new();
    // Enable fuel-based CPU accounting for sandboxed execution.
    config.consume_fuel(true);

    let engine = Engine::new(&config).context("Failed to create Wasmtime engine")?;

    let module_path = env::var("OMNIKERNEL_WASM_MODULE")
        .unwrap_or_else(|_| "/var/lib/omnikernel/policy.wasm".to_string());

    let module = if std::path::Path::new(&module_path).exists() {
        tracing::info!(path = %module_path, "Loading WASM policy module");
        Module::from_file(&engine, &module_path)
            .with_context(|| format!("Failed to load WASM module from '{module_path}'"))?
    } else {
        tracing::warn!(
            path = %module_path,
            "WASM policy module not found — running with empty sandbox (audit mode only)"
        );
        // Minimal valid empty module as a safe fallback.
        Module::new(&engine, "(module)").context("Failed to compile fallback WASM module")?
    };

    let mut store = Store::new(&engine, ());

    // Set fuel limit — the module is trapped if it exceeds this budget.
    store
        .set_fuel(fuel_limit)
        .context("Failed to configure WASM fuel limit")?;

    let _instance =
        Instance::new(&mut store, &module, &[]).context("Failed to instantiate WASM module")?;

    tracing::info!(fuel_limit, "Wasmtime sandbox ready");
    Ok(())
}

