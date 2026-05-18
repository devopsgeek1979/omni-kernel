mod config;
mod license;
mod security;
mod wasm;

use anyhow::{Context, Result};
use security::ebpf::SecurityRuntime;

#[tokio::main]
async fn main() -> Result<()> {
    // Structured logging — level controlled by RUST_LOG (default: info).
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "omnikernel_agent=info,warn".parse().unwrap()),
        )
        .init();

    tracing::info!(version = env!("CARGO_PKG_VERSION"), "OmniKernel Agent starting");

    // License must be validated before any other subsystem is initialised.
    let _license = license::validate_license()
        .await
        .context("License validation failed — agent cannot start without a valid enterprise license")?;

    // Load security policy from environment variables.
    let policy = config::SecurityPolicy::from_env()
        .context("Failed to load security policy from environment")?;

    // Initialise eBPF LSM runtime and ring-buffer event consumer.
    let runtime = SecurityRuntime::initialize(policy)
        .await
        .context("Failed to initialise eBPF security runtime")?;

    tracing::info!("OmniKernel security runtime active — awaiting events");

    // Initialise Wasmtime sandbox.
    wasm::runtime::start_wasm_runtime()
        .await
        .context("Failed to start Wasmtime sandbox runtime")?;

    // Block until SIGINT / SIGTERM.
    tokio::signal::ctrl_c()
        .await
        .context("Failed to install shutdown signal handler")?;

    tracing::info!("Shutdown signal received — stopping agent");

    runtime.shutdown().await.context("eBPF runtime shutdown error")?;

    tracing::info!("OmniKernel Agent stopped cleanly");
    Ok(())
}

