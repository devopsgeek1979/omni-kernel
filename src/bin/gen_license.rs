//! OmniKernel Enterprise License Key Generator
//!
//! Generates HMAC-SHA256-signed license keys for cloud and private cloud
//! deployments.  The key encodes a JSON payload containing customer name,
//! deployment type, node limit, expiry, and enabled features.
//!
//! **Security note**: The `LICENSE_AUTHORITY_KEY` embedded here must match
//! the one compiled into the agent binary.  Manage it with a secrets manager
//! (e.g. HashiCorp Vault, AWS Secrets Manager) and inject it at build time.
//! Never commit the production signing key to source control.
//!
//! # Usage
//! ```text
//! gen_license --customer "Acme Corp" --deployment cloud --node-limit 20 --days 365
//! gen_license --customer "SecureCorp" --deployment private-cloud --node-limit 5 --days 730
//! ```

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::{Parser, ValueEnum};
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// Must exactly match `LICENSE_AUTHORITY_KEY` in `src/license.rs`.
/// Replace at build time via your key-management pipeline.
const LICENSE_AUTHORITY_KEY: &[u8] = b"omnikernel-license-authority-v1-changeme";

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "gen_license",
    about = "Generate a signed OmniKernel enterprise license key",
    long_about = "Generates an HMAC-SHA256-signed license key for cloud or private-cloud deployments.\n\
                  The key is printed to stdout in the format expected by OMNIKERNEL_LICENSE."
)]
struct Cli {
    /// Customer or organisation name embedded in the license.
    #[arg(long)]
    customer: String,

    /// Deployment topology this license is issued for.
    #[arg(long, value_enum, default_value = "cloud")]
    deployment: DeploymentArg,

    /// Maximum number of agent nodes permitted.
    #[arg(long, default_value = "10")]
    node_limit: u32,

    /// License validity in days from now.
    #[arg(long, default_value = "365")]
    days: u64,

    /// Comma-separated feature flags to enable.
    #[arg(
        long,
        value_delimiter = ',',
        default_value = "ebpf_lsm,wasm_sandbox,mesh_hub"
    )]
    features: Vec<String>,
}

#[derive(Clone, ValueEnum)]
enum DeploymentArg {
    Cloud,
    PrivateCloud,
    OnPremises,
}

// ---------------------------------------------------------------------------
// License payload (must mirror src/license.rs::LicensePayload)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct LicensePayload {
    license_id:  String,
    customer:    String,
    deployment:  String,
    node_limit:  u32,
    issued_at:   u64,
    expires_at:  u64,
    features:    Vec<String>,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let cli = Cli::parse();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("System clock error")?
        .as_secs();

    let deployment_str = match cli.deployment {
        DeploymentArg::Cloud        => "cloud",
        DeploymentArg::PrivateCloud => "private_cloud",
        DeploymentArg::OnPremises   => "on_premises",
    };

    let payload = LicensePayload {
        license_id:  Uuid::new_v4().to_string(),
        customer:    cli.customer.clone(),
        deployment:  deployment_str.to_string(),
        node_limit:  cli.node_limit,
        issued_at:   now,
        expires_at:  now + cli.days * 86400,
        features:    cli.features.clone(),
    };

    let json       = serde_json::to_vec(&payload).context("Failed to serialise payload")?;
    let b64_payload = URL_SAFE_NO_PAD.encode(&json);

    // Sign the base64 payload (not the raw JSON) — must match verify_license_key().
    let mut mac = HmacSha256::new_from_slice(LICENSE_AUTHORITY_KEY)
        .expect("HMAC accepts any key length");
    mac.update(b64_payload.as_bytes());
    let b64_sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

    let license_key = format!("{b64_payload}.{b64_sig}");

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  OmniKernel Enterprise License");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  Customer   : {}", cli.customer);
    println!("  License ID : {}", payload.license_id);
    println!("  Deployment : {}", deployment_str);
    println!("  Node limit : {}", cli.node_limit);
    println!("  Expires in : {} days", cli.days);
    println!("  Features   : {}", cli.features.join(", "));
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    println!("License key:");
    println!("{license_key}");
    println!();
    println!("Set the key in your deployment environment:");
    println!("  export OMNIKERNEL_LICENSE={license_key}");
    println!();
    println!("Or add to /etc/omnikernel/agent.env (mode 0640):");
    println!("  OMNIKERNEL_LICENSE={license_key}");

    Ok(())
}
