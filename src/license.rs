//! Enterprise license validation for OmniKernel Agent.
//!
//! License key format: `<base64url-payload>.<base64url-hmac-signature>`
//!
//! The payload is a URL-safe base64-encoded JSON [`LicensePayload`].
//! The signature is HMAC-SHA256 over the raw base64url payload bytes,
//! keyed with `LICENSE_AUTHORITY_KEY`.
//!
//! **Cloud** deployments additionally perform an online check against the
//! OmniKernel license server (`OMNIKERNEL_LICENSE_SERVER_URL`).
//! **Private cloud** and **on-premises** deployments validate entirely offline.
//!
//! # Generating license keys
//! Use the bundled `gen_license` binary (see `src/bin/gen_license.rs`).

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    env,
    time::{SystemTime, UNIX_EPOCH},
};

type HmacSha256 = Hmac<Sha256>;

/// Embedded license-authority HMAC key.
///
/// **IMPORTANT**: Replace this value at build time via your secrets-management
/// pipeline before shipping production binaries. Never commit the real key to
/// source control. The `gen_license` tool must use the identical key.
const LICENSE_AUTHORITY_KEY: &[u8] = b"omnikernel-license-authority-v1-changeme";

/// How many seconds before expiry a renewal warning is emitted.
const RENEWAL_WARNING_SECS: u64 = 30 * 24 * 3600; // 30 days

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentType {
    /// Public cloud deployment — requires online license validation.
    Cloud,
    /// Customer-managed private cloud — validated entirely offline.
    PrivateCloud,
    /// Traditional on-premises deployment — validated entirely offline.
    OnPremises,
}

/// JSON body embedded in every license key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicensePayload {
    /// Unique license identifier (UUID v4).
    pub license_id: String,
    /// Human-readable customer / organisation name.
    pub customer: String,
    /// Deployment topology the license was issued for.
    pub deployment: DeploymentType,
    /// Maximum number of agent nodes permitted under this license.
    pub node_limit: u32,
    /// Unix timestamp of issuance.
    pub issued_at: u64,
    /// Unix timestamp of expiry.
    pub expires_at: u64,
    /// Feature flags enabled by this license (e.g. `"ebpf_lsm"`, `"wasm_sandbox"`).
    pub features: Vec<String>,
}

/// Fully validated license, available to the rest of the application after
/// [`validate_license`] returns successfully.
#[derive(Debug, Clone)]
pub struct ValidatedLicense {
    pub payload: LicensePayload,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Validate the license present in `OMNIKERNEL_LICENSE`.
///
/// * Checks the HMAC-SHA256 signature.
/// * Checks the expiry timestamp.
/// * For `cloud` deployments, additionally contacts the license server.
///
/// Returns a [`ValidatedLicense`] on success.  The agent **must not** start
/// any other subsystem until this function returns `Ok`.
pub async fn validate_license() -> Result<ValidatedLicense> {
    let raw = env::var("OMNIKERNEL_LICENSE")
        .context("OMNIKERNEL_LICENSE environment variable not set — an enterprise license key is required")?;

    if raw.trim().is_empty() {
        bail!("OMNIKERNEL_LICENSE is empty — a valid enterprise license key is required");
    }

    let validated = verify_license_key(raw.trim())
        .context("License key cryptographic verification failed")?;

    let now = now_secs()?;

    if now >= validated.payload.expires_at {
        bail!(
            "License '{}' for '{}' expired. Please renew your OmniKernel enterprise license.",
            validated.payload.license_id,
            validated.payload.customer,
        );
    }

    let secs_remaining = validated.payload.expires_at.saturating_sub(now);
    if secs_remaining <= RENEWAL_WARNING_SECS {
        tracing::warn!(
            days_remaining = secs_remaining / 86400,
            license_id = %validated.payload.license_id,
            "Enterprise license expiring soon — please contact sales@omnikernel.io to renew"
        );
    }

    match &validated.payload.deployment {
        DeploymentType::Cloud => {
            validate_online(&validated)
                .await
                .context("Online cloud license validation failed")?;
            tracing::info!("Cloud deployment: license validated online and offline");
        }
        DeploymentType::PrivateCloud => {
            tracing::info!("Private cloud deployment: license validated offline");
        }
        DeploymentType::OnPremises => {
            tracing::info!("On-premises deployment: license validated offline");
        }
    }

    tracing::info!(
        customer      = %validated.payload.customer,
        license_id    = %validated.payload.license_id,
        deployment    = ?validated.payload.deployment,
        node_limit    = validated.payload.node_limit,
        days_remaining = secs_remaining / 86400,
        features      = ?validated.payload.features,
        "Enterprise license active"
    );

    Ok(validated)
}

/// Returns the canonical node identifier for this agent instance.
///
/// Resolution order: `OMNIKERNEL_NODE_ID` → `HOSTNAME` → `/etc/hostname` → `"unknown-node"`.
pub fn effective_node_id() -> String {
    env::var("OMNIKERNEL_NODE_ID")
        .or_else(|_| env::var("HOSTNAME"))
        .or_else(|_| {
            std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|_| "unknown-node".to_string())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn verify_license_key(raw: &str) -> Result<ValidatedLicense> {
    // Format: <base64url_payload>.<base64url_signature>
    let (b64_payload, b64_sig) = raw
        .split_once('.')
        .context("Invalid license key format — expected <payload>.<signature>")?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(b64_payload)
        .context("Failed to base64-decode license payload")?;

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(b64_sig)
        .context("Failed to base64-decode license signature")?;

    // HMAC-SHA256 constant-time verification.
    let mut mac = HmacSha256::new_from_slice(LICENSE_AUTHORITY_KEY)
        .expect("HMAC accepts any key length");
    mac.update(b64_payload.as_bytes());
    mac.verify_slice(&sig_bytes)
        .context("License signature invalid — the key may be tampered or issued by an unknown authority")?;

    let payload: LicensePayload = serde_json::from_slice(&payload_bytes)
        .context("Failed to deserialise license payload JSON")?;

    Ok(ValidatedLicense { payload })
}

/// Online check for cloud deployments: calls the OmniKernel license server.
async fn validate_online(license: &ValidatedLicense) -> Result<()> {
    let server_url = env::var("OMNIKERNEL_LICENSE_SERVER_URL")
        .unwrap_or_else(|_| "https://license.omnikernel.io/v1/validate".to_string());

    let body = serde_json::json!({
        "license_id":    &license.payload.license_id,
        "node_id":       effective_node_id(),
        "agent_version": env!("CARGO_PKG_VERSION"),
    });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .context("Failed to build HTTP client for online license validation")?;

    let resp = client
        .post(&server_url)
        .json(&body)
        .send()
        .await
        .context("Failed to reach OmniKernel license server")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let msg = resp.text().await.unwrap_or_default();
        bail!("License server rejected the key (HTTP {}): {}", status, msg);
    }

    Ok(())
}

fn now_secs() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("System clock is set before the Unix epoch")
        .map(|d| d.as_secs())
}
