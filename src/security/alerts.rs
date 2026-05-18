use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde::Serialize;
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize)]
pub struct SecurityAlert {
    pub node_id: String,
    pub operation: String,
    pub path: String,
    pub pid: u32,
    /// Unix timestamp of the event (seconds).
    pub timestamp: u64,
    /// HMAC-SHA256 hex signature over `node_id:operation:path:pid:timestamp`.
    pub signature: String,
}

/// Send a signed security alert to the mesh hub.
///
/// The alert payload is authenticated with HMAC-SHA256 (not raw SHA256 —
/// raw `hash(key || payload)` is vulnerable to hash-length-extension attacks).
pub async fn send_alert(
    hub_url: &str,
    signing_key: &str,
    node_id: &str,
    operation: &str,
    path: &str,
    pid: u32,
) -> Result<()> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("System clock is before the Unix epoch")?
        .as_secs();

    // Canonical message: colon-separated fields including timestamp to prevent replay.
    let message = format!("{node_id}:{operation}:{path}:{pid}:{timestamp}");

    let mut mac = HmacSha256::new_from_slice(signing_key.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(message.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    let alert = SecurityAlert {
        node_id: node_id.to_string(),
        operation: operation.to_string(),
        path: path.to_string(),
        pid,
        timestamp,
        signature,
    };

    Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("Failed to build HTTP client")?
        .post(format!("{hub_url}/api/v1/security/alerts"))
        .json(&alert)
        .send()
        .await
        .context("Failed to send security alert to mesh hub")?
        .error_for_status()
        .context("Mesh hub returned an error for the security alert")?;

    Ok(())
}

