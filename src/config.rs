use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicy {
    /// Filesystem paths the agent permits; checked against the eBPF whitelist.
    pub allowed_paths: Vec<String>,
    /// URL of the mesh hub that receives security alerts.
    pub mesh_hub_url: String,
    /// Unique identifier for this agent node.
    pub node_id: String,
    /// HMAC-SHA256 key used to authenticate security alert payloads.
    ///
    /// Load from a secrets manager or environment variable.
    /// **Never hard-code this value in source control.**
    pub signing_key: String,
}

impl SecurityPolicy {
    /// Build the security policy from environment variables.
    ///
    /// **Required** environment variables:
    /// - `OMNIKERNEL_SIGNING_KEY` — HMAC key for alert authentication (min 32 chars)
    ///
    /// **Optional** environment variables:
    /// - `OMNIKERNEL_MESH_HUB_URL`   — mesh hub endpoint (default: `https://mesh.local`)
    /// - `OMNIKERNEL_NODE_ID`         — node identifier (default: hostname)
    /// - `OMNIKERNEL_ALLOWED_PATHS`   — colon-separated path whitelist
    pub fn from_env() -> Result<Self> {
        let signing_key = env::var("OMNIKERNEL_SIGNING_KEY")
            .context("OMNIKERNEL_SIGNING_KEY must be set to a secure random HMAC key")?;

        if signing_key.len() < 32 {
            bail!(
                "OMNIKERNEL_SIGNING_KEY is too short ({} chars) — minimum 32 characters required",
                signing_key.len()
            );
        }

        let mesh_hub_url = env::var("OMNIKERNEL_MESH_HUB_URL")
            .unwrap_or_else(|_| "https://mesh.local".to_string());

        let node_id = crate::license::effective_node_id();

        let allowed_paths = env::var("OMNIKERNEL_ALLOWED_PATHS")
            .map(|v| v.split(':').map(str::to_string).collect::<Vec<_>>())
            .unwrap_or_else(|_| default_allowed_paths());

        Ok(Self {
            allowed_paths,
            mesh_hub_url,
            node_id,
            signing_key,
        })
    }
}

fn default_allowed_paths() -> Vec<String> {
    vec![
        "/etc/nginx/".into(),
        "/usr/sbin/nginx".into(),
        "/var/lib/omnikernel/".into(),
    ]
}

