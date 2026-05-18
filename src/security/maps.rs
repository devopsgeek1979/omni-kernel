use anyhow::{Context, Result};
use aya::{maps::HashMap, Ebpf};

/// Populate the eBPF `whitelist` map with the paths from `allowed`.
///
/// Paths longer than 255 bytes are truncated to fit the fixed-size map key;
/// a warning is emitted so operators can fix their policy configuration.
pub fn populate_whitelist(bpf: &mut Ebpf, allowed: &[String]) -> Result<()> {
    let mut map: HashMap<_, [u8; 256], u8> = HashMap::try_from(
        bpf.take_map("whitelist")
            .context("eBPF 'whitelist' map not found — ensure the BPF object was compiled correctly")?,
    )?;

    for path in allowed {
        let bytes = path.as_bytes();
        if bytes.len() > 255 {
            tracing::warn!(
                path = %path,
                length = bytes.len(),
                "Whitelist path exceeds 255 bytes and will be truncated — consider shortening the path"
            );
        }

        let mut key = [0u8; 256];
        let len = bytes.len().min(255);
        key[..len].copy_from_slice(&bytes[..len]);

        map.insert(key, 1u8, 0)
            .with_context(|| format!("Failed to insert path into eBPF whitelist map: {path}"))?;
    }

    tracing::info!(count = allowed.len(), "eBPF whitelist populated");
    Ok(())
}

