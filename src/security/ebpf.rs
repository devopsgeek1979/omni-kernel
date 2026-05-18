use anyhow::{Context, Result};
use aya::{maps::ring_buf::RingBuf, maps::MapData, programs::Lsm, Ebpf};
use std::env;
use tokio::io::unix::AsyncFd;

use crate::{
    config::SecurityPolicy,
    security::{alerts, maps},
};

pub struct SecurityRuntime {
    /// Holds the loaded eBPF object; programs are automatically detached on drop.
    bpf: Ebpf,
}

impl SecurityRuntime {
    /// Load the eBPF object, attach LSM programs, populate the whitelist, and
    /// spawn the background ring-buffer event consumer.
    ///
    /// The BPF object path is read from `OMNIKERNEL_BPF_OBJECT` (default:
    /// `/opt/omnikernel-agent/omnikernel_lsm.o`).
    pub async fn initialize(policy: SecurityPolicy) -> Result<Self> {
        let bpf_path = env::var("OMNIKERNEL_BPF_OBJECT")
            .unwrap_or_else(|_| "/opt/omnikernel-agent/omnikernel_lsm.o".to_string());

        let mut bpf = Ebpf::load_file(&bpf_path)
            .with_context(|| format!("Failed to load eBPF object from '{bpf_path}'"))?;

        // Populate the path whitelist before attaching programs.
        maps::populate_whitelist(&mut bpf, &policy.allowed_paths)?;

        // Load and attach `lsm/file_open`.
        let file_open: &mut Lsm = bpf
            .program_mut("omnikernel_file_open")
            .context("eBPF program 'omnikernel_file_open' not found in BPF object")?
            .try_into()?;
        file_open
            .load()
            .context("Failed to load 'omnikernel_file_open' LSM program")?;
        file_open
            .attach()
            .context("Failed to attach 'omnikernel_file_open' LSM program")?;

        // Load and attach `lsm/bprm_check_security`.
        let exec: &mut Lsm = bpf
            .program_mut("omnikernel_exec")
            .context("eBPF program 'omnikernel_exec' not found in BPF object")?
            .try_into()?;
        exec.load()
            .context("Failed to load 'omnikernel_exec' LSM program")?;
        exec.attach()
            .context("Failed to attach 'omnikernel_exec' LSM program")?;

        // Take the ring buffer and hand ownership to the background task.
        let ring: RingBuf<_> = RingBuf::try_from(
            bpf.take_map("security_events")
                .context("eBPF 'security_events' ring-buffer map not found — ensure the BPF object defines it")?,
        )?;

        tokio::spawn(event_loop(
            ring,
            policy.mesh_hub_url.clone(),
            policy.signing_key.clone(),
            policy.node_id.clone(),
        ));

        // Notify the mesh hub that the runtime has started.
        alerts::send_alert(
            &policy.mesh_hub_url,
            &policy.signing_key,
            &policy.node_id,
            "runtime_initialized",
            "ebpf_lsm",
            0,
        )
        .await
        .unwrap_or_else(|e| tracing::warn!(error = %e, "Failed to send startup alert to mesh hub"));

        tracing::info!(bpf_path, "eBPF LSM runtime initialised");
        Ok(Self { bpf })
    }

    /// Graceful shutdown: dropping `bpf` causes aya to detach all programs.
    pub async fn shutdown(self) -> Result<()> {
        drop(self.bpf);
        tracing::info!("eBPF runtime shutdown complete");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Ring-buffer event consumer
// ---------------------------------------------------------------------------

/// Background task: reads [`SecurityEvent`] records from the eBPF ring buffer
/// and forwards denied-access events to the mesh hub as signed alerts.
async fn event_loop(
    ring: RingBuf<MapData>,
    hub_url: String,
    signing_key: String,
    node_id: String,
) {
    let mut async_fd = match AsyncFd::new(ring) {
        Ok(fd) => fd,
        Err(e) => {
            tracing::error!(error = %e, "Failed to create AsyncFd for security_events ring buffer");
            return;
        }
    };

    tracing::info!("Security event consumer loop started");

    loop {
        let mut guard = match async_fd.readable_mut().await {
            Ok(g) => g,
            Err(e) => {
                tracing::error!(error = %e, "Ring-buffer poll error");
                break;
            }
        };

        let rb = guard.get_inner_mut();
        while let Some(event_bytes) = rb.next() {
            process_event(&event_bytes, &hub_url, &signing_key, &node_id).await;
        }
        guard.clear_ready();
    }

    tracing::info!("Security event consumer loop terminated");
}

/// Parse a raw ring-buffer record and, for denied events, send a mesh alert.
///
/// Expected C struct layout (`struct security_event` in `omnikernel_lsm.bpf.c`):
/// ```text
/// offset  0 : u32  pid       (4 bytes)
/// offset  4 : u32  uid       (4 bytes)
/// offset  8 : u8   operation (1 byte)  — 0 = file_open, 1 = exec
/// offset  9 : u8   pad[3]   (3 bytes)
/// offset 12 : char path[256] (256 bytes)
/// offset 268: i32  verdict   (4 bytes) — 0 = allow, -EPERM = deny
/// total     : 272 bytes
/// ```
async fn process_event(data: &[u8], hub_url: &str, signing_key: &str, node_id: &str) {
    const EVENT_SIZE: usize = 4 + 4 + 1 + 3 + 256 + 4; // 272 bytes

    if data.len() < EVENT_SIZE {
        tracing::warn!(
            received = data.len(),
            expected = EVENT_SIZE,
            "Undersized security event dropped"
        );
        return;
    }

    let pid = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
    let operation_code = data[8];
    let path_bytes = &data[12..268];
    let path_end = path_bytes.iter().position(|&b| b == 0).unwrap_or(256);
    let path = String::from_utf8_lossy(&path_bytes[..path_end]).into_owned();
    let verdict = i32::from_ne_bytes([data[268], data[269], data[270], data[271]]);

    let operation = match operation_code {
        0 => "file_open",
        1 => "exec",
        _ => "unknown",
    };

    if verdict != 0 {
        tracing::warn!(
            pid,
            operation,
            path = %path,
            "eBPF LSM denied access"
        );
        if let Err(e) =
            alerts::send_alert(hub_url, signing_key, node_id, operation, &path, pid).await
        {
            tracing::error!(error = %e, "Failed to forward denied-access alert to mesh hub");
        }
    } else {
        tracing::trace!(pid, operation, path = %path, "eBPF LSM permitted access");
    }
}

