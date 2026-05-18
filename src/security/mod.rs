#[cfg(target_os = "linux")]
pub mod alerts;
#[cfg(target_os = "linux")]
pub mod ebpf;
#[cfg(not(target_os = "linux"))]
pub mod ebpf {
	use anyhow::{bail, Result};

	use crate::config::SecurityPolicy;

	pub struct SecurityRuntime;

	impl SecurityRuntime {
		pub async fn initialize(_policy: SecurityPolicy) -> Result<Self> {
			bail!("The eBPF security runtime is only supported on Linux hosts")
		}

		pub async fn shutdown(self) -> Result<()> {
			Ok(())
		}
	}
}
#[cfg(target_os = "linux")]
pub mod maps;
