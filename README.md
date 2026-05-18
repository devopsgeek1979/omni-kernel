# OmniKernel Agent

OmniKernel Agent is a Linux host security control plane built with Rust, eBPF LSM, and Wasmtime.
It helps teams enforce file and execution policies at the kernel boundary, stream signed alerts,
and operate with a repeatable delivery pipeline.

## Why This Tool

Most host security stacks detect issues after compromise. OmniKernel Agent moves enforcement closer
to the kernel so unauthorized file access and process execution can be blocked or audited in real time.

Key outcomes:

- Reduce time-to-detect for suspicious host behavior.
- Enforce host policy consistently across environments.
- Produce signed, structured alerts for SIEM or mesh ingestion.
- Keep deployment predictable through CI, packaging, and systemd integration.

## What Is Built

- eBPF LSM policy hooks for `file_open` and `bprm_check_security`
- Ring buffer event pipeline from kernel space to user space
- HMAC-signed alert publishing to a mesh hub endpoint
- License validation gate before runtime initialization
- Wasmtime policy runtime with fuel limits
- Linux release packaging and GitHub automation
- Demo site on GitHub Pages for customer walkthroughs

## Tooling Stack

- Runtime: Rust, Tokio, Aya, Wasmtime
- Kernel policy: eBPF LSM, BTF, ring buffer maps
- Delivery: GitHub Actions (`ci`, `package`, `pages`)
- Service model: systemd unit in [configs/systemd.service](configs/systemd.service)

## End-to-End Process

The lifecycle customers invest in is visible and testable:

1. Build and validate source (`cargo check`, `cargo test`).
2. Build eBPF object and generate `ebpf/vmlinux.h` automatically when missing.
3. Package release artifacts for Linux deployment.
4. Deploy service with environment-backed policy and license configuration.
5. Enforce or audit at kernel hooks and emit signed alerts.
6. Track delivery status with GitHub workflows and demo visibility on Pages.

The live demo documents this flow: [OmniKernel Agent Demo](https://devopsgeek1979.github.io/omni-kernel/).

## Benefits in Customer Environments

Security benefits:

- Kernel-adjacent enforcement lowers bypass opportunities compared to user-space-only controls.
- Signed alert payloads improve trust and downstream correlation quality.
- License gate prevents unmanaged runtime activation in restricted environments.

Operational benefits:

- Clear deployment model for cloud, private cloud, and on-premises Linux hosts.
- Small, explicit artifact set simplifies release governance.
- CI and packaging workflows reduce manual drift during rollouts.

Business benefits:

- Faster incident response by surfacing high-fidelity host events.
- Lower operational risk with repeatable release and startup checks.
- Better stakeholder transparency through the public demo narrative.

## Role-Based Value

CISO and security leadership:

- Gain stronger confidence in host-level policy enforcement.
- Improve board-level reporting with clearer control evidence.

SOC and incident response teams:

- Receive high-fidelity, signed host signals for triage.
- Reduce alert noise by focusing on policy-relevant events.

Platform and SRE teams:

- Use deterministic packaging and service rollout patterns.
- Minimize environment drift with CI and release automation.

DevOps and engineering teams:

- Shift host policy checks earlier into the release lifecycle.
- Keep runtime behavior visible through reproducible workflows.

## Prerequisites

- Linux kernel 5.13 or newer
- Kernel BTF available (`/sys/kernel/btf/vmlinux`)
- `CONFIG_BPF_LSM=y`
- Rust stable toolchain
- `clang`, `llvm`, and `libbpf` headers

## Build and Validate

```bash
cargo check
cargo test --all-targets
cargo build --release
```

For non-Linux developer machines, compile checks still work, but the eBPF runtime is Linux-only and intentionally refuses to start.

## Package for Linux

```bash
./scripts/package-release.sh
```

The package includes:

- `omnikernel-agent` release binary
- `omnikernel_lsm.o` eBPF object
- systemd service file
- environment template
- checksum file for integrity verification

Symbol stripping is enabled to raise reverse-engineering cost, but no packaging strategy can make reverse engineering impossible.

## Configure and Run

Set required environment values (for example via `/etc/omnikernel/agent.env`):

- `OMNIKERNEL_LICENSE`
- `OMNIKERNEL_SIGNING_KEY`
- `OMNIKERNEL_MESH_HUB_URL`
- `OMNIKERNEL_ALLOWED_PATHS`
- `OMNIKERNEL_BPF_OBJECT`

Then run the service with systemd using [configs/systemd.service](configs/systemd.service).

## CI, Packaging, and Demo Workflows

- CI checks: [.github/workflows/ci.yml](.github/workflows/ci.yml)
- Linux package pipeline: [.github/workflows/package.yml](.github/workflows/package.yml)
- GitHub Pages demo deployment: [.github/workflows/pages.yml](.github/workflows/pages.yml)

## Deployment and Rollback

Detailed guides for enterprise deployment and risk mitigation:

- **[DEPLOYMENT.md](DEPLOYMENT.md)** — Step-by-step production rollout guide covering staging, policy tuning, phased enforcement, and monitoring.
- **[ROLLBACK.md](ROLLBACK.md)** — Procedures to safely roll back the agent if issues are detected, including verification, gradual fleet reversion, and re-deployment strategy.

### Key Deployment Phases

1. **Staging & Audit Mode** (48–72 hours): Deploy to non-production nodes, collect baseline events, tune policy whitelist.
2. **Pilot Enforcement** (24–48 hours): Enable blocking on a small group, monitor for false positives and service stability.
3. **Phased Rollout** (4 phases): Roll out to 5% → 25% → 50% → 100% of production fleet with monitoring between each wave.
4. **Operations**: Monitor event denial rate, alert delivery latency, and agent service health metrics.

### When to Roll Back

Roll back if:
- Agent service crashes or causes kernel panics.
- eBPF program verification fails.
- Excessive false-positive denials impact workloads.
- Performance degradation occurs (CPU, memory, I/O).

Before-and-after metrics are visible in the demo site: unauthorized execution detection improves from **0/hr (undetected)** to **42/hr (blocked at kernel boundary)** with latency dropping from **2–5 seconds** to **165–240 ms**.

## Demo Scope

The demo site explains:

- Architecture and toolchain
- End-to-end deployment and runtime process
- Customer-facing benefits and adoption value
- Event flow simulation from license gate to policy runtime

## Limitations and Notes

- eBPF LSM enforcement is Linux-only.
- Kernel configuration and BTF availability are mandatory for runtime enforcement.
- The demo site is educational; it does not execute production enforcement logic.
