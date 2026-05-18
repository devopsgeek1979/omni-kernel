# OmniKernel Agent

Enterprise-grade Rust + eBPF + Wasmtime host security subsystem.

## Features

- eBPF LSM enforcement
- Wasmtime sandbox runtime
- Runtime whitelist injection
- Cryptographic alert streaming
- License-aware execution model
- Cloud + on-prem deployability

## Build

```bash
cargo build --release
```

For non-Linux developer machines, use `cargo check` to validate the crate graph and shared logic.
The agent binary compiles there, but the eBPF runtime stays Linux-only and will refuse to start.

## Requirements

- Linux >= 5.13
- BTF enabled
- CONFIG_BPF_LSM=y
- Rust stable
- clang + llvm

## GitHub CI

The repository includes a lightweight GitHub Actions workflow that runs `cargo check` and
`cargo test` on `ubuntu-latest`, which matches a standard small GitHub-hosted runner well.

## Packaging

Build a Linux release package with:

```bash
./scripts/package-release.sh
```

That package intentionally ships only the production agent binary, the eBPF object,
the systemd unit, and an example environment file. It also strips symbols from the
binary to raise reverse-engineering cost, but it does not make reverse engineering impossible.

The same package flow is available in GitHub Actions through [.github/workflows/package.yml](.github/workflows/package.yml),
which runs on `ubuntu-latest` and publishes the tarball as a workflow artifact.
