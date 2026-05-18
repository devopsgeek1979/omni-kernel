#!/usr/bin/env bash
# Build the OmniKernel eBPF LSM object.
#
# Requirements:
#   - clang >= 12 with BPF target support
#   - libbpf headers (install via libbpf-dev / libbpf-devel)
#   - BTF-enabled kernel headers or vmlinux.h generated with bpftool
#
# Usage: ./scripts/build-ebpf.sh [output-dir]
set -euo pipefail

OUTPUT_DIR="${1:-target/bpf}"
mkdir -p "${OUTPUT_DIR}"

# Locate libbpf headers (adjust path for your distribution).
LIBBPF_INCLUDE="${LIBBPF_INCLUDE:-/usr/include}"

echo "Building OmniKernel eBPF LSM object..."

clang \
  -O2 \
  -g \
  -Wall \
  -Wno-unused-value \
  -Wno-pointer-sign \
  -Wno-compare-distinct-pointer-types \
  -target bpf \
  -D __TARGET_ARCH_x86 \
  -I "${LIBBPF_INCLUDE}" \
  -I ebpf \
  -c ebpf/omnikernel_lsm.bpf.c \
  -o "${OUTPUT_DIR}/omnikernel_lsm.o"

echo "eBPF object written to ${OUTPUT_DIR}/omnikernel_lsm.o"

# Strip unneeded sections but retain BTF — required for CO-RE and bpf_d_path.
llvm-strip -g "${OUTPUT_DIR}/omnikernel_lsm.o" 2>/dev/null || true

echo "Build complete."

