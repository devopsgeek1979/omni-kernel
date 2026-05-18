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

VMLINUX_HEADER="ebpf/vmlinux.h"

resolve_bpftool() {
  if command -v bpftool >/dev/null 2>&1; then
    command -v bpftool
    return 0
  fi

  local candidate
  for candidate in /usr/lib/linux-tools/*/bpftool; do
    if [[ -x "${candidate}" ]]; then
      echo "${candidate}"
      return 0
    fi
  done

  return 1
}

if [[ ! -f "${VMLINUX_HEADER}" ]]; then
  BPFT_TOOL="$(resolve_bpftool || true)"
  if [[ -z "${BPFT_TOOL}" ]]; then
    echo "Missing ${VMLINUX_HEADER} and bpftool is not installed." >&2
    echo "Install bpftool or provide ebpf/vmlinux.h before building." >&2
    exit 1
  fi

  if [[ ! -f /sys/kernel/btf/vmlinux ]]; then
    echo "Kernel BTF file /sys/kernel/btf/vmlinux not found; cannot generate ${VMLINUX_HEADER}." >&2
    exit 1
  fi

  echo "Generating ${VMLINUX_HEADER} from kernel BTF..."
  "${BPFT_TOOL}" btf dump file /sys/kernel/btf/vmlinux format c > "${VMLINUX_HEADER}"
fi

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

