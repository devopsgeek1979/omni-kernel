#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKAGE_NAME="omnikernel-agent"
ARCHIVE_PREFIX="${PACKAGE_NAME}-linux-x86_64"
VERSION="${VERSION:-$(grep '^version = ' "${ROOT_DIR}/Cargo.toml" | head -1 | cut -d '"' -f2)}"
BUILD_DIR="${ROOT_DIR}/target/package"
STAGE_DIR="${BUILD_DIR}/${ARCHIVE_PREFIX}-${VERSION}"
BPF_OUTPUT_DIR="${ROOT_DIR}/target/bpf"
BIN_PATH="${ROOT_DIR}/target/release/${PACKAGE_NAME}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

require_cmd cargo
require_cmd tar
require_cmd sha256sum

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Packaging is only supported on Linux because it builds the eBPF object." >&2
  exit 1
fi

rm -rf "${STAGE_DIR}"
mkdir -p "${STAGE_DIR}/bin" "${STAGE_DIR}/lib/omnikernel" "${STAGE_DIR}/configs"

pushd "${ROOT_DIR}" >/dev/null
cargo build --release --bin "${PACKAGE_NAME}"
bash ./scripts/build-ebpf.sh "${BPF_OUTPUT_DIR}"
popd >/dev/null

install -m 0755 "${BIN_PATH}" "${STAGE_DIR}/bin/${PACKAGE_NAME}"
install -m 0644 "${BPF_OUTPUT_DIR}/omnikernel_lsm.o" "${STAGE_DIR}/lib/omnikernel/omnikernel_lsm.o"
install -m 0644 "${ROOT_DIR}/configs/systemd.service" "${STAGE_DIR}/configs/systemd.service"
install -m 0644 "${ROOT_DIR}/README.md" "${STAGE_DIR}/README.md"
install -m 0644 "${ROOT_DIR}/LICENSE.txt" "${STAGE_DIR}/LICENSE.txt"

cat > "${STAGE_DIR}/configs/agent.env.example" <<'EOF'
OMNIKERNEL_SIGNING_KEY=replace-with-32-plus-char-secret
OMNIKERNEL_LICENSE=replace-with-issued-license
OMNIKERNEL_MESH_HUB_URL=https://mesh.local
OMNIKERNEL_ALLOWED_PATHS=/etc/nginx/:/usr/sbin/nginx:/var/lib/omnikernel/
OMNIKERNEL_BPF_OBJECT=/opt/omnikernel-agent/lib/omnikernel/omnikernel_lsm.o
EOF

if command -v llvm-strip >/dev/null 2>&1; then
  llvm-strip --strip-all "${STAGE_DIR}/bin/${PACKAGE_NAME}" || true
elif command -v strip >/dev/null 2>&1; then
  strip --strip-all "${STAGE_DIR}/bin/${PACKAGE_NAME}" || true
fi

pushd "${BUILD_DIR}" >/dev/null
tar -czf "${ARCHIVE_PREFIX}-${VERSION}.tar.gz" "${ARCHIVE_PREFIX}-${VERSION}"
sha256sum "${ARCHIVE_PREFIX}-${VERSION}.tar.gz" > "${ARCHIVE_PREFIX}-${VERSION}.tar.gz.sha256"
popd >/dev/null

echo "Package created: ${BUILD_DIR}/${ARCHIVE_PREFIX}-${VERSION}.tar.gz"
echo "Checksum file: ${BUILD_DIR}/${ARCHIVE_PREFIX}-${VERSION}.tar.gz.sha256"