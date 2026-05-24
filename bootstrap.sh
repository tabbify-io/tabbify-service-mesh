#!/usr/bin/env bash
#
# bootstrap.sh — provision a fresh Ubuntu host as a tabbify-service-mesh node.
#
# Downloads the static mesh binaries from S3 into /usr/local/bin and lays
# down a config stub at /etc/tabbify/mesh.env. Idempotent: re-running it
# re-downloads the latest binaries and leaves an existing mesh.env untouched.
#
# Usage:
#   curl -fsSL <base-url>/bootstrap.sh | sudo bash
#   # or
#   sudo ./bootstrap.sh
#
# Configuration (environment variables):
#   MESH_RELEASE_BASE_URL   Base URL the binaries are fetched from. Defaults
#                           to the public S3 object URL of the release bucket.
#                           >>> REPLACE the placeholder below (or export this
#                           var) with your real bucket/region, e.g.:
#                             https://tabbify-mesh-releases.s3.eu-central-1.amazonaws.com/mesh
#                           This must match RELEASE_S3_BUCKET / AWS_REGION used
#                           by the release workflow. If the bucket is private,
#                           point this at a CloudFront/presigned URL instead.

set -euo pipefail

# --- Configuration ---------------------------------------------------------

# TODO(leo): replace <BUCKET> and <REGION> with the real release bucket.
DEFAULT_BASE_URL="https://<BUCKET>.s3.<REGION>.amazonaws.com/mesh"
BASE_URL="${MESH_RELEASE_BASE_URL:-${DEFAULT_BASE_URL}}"

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/tabbify"
CONFIG_FILE="${CONFIG_DIR}/mesh.env"

# Binaries produced by the release workflow. Keep this list in sync with the
# upload step in .github/workflows/release.yml.
BINARIES=(
  "tabbify-mesh-coordinator"
  "tabbify-mesh"
  "tabbify-mesh-ca"
)

# --- Helpers ---------------------------------------------------------------

log() {
  printf '==> %s\n' "$*"
}

err() {
  printf 'error: %s\n' "$*" >&2
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    err "this script writes to ${INSTALL_DIR} and ${CONFIG_DIR}; run it as root (e.g. with sudo)."
    exit 1
  fi
}

require_curl() {
  if ! command -v curl >/dev/null 2>&1; then
    err "curl is required but not installed. Install it with: apt-get install -y curl"
    exit 1
  fi
}

check_base_url() {
  case "${BASE_URL}" in
    *"<BUCKET>"* | *"<REGION>"*)
      err "MESH_RELEASE_BASE_URL is not configured."
      err "Set it to your release bucket URL, e.g.:"
      err "  export MESH_RELEASE_BASE_URL=https://my-bucket.s3.eu-central-1.amazonaws.com/mesh"
      exit 1
      ;;
  esac
}

# --- Main ------------------------------------------------------------------

require_root
require_curl
check_base_url

log "Installing mesh binaries from ${BASE_URL}"
mkdir -p "${INSTALL_DIR}"

for bin in "${BINARIES[@]}"; do
  dest="${INSTALL_DIR}/${bin}"
  log "Downloading ${bin}"
  # Download to a temp file first so a failed fetch never leaves a
  # half-written or non-executable binary in place.
  tmp="$(mktemp)"
  if ! curl -fsSL "${BASE_URL}/${bin}" -o "${tmp}"; then
    err "failed to download ${bin} from ${BASE_URL}/${bin}"
    rm -f "${tmp}"
    exit 1
  fi
  chmod +x "${tmp}"
  mv -f "${tmp}" "${dest}"
  log "Installed ${dest}"
done

# Create the config stub only if it does not already exist, so re-running
# bootstrap.sh never clobbers a host's real configuration.
if [ ! -f "${CONFIG_FILE}" ]; then
  log "Creating config stub at ${CONFIG_FILE}"
  mkdir -p "${CONFIG_DIR}"
  cat > "${CONFIG_FILE}" <<'EOF'
# tabbify-service-mesh node configuration.
# Fill these in before starting the mesh peer.

# Coordinator endpoint this node joins, e.g. https://coordinator.example.com:8888
MESH_COORDINATOR=

# Join token issued by the coordinator / auth service.
MESH_JOIN_TOKEN=
EOF
  chmod 600 "${CONFIG_FILE}"
  log "Wrote ${CONFIG_FILE} (edit it to set MESH_COORDINATOR and MESH_JOIN_TOKEN)"
else
  log "Config ${CONFIG_FILE} already exists — leaving it untouched"
fi

log "Done. Installed: ${BINARIES[*]}"
cat <<EOF

Next steps:
  1. Edit ${CONFIG_FILE} and set MESH_COORDINATOR and MESH_JOIN_TOKEN.
  2. Join the mesh as a peer, e.g.:
       set -a && . ${CONFIG_FILE} && set +a
       tabbify-mesh join --name "\$(hostname)"

Optional — run the peer under systemd. Create
/etc/systemd/system/tabbify-mesh.service with something like:

  [Unit]
  Description=Tabbify mesh peer
  After=network-online.target
  Wants=network-online.target

  [Service]
  EnvironmentFile=${CONFIG_FILE}
  ExecStart=${INSTALL_DIR}/tabbify-mesh join --name %H
  Restart=on-failure

  [Install]
  WantedBy=multi-user.target

then: systemctl daemon-reload && systemctl enable --now tabbify-mesh
EOF
