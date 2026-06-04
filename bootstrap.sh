#!/bin/sh
# bootstrap.sh — join this machine to the Tabbify mesh with one command
# (Tailscale-style: no config, the production coordinator + TLS relay
# are baked into the binary). Any systemd Linux:
#
#   curl -fsSL https://tabbify-releases-leo.s3.eu-central-1.amazonaws.com/mesh/install | sudo sh
#
# What it does:
#   - downloads the static `tabbify-mesh` joiner for THIS arch
#     (x86_64 / aarch64), sha256-verified against the release manifest
#     (x86_64), into /usr/local/bin (it is also the CLI: status/peers)
#   - installs the tabbify-mesh systemd service: joins on boot,
#     auto-restarts, keeps a persistent identity (stable overlay
#     address across restarts) under /var/lib/tabbify-mesh
#   - the joiner SELF-MANAGES host integration: the firewall trust rule
#     for its own TUN device (re-asserted every 60s, tailscaled-style),
#     NAT traversal, and the TLS relay fallback — a machine behind any
#     NAT/corporate firewall still becomes reachable
#
# This is the MESH-ONLY install (a machine that should be on the network
# without running apps). To also RUN apps (containers / Firecracker
# microVMs), install the supervisor instead — the mesh is built into it:
#
#   curl -fsSL https://tabbify-releases-leo.s3.eu-central-1.amazonaws.com/supervisor/install | sudo sh
#
# Re-running upgrades the binary in place and restarts the service.
#
# Uninstall:
#   systemctl disable --now tabbify-mesh
#   rm -rf /usr/local/bin/tabbify-mesh /var/lib/tabbify-mesh /etc/systemd/system/tabbify-mesh.service
set -eu

BASE="${TABBIFY_RELEASE_BASE_URL:-https://tabbify-releases-leo.s3.eu-central-1.amazonaws.com}"
BIN=/usr/local/bin/tabbify-mesh
STATE=/var/lib/tabbify-mesh

if [ -t 1 ]; then G='\033[1;32m'; Y='\033[1;33m'; R='\033[1;31m'; N='\033[0m'; else G=''; Y=''; R=''; N=''; fi
log()  { printf "${G}==>${N} %s\n" "$*"; }
warn() { printf "${Y}warn:${N} %s\n" "$*" >&2; }
die()  { printf "${R}error:${N} %s\n" "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root:  curl -fsSL .../mesh/install | sudo sh"
command -v curl >/dev/null 2>&1 || die "curl is required"
command -v systemctl >/dev/null 2>&1 || die "systemd is required (this installer manages a systemd unit)"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required (coreutils/busybox)"
command -v ip >/dev/null 2>&1 || die "iproute2 ('ip') is required to configure the mesh TUN device"

ARCH=$(uname -m)
case "$ARCH" in
  x86_64) : ;;
  aarch64|arm64) ARCH=aarch64 ;;
  *) die "unsupported architecture: $ARCH (x86_64 / aarch64 only)" ;;
esac

# ── resolve + download (sha256-verified on x86_64) ──────────────────────
MANIFEST=$(curl -fsSL "$BASE/mesh/latest") || die "cannot fetch $BASE/mesh/latest"
VER=$(printf '%s' "$MANIFEST" | grep -o '"latest":[[:space:]]*"[^"]*"' | grep -o '"v[^"]*"$' | tr -d '"')
[ -n "$VER" ] || die "could not resolve the latest mesh version"
log "Tabbify mesh joiner $VER ($ARCH)"

tmp=$(mktemp)
curl -fSL -o "$tmp" "$BASE/mesh/$VER/$ARCH/tabbify-mesh" \
  || die "download failed: $BASE/mesh/$VER/$ARCH/tabbify-mesh (no $ARCH build for $VER?)"
if [ "$ARCH" = x86_64 ]; then
  want=$(printf '%s' "$MANIFEST" | grep -o '"tabbify-mesh":[[:space:]]*"[a-f0-9]*"' | grep -o '[a-f0-9]\{64\}') || true
  got=$(sha256sum "$tmp" | cut -d' ' -f1)
  [ "$want" = "$got" ] || die "tabbify-mesh sha256 mismatch (manifest $want, downloaded $got)"
fi
chmod +x "$tmp"
mv "$tmp" "$BIN"
"$BIN" --version >/dev/null 2>&1 || die "downloaded binary failed its --version self-check"

# ── informational capability check ──────────────────────────────────────
command -v ip6tables >/dev/null 2>&1 \
  || warn "ip6tables missing — the joiner cannot self-manage firewall trust; inbound overlay connections may be filtered by your firewall"

# ── systemd unit ─────────────────────────────────────────────────────────
NODE_NAME=$(uname -n)
mkdir -p "$STATE"
log "installing tabbify-mesh.service (node name: $NODE_NAME)"

cat > /etc/systemd/system/tabbify-mesh.service <<EOF
[Unit]
Description=Tabbify mesh joiner
Wants=network-online.target
After=network-online.target

[Service]
# Foreground daemon. --manage-firewall: keep an iface-scoped INPUT
# ACCEPT for the mesh TUN (asserted at bring-up, re-asserted every 60s,
# removed on exit) so distro firewalls don't drop inbound overlay
# connections — the tailscaled pattern.
ExecStart=$BIN join --name $NODE_NAME --manage-firewall
# HOME anchors the persistent identity ($STATE/.tabbify-mesh/keypair):
# the same WireGuard key on every start means the same stable overlay
# address (the coordinator's roster is keyed by public key).
Environment=HOME=$STATE
WorkingDirectory=$STATE
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable tabbify-mesh.service >/dev/null 2>&1
systemctl restart tabbify-mesh.service

# ── wait for the join and report the overlay address ───────────────────
log "joining the mesh (up to 45s)..."
i=0
ULA=""
while [ $i -lt 45 ]; do
  # The standalone joiner logs JSON ("my_ula":"fd5a:…"), unlike the
  # supervisor's key=value format — the two greps are NOT interchangeable.
  ULA=$(journalctl -u tabbify-mesh --since "-3 min" --no-pager 2>/dev/null \
    | grep -o '"my_ula":"[0-9a-f:]*"' | tail -1 | cut -d'"' -f4) || true
  if [ -n "$ULA" ] && systemctl is-active --quiet tabbify-mesh; then
    break
  fi
  i=$((i + 3)); sleep 3
done

if [ -n "$ULA" ]; then
  log "machine '$NODE_NAME' is ON the mesh: $ULA"
  log "peers:   $BIN peers"
  log "leave:   systemctl disable --now tabbify-mesh"
else
  warn "service started but the join was not confirmed within 45s"
  warn "inspect:  journalctl -u tabbify-mesh -f"
fi
