# syntax=docker/dockerfile:1
#
# Coordinator image — the ONLY containerized mesh component. It is a pure HTTP
# control-plane (axum on :8888): no TUN, no CAP_NET_ADMIN, so it runs cleanly
# in a container. joiner/fabric/CA are NOT containerized (they drive a host TUN
# device + need CAP_NET_ADMIN) and ship as bare static binaries via S3.
#
# The binary is fully static (musl + ring), so distroless/static — which has no
# libc but ships CA certificates + tzdata — is sufficient and minimal.
#
# The binary must already be built into the build context before `docker build`:
#   cargo build --release --target x86_64-unknown-linux-musl
# The release workflow builds it, then builds + pushes this image to ECR.
#
# Run with `network_mode: host` so the coordinator observes each peer's real
# source IP:port (used for NAT hole-punch coordination); behind a bridge NAT it
# would see only the docker gateway address.
FROM gcr.io/distroless/static-debian12:nonroot

ARG BIN=target/x86_64-unknown-linux-musl/release/tabbify-mesh-coordinator
COPY ${BIN} /usr/local/bin/coordinator

EXPOSE 8888
ENTRYPOINT ["/usr/local/bin/coordinator"]
