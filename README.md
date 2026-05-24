# tabbify-service-mesh

A Tailscale-style overlay mesh: a coordinator, a peer joiner, and a small CA,
built on userspace WireGuard (boringtun) with mTLS.

Workspace binaries:

| Binary | Crate | Role |
| --- | --- | --- |
| `tabbify-mesh-coordinator` | `crates/mesh-coordinator` | Coordinator / control plane |
| `tabbify-mesh` | `tools/tabbify-mesh` | Peer CLI (join the mesh) |
| `tabbify-mesh-ca` | `tools/tabbify-mesh-ca` | mTLS CA helper |

See `justfile` for local dev recipes (`just build`, `just coordinator`, `just joiner`, ...).

## Releases & deployment

CI builds fully static Linux binaries (`x86_64-unknown-linux-musl`) and
uploads them to S3, from where a fresh Ubuntu host installs them with
`bootstrap.sh`.

### Release pipeline

`.github/workflows/release.yml` runs on a pushed `v*` tag or via manual
`workflow_dispatch`. It compiles the three binaries above for the musl target
and uploads them — plus `bootstrap.sh` — to `s3://<bucket>/mesh/`.

The workflow needs these repo settings (Settings -> Secrets and variables -> Actions):

| Kind | Name | Purpose |
| --- | --- | --- |
| Secret | `AWS_ROLE_ARN` | IAM role assumed via GitHub OIDC; needs `s3:PutObject` on `s3://<bucket>/mesh/*` |
| Variable | `AWS_REGION` | Region of the release bucket, e.g. `eu-central-1` |
| Variable | `RELEASE_S3_BUCKET` | Bucket name (no `s3://` prefix) |

One-time AWS setup (repo owner): create a GitHub OIDC identity provider
(`https://token.actions.githubusercontent.com`, audience `sts.amazonaws.com`)
and an IAM role whose trust policy is scoped to this repo and whose permission
policy grants `s3:PutObject` on the bucket's `mesh/` prefix. An access-key
alternative is documented in the workflow header.

### Provisioning a host

On a fresh Ubuntu machine:

```sh
export MESH_RELEASE_BASE_URL="https://<bucket>.s3.<region>.amazonaws.com/mesh"
curl -fsSL "$MESH_RELEASE_BASE_URL/bootstrap.sh" | sudo bash
```

`bootstrap.sh` is idempotent. It installs the three binaries into
`/usr/local/bin` and writes a config stub to `/etc/tabbify/mesh.env`
(`MESH_COORDINATOR`, `MESH_JOIN_TOKEN`) if one is not already present. Set
`MESH_RELEASE_BASE_URL` to your bucket's public object URL (it defaults to a
placeholder). The script also prints an optional systemd unit for running the
peer as a service.
