# tabbify-service-mesh — task runner.
# Run `just` (or `just --list`) to see all recipes.

# Show the list of available recipes.
default:
    @just --list

# Build the whole workspace.
build:
    cargo build --workspace

# Run the workspace test suite.
test:
    cargo test --workspace

# Lint with clippy; warnings are errors.
lint:
    cargo clippy --all-targets -- -D warnings

# Format the workspace with rustfmt.
fmt:
    cargo fmt

# Run the coordinator locally in plaintext mode (no mTLS, dev only).
coordinator:
    TABBIFY_ALLOW_INSECURE=1 cargo run -p tabbify-mesh-coordinator -- \
        --bind 127.0.0.1:8888 \
        --insecure-no-mtls

# Join the local mesh as a peer (pass --name <NAME>, e.g. `just joiner --name mac`).
joiner *ARGS:
    cargo run -p tabbify-mesh -- join --insecure-no-mtls {{ ARGS }}

# Initialize a fresh mTLS CA (ca.crt + ca.key) under ./mesh-ca.
ca-init:
    cargo run -p tabbify-mesh-ca -- init
