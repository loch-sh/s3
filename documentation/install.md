# Installation and Getting Started

## Table of Contents

- [Prerequisites](#prerequisites)
- [Build from Source](#build-from-source)
- [Docker](#docker)
- [Environment Variables](#environment-variables)
- [Authentication Modes](#authentication-modes)
- [Auto-Bootstrap](#auto-bootstrap)

---

## Prerequisites

| Tool | Minimum Version | Usage |
|------|----------------|-------|
| [Rust](https://rustup.rs/) | 1.85 | Build from source |
| [Docker](https://www.docker.com/) | 20+ | Container deployment |
| [`cross`](https://github.com/cross-rs/cross) | any | Cross-compilation only (optional) |

---

## Build from Source

```bash
# Optimized build
cargo build --release

# Start the server (listens on port 8080 by default)
./target/release/s3
```

The user management CLI binary is also compiled:

```bash
./target/release/loch-s3 --help
```

### Cross-Compilation Targets

Linux and Windows require [`cross`](https://github.com/cross-rs/cross). macOS targets build natively.

```bash
cargo install cross

make linux-amd64      # x86_64-unknown-linux-musl
make linux-arm64      # aarch64-unknown-linux-musl
make windows-amd64    # x86_64-pc-windows-gnu
make macos-amd64      # x86_64-apple-darwin  (macOS only)
make macos-arm64      # aarch64-apple-darwin  (macOS only)
make all              # all targets
```

Binaries are output to `dist/<platform>/`.

---

## Docker

### Public Image

Multi-architecture images (`linux/amd64` + `linux/arm64`) are published to GitHub Container Registry on each version tag:

```
ghcr.io/loch-sh/s3
```

### Minimal Launch (No Authentication)

```bash
docker run -p 8080:8080 -v s3-data:/data ghcr.io/loch-sh/s3
```

### Single-User Mode

```bash
docker run -p 8080:8080 -v s3-data:/data \
  -e S3_ACCESS_KEY_ID=myaccesskey \
  -e S3_SECRET_ACCESS_KEY=mysecretkey \
  ghcr.io/loch-sh/s3
```

### Multi-User Mode (Auto-Bootstrap on First Start)

```bash
docker run -p 8080:8080 -v s3-data:/data \
  -e S3_USERS_FILE=/data/.users.json \
  -e S3_ADMIN_API_KEY=my-admin-key \
  ghcr.io/loch-sh/s3
```

### With SSE-S3 Encryption

```bash
docker run -p 8080:8080 -v s3-data:/data \
  -e S3_ACCESS_KEY_ID=myaccesskey \
  -e S3_SECRET_ACCESS_KEY=mysecretkey \
  -e S3_ENCRYPTION_KEY=$(openssl rand -base64 32) \
  ghcr.io/loch-sh/s3
```

### Docker Compose

Two Compose files are provided in the repository:

**`docker-compose.yml`** — single-user with Caddy as reverse proxy:

```bash
docker compose up
```

**`docker-compose.multiuser.yml`** — multi-user with Caddy:

```bash
docker compose -f docker-compose.multiuser.yml up
```

Both files mount a persistent volume for data and include Caddy for TLS termination.

### Local Image Build

```bash
make docker                  # Single-arch build
make docker-multiplatform    # Multi-arch build (without push)
make docker-push             # Multi-arch build + push to registry
```

---

## Environment Variables

All configuration is done via environment variables. No configuration file is required.

| Variable | Default | Description |
|----------|---------|-------------|
| `S3_PORT` | `8080` | Port the server listens on |
| `S3_DATA_DIR` | `./data` | Directory for storing objects |
| `S3_USERS_FILE` | _(none)_ | Path to the users JSON file — enables multi-user mode |
| `S3_ACCESS_KEY_ID` | _(none)_ | Access key for single-user mode (ignored if `S3_USERS_FILE` is set) |
| `S3_SECRET_ACCESS_KEY` | _(none)_ | Secret key for single-user mode (ignored if `S3_USERS_FILE` is set) |
| `S3_ADMIN_API_KEY` | _(none)_ | Bearer token for the `/_loch/users` administration API |
| `S3_UPLOAD_TTL` | `86400` | Multipart upload expiry in seconds (default: 24 hours) |
| `S3_ENCRYPTION_KEY` | _(none)_ | Base64-encoded SSE-S3 master key (exactly 32 bytes) |

**Notes:**

- `S3_ACCESS_KEY_ID` and `S3_SECRET_ACCESS_KEY` must be set together or not at all.
- `S3_ENCRYPTION_KEY` must be exactly 32 bytes (256 bits) encoded in base64. Generate with `openssl rand -base64 32`.
- `S3_ADMIN_API_KEY` only has effect in multi-user mode (`S3_USERS_FILE`). In single-user mode (environment variables), the admin API is disabled even if the key is set.

---

## Authentication Modes

The three modes are mutually exclusive and evaluated in the following priority order:

### 1. Multi-User — `S3_USERS_FILE`

Multiple users with individual credentials. Each user owns their buckets. Cross-user access is controlled by bucket policies.

- The root user has access to everything.
- The bucket owner has full access to their bucket.
- Other users only have access if a bucket policy explicitly grants it.
- The `/_loch/users` administration API is available if `S3_ADMIN_API_KEY` is configured.
- Buckets are private by default.

```bash
S3_USERS_FILE=/data/users.json \
S3_ADMIN_API_KEY=my-admin-key \
./target/release/s3
```

### 2. Single-User — `S3_ACCESS_KEY_ID` + `S3_SECRET_ACCESS_KEY`

A single root user. Backward-compatible mode for tools that expect a static credential pair.

```bash
S3_ACCESS_KEY_ID=myaccesskey \
S3_SECRET_ACCESS_KEY=mysecretkey \
./target/release/s3
```

### 3. Open Access — No Variables Configured

All requests are accepted without authentication. Suitable for local development only.

```bash
S3_PORT=9000 S3_DATA_DIR=/tmp/s3-data ./target/release/s3
```

---

## Auto-Bootstrap

When `S3_USERS_FILE` is set but the file does not yet exist, the server automatically creates a root user with random credentials on first start:

```
=============================================================
  Users file not found — bootstrapping with a new root user
  File:              /data/users.json
  Access Key ID:     EIWcQK7Dp5dub4Fy9B2m
  Secret Access Key: stored in the users file (cat /data/users.json)
=============================================================
```

The file is created with `0600` permissions (owner read/write only). The parent directory is created automatically if needed.

For automated deployments, you can create the file manually before the first start:

```json
{
  "users": [
    {
      "user_id": "root",
      "display_name": "Root",
      "access_key_id": "AKIAROOTKEY000000000",
      "secret_access_key": "MyRootSecretKey40CharactersMinimum",
      "is_root": true
    }
  ]
}
```

File constraints:
- Exactly one user with `"is_root": true`.
- All `user_id` and `access_key_id` values must be unique.
- No field may be empty.

Changes made via the administration API are persisted atomically to this file (written to a `.tmp` file then renamed). No restart is required.
