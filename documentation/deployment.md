# Managed and Hardened Deployment

This page describes how to run Loch S3 as a managed service (one container per tenant), with a read-only root filesystem, a fixed unprivileged user, a storage quota and a health probe. The behaviors below are covered by the integration tests; figures marked "measured" come from manual runs of the 1.3.0 image (Docker Desktop, aws-cli 2.34).

## Table of Contents

- [Container Image](#container-image)
- [Read-Only Root Filesystem and Mounts](#read-only-root-filesystem-and-mounts)
- [Read-Only Users File](#read-only-users-file)
- [Initial Buckets](#initial-buckets)
- [Storage Quota](#storage-quota)
- [Health and Usage Endpoints](#health-and-usage-endpoints)
- [Shutdown Behavior](#shutdown-behavior)
- [Limits and Sizes](#limits-and-sizes)
- [Resource Usage](#resource-usage)
- [Client Compatibility](#client-compatibility)

---

## Container Image

| Item | Value |
|------|-------|
| Image | `ghcr.io/loch-sh/s3:<version>` (multi-arch `linux/amd64`, `linux/arm64`) |
| Base images | `mirror.gcr.io/library/rust:1.97.1-alpine3.24` (build), `mirror.gcr.io/library/alpine:3.24.3` (runtime), pinned by digest |
| User | `10001:10001` (numeric, fixed). Any other uid works too (`--user`), as long as it can write `S3_DATA_DIR` |
| Port | `8080` (`S3_PORT`) |
| Data | `/data` (`S3_DATA_DIR`), declared as a volume |
| Healthcheck | Built in: `wget -q -O /dev/null http://127.0.0.1:${S3_PORT}/_loch/health` every 30 s |

To upgrade a base image, bump its tag in the `Dockerfile`, then refresh the digest with `docker buildx imagetools inspect mirror.gcr.io/library/<image>:<tag>`.

---

## Read-Only Root Filesystem and Mounts

The server only writes to `S3_DATA_DIR`. It runs with:

```bash
docker run -d \
  --read-only --tmpfs /tmp:size=16m \
  --cap-drop ALL --security-opt no-new-privileges \
  --user 10001:10001 \
  --memory 128m --cpus 0.5 --pids-limit 64 \
  -v /srv/tenant-a/data:/data \
  -v /srv/tenant-a/conf:/etc/s3:ro \
  -e S3_USERS_FILE=/etc/s3/users.json \
  -e S3_MAX_STORAGE_BYTES=10737418240 \
  -e S3_INIT_BUCKETS=media,backups \
  -p 127.0.0.1:8080:8080 \
  ghcr.io/loch-sh/s3:<version>
```

Docker Compose equivalent:

```yaml
services:
  s3:
    image: ghcr.io/loch-sh/s3:<version>
    read_only: true
    tmpfs: ["/tmp:size=16m"]
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    user: "10001:10001"
    mem_limit: 128m
    cpus: 0.5
    pids_limit: 64
    environment:
      S3_USERS_FILE: /etc/s3/users.json
      S3_MAX_STORAGE_BYTES: "10737418240"
      S3_INIT_BUCKETS: media,backups
    volumes:
      - /srv/tenant-a/data:/data
      - /srv/tenant-a/conf:/etc/s3:ro
    ports: ["127.0.0.1:8080:8080"]
```

| Mount | Mode | Owner | Notes |
|-------|------|-------|-------|
| `/data` | read-write | container uid | Only writable path. Must be owned by (or writable for) the container uid, and be a single filesystem: temporary files are written to `/data/.loch-tmp/` and renamed into buckets |
| users file (directory or file) | read-only | container uid, file mode `0400` | Never written when `S3_ADMIN_API_KEY` is unset |
| `/tmp` | tmpfs (optional) | — | Not used by the server; harmless to provide |

Tested: read-only root filesystem, `cap_drop: ALL`, `no-new-privileges`, uid `10001` (image default) and an arbitrary uid via `--user`, users file `0400` in a `0555` directory mounted read-only, memory/CPU/PID limits.

---

## Read-Only Users File

With `S3_USERS_FILE` set and **no** `S3_ADMIN_API_KEY`:

- the file is read once at startup and **never written** (no migration, no rewrite); `/_loch/users` returns `403 AccessDenied`; the startup log reads `User management API: disabled`;
- a `0400` file owned by the container uid is accepted (only read access is needed);
- if the file does not exist, the server tries to bootstrap it (create a root user). In a read-only directory this fails and the **process exits with status 1**: it never starts with open access or with an in-memory root account;
- an invalid file (bad JSON, no root user, duplicate keys) also exits with status 1;
- non-root users can be listed in the same file, for example a read-only key on one bucket, granted through a bucket policy with the principal `arn:loch:iam:::user/<user_id>`. Changes to the file take effect on restart.

Example with a root account and a read-only user:

```json
{
  "users": [
    {"user_id": "root", "display_name": "Root", "access_key_id": "AKIA...", "secret_access_key": "...", "is_root": true},
    {"user_id": "reader", "display_name": "Reader", "access_key_id": "AKIB...", "secret_access_key": "..."}
  ]
}
```

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:loch:iam:::user/reader"},
    "Action": ["s3:GetObject", "s3:ListBucket"],
    "Resource": ["arn:loch:s3:::media", "arn:loch:s3:::media/*"]
  }]
}
```

---

## Initial Buckets

`S3_INIT_BUCKETS=a,b,c` creates the listed buckets at startup when they do not exist:

- owned by the root user of the users file (no owner in open or single-user mode);
- idempotent: an existing bucket is left untouched (owner, contents and settings unchanged);
- names are validated like `CreateBucket` (3–63 characters, lowercase letters, digits, `-` and `.`); an invalid name makes the **process exit with status 1**. Spaces around names and duplicates are ignored.

---

## Storage Quota

`S3_MAX_STORAGE_BYTES` (bytes, unset or empty = unlimited) caps the total size of `S3_DATA_DIR`: objects, object versions, multipart parts in progress and internal metadata files.

| Operation | Behavior |
|-----------|----------|
| PutObject | The declared size (`Content-Length`, or `x-amz-decoded-content-length` for aws-chunked) is reserved before reading the body; the body is then reserved chunk by chunk. The upload stops as soon as the quota would be crossed |
| UploadPart | Same as PutObject. Parts count toward the quota while the upload is in progress |
| CompleteMultipartUpload | Space-neutral (parts are already counted, the upload directory is removed). Refused only if usage is already above the limit (e.g. the limit was lowered) |
| CopyObject | The source size is reserved before copying |
| Versioned buckets | Writes reserve twice the size (current copy + version) |
| Overwrite | Needs room for the new object before the old one is released (both exist on disk until the atomic rename) |
| Delete, abort, expiry | Space is released immediately (versioned deletes are reconciled by a background recount within a second) |
| Quota already exceeded | Every write is refused, including empty objects and CreateMultipartUpload; deletes still work |

Refusals use the error code `QuotaExceeded` with HTTP status **403** (same code as Ceph RGW). A 403 is not retried by AWS SDKs, unlike a 5xx. When the upload is refused mid-stream, the server answers and closes the connection; some clients report a connection reset instead of the 403.

Accounting: usage is computed once at startup (one walk of the data directory) and kept in memory. All reservations go through a single lock, so concurrent uploads cannot exceed the quota together. A background recount runs every 5 minutes, and shortly after operations whose exact size delta is not tracked (versioned writes/deletes, bucket deletion), to reconcile small files (metadata sidecars, ACLs, encryption tags of 16 bytes per MiB). Sizes are apparent file sizes, not disk blocks. Concurrent overwrites and deletes of the same key are serialized for accounting, so the counter stays exact. A write committed while a recount walks the directory may be counted twice until the next recount (the counter errs on the side of refusing, never of exceeding). Temporary files of writes in progress (`/data/.loch-tmp/`) are covered by reservations and excluded from the recount; while a multipart upload is completed or an object is encrypted, the disk briefly holds a second copy that the quota does not count.

Reservations are held while a body is being received: an upload that sends no data for 60 seconds is aborted with `400 RequestTimeout` and releases its reservation. HTTP/1 request headers must arrive within 30 seconds.

---

## Health and Usage Endpoints

### `GET /_loch/health` (no authentication)

| Situation | Status | Body |
|-----------|--------|------|
| Healthy, no quota configured | `200` | `{"status":"ok"}` |
| Healthy, quota configured | `200` | `{"status":"ok","quota":"ok"}` or `{"status":"ok","quota":"exceeded"}` |
| Data directory unreachable | `503` | `{"status":"error"}` (plus `quota` when configured) |

`HEAD` is supported (same status, no body). No secret, bucket name, user name or figure is returned. Health requests are not logged. Busybox compatible:

```bash
wget -q -O /dev/null http://127.0.0.1:8080/_loch/health
```

### `GET /_loch/usage` (root only)

Signed with SigV4 by the root user (open access when no credentials are configured). Non-root users get `403 AccessDenied`.

```bash
curl --aws-sigv4 "aws:amz:us-east-1:s3" -u "$ROOT_KEY:$ROOT_SECRET" http://127.0.0.1:8080/_loch/usage
# {"used_bytes":25000106,"reserved_bytes":0,"limit_bytes":104857600}
```

`limit_bytes` is `null` when unlimited; `reserved_bytes` is held by uploads in progress.

---

## Shutdown Behavior

On `SIGTERM` (container stop) or `SIGINT`, the server stops accepting connections and lets in-flight requests finish for up to `S3_SHUTDOWN_GRACE` seconds (default `8`, below Docker's default 10 s stop timeout), then exits.

- An upload still running at that point is aborted: the object is not created (writes go to a temporary file renamed only on success).
- Its temporary file is left in `/data/.loch-tmp/` and removed at the next startup (`Removed N stale temporary file(s)` in the log). Temporary files are never counted in the quota.
- Objects whose key ends in `.tmp` are ordinary objects: they are listed, counted and never removed by this cleanup. Upgrading from 1.2 or earlier: those versions wrote temporary files next to the object (`{name}.{uuid}.tmp`); a leftover from a crash now shows up as an object of that name and can be deleted like any object.

---

## Limits and Sizes

| Item | Limit |
|------|-------|
| Request headers (HTTP/1) | Must be received within 30 s |
| Upload body | Aborted after 60 s without data (`400 RequestTimeout`) |
| Object size (PutObject, UploadPart) | No server limit other than the quota and disk space; the body is streamed to disk |
| Multipart upload | Parts are numbered by the client; no server limit on part size or count; parts expire after `S3_UPLOAD_TTL` (default 24 h) |
| XML/JSON request bodies | Read in memory with a per-endpoint limit: bucket policy 20 KiB; CORS, ACL, encryption and versioning configurations 64 KiB; `CompleteMultipartUpload` 10 MB. Beyond: `413 EntityTooLarge` |
| User metadata (`x-amz-meta-*`) | 2 048 bytes in total (AWS limit), `EntityTooLarge` (413) beyond |
| Object key | 1 024 bytes |
| aws-chunked chunk header line | 4 096 bytes |
| Presigned URL expiry | 1 s to 7 days |

---

## Resource Usage

Measured (1.3.0 image, container limited to 128 MiB / 0.5 CPU):

- memory at rest: about 3–4 MiB; during a 25 MB multipart upload and parallel ranged download with aws-cli, a few MiB (bodies are streamed, including aws-chunked bodies, which are decoded on the fly);
- threads: tokio worker threads (one per available CPU) plus a blocking pool for file I/O capped by `S3_MAX_BLOCKING_THREADS` (default `32`, tokio's default is 512). Keep the PID limit above `S3_MAX_BLOCKING_THREADS` plus the number of CPUs plus a few.

---

## Client Compatibility

- **Region**: any region is accepted. SigV4 signatures are verified with the region given by the client in its credential scope; `us-east-1` is a good default to show to users.
- **CreateBucket**: the optional `CreateBucketConfiguration` body (`LocationConstraint`) is accepted and ignored.
- **aws-chunked uploads with trailing checksums** (the default of recent AWS SDKs and aws-cli 2.23+: `STREAMING-UNSIGNED-PAYLOAD-TRAILER` with `x-amz-checksum-crc32`/`crc64nvme`): the body is decoded on the fly and stored correctly; trailing checksums and chunk signatures are **not verified**, and `x-amz-content-sha256` is not compared with the body. The stored ETag is the MD5 of the decoded payload. A body without its final zero-size chunk, or with malformed framing, is rejected with `400 InvalidArgument`.
- **Range requests**: `GetObject` (current object or `versionId`) supports `Range: bytes=a-b`, `bytes=a-` and `bytes=-n`, with `206 Partial Content`, `Content-Range` and `Accept-Ranges: bytes`. Unsatisfiable ranges return `416 InvalidRange`. Malformed or multi-range headers are ignored (full object, like S3). Encrypted objects (SSE-S3, SSE-C) only decrypt the 1 MiB chunks covering the range. `HEAD` ignores `Range`. `partNumber` on GET is not supported.
- Tested with aws-cli 2.34 (put, multipart, parallel ranged download, `--range`).
