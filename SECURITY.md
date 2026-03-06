# Security Hardening

This document describes the security vulnerabilities that were identified during an audit and the mitigations applied.

## Vulnerabilities Fixed

### 1. Path Traversal (CWE-22) — CRITICAL

**Risk:** An attacker could use `../` sequences in bucket names or object keys to read/write files outside the `data/` directory.

**Mitigation:**
- `validate_bucket_name()` enforces S3 naming rules: 3-63 chars, `[a-z0-9.-]`, no `..` sequences
- `validate_object_key()` rejects null bytes, empty keys, and keys > 1024 bytes
- `safe_bucket_path()` validates the bucket name and verifies the resulting path is contained within `data_dir`
- `object_path()` uses `assert_path_within()` which rejects any `Component::ParentDir` (i.e. `..`) and verifies containment via `starts_with()`
- Does **not** use `canonicalize()` (which requires the path to exist), instead inspects path components directly

**Files:** `src/storage/mod.rs`

### 2. Symlink Attacks (CWE-59) — HIGH

**Risk:** A symlink placed inside `data/` could point to arbitrary filesystem locations, bypassing path containment checks.

**Mitigation:**
- `is_regular_file()` and `is_real_dir()` helpers use `tokio::fs::symlink_metadata()` which does **not** follow symlinks
- All file/directory existence checks throughout the codebase use these helpers instead of `.is_file()`, `.is_dir()`, or `.exists()` (which follow symlinks)
- `list_buckets` and `collect_keys` skip symlinks entirely
- Bucket creation uses `symlink_metadata` to detect pre-existing symlinks

**Files:** `src/storage/mod.rs`, `src/storage/bucket.rs`, `src/storage/object.rs`, `src/storage/multipart.rs`, `src/storage/policy.rs`, `src/storage/cors.rs`

### 3. GET Object Memory Exhaustion — HIGH

**Risk:** `get_object` loaded the entire file into memory via `fs::read()`, allowing a single large file download to exhaust server RAM.

**Mitigation:**
- Replaced `get_object()` (which returned `Vec<u8>`) with `get_object_meta()` (which returns metadata + file path)
- The handler opens the file and streams it using `tokio_util::io::ReaderStream` + `http_body_util::StreamBody`
- Memory usage is now O(buffer_size) regardless of file size

**Files:** `src/storage/object.rs`, `src/handlers/object.rs`

### 4. Unbounded Request Body Size (CWE-400) — HIGH

**Risk:** Policy, CORS, and multipart completion bodies were read entirely into memory with no size limit, enabling denial-of-service via oversized payloads.

**Mitigation:**
- `read_body_limited()` helper streams the body frame-by-frame and returns `EntityTooLarge` (HTTP 413) if the size exceeds the limit
- Limits applied:
  - Bucket policies: 20 KB
  - CORS configurations: 64 KB
  - CompleteMultipartUpload XML: 10 MB
- `max-keys` parameter for ListObjectsV2 is capped at 1000 (AWS spec maximum)
- `partNumber` for UploadPart is validated to be within 1-10000

**Files:** `src/handlers/mod.rs`, `src/handlers/policy.rs`, `src/handlers/cors.rs`, `src/handlers/multipart.rs`, `src/handlers/object.rs`, `src/router.rs`

### 5. SigV4 Timestamp Validation (CWE-287) — MODERATE

**Risk:** Signed requests had no expiry — a captured signature could be replayed indefinitely.

**Mitigation:**
- The `x-amz-date` header is parsed via `chrono::NaiveDateTime` and compared against server time
- Requests with a timestamp more than 15 minutes (900 seconds) from server time are rejected with `RequestTimeTooSkewed`

**Files:** `src/auth.rs`, `src/error.rs`

### 13. Presigned URL Invalid Auth Bypass (CWE-287) — MODERATE

**Risk:** A presigned URL with an invalid or tampered signature could fall through to the anonymous-access check (bucket policies / ACLs), potentially granting access to objects in public buckets without a valid signature.

**Mitigation:**
- `is_presigned_request()` detects query-string SigV4 auth (presence of `X-Amz-Algorithm` in the query)
- In `check_auth`, presigned requests that fail signature verification are denied immediately with no fallback to anonymous access checks — the `is_presigned` flag short-circuits before policy/ACL evaluation
- Expired presigned URLs return `ExpiredToken` (HTTP 403) rather than `AccessDenied`, to distinguish expiry from bad credentials

**Files:** `src/auth.rs`, `src/router.rs`, `src/error.rs`

### 6. Timing Attack on Signature Comparison (CWE-208) — MODERATE

**Risk:** Standard `==` comparison of signatures leaks timing information, potentially allowing an attacker to discover valid signatures byte-by-byte.

**Mitigation:**
- Signature comparison uses `subtle::ConstantTimeEq` (`ct_eq()`) which takes constant time regardless of where the first difference occurs
- Length is checked first to avoid length-based timing leaks

**Files:** `src/auth.rs`

### 7. TOCTOU Race Conditions (CWE-367) — MODERATE

**Risk:** Deterministic temp file names (e.g. `key.tmp`) created a window between file creation and rename where concurrent operations could interfere.

**Mitigation:**
- All temporary files now include a UUID v4 in their name: `{filename}.{uuid}.tmp`
- This eliminates collisions between concurrent uploads to the same key

**Files:** `src/storage/object.rs`, `src/storage/multipart.rs`

### 8. Input Validation (CWE-20) — MODERATE

**Risk:** Bucket names and object keys were not validated, allowing invalid names that could cause unexpected filesystem behavior.

**Mitigation:**
- `validate_bucket_name()`: enforces 3-63 characters, lowercase alphanumeric plus `.` and `-`, no `..` sequences, no leading/trailing `-` or `.`
- `validate_object_key()`: rejects empty keys, keys > 1024 bytes, and keys containing null bytes
- Part numbers validated to 1-10000 range (AWS spec)

**Files:** `src/storage/mod.rs`, `src/router.rs`

### 10. Directory Marker Sentinel Collision (CWE-706) — HIGH

**Risk:** S3 keys ending with `/` (directory marker objects) are stored internally as a `.dir_marker` sentinel file. An attacker could upload a key like `foo/.dir_marker` to collide with the internal sentinel for `foo/`, reading or overwriting the directory marker object.

**Mitigation:**
- `validate_object_key()` rejects any key where a path component equals `.dir_marker`
- The sentinel name is defined as a constant (`DIR_MARKER`) to ensure consistency between validation and storage logic

**Files:** `src/storage/mod.rs`

### 11. Internal State File Overwrite via Object Keys (CWE-706) — HIGH

**Risk:** Bucket state is stored in hidden dot-files at the root of each bucket directory (`.metadata`, `.meta`, `.policy.json`, `.cors.json`, `.encryption.json`, `.acl.xml`, `.acl`, `.uploads`, `.versions`, `.versioning.json`). An attacker could use these names as object keys to overwrite bucket configuration, ACLs, or encryption settings.

**Mitigation:**
- `validate_object_key()` rejects any key whose first path component matches an entry in `INTERNAL_NAMES`, returning `AccessDenied`
- Internal names in nested paths (e.g., `dir/.metadata`) are allowed since they reside in subdirectories and do not collide with bucket-level state files
- Internal names are excluded from `ListObjects` results and "bucket empty" checks via `INTERNAL_NAMES` filtering in `collect_keys()`

**Files:** `src/storage/mod.rs`, `src/storage/object.rs`

### 14. CopyObject Anonymous Source Authorization Bypass (CWE-862) — HIGH

**Risk:** The authentication check (`check_auth`) only evaluates the destination bucket/key. For `CopyObject` (PUT with `x-amz-copy-source`), if the destination bucket allows anonymous writes via bucket policy, an unauthenticated attacker could copy any private object into the world-writable bucket using `x-amz-copy-source`, effectively reading objects they have no access to.

**Mitigation:**
- In `router.rs`, when routing a CopyObject request that was granted anonymous access (auth failed but policy allowed), the source bucket/key is parsed from `x-amz-copy-source` and verified for anonymous GET access via `check_anonymous_access` + `check_acl_anonymous`
- If the source bucket does not allow anonymous GET, the request is denied with `403 AccessDenied` before calling the handler
- Authenticated requests (valid credentials) are unaffected — they retain access to all buckets they are authorized for

**Files:** `src/router.rs`

### 15. Integer Overflow in aws-chunked Decoder (CWE-190) — MEDIUM

**Risk:** The `decode_aws_chunked` function parses a hex chunk size and then computes `pos + chunk_size`. On a 64-bit target in release mode (where integer overflow wraps silently), a malicious chunk size of `usize::MAX` would cause `pos + chunk_size` to wrap to a value smaller than `pos`. The subsequent slice `data[pos..end]` with `end < pos` would then **panic**, crashing the active server task.

**Mitigation:**
- `pos.saturating_add(chunk_size)` is used instead of plain `+`, capping the result at `usize::MAX` rather than wrapping
- The terminal `pos = end + 2` advance also uses `saturating_add` for consistency
- Combined with the `.min(data.len())` clamp, `end >= pos` is always guaranteed

**Files:** `src/storage/object.rs`

### 16. Unbounded User Metadata (CWE-400) — LOW

**Risk:** `x-amz-meta-*` headers were accepted without any size limit. An authenticated client could send megabytes of per-object metadata, consuming unbounded disk space and inflating every subsequent HEAD/GET response.

**Mitigation:**
- `extract_metadata()` now accumulates the total byte length of all metadata keys and values
- If the total exceeds **2 048 bytes** (matching the AWS S3 limit), the function returns `S3Error::EntityTooLarge` (HTTP 413)
- Both `PutObject` and `CopyObject` (with `x-amz-metadata-directive: REPLACE`) propagate this error to the client

**Files:** `src/handlers/object.rs`

### 12. Sidecar File Cleanup on Object Deletion — MODERATE

**Risk:** When an object was deleted, its associated sidecar files (ACL in `.acl/{key}.xml`, metadata in `.meta/{key}.json`) were not systematically cleaned up, leaving orphan files on disk. In versioned buckets, deleting all versions of an object also left sidecar files behind.

**Mitigation:**
- `delete_object()` now calls both `delete_object_metadata()` and `delete_object_acl()` to clean up sidecar files
- `sync_normal_path()` (called after deleting a specific version) also cleans up both metadata and ACL when no data version remains
- Empty parent directories within `.meta/` and `.acl/` are cleaned up recursively after file removal

**Files:** `src/storage/acl.rs`, `src/storage/object.rs`, `src/storage/versioning.rs`

### 9. CORS Header Parsing Panics — LOW

**Risk:** `.parse().unwrap()` on user-supplied Origin header values in CORS response handling could panic if the value contained invalid HTTP header characters.

**Mitigation:**
- Replaced all `.parse().unwrap()` calls with `HeaderValue::from_str()` with proper error handling
- Invalid header values are silently skipped instead of crashing the server
- Static header values use `HeaderValue::from_static()` which is infallible
- Extracted into a reusable `add_cors_to_response()` helper to eliminate duplication

**Files:** `src/router.rs`

## Presigned URLs

Presigned URLs embed SigV4 authentication in the query string, enabling time-limited access to specific objects without requiring the caller to have AWS credentials.

### How It Works

A presigned URL includes the following query parameters, all of which are covered by the signature:

| Parameter | Description |
|-----------|-------------|
| `X-Amz-Algorithm` | Always `AWS4-HMAC-SHA256` |
| `X-Amz-Credential` | `ACCESS_KEY/DATE/REGION/s3/aws4_request` (URL-encoded) |
| `X-Amz-Date` | Signing timestamp (`YYYYMMDDTHHmmSSZ`) |
| `X-Amz-Expires` | Validity duration in seconds |
| `X-Amz-SignedHeaders` | Semicolon-separated list of signed headers (must include `host`) |
| `X-Amz-Signature` | HMAC-SHA256 of the canonical request |

The signature covers the HTTP method, URL path, all query parameters (except `X-Amz-Signature` itself), and the signed headers. Tampering with any parameter invalidates the signature.

### Security Properties

- **Method binding**: The HTTP method is part of the signed canonical request. A presigned `GET` cannot be reused as a `PUT` or `DELETE`.
- **Expiry**: The server rejects URLs whose `X-Amz-Date + X-Amz-Expires` is in the past (`ExpiredToken`, HTTP 403). Expiry is enforced server-side regardless of when the URL was generated.
- **No anonymous fallback**: A presigned URL with an invalid or expired signature is immediately rejected with no fallback to bucket policy or ACL anonymous access.
- **Constant-time comparison**: The signature comparison uses `subtle::ConstantTimeEq` to prevent timing attacks.
- **Path binding**: The signed path prevents a presigned URL for one object from being used to access another.

### Expiry Bounds

`X-Amz-Expires` is validated server-side: values of `0` or greater than `604 800` seconds (7 days) are rejected with `403 AccessDenied`, matching AWS S3 behavior.

### Generate a presigned URL

Presigned URLs can be generated by any AWS-compatible client. Example using the AWS CLI:

```bash
# Presigned GET valid for 1 hour
aws --endpoint-url http://localhost:8080 s3 presign s3://my-bucket/myfile.txt --expires-in 3600
```

The generated URL can be used without any AWS credentials:

```bash
curl "http://localhost:8080/my-bucket/myfile.txt?X-Amz-Algorithm=...&X-Amz-Signature=..."
```

---

## Server-Side Encryption (SSE)

Loch S3 supports server-side encryption to protect data at rest. Two modes are available.

### SSE-S3: Server-Managed Keys

**Configuration:** Set `S3_ENCRYPTION_KEY` to a base64-encoded 32-byte master key.

```bash
export S3_ENCRYPTION_KEY=$(openssl rand -base64 32)
```

**Key derivation:** The master key is never used directly. A unique data encryption key is derived per object using **HKDF-SHA256** with a random 32-byte salt and the info string `loch-s3-sse-s3`. This ensures that compromising one object does not help decrypt others.

**Request headers:** `x-amz-server-side-encryption: AES256` on PUT. Decryption on GET/HEAD is transparent.

### SSE-C: Customer-Provided Keys

No server-side configuration required. The client provides a 256-bit AES key with each PUT and GET/HEAD request.

**Request headers:**
- `x-amz-server-side-encryption-customer-algorithm: AES256`
- `x-amz-server-side-encryption-customer-key: <base64-key>`
- `x-amz-server-side-encryption-customer-key-md5: <base64-md5>`

The key itself is **never stored** on disk. Only its MD5 is persisted for verification.

### Encryption Algorithm

All encryption uses **AES-256-GCM** (authenticated encryption). Objects are encrypted in chunks of 1 MiB:

- A random 96-bit base nonce is generated per object
- Chunk `i` uses nonce `base_nonce XOR i` (deterministic, no per-chunk nonce storage)
- Each chunk produces `plaintext_size + 16` bytes (16-byte GCM authentication tag)
- This supports streaming encryption/decryption without loading the entire file into memory

### Bucket Default Encryption

Buckets can be configured with a default encryption policy via `PUT /{bucket}?encryption`. When set, objects uploaded without explicit encryption headers will automatically use SSE-S3 (AES256).

- **Configuration API:** `PUT`, `GET`, `DELETE` on `/{bucket}?encryption` with `ServerSideEncryptionConfiguration` XML body
- **Algorithm validation:** only `AES256` is accepted; other values return `InvalidArgument`
- **Automatic application:** `PutObject` and `CreateMultipartUpload` check for bucket default encryption when no SSE headers are present
- **Requires master key:** bucket default encryption has no effect if `S3_ENCRYPTION_KEY` is not configured (objects are stored in plaintext)
- **Storage:** configuration is stored as `.encryption.json` inside the bucket directory

### Ciphertext Layout

```
[chunk_0_ciphertext + tag_0][chunk_1_ciphertext + tag_1]...[chunk_N_ciphertext + tag_N]
```

### ETag Handling

The ETag of an encrypted object is the **MD5 of the plaintext**, computed during the initial streaming write (before encryption) and stored in the metadata sidecar. This is consistent across PUT, GET, and HEAD.

### Multipart Uploads

Parts are stored as plaintext in `.uploads/`. Encryption happens at `CompleteMultipartUpload` time, after assembly. For SSE-C, the key must be provided at both `UploadPart` (validation) and `CompleteMultipartUpload` (encryption).

### CopyObject

All source/destination encryption combinations are supported. SSE-S3 sources are decrypted transparently. SSE-C sources require `x-amz-copy-source-server-side-encryption-customer-*` headers. The destination can independently request SSE-S3 or SSE-C.

### Versioning

Each version stores its own encryption parameters. Different versions of the same object can use different encryption modes. Encryption metadata is preserved through delete marker removal and version restoration.

### What Is Stored on Disk

| Data | Location | Encrypted? |
|------|----------|------------|
| Object data | `{bucket}/{key}` | Yes (ciphertext) |
| Encryption params | `.meta/{key}.json` | No (nonce, salt, algorithm, plaintext size) |
| Customer key | *(nowhere)* | Never stored, only MD5 |
| Master key | Environment variable | Not persisted by the server |
| In-progress multipart parts | `.uploads/{id}/{part}` | No (plaintext, encrypted at completion) |

### Error Cases

| Scenario | HTTP Status | Error Code |
|----------|-------------|------------|
| GET/HEAD SSE-C object without key | 400 | `MissingSecurityHeader` |
| GET/HEAD SSE-C object with wrong key | 403 | `AccessDenied` |
| Invalid algorithm (not `AES256`) | 400 | `InvalidEncryptionAlgorithmError` |
| Key MD5 does not match | 400 | `InvalidArgument` |
| SSE-S3 without `S3_ENCRYPTION_KEY` | 400 | `ServerSideEncryptionConfigurationNotFoundError` |
| Both `x-amz-server-side-encryption` and SSE-C headers | 400 | `InvalidArgument` |

### Recommendations

- **Protect the master key.** If `S3_ENCRYPTION_KEY` is lost, SSE-S3 objects cannot be decrypted.
- **Use HTTPS in production.** SSE protects data at rest; use a TLS reverse proxy (Caddy, Nginx) for data in transit.
- **Enable authentication.** Without credentials, SSE-C keys are sent in plaintext over HTTP.

**Files:** `src/encryption.rs`, `src/handlers/object.rs`, `src/handlers/multipart.rs`, `src/storage/object.rs`, `src/storage/multipart.rs`, `src/storage/versioning.rs`

## Security Audit Log

### 2026-03-06 — Dependency CVE Scan

Tool: `cargo-audit v0.22.1` against RustSec advisory database (946 advisories).

**Result: 0 vulnerabilities in 251 crate dependencies.**

All direct and transitive dependencies are free of known CVEs as of this date.

### 2026-03-06 — Code Audit Findings

| Finding | Severity | Status |
|---------|----------|--------|
| Presigned URL invalid-auth bypass (CWE-287) | Moderate | Fixed — §13 above |
| `aws_chunked` upload buffered in memory | Low | Known — chunked-encoded bodies are buffered in full before streaming to disk; only affects AWS SDK streaming uploads. Mitigated by OS-level connection limits. |
| `aws_chunked` chunk-size integer overflow → panic (CWE-190) | Medium | Fixed — §15 above (`saturating_add`) |
| CopyObject anonymous source authorization bypass (CWE-862) | High | Fixed — §14 above (source bucket policy/ACL check for anonymous requests) |
| Unbounded user metadata (CWE-400) | Low | Fixed — §16 above (2 048-byte limit, returns 413) |
| `ListObjects` ETag/size discrepancy for encrypted objects | Informational | Known — `ListObjects` reports ciphertext size and MD5; `HeadObject` / `GetObject` report plaintext size and plaintext MD5. Correctness gap, not a security issue. |
| `X-Amz-Expires` has no server-side upper bound | Low | Fixed — values `0` or `> 604 800 s` are rejected with 403 (`MAX_PRESIGNED_EXPIRES_SECS` in `src/auth.rs`). |

---

## Dependencies Added

| Crate | Version | Purpose |
|-------|---------|---------|
| `subtle` | 2 | Constant-time byte comparison for signature verification |
| `tokio-util` | 0.7 (feature `io`) | `ReaderStream` for streaming GET responses |
| `futures-util` | 0.3 | `TryStreamExt::map_ok()` for stream frame mapping |
| `aes-gcm` | 0.10 | AES-256-GCM authenticated encryption |
| `hkdf` | 0.12 | HKDF-SHA256 key derivation for SSE-S3 |
| `base64` | 0.22 | Base64 encoding/decoding for keys and nonces |
| `rand` | 0.8 | Cryptographic random number generation (nonces, salts) |
