# API Reference

## Table of Contents

- [S3 Endpoints](#s3-endpoints)
- [Administration API — User Management](#administration-api--user-management)
- [Bucket Policies](#bucket-policies)
- [CORS Configuration](#cors-configuration)
- [Server-Side Encryption](#server-side-encryption)
- [Versioning](#versioning)
- [ACLs](#acls)
- [Multipart Upload](#multipart-upload)

---

## S3 Endpoints

All S3 endpoints use AWS Signature V4 authentication when the server is configured with credentials. Only path-style URLs are supported (no virtual-hosted style).

### Buckets

| Operation | Method | Path |
|-----------|--------|------|
| ListBuckets | `GET` | `/` |
| CreateBucket | `PUT` | `/{bucket}` |
| HeadBucket | `HEAD` | `/{bucket}` |
| DeleteBucket | `DELETE` | `/{bucket}` |
| GetBucketLocation | `GET` | `/{bucket}?location` |

### Objects

| Operation | Method | Path |
|-----------|--------|------|
| ListObjectsV2 | `GET` | `/{bucket}?list-type=2` |
| PutObject | `PUT` | `/{bucket}/{key}` |
| GetObject | `GET` | `/{bucket}/{key}` |
| HeadObject | `HEAD` | `/{bucket}/{key}` |
| DeleteObject | `DELETE` | `/{bucket}/{key}` |
| CopyObject | `PUT` | `/{bucket}/{key}` + `x-amz-copy-source` header |
| GetObject (presigned) | `GET` | `/{bucket}/{key}?X-Amz-Algorithm=...` |
| PutObject (presigned) | `PUT` | `/{bucket}/{key}?X-Amz-Algorithm=...` |

### Multipart Upload

| Operation | Method | Path |
|-----------|--------|------|
| CreateMultipartUpload | `POST` | `/{bucket}/{key}?uploads` |
| UploadPart | `PUT` | `/{bucket}/{key}?partNumber=N&uploadId=X` |
| CompleteMultipartUpload | `POST` | `/{bucket}/{key}?uploadId=X` |
| AbortMultipartUpload | `DELETE` | `/{bucket}/{key}?uploadId=X` |
| ListParts | `GET` | `/{bucket}/{key}?uploadId=X` |
| ListMultipartUploads | `GET` | `/{bucket}?uploads` |

### Versioning

| Operation | Method | Path |
|-----------|--------|------|
| PutBucketVersioning | `PUT` | `/{bucket}?versioning` |
| GetBucketVersioning | `GET` | `/{bucket}?versioning` |
| ListObjectVersions | `GET` | `/{bucket}?versions` |
| GetObject (versioned) | `GET` | `/{bucket}/{key}?versionId=X` |
| HeadObject (versioned) | `HEAD` | `/{bucket}/{key}?versionId=X` |
| DeleteObject (versioned) | `DELETE` | `/{bucket}/{key}?versionId=X` |

### Policies, CORS, ACLs, Encryption

| Operation | Method | Path |
|-----------|--------|------|
| PutBucketPolicy | `PUT` | `/{bucket}?policy` |
| GetBucketPolicy | `GET` | `/{bucket}?policy` |
| DeleteBucketPolicy | `DELETE` | `/{bucket}?policy` |
| PutBucketCors | `PUT` | `/{bucket}?cors` |
| GetBucketCors | `GET` | `/{bucket}?cors` |
| DeleteBucketCors | `DELETE` | `/{bucket}?cors` |
| OPTIONS (CORS preflight) | `OPTIONS` | `/{bucket}/{key}` |
| GetBucketAcl | `GET` | `/{bucket}?acl` |
| PutBucketAcl | `PUT` | `/{bucket}?acl` |
| GetObjectAcl | `GET` | `/{bucket}/{key}?acl` |
| PutObjectAcl | `PUT` | `/{bucket}/{key}?acl` |
| PutBucketEncryption | `PUT` | `/{bucket}?encryption` |
| GetBucketEncryption | `GET` | `/{bucket}?encryption` |
| DeleteBucketEncryption | `DELETE` | `/{bucket}?encryption` |

---

## Administration API — User Management

Available only in multi-user mode (`S3_USERS_FILE` configured). Protected by a Bearer token (`S3_ADMIN_API_KEY`).

All requests must include the header:

```
Authorization: Bearer <S3_ADMIN_API_KEY>
```

Token comparison is performed in constant time to prevent timing attacks.

### Endpoints

| Operation | Method | Path | Description |
|-----------|--------|------|-------------|
| ListUsers | `GET` | `/_loch/users` | List all users |
| GetUser | `GET` | `/_loch/users/{user_id}` | Get a specific user |
| CreateOrUpdateUser | `PUT` | `/_loch/users/{user_id}` | Create or update a user |
| DeleteUser | `DELETE` | `/_loch/users/{user_id}` | Delete a user |

**`user_id` constraints:** 1 to 128 characters, alphanumeric, hyphens (`-`) and underscores (`_`) only.

### List All Users

```bash
curl -H "Authorization: Bearer my-admin-key" \
  http://localhost:8080/_loch/users
```

Response (HTTP 200):

```json
{
  "users": [
    {
      "user_id": "root",
      "display_name": "Root",
      "access_key_id": "EIWcQK7Dp5dub4Fy9B2m",
      "is_root": true
    },
    {
      "user_id": "alice",
      "display_name": "Alice",
      "access_key_id": "AKIAALICE00000000",
      "is_root": false
    }
  ]
}
```

### Get a Specific User

```bash
curl -H "Authorization: Bearer my-admin-key" \
  http://localhost:8080/_loch/users/alice
```

Response (HTTP 200):

```json
{
  "user_id": "alice",
  "display_name": "Alice",
  "access_key_id": "AKIAALICE00000000",
  "is_root": false
}
```

The `secret_access_key` is never returned. It is write-only.

### Create a User

```bash
curl -X PUT \
  -H "Authorization: Bearer my-admin-key" \
  -H "Content-Type: application/json" \
  -d '{"display_name": "Alice", "access_key_id": "AKIAALICE00000000", "secret_access_key": "AliceSecretKey40CharactersMinimum"}' \
  http://localhost:8080/_loch/users/alice
```

Response:
- HTTP 201 if the user was created.
- HTTP 200 if the user already existed and was updated.
- Empty body in both cases.

**Rules:**
- `is_root` cannot be set via the API (ignored in the request body). Only the JSON file can define the root user.
- The root user cannot be modified via the API.
- The `access_key_id` must be unique across all users.

### Update a User

Identical to creation. Use `PUT` on `/_loch/users/{user_id}`. All fields (`display_name`, `access_key_id`, `secret_access_key`) are replaced.

### Delete a User

```bash
curl -X DELETE \
  -H "Authorization: Bearer my-admin-key" \
  http://localhost:8080/_loch/users/alice
```

Response: HTTP 204 (empty body). The root user cannot be deleted.

### Error Codes

Errors are returned as JSON with a `message` field:

```json
{"message": "User 'alice' not found"}
```

| HTTP | Situation |
|------|-----------|
| 400 | Invalid JSON body, invalid user_id, validation constraint |
| 403 | Missing or incorrect Bearer token, API disabled |
| 405 | Single-user mode (env vars) — API not available |

---

## Bucket Policies

Bucket policies use the standard AWS IAM JSON format. They control anonymous access and per-user access.

### Policy Document Format

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "OptionalStatementName",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:loch:s3:::my-bucket/*"
    }
  ]
}
```

**Accepted versions:** `2012-10-17` and `2008-10-17`.

### Supported Actions

| Action | Description |
|--------|-------------|
| `s3:GetObject` | Download an object |
| `s3:PutObject` | Upload an object |
| `s3:DeleteObject` | Delete an object |
| `s3:ListBucket` | List objects in a bucket |
| `s3:GetBucketLocation` | Get the bucket region |
| `s3:*` | All of the above actions |

### ARN Format

| Resource | ARN Format |
|----------|-----------|
| Bucket | `arn:loch:s3:::my-bucket` |
| All objects in a bucket | `arn:loch:s3:::my-bucket/*` |
| Objects under a prefix | `arn:loch:s3:::my-bucket/public/*` |
| Total wildcard | `*` |
| User | `arn:loch:iam:::user/{user_id}` |

`arn:aws:s3:::` ARNs are accepted as aliases for `arn:loch:s3:::` for compatibility with AWS tooling.

### Principal

| Value | Meaning |
|-------|---------|
| `"*"` | Anonymous (public) access |
| `{"AWS": "arn:loch:iam:::user/alice"}` | Specific user |
| `{"AWS": ["arn:loch:iam:::user/alice", "arn:loch:iam:::user/bob"]}` | Multiple users |

### Evaluation Rules

- An explicit `Deny` always takes precedence over an `Allow`.
- Without a policy, buckets are private by default (when authentication is enabled).
- The bucket owner and the root user always have access, regardless of the policy.

### Put a Policy

```bash
curl -X PUT \
  -H "Authorization: <sigv4>" \
  -H "Content-Type: application/json" \
  --data-binary @policy.json \
  http://localhost:8080/my-bucket?policy
```

The request body must be a valid policy document as described above. For CLI-based policy examples (public read, per-user access, explicit deny), see [aws-cli.md — Bucket Policies](./aws-cli.md#bucket-policies).

### Get and Delete a Policy

```bash
# Read the current policy
curl -H "Authorization: <sigv4>" \
  http://localhost:8080/my-bucket?policy

# Delete the policy
curl -X DELETE \
  -H "Authorization: <sigv4>" \
  http://localhost:8080/my-bucket?policy
```

---

## CORS Configuration

CORS allows browsers to make cross-origin requests to the server.

### CORS Configuration Document Format

The request body for `PutBucketCors` is an XML document:

```xml
<CORSConfiguration>
  <CORSRule>
    <AllowedOrigin>https://example.com</AllowedOrigin>
    <AllowedMethod>GET</AllowedMethod>
    <AllowedMethod>PUT</AllowedMethod>
    <AllowedMethod>DELETE</AllowedMethod>
    <AllowedHeader>*</AllowedHeader>
    <ExposeHeader>ETag</ExposeHeader>
    <MaxAgeSeconds>3600</MaxAgeSeconds>
  </CORSRule>
</CORSConfiguration>
```

### CORS Rule Fields

| Field | Required | Description |
|-------|----------|-------------|
| `AllowedOrigins` | Yes | Allowed origins. `"*"` for any. Supports wildcards (`https://*.example.com`). |
| `AllowedMethods` | Yes | Allowed HTTP methods (`GET`, `PUT`, `POST`, `DELETE`, `HEAD`). |
| `AllowedHeaders` | No | Headers allowed in the request. `"*"` for any. |
| `ExposeHeaders` | No | Headers exposed in the response to the browser. |
| `MaxAgeSeconds` | No | How long the browser may cache the preflight result. |

Multiple rules can be defined. The first rule matching the origin and method is applied.

### Put, Get, and Delete CORS Configuration

```bash
# Put
curl -X PUT \
  -H "Authorization: <sigv4>" \
  -H "Content-Type: application/xml" \
  --data-binary @cors.xml \
  http://localhost:8080/my-bucket?cors

# Get
curl -H "Authorization: <sigv4>" \
  http://localhost:8080/my-bucket?cors

# Delete
curl -X DELETE \
  -H "Authorization: <sigv4>" \
  http://localhost:8080/my-bucket?cors
```

For CLI-based CORS examples, see [aws-cli.md — CORS](./aws-cli.md#cors).

---

## Server-Side Encryption

Loch S3 supports two encryption modes: SSE-S3 (server-managed key) and SSE-C (customer-provided key). Both use AES-256-GCM with 1 MiB chunk encryption.

### SSE-S3 — Server-Managed Key

Requires `S3_ENCRYPTION_KEY` to be configured on the server. The key is derived per object via HKDF-SHA256 (random per-object salt + master key). A random 12-byte nonce is generated per object, then modified by chunk index (`nonce XOR chunk_index`).

To upload an object with SSE-S3, include the header `x-amz-server-side-encryption: AES256` in the `PutObject` request. Decryption on `GetObject` is transparent — no additional headers are needed.

### Bucket Default Encryption

A bucket can be configured to automatically encrypt all objects with SSE-S3 (`S3_ENCRYPTION_KEY` required). The `PutBucketEncryption` request body is an XML document:

```xml
<ServerSideEncryptionConfiguration>
  <Rule>
    <ApplyServerSideEncryptionByDefault>
      <SSEAlgorithm>AES256</SSEAlgorithm>
    </ApplyServerSideEncryptionByDefault>
  </Rule>
</ServerSideEncryptionConfiguration>
```

```bash
# Put default encryption
curl -X PUT \
  -H "Authorization: <sigv4>" \
  -H "Content-Type: application/xml" \
  --data-binary @encryption.xml \
  http://localhost:8080/my-bucket?encryption

# Get default encryption
curl -H "Authorization: <sigv4>" \
  http://localhost:8080/my-bucket?encryption

# Delete default encryption
curl -X DELETE \
  -H "Authorization: <sigv4>" \
  http://localhost:8080/my-bucket?encryption
```

### SSE-C — Customer-Provided Key

No server configuration is required. The key is provided by the client with each request using the headers below. The same key must be supplied for every `GetObject` request.

### Encryption HTTP Headers

| Header | Mode | Description |
|--------|------|-------------|
| `x-amz-server-side-encryption: AES256` | SSE-S3 | Requests SSE-S3 encryption |
| `x-amz-server-side-encryption-customer-algorithm: AES256` | SSE-C | Client algorithm (always `AES256`) |
| `x-amz-server-side-encryption-customer-key: <base64>` | SSE-C | Base64-encoded client key (32 bytes) |
| `x-amz-server-side-encryption-customer-key-md5: <base64>` | SSE-C | Base64-encoded MD5 of the key |

SSE-S3 and SSE-C headers cannot be combined on the same request.

For full CLI-based upload, download, and cross-mode copy examples, see [aws-cli.md — Server-Side Encryption](./aws-cli.md#server-side-encryption).

---

## Versioning

Versioning allows multiple versions of the same object to be retained. Can be enabled and suspended per bucket.

### PutBucketVersioning Request Body

```xml
<VersioningConfiguration>
  <Status>Enabled</Status>
</VersioningConfiguration>
```

Valid values for `Status` are `Enabled` and `Suspended`.

### Versioning Behavior

- When enabled, each `PutObject` creates a new version and returns `x-amz-version-id` in the response.
- Deleting an object without a `versionId` creates a delete marker; previous versions are preserved.
- Deleting an object with a specific `versionId` permanently removes that version.
- After suspension, new `PutObject` requests write to the `null` version. Existing versions are preserved.

For CLI-based versioning examples (enable, check status, list versions, access a specific version, delete, suspend), see [aws-cli.md — Versioning](./aws-cli.md#versioning).

---

## ACLs

Access Control Lists (ACLs) control access to buckets and objects via predefined canned ACLs.

### Supported Canned ACLs

| ACL | Description |
|-----|-------------|
| `private` | Access reserved to the owner |
| `public-read` | Public read, write reserved to the owner |
| `public-read-write` | Public read and write |

ACLs are applied by including the `x-amz-acl` header on `PutBucketAcl` and `PutObjectAcl` requests, or via a request body in the standard ACL XML format.

For CLI-based ACL examples, see [aws-cli.md — ACLs](./aws-cli.md#acls).

---

## Multipart Upload

Large files are split into parts and reassembled on the server. The AWS CLI triggers multipart upload automatically for files above a certain threshold.

Incomplete multipart uploads are automatically cleaned up after `S3_UPLOAD_TTL` seconds (default: 86400 seconds / 24 hours). Cleanup runs every 5 minutes in the background.

### Lifecycle

1. `POST /{bucket}/{key}?uploads` — initiate the upload, returns `UploadId`.
2. `PUT /{bucket}/{key}?partNumber=N&uploadId=X` — upload each part (minimum 5 MiB per part, except the last). Returns an `ETag`.
3. `POST /{bucket}/{key}?uploadId=X` — complete the upload with the list of part numbers and ETags.

To abort, send `DELETE /{bucket}/{key}?uploadId=X`.

### CompleteMultipartUpload Request Body

```xml
<CompleteMultipartUpload>
  <Part>
    <PartNumber>1</PartNumber>
    <ETag>"abc123"</ETag>
  </Part>
  <Part>
    <PartNumber>2</PartNumber>
    <ETag>"def456"</ETag>
  </Part>
</CompleteMultipartUpload>
```

The ETag of the assembled object is computed as `MD5(concat(md5_of_each_part))-N` where N is the number of parts.

For CLI-based multipart examples (full lifecycle, list parts, abort), see [aws-cli.md — Multipart Upload](./aws-cli.md#multipart-upload).
