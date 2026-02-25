# Loch S3

A lightweight, S3-compatible object storage server written in Rust. Stores objects on the local filesystem and exposes an API compatible with the AWS CLI and S3 SDKs.

## Opinion

The main goal is to provide an alternative for self-hosting an S3 server. It only handles the communication, not the underlying storage or sharding — the data directory can be mounted from any filesystem (like Docker mount, volume, or even k8s storage classes), regardless of the driver.

It is designed primarily for server-to-server use, as it is better in our opinion to cache things at the application level. For example, images should be resized on execution servers and stored as cache. S3 in this case acts as shared reference storage.

## Features

- **Bucket operations**: Create, delete, list, and head buckets
- **Object operations**: Put, get, delete, head, list, and copy objects (streaming to disk)
- **Object metadata**: Persist and return Content-Type, Cache-Control, Content-Disposition, Content-Encoding, Content-Language, Expires, and custom `x-amz-meta-*` headers
- **Object versioning**: Enable/suspend versioning per bucket, version-specific get/head/delete, delete markers, list object versions
- **Multipart upload**: Create, upload parts, complete, abort, list parts and uploads
- **AWS CLI compatible**: Works with `aws s3`, `aws s3api`, and S3 SDKs via `--endpoint-url`
- **Server-side encryption**: SSE-S3 (server-managed key) and SSE-C (customer-provided key) with AES-256-GCM
- **Authentication**: Optional AWS Signature V4 authentication
- **Bucket policies**: Per-bucket public access control (anonymous read, etc.)
- **Access control lists (ACLs)**: Bucket and object ACLs with canned ACL support (`private`, `public-read`, `public-read-write`)
- **Bucket default encryption**: Configure a default SSE-S3 encryption policy per bucket
- **CORS**: Cross-Origin Resource Sharing support for browser-based access
- **HTTP/2 support**: Auto-negotiation between HTTP/1.1 and HTTP/2 for improved performance
- **Concurrent**: Handles multiple requests in parallel with atomic writes
- **Docker ready**: Multi-stage Alpine-based image (~15 MB)

## Supported Endpoints

| Operation                | Method    | Path                                           |
| ------------------------ | --------- | ---------------------------------------------- |
| ListBuckets              | `GET`     | `/`                                            |
| CreateBucket             | `PUT`     | `/{bucket}`                                    |
| HeadBucket               | `HEAD`    | `/{bucket}`                                    |
| DeleteBucket             | `DELETE`  | `/{bucket}`                                    |
| ListObjectsV2            | `GET`     | `/{bucket}?list-type=2`                        |
| PutObject                | `PUT`     | `/{bucket}/{key}`                              |
| GetObject                | `GET`     | `/{bucket}/{key}`                              |
| HeadObject               | `HEAD`    | `/{bucket}/{key}`                              |
| DeleteObject             | `DELETE`  | `/{bucket}/{key}`                              |
| CopyObject               | `PUT`     | `/{bucket}/{key}` + `x-amz-copy-source` header |
| CreateMultipartUpload    | `POST`    | `/{bucket}/{key}?uploads`                      |
| UploadPart               | `PUT`     | `/{bucket}/{key}?partNumber=N&uploadId=X`      |
| CompleteMultipartUpload  | `POST`    | `/{bucket}/{key}?uploadId=X`                   |
| AbortMultipartUpload     | `DELETE`  | `/{bucket}/{key}?uploadId=X`                   |
| ListParts                | `GET`     | `/{bucket}/{key}?uploadId=X`                   |
| ListMultipartUploads     | `GET`     | `/{bucket}?uploads`                            |
| PutBucketPolicy          | `PUT`     | `/{bucket}?policy`                             |
| GetBucketPolicy          | `GET`     | `/{bucket}?policy`                             |
| DeleteBucketPolicy       | `DELETE`  | `/{bucket}?policy`                             |
| PutBucketVersioning      | `PUT`     | `/{bucket}?versioning`                         |
| GetBucketVersioning      | `GET`     | `/{bucket}?versioning`                         |
| ListObjectVersions       | `GET`     | `/{bucket}?versions`                           |
| GetObject (versioned)    | `GET`     | `/{bucket}/{key}?versionId=X`                  |
| HeadObject (versioned)   | `HEAD`    | `/{bucket}/{key}?versionId=X`                  |
| DeleteObject (versioned) | `DELETE`  | `/{bucket}/{key}?versionId=X`                  |
| PutBucketCors            | `PUT`     | `/{bucket}?cors`                               |
| GetBucketCors            | `GET`     | `/{bucket}?cors`                               |
| DeleteBucketCors         | `DELETE`  | `/{bucket}?cors`                               |
| OPTIONS (CORS preflight) | `OPTIONS` | `/{bucket}/{key}`                              |
| GetBucketAcl             | `GET`     | `/{bucket}?acl`                                |
| PutBucketAcl             | `PUT`     | `/{bucket}?acl`                                |
| GetObjectAcl             | `GET`     | `/{bucket}/{key}?acl`                          |
| PutObjectAcl             | `PUT`     | `/{bucket}/{key}?acl`                          |
| PutBucketEncryption      | `PUT`     | `/{bucket}?encryption`                         |
| GetBucketEncryption      | `GET`     | `/{bucket}?encryption`                         |
| DeleteBucketEncryption   | `DELETE`  | `/{bucket}?encryption`                         |

## Prerequisites

- [Rust](https://rustup.rs/) 1.85+ (for building from source)
- [Docker](https://www.docker.com/) (for container usage)
- [`cross`](https://github.com/cross-rs/cross) (optional, for cross-compilation)

## Build & Run

### From source

```bash
make release
./target/release/s3
```

### With Docker

```bash
make docker
docker run -p 9000:8080 -v s3-data:/data ghcr.io/loch-sh/s3

# With authentication:
docker run -p 9000:8080 -v s3-data:/data \
  -e S3_ACCESS_KEY_ID=myaccesskey \
  -e S3_SECRET_ACCESS_KEY=mysecretkey \
  ghcr.io/loch-sh/s3

# With authentication + SSE-S3 encryption:
docker run -p 9000:8080 -v s3-data:/data \
  -e S3_ACCESS_KEY_ID=myaccesskey \
  -e S3_SECRET_ACCESS_KEY=mysecretkey \
  -e S3_ENCRYPTION_KEY=$(openssl rand -base64 32) \
  ghcr.io/loch-sh/s3
```

Multi-platform images (`linux/amd64` + `linux/arm64`) are automatically built and pushed to [GitHub Container Registry](https://ghcr.io/loch-sh/s3) on every push to `main` and on version tags (`v*`).

### Multi-platform Docker image (local)

Build a multi-arch image locally using [Docker Buildx](https://docs.docker.com/build/buildx/):

```bash
make docker-multiplatform    # Build only
make docker-push            # Build and push to registry
```

### Cross-compilation

Linux and Windows cross-compilation requires [`cross`](https://github.com/cross-rs/cross). macOS targets build natively with `cargo`.

```bash
cargo install cross

make linux-amd64      # x86_64-unknown-linux-musl  (requires cross)
make linux-arm64      # aarch64-unknown-linux-musl  (requires cross)
make windows-amd64    # x86_64-pc-windows-gnu       (requires cross)
make macos-amd64      # x86_64-apple-darwin         (macOS only)
make macos-arm64      # aarch64-apple-darwin        (macOS only)
make all              # All targets above
```

Binaries are output to `dist/<platform>/`.

## Configuration

Configuration is done via environment variables:

| Variable               | Default  | Description                                  |
| ---------------------- | -------- | -------------------------------------------- |
| `S3_PORT`              | `8080`   | Port the server listens on                   |
| `S3_DATA_DIR`          | `./data` | Directory for storing objects                |
| `S3_ACCESS_KEY_ID`     | _(none)_ | Access key for authentication (optional)     |
| `S3_SECRET_ACCESS_KEY` | _(none)_ | Secret key for authentication (optional)     |
| `S3_UPLOAD_TTL`        | `86400`  | Multipart upload expiry in seconds (24h)     |
| `S3_ENCRYPTION_KEY`    | _(none)_ | Base64-encoded 32-byte master key for SSE-S3 |

When both `S3_ACCESS_KEY_ID` and `S3_SECRET_ACCESS_KEY` are set, the server requires AWS Signature V4 authentication on all requests. When unset, all requests are allowed without authentication.

When `S3_ENCRYPTION_KEY` is set, the server supports SSE-S3 encryption (`x-amz-server-side-encryption: AES256`). SSE-C (customer-provided keys) works regardless of this setting. See [SECURITY.md](SECURITY.md) for details.

Example without authentication:

```bash
S3_PORT=9000 S3_DATA_DIR=/tmp/s3-data ./target/release/s3
```

Example with authentication:

```bash
S3_ACCESS_KEY_ID=myaccesskey S3_SECRET_ACCESS_KEY=mysecretkey ./target/release/s3
```

## Usage with AWS CLI

Configure the AWS CLI with credentials matching the server:

```bash
# If the server has authentication enabled, use the same credentials:
export AWS_ACCESS_KEY_ID=myaccesskey
export AWS_SECRET_ACCESS_KEY=mysecretkey
export AWS_DEFAULT_REGION=loch-sh

# If no authentication is configured on the server, use any dummy values:
# export AWS_ACCESS_KEY_ID=test
# export AWS_SECRET_ACCESS_KEY=test
# export AWS_DEFAULT_REGION=loch-sh
```

### Using HTTP/2

The AWS CLI v2 supports HTTP/2. To enable it, configure your AWS CLI to use HTTP/2:

```bash
# Enable HTTP/2 globally via environment variable
export AWS_USE_HTTP2=true

# Or configure it in ~/.aws/config
aws configure set default.use_http2 true

# Now all AWS CLI commands will use HTTP/2 when connecting to the server
aws --endpoint-url http://localhost:8080 s3 ls

# Verify HTTP/2 is being used (with debug output)
aws --endpoint-url http://localhost:8080 s3 ls --debug 2>&1 | grep -i "http/2"
```

For better HTTP/2 performance in production, use a TLS reverse proxy (nginx, traefik) that supports ALPN negotiation:

```bash
# With HTTPS endpoint, HTTP/2 negotiation is automatic via ALPN
aws --endpoint-url https://s3.example.com s3 ls
```

### Bucket operations

```bash
# Create a bucket
aws --endpoint-url http://localhost:8080 s3 mb s3://my-bucket

# List buckets
aws --endpoint-url http://localhost:8080 s3 ls

# Delete a bucket
aws --endpoint-url http://localhost:8080 s3 rb s3://my-bucket
```

### Object operations

```bash
# Upload a file
aws --endpoint-url http://localhost:8080 s3 cp myfile.txt s3://my-bucket/myfile.txt

# List objects
aws --endpoint-url http://localhost:8080 s3 ls s3://my-bucket

# Download a file
aws --endpoint-url http://localhost:8080 s3 cp s3://my-bucket/myfile.txt downloaded.txt

# Copy an object
aws --endpoint-url http://localhost:8080 s3 cp s3://my-bucket/myfile.txt s3://my-bucket/copy.txt

# Delete an object
aws --endpoint-url http://localhost:8080 s3 rm s3://my-bucket/myfile.txt
```

### Bucket policy (public read)

When authentication is enabled, you can allow anonymous read access to a bucket via a bucket policy:

```bash
# Set a policy allowing public read on a bucket
aws --endpoint-url http://localhost:8080 s3api put-bucket-policy \
  --bucket my-bucket \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-bucket/*"
    }]
  }'

# Now anyone can download objects without credentials
curl http://localhost:8080/my-bucket/myfile.txt
```

Supported actions: `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject`, `s3:ListBucket`, `s3:GetBucketLocation`, `s3:*`.

### Multipart upload

Large files are automatically split into parts by the AWS CLI. You can also use multipart upload explicitly:

```bash
# Initiate a multipart upload
UPLOAD_ID=$(aws --endpoint-url http://localhost:8080 s3api create-multipart-upload \
  --bucket my-bucket --key largefile.bin --query UploadId --output text)

# Upload parts
aws --endpoint-url http://localhost:8080 s3api upload-part \
  --bucket my-bucket --key largefile.bin --upload-id "$UPLOAD_ID" \
  --part-number 1 --body part1.bin

# Complete the upload
aws --endpoint-url http://localhost:8080 s3api complete-multipart-upload \
  --bucket my-bucket --key largefile.bin --upload-id "$UPLOAD_ID" \
  --multipart-upload 'Parts=[{PartNumber=1,ETag="..."}]'

# Or abort
aws --endpoint-url http://localhost:8080 s3api abort-multipart-upload \
  --bucket my-bucket --key largefile.bin --upload-id "$UPLOAD_ID"
```

Incomplete multipart uploads are automatically cleaned up after `S3_UPLOAD_TTL` seconds (default: 24 hours).

### Object versioning

```bash
# Enable versioning on a bucket
aws --endpoint-url http://localhost:8080 s3api put-bucket-versioning \
  --bucket my-bucket \
  --versioning-configuration Status=Enabled

# Check versioning status
aws --endpoint-url http://localhost:8080 s3api get-bucket-versioning \
  --bucket my-bucket

# Upload an object (returns a version ID)
aws --endpoint-url http://localhost:8080 s3 cp myfile.txt s3://my-bucket/myfile.txt

# List all versions of objects
aws --endpoint-url http://localhost:8080 s3api list-object-versions \
  --bucket my-bucket

# Get a specific version
aws --endpoint-url http://localhost:8080 s3api get-object \
  --bucket my-bucket --key myfile.txt --version-id <version-id> output.txt

# Delete an object (creates a delete marker, previous versions remain)
aws --endpoint-url http://localhost:8080 s3api delete-object \
  --bucket my-bucket --key myfile.txt

# Permanently delete a specific version
aws --endpoint-url http://localhost:8080 s3api delete-object \
  --bucket my-bucket --key myfile.txt --version-id <version-id>

# Suspend versioning (new writes use "null" version ID)
aws --endpoint-url http://localhost:8080 s3api put-bucket-versioning \
  --bucket my-bucket \
  --versioning-configuration Status=Suspended
```

### Object metadata

Object metadata (system headers and custom `x-amz-meta-*` headers) are persisted on PUT and returned on GET/HEAD:

```bash
# Upload with custom metadata
aws --endpoint-url http://localhost:8080 s3api put-object \
  --bucket my-bucket --key myfile.txt --body myfile.txt \
  --content-type "text/plain; charset=utf-8" \
  --cache-control "max-age=3600" \
  --content-disposition "attachment" \
  --expires "2030-12-01T00:00:00Z" \
  --metadata '{"author":"alice","project":"loch-s3"}'

# Retrieve object — metadata is returned in response headers
aws --endpoint-url http://localhost:8080 s3api head-object \
  --bucket my-bucket --key myfile.txt

# Copy with metadata preserved (default)
aws --endpoint-url http://localhost:8080 s3api copy-object \
  --bucket my-bucket --key copy.txt \
  --copy-source my-bucket/myfile.txt

# Copy with metadata replaced
aws --endpoint-url http://localhost:8080 s3api copy-object \
  --bucket my-bucket --key copy.txt \
  --copy-source my-bucket/myfile.txt \
  --metadata-directive REPLACE \
  --content-type "application/octet-stream" \
  --metadata '{"author":"bob"}'
```

Supported metadata headers: `Content-Type`, `Cache-Control`, `Content-Disposition`, `Content-Encoding`, `Content-Language`, `Expires`, and any `x-amz-meta-*` custom header.

### Server-side encryption

Loch S3 supports two encryption modes: SSE-S3 (server-managed key) and SSE-C (customer-provided key).

#### SSE-S3 (server-managed key)

Generate a master key and start the server:

```bash
export S3_ENCRYPTION_KEY=$(openssl rand -base64 32)
./target/release/s3
```

Upload and retrieve encrypted objects:

```bash
# Upload with SSE-S3
aws --endpoint-url http://localhost:8080 s3api put-object \
  --bucket my-bucket --key secret.txt --body secret.txt \
  --server-side-encryption AES256

# Download (decryption is transparent)
aws --endpoint-url http://localhost:8080 s3api get-object \
  --bucket my-bucket --key secret.txt output.txt
```

#### SSE-C (customer-provided key)

The client provides the encryption key with each request. No server-side configuration is required.

```bash
# Generate a 256-bit key
KEY=$(openssl rand -base64 32)
KEY_MD5=$(echo -n "$KEY" | base64 -d | openssl dgst -md5 -binary | base64)

# Upload with SSE-C
aws --endpoint-url http://localhost:8080 s3api put-object \
  --bucket my-bucket --key secret.txt --body secret.txt \
  --sse-customer-algorithm AES256 \
  --sse-customer-key "$KEY" \
  --sse-customer-key-md5 "$KEY_MD5"

# Download (must provide the same key)
aws --endpoint-url http://localhost:8080 s3api get-object \
  --bucket my-bucket --key secret.txt output.txt \
  --sse-customer-algorithm AES256 \
  --sse-customer-key "$KEY" \
  --sse-customer-key-md5 "$KEY_MD5"
```

#### Copy between encryption modes

```bash
# Copy SSE-C source to SSE-S3 destination
aws --endpoint-url http://localhost:8080 s3api copy-object \
  --bucket my-bucket --key dest.txt \
  --copy-source my-bucket/source.txt \
  --copy-source-sse-customer-algorithm AES256 \
  --copy-source-sse-customer-key "$KEY" \
  --copy-source-sse-customer-key-md5 "$KEY_MD5" \
  --server-side-encryption AES256
```

### CORS configuration

```bash
# Set CORS on a bucket
aws --endpoint-url http://localhost:8080 s3api put-bucket-cors \
  --bucket my-bucket \
  --cors-configuration '{
    "CORSRules": [{
      "AllowedOrigins": ["https://example.com"],
      "AllowedMethods": ["GET", "PUT"],
      "AllowedHeaders": ["*"],
      "MaxAgeSeconds": 3600
    }]
  }'
```

### Access control lists (ACLs)

Bucket and object ACLs can be set using a canned ACL or a full XML body:

```bash
# Set a canned ACL on a bucket
aws --endpoint-url http://localhost:8080 s3api put-bucket-acl \
  --bucket my-bucket \
  --acl public-read

# Set a canned ACL on an object
aws --endpoint-url http://localhost:8080 s3api put-object-acl \
  --bucket my-bucket --key myfile.txt \
  --acl public-read

# Get the bucket ACL
aws --endpoint-url http://localhost:8080 s3api get-bucket-acl \
  --bucket my-bucket

# Get the object ACL
aws --endpoint-url http://localhost:8080 s3api get-object-acl \
  --bucket my-bucket --key myfile.txt
```

Supported canned ACLs: `private`, `public-read`, `public-read-write`.

### Bucket default encryption

Configure a bucket to encrypt all objects with SSE-S3 by default (requires `S3_ENCRYPTION_KEY` to be set on the server):

```bash
# Enable default SSE-S3 encryption on a bucket
aws --endpoint-url http://localhost:8080 s3api put-bucket-encryption \
  --bucket my-bucket \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      }
    }]
  }'

# Check the encryption configuration
aws --endpoint-url http://localhost:8080 s3api get-bucket-encryption \
  --bucket my-bucket

# Remove the encryption configuration
aws --endpoint-url http://localhost:8080 s3api delete-bucket-encryption \
  --bucket my-bucket
```

## Testing

```bash
make test
```

The integration test suite covers:

- Bucket CRUD lifecycle
- Object CRUD lifecycle
- Nested object keys (directory-like paths)
- Object copy/rename
- Error cases (nonexistent bucket/key, duplicate bucket, non-empty bucket deletion)
- Concurrent uploads (20 parallel writes)
- Concurrent upload + delete race conditions
- Authentication: rejection of unsigned/invalid requests, acceptance of valid SigV4 signatures
- Full CRUD with authenticated requests
- Server without credentials allows all requests
- Bucket policy CRUD and anonymous access via policies
- CORS configuration, preflight requests, and response headers
- Multipart upload: full lifecycle, abort, list parts/uploads, invalid part order
- Streaming upload of large objects (1 MB+)
- Multipart state does not appear in object listings
- Object versioning: enable/get status, multiple versions, version-specific get/head, delete markers, delete marker removal, permanent version deletion, list object versions, copy with source versionId, pre-existing object migration, versioning does not affect ListObjectsV2
- Object metadata: roundtrip persistence (PUT/GET/HEAD), Content-Type override, backward compatibility, copy with COPY/REPLACE directive, metadata cleanup on delete
- Server-side encryption: SSE-S3 PUT/GET/HEAD, SSE-C PUT/GET/HEAD, SSE-S3/SSE-C multipart upload, copy between encryption modes, error cases (missing key, wrong key, invalid algorithm, no master key configured), ETag integrity, large object multi-chunk encryption

## Known Limitations

- Single credential pair only (no multi-user support, except anonymous one and main user)
- Path-style URLs only (no virtual-hosted-style)
- No SSE-KMS (only SSE-S3 and SSE-C are supported)

## License

MIT
