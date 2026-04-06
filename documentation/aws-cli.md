# AWS CLI

Loch S3 is compatible with the AWS CLI via `--endpoint-url`. The region to use is `loch-sh`.

## Table of Contents

- [Credentials](#credentials)
- [Bucket Operations](#bucket-operations)
- [Object Operations](#object-operations)
- [Upload with Metadata](#upload-with-metadata)
- [Presigned URLs](#presigned-urls)
- [HTTP/2](#http2)
- [Bucket Policies](#bucket-policies)
- [CORS](#cors)
- [Server-Side Encryption](#server-side-encryption)
- [Versioning](#versioning)
- [ACLs](#acls)
- [Multipart Upload](#multipart-upload)

---

## Credentials

```bash
# With authentication
export AWS_ACCESS_KEY_ID=myaccesskey
export AWS_SECRET_ACCESS_KEY=mysecretkey
export AWS_DEFAULT_REGION=loch-sh

# Without authentication (open-access server)
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=loch-sh
```

## Bucket Operations

```bash
# Create a bucket
aws --endpoint-url http://localhost:8080 s3 mb s3://my-bucket

# List buckets
aws --endpoint-url http://localhost:8080 s3 ls

# Delete a bucket (must be empty)
aws --endpoint-url http://localhost:8080 s3 rb s3://my-bucket
```

## Object Operations

```bash
# Upload a file
aws --endpoint-url http://localhost:8080 s3 cp myfile.txt s3://my-bucket/myfile.txt

# List objects in a bucket
aws --endpoint-url http://localhost:8080 s3 ls s3://my-bucket

# Download a file
aws --endpoint-url http://localhost:8080 s3 cp s3://my-bucket/myfile.txt downloaded.txt

# Copy an object
aws --endpoint-url http://localhost:8080 s3 cp s3://my-bucket/myfile.txt s3://my-bucket/copy.txt

# Delete an object
aws --endpoint-url http://localhost:8080 s3 rm s3://my-bucket/myfile.txt

# Upload an entire directory (recursive)
aws --endpoint-url http://localhost:8080 s3 cp ./local-dir s3://my-bucket/prefix/ --recursive
```

## Upload with Metadata

```bash
aws --endpoint-url http://localhost:8080 s3api put-object \
  --bucket my-bucket \
  --key myfile.txt \
  --body myfile.txt \
  --content-type "text/plain; charset=utf-8" \
  --cache-control "max-age=3600" \
  --content-disposition "attachment" \
  --expires "2030-12-01T00:00:00Z" \
  --metadata '{"author":"alice","project":"loch-s3"}'
```

Supported metadata headers: `Content-Type`, `Cache-Control`, `Content-Disposition`, `Content-Encoding`, `Content-Language`, `Expires`, and any custom `x-amz-meta-*` header.

## Presigned URLs

Presigned URLs allow temporary access to an object without exposing credentials.

```bash
# Generate a GET URL valid for 1 hour
aws --endpoint-url http://localhost:8080 s3 presign s3://my-bucket/file.txt --expires-in 3600

# Download via the URL (without credentials)
curl "http://localhost:8080/my-bucket/file.txt?X-Amz-Algorithm=..."

# Generate a PUT URL for a direct upload
PRESIGNED=$(aws --endpoint-url http://localhost:8080 s3 presign \
  --expires-in 300 s3://my-bucket/upload.bin)

curl -X PUT --data-binary @localfile.bin "$PRESIGNED"
```

After expiry, the server returns `403 ExpiredToken`.

## HTTP/2

The AWS CLI v2 supports HTTP/2. Loch S3 automatically negotiates HTTP/1.1 or HTTP/2:

```bash
# Enable HTTP/2
export AWS_USE_HTTP2=true

# Or in ~/.aws/config
aws configure set default.use_http2 true
```

In production, place a TLS reverse proxy (Nginx, Caddy, Traefik) in front of the server to benefit from automatic ALPN negotiation.

---

## Bucket Policies

### Example: Public Read Access

```bash
aws --endpoint-url http://localhost:8080 s3api put-bucket-policy \
  --bucket my-bucket \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": "*",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:loch:s3:::my-bucket",
        "arn:loch:s3:::my-bucket/*"
      ]
    }]
  }'
```

### Example: Access Restricted to a Specific User

```bash
aws --endpoint-url http://localhost:8080 s3api put-bucket-policy \
  --bucket my-bucket \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"AWS": "arn:loch:iam:::user/alice"},
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:loch:s3:::my-bucket",
        "arn:loch:s3:::my-bucket/*"
      ]
    }]
  }'
```

### Example: Explicit Deny on an Action

```bash
aws --endpoint-url http://localhost:8080 s3api put-bucket-policy \
  --bucket my-bucket \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:*",
        "Resource": "arn:loch:s3:::my-bucket/*"
      },
      {
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:DeleteObject",
        "Resource": "arn:loch:s3:::my-bucket/*"
      }
    ]
  }'
```

### Read and Delete a Policy

```bash
# Read
aws --endpoint-url http://localhost:8080 s3api get-bucket-policy --bucket my-bucket

# Delete
aws --endpoint-url http://localhost:8080 s3api delete-bucket-policy --bucket my-bucket
```

---

## CORS

### Set the CORS Configuration

```bash
aws --endpoint-url http://localhost:8080 s3api put-bucket-cors \
  --bucket my-bucket \
  --cors-configuration '{
    "CORSRules": [{
      "AllowedOrigins": ["https://example.com"],
      "AllowedMethods": ["GET", "PUT", "DELETE"],
      "AllowedHeaders": ["*"],
      "ExposeHeaders": ["ETag"],
      "MaxAgeSeconds": 3600
    }]
  }'
```

### Read and Delete the CORS Configuration

```bash
# Read
aws --endpoint-url http://localhost:8080 s3api get-bucket-cors --bucket my-bucket

# Delete
aws --endpoint-url http://localhost:8080 s3api delete-bucket-cors --bucket my-bucket
```

---

## Server-Side Encryption

### SSE-S3 — Upload and Download

```bash
# Generate and configure the master key
export S3_ENCRYPTION_KEY=$(openssl rand -base64 32)
./target/release/s3

# Upload with SSE-S3
aws --endpoint-url http://localhost:8080 s3api put-object \
  --bucket my-bucket \
  --key secret.txt \
  --body secret.txt \
  --server-side-encryption AES256

# Download (decryption is transparent)
aws --endpoint-url http://localhost:8080 s3api get-object \
  --bucket my-bucket --key secret.txt output.txt
```

### Bucket Default Encryption

```bash
# Enable default encryption for a bucket
aws --endpoint-url http://localhost:8080 s3api put-bucket-encryption \
  --bucket my-bucket \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      }
    }]
  }'

# Check
aws --endpoint-url http://localhost:8080 s3api get-bucket-encryption --bucket my-bucket

# Delete
aws --endpoint-url http://localhost:8080 s3api delete-bucket-encryption --bucket my-bucket
```

### SSE-C — Upload and Download

```bash
# Generate a 256-bit key
KEY=$(openssl rand -base64 32)
KEY_MD5=$(echo -n "$KEY" | base64 -d | openssl dgst -md5 -binary | base64)

# Upload with SSE-C
aws --endpoint-url http://localhost:8080 s3api put-object \
  --bucket my-bucket \
  --key secret.txt \
  --body secret.txt \
  --sse-customer-algorithm AES256 \
  --sse-customer-key "$KEY" \
  --sse-customer-key-md5 "$KEY_MD5"

# Download (the same key is required)
aws --endpoint-url http://localhost:8080 s3api get-object \
  --bucket my-bucket \
  --key secret.txt output.txt \
  --sse-customer-algorithm AES256 \
  --sse-customer-key "$KEY" \
  --sse-customer-key-md5 "$KEY_MD5"
```

### Copy Between Encryption Modes

```bash
# Copy from an SSE-C source to an SSE-S3 destination
aws --endpoint-url http://localhost:8080 s3api copy-object \
  --bucket my-bucket \
  --key destination.txt \
  --copy-source my-bucket/source.txt \
  --copy-source-sse-customer-algorithm AES256 \
  --copy-source-sse-customer-key "$KEY" \
  --copy-source-sse-customer-key-md5 "$KEY_MD5" \
  --server-side-encryption AES256
```

---

## Versioning

### Enable Versioning

```bash
aws --endpoint-url http://localhost:8080 s3api put-bucket-versioning \
  --bucket my-bucket \
  --versioning-configuration Status=Enabled
```

### Check Status

```bash
aws --endpoint-url http://localhost:8080 s3api get-bucket-versioning \
  --bucket my-bucket
```

### Upload and List Versions

```bash
# Each PUT creates a new version (returns x-amz-version-id)
aws --endpoint-url http://localhost:8080 s3 cp file.txt s3://my-bucket/file.txt

# List all versions
aws --endpoint-url http://localhost:8080 s3api list-object-versions \
  --bucket my-bucket
```

### Access a Specific Version

```bash
# Download a specific version
aws --endpoint-url http://localhost:8080 s3api get-object \
  --bucket my-bucket \
  --key file.txt \
  --version-id <version-id> \
  output.txt

# HEAD a specific version
aws --endpoint-url http://localhost:8080 s3api head-object \
  --bucket my-bucket \
  --key file.txt \
  --version-id <version-id>
```

### Delete

```bash
# Delete the current object (creates a delete marker, previous versions are preserved)
aws --endpoint-url http://localhost:8080 s3api delete-object \
  --bucket my-bucket \
  --key file.txt

# Permanently delete a specific version
aws --endpoint-url http://localhost:8080 s3api delete-object \
  --bucket my-bucket \
  --key file.txt \
  --version-id <version-id>
```

### Suspend Versioning

```bash
aws --endpoint-url http://localhost:8080 s3api put-bucket-versioning \
  --bucket my-bucket \
  --versioning-configuration Status=Suspended
```

After suspension, new PUTs use the `null` `versionId`. Existing versions are preserved.

---

## ACLs

### Apply an ACL to a Bucket

```bash
aws --endpoint-url http://localhost:8080 s3api put-bucket-acl \
  --bucket my-bucket \
  --acl public-read
```

### Apply an ACL to an Object

```bash
aws --endpoint-url http://localhost:8080 s3api put-object-acl \
  --bucket my-bucket \
  --key my-object.txt \
  --acl public-read
```

### Read ACLs

```bash
# ACL of a bucket
aws --endpoint-url http://localhost:8080 s3api get-bucket-acl --bucket my-bucket

# ACL of an object
aws --endpoint-url http://localhost:8080 s3api get-object-acl \
  --bucket my-bucket \
  --key my-object.txt
```

---

## Multipart Upload

Large files are split into parts and reassembled on the server. The AWS CLI triggers multipart upload automatically for files above a certain threshold.

Incomplete multipart uploads are automatically cleaned up after `S3_UPLOAD_TTL` seconds (default: 86400 seconds / 24 hours).

### Full Lifecycle

```bash
# 1. Initiate the upload
UPLOAD_ID=$(aws --endpoint-url http://localhost:8080 s3api create-multipart-upload \
  --bucket my-bucket \
  --key large-file.bin \
  --query UploadId \
  --output text)

# 2. Upload parts (minimum 5 MiB per part except the last)
ETAG1=$(aws --endpoint-url http://localhost:8080 s3api upload-part \
  --bucket my-bucket \
  --key large-file.bin \
  --upload-id "$UPLOAD_ID" \
  --part-number 1 \
  --body part1.bin \
  --query ETag \
  --output text)

# 3. Complete the upload
aws --endpoint-url http://localhost:8080 s3api complete-multipart-upload \
  --bucket my-bucket \
  --key large-file.bin \
  --upload-id "$UPLOAD_ID" \
  --multipart-upload "Parts=[{PartNumber=1,ETag=$ETAG1}]"
```

### List Parts and In-Progress Uploads

```bash
# Parts of an in-progress upload
aws --endpoint-url http://localhost:8080 s3api list-parts \
  --bucket my-bucket \
  --key large-file.bin \
  --upload-id "$UPLOAD_ID"

# All in-progress multipart uploads
aws --endpoint-url http://localhost:8080 s3api list-multipart-uploads \
  --bucket my-bucket
```

### Abort an Upload

```bash
aws --endpoint-url http://localhost:8080 s3api abort-multipart-upload \
  --bucket my-bucket \
  --key large-file.bin \
  --upload-id "$UPLOAD_ID"
```

The ETag of an object assembled via multipart is computed as `MD5(concat(md5_of_each_part))-N` where N is the number of parts.
