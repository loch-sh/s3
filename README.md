# Loch S3

A lightweight, S3-compatible object storage server written in Rust. Stores objects on the local filesystem and exposes an API compatible with the AWS CLI and S3 SDKs.

Designed for self-hosted server-to-server use: application-level cache, shared reference storage. The data directory can be mounted from any filesystem (Docker volume, k8s storage class, network mount).

## Documentation

- [Installation](documentation/install.md) — build from source, Docker, environment variables, authentication modes
- [Usage](documentation/usage.md) — `loch-s3` CLI, Cyberduck
- [AWS CLI](documentation/aws-cli.md) — bucket/object operations, metadata, presigned URLs, HTTP/2
- [API reference](documentation/api.md) — S3 endpoints, admin API, bucket policies, CORS, encryption, versioning

## Quick start

```bash
# No authentication
S3_DATA_DIR=/tmp/s3-data ./s3

# Single-user
S3_ACCESS_KEY_ID=mykey S3_SECRET_ACCESS_KEY=mysecret ./s3

# Multi-user (auto-bootstraps on first run, prints root credentials)
S3_USERS_FILE=users.json S3_ADMIN_API_KEY=my-admin-key ./s3
```

```bash
# AWS CLI
export AWS_ACCESS_KEY_ID=mykey AWS_SECRET_ACCESS_KEY=mysecret AWS_DEFAULT_REGION=loch-sh
aws --endpoint-url http://localhost:8080 s3 mb s3://my-bucket
aws --endpoint-url http://localhost:8080 s3 cp file.txt s3://my-bucket/file.txt
```

## Features

- Bucket and object CRUD, copy, streaming upload
- Object metadata (`Content-Type`, `Cache-Control`, custom `x-amz-meta-*`)
- Object versioning, multipart upload, presigned URLs
- Multi-user with bucket ownership and ARN-based bucket policies
- User management REST API (`/_loch/users`)
- SSE-S3 and SSE-C encryption (AES-256-GCM)
- CORS, ACLs, bucket default encryption
- AWS Signature V4, HTTP/2
- Docker multi-arch image (~15 MB)

## Known limitations

- Path-style URLs only (no virtual-hosted-style)
- No SSE-KMS
- No IAM policies (bucket policies only)

## License

Apache 2.0 — see [LICENSE](LICENSE).
