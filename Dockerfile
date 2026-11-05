# Base images are pinned by version and digest (multi-arch index), pulled from
# the Docker Hub mirror on Google Container Registry (no Docker Hub rate limit).
# To upgrade: bump the tag, then refresh the digest with
#   docker buildx imagetools inspect mirror.gcr.io/library/<image>:<tag>

# Stage 1: Build
FROM mirror.gcr.io/library/rust:1.97.1-alpine3.24@sha256:3c38f3f82c2f3d73da3b38e18d279393a04cb43ddded0e35088a8c3324d40900 AS builder
RUN apk add --no-cache musl-dev
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release --locked

# Stage 2: Runtime
FROM mirror.gcr.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
# Fixed, unprivileged uid/gid 100:101: the values Alpine assigned to the `s3`
# system user in images up to 1.2.0, so existing /data volumes stay writable.
# The server also runs under any other uid
# (e.g. `docker run --user 1234:1234`) as long as it can write S3_DATA_DIR.
RUN addgroup -S -g 101 s3 && adduser -S -u 100 -G s3 -H -h /data s3
COPY --from=builder /app/target/release/s3 /usr/local/bin/s3
COPY --from=builder /app/target/release/loch-s3 /usr/local/bin/loch-s3
RUN mkdir -p /data && chown 100:101 /data
USER 100:101
EXPOSE 8080
ENV S3_PORT=8080
ENV S3_DATA_DIR=/data
VOLUME ["/data"]
# busybox wget is part of the base image
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O /dev/null "http://127.0.0.1:${S3_PORT}/_loch/health" || exit 1
CMD ["s3"]
