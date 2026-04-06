# Stage 1: Build
FROM rust:alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release

# Stage 2: Runtime
FROM alpine:latest
RUN addgroup -S s3 && adduser -S s3 -G s3
COPY --from=builder /app/target/release/s3 /usr/local/bin/s3
COPY --from=builder /app/target/release/loch-s3 /usr/local/bin/loch-s3
RUN mkdir -p /data && chown s3:s3 /data
USER s3
EXPOSE 8080
ENV S3_PORT=8080
ENV S3_DATA_DIR=/data
CMD ["s3"]
