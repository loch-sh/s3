NAME    = s3
DIST    = dist
IMAGE   = loch/$(NAME)
PLATFORMS = linux/amd64,linux/arm64

# Rust target triples
TARGET_LINUX_AMD64   = x86_64-unknown-linux-musl
TARGET_LINUX_ARM64   = aarch64-unknown-linux-musl
TARGET_WINDOWS_AMD64 = x86_64-pc-windows-gnu
TARGET_WINDOWS_ARM64 = aarch64-pc-windows-gnullvm

.PHONY: all build release test clean docker docker-multiplatform docker-push \
        linux-amd64 linux-arm64 windows-amd64 windows-arm64

build:
	cargo build

release:
	cargo build --release

test:
	cargo test

# Cross-compilation targets (requires: cargo install cross)

linux-amd64:
	cross build --release --target $(TARGET_LINUX_AMD64)
	@mkdir -p $(DIST)/linux-amd64
	cp target/$(TARGET_LINUX_AMD64)/release/$(NAME) $(DIST)/linux-amd64/$(NAME)

linux-arm64:
	cross build --release --target $(TARGET_LINUX_ARM64)
	@mkdir -p $(DIST)/linux-arm64
	cp target/$(TARGET_LINUX_ARM64)/release/$(NAME) $(DIST)/linux-arm64/$(NAME)

windows-amd64:
	cross build --release --target $(TARGET_WINDOWS_AMD64)
	@mkdir -p $(DIST)/windows-amd64
	cp target/$(TARGET_WINDOWS_AMD64)/release/$(NAME).exe $(DIST)/windows-amd64/$(NAME).exe

windows-arm64:
	cross build --release --target $(TARGET_WINDOWS_ARM64)
	@mkdir -p $(DIST)/windows-arm64
	cp target/$(TARGET_WINDOWS_ARM64)/release/$(NAME).exe $(DIST)/windows-arm64/$(NAME).exe

all: linux-amd64 linux-arm64 windows-amd64 windows-arm64

docker:
	docker build -t $(IMAGE) .

# Multi-platform Docker images (requires: docker buildx)

docker-multiplatform:
	docker buildx build --platform $(PLATFORMS) -t $(IMAGE) .

docker-push:
	docker buildx build --platform $(PLATFORMS) -t $(IMAGE) --push .

clean:
	cargo clean
	rm -rf $(DIST)
