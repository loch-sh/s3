NAME    = s3
DIST    = dist
IMAGE   = loch-sh/$(NAME)
PLATFORMS = linux/amd64,linux/arm64

# Rust target triples
TARGET_LINUX_AMD64   = x86_64-unknown-linux-musl
TARGET_LINUX_ARM64   = aarch64-unknown-linux-musl
TARGET_WINDOWS_AMD64 = x86_64-pc-windows-gnu
TARGET_MACOS_AMD64   = x86_64-apple-darwin
TARGET_MACOS_ARM64   = aarch64-apple-darwin

.PHONY: all build release test clean docker docker-multiplatform docker-push \
        linux-amd64 linux-arm64 windows-amd64 macos-amd64 macos-arm64

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

macos-amd64:
	rustup target add $(TARGET_MACOS_AMD64)
	cargo build --release --target $(TARGET_MACOS_AMD64)
	@mkdir -p $(DIST)/macos-amd64
	cp target/$(TARGET_MACOS_AMD64)/release/$(NAME) $(DIST)/macos-amd64/$(NAME)

macos-arm64:
	rustup target add $(TARGET_MACOS_ARM64)
	cargo build --release --target $(TARGET_MACOS_ARM64)
	@mkdir -p $(DIST)/macos-arm64
	cp target/$(TARGET_MACOS_ARM64)/release/$(NAME) $(DIST)/macos-arm64/$(NAME)

all: linux-amd64 linux-arm64 windows-amd64 macos-amd64 macos-arm64

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
