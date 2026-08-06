# syntax=docker/dockerfile:1
# Builds the `acmebot` Rust CLI (rust/acmebot-cli) into a minimal runtime image,
# suitable for running certificate issuance jobs (e.g. as a Kubernetes CronJob/Job).
#
# Multi-arch: built for linux/amd64 and linux/arm64 via `docker buildx build --platform ...`
# (see .github/workflows/ci.yml). Docker/buildx automatically selects the matching
# BUILDPLATFORM builder and TARGETPLATFORM output per the --platform list.

ARG RUST_VERSION=1

FROM --platform=$BUILDPLATFORM rust:${RUST_VERSION}-slim-bookworm AS build
WORKDIR /src

# CA certificates so cargo can fetch crates over HTTPS during the build.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG TARGETPLATFORM
# Map Docker's TARGETPLATFORM to the matching Rust target triple and install it,
# then cross-compile via `cargo build --target` so the build stage always runs
# natively on BUILDPLATFORM even when TARGETPLATFORM differs (fast QEMU-free builds).
RUN case "$TARGETPLATFORM" in \
        "linux/amd64") echo x86_64-unknown-linux-gnu > /tmp/rust_target ;; \
        "linux/arm64") echo aarch64-unknown-linux-gnu > /tmp/rust_target ;; \
        *) echo "Unsupported TARGETPLATFORM: $TARGETPLATFORM" >&2; exit 1 ;; \
    esac \
    && rustup target add "$(cat /tmp/rust_target)"

# Cross-compilation linker/toolchain for the non-native target.
RUN case "$(cat /tmp/rust_target)" in \
        "aarch64-unknown-linux-gnu") \
            dpkg --add-architecture arm64 \
            && apt-get update \
            && apt-get install -y --no-install-recommends g++-aarch64-linux-gnu libc6-dev-arm64-cross \
            && rm -rf /var/lib/apt/lists/* ;; \
        *) ;; \
    esac
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc

# Copy only manifests first to leverage Docker layer caching for dependency builds.
COPY rust/Cargo.toml rust/Cargo.lock rust/
COPY rust/acmebot-acme/Cargo.toml rust/acmebot-acme/
COPY rust/acmebot-cli/Cargo.toml rust/acmebot-cli/
RUN mkdir -p rust/acmebot-acme/src rust/acmebot-cli/src \
    && echo "fn main() {}" > rust/acmebot-cli/src/main.rs \
    && echo "" > rust/acmebot-acme/src/lib.rs

WORKDIR /src/rust
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo build --release --package acmebot-cli --target "$(cat /tmp/rust_target)" || true

# Now copy the real source and build the actual binary.
COPY rust/acmebot-acme/ acmebot-acme/
COPY rust/acmebot-cli/ acmebot-cli/
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    touch acmebot-acme/src/lib.rs acmebot-cli/src/main.rs \
    && cargo build --release --package acmebot-cli --target "$(cat /tmp/rust_target)" \
    && install -Dm755 "target/$(cat /tmp/rust_target)/release/acmebot" /out/acmebot

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --shell /usr/sbin/nologin acmebot

COPY --from=build /out/acmebot /usr/local/bin/acmebot

USER acmebot
ENTRYPOINT ["/usr/local/bin/acmebot"]
CMD ["--help"]
