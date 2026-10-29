# Builds linux/amd64 binaries for the cluster. Runs natively on the build
# host and cross-compiles when it isn't amd64, which is much faster than
# emulation. Output only, used with `docker buildx build --output`.
FROM --platform=$BUILDPLATFORM rust:1-bookworm AS build
ARG BUILDARCH
RUN if [ "$BUILDARCH" != amd64 ]; then \
      apt-get update && apt-get install -y --no-install-recommends gcc-x86-64-linux-gnu libc6-dev-amd64-cross; \
    fi && rustup target add x86_64-unknown-linux-gnu
# `--build-arg CARGO_PROFILE_RELEASE_DEBUG=true` adds symbols for profiling.
ARG CARGO_PROFILE_RELEASE_DEBUG=false
ENV CARGO_PROFILE_RELEASE_DEBUG=$CARGO_PROFILE_RELEASE_DEBUG \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc \
    CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    if [ "$BUILDARCH" = amd64 ]; then unset CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER CC_x86_64_unknown_linux_gnu; fi && \
    cargo build --release --target x86_64-unknown-linux-gnu \
      -p tunnel-server -p tunnel-client -p tunnel-bench && \
    mkdir /out && cp target/x86_64-unknown-linux-gnu/release/tunnel-server \
      target/x86_64-unknown-linux-gnu/release/tunnel-client \
      target/x86_64-unknown-linux-gnu/release/tunnel-bench /out/

FROM scratch
COPY --from=build /out/ /
