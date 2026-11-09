# syntax=docker/dockerfile:1
# Cairn container image.
#
#   From source (any arch, default target):  docker build -f deploy/Dockerfile -t cairn .
#   Release (prebuilt static binaries, used by .github/workflows/release.yml):
#     docker buildx build -f deploy/Dockerfile --target release \
#       --platform linux/amd64,linux/arm64 .      # expects dist/image/<arch>/cairn
#
# Both final images: static musl binary on distroless/static (CA certs + tzdata, no shell, no
# package manager), runs as uid/gid 65532 ("nonroot"), data in the /data volume, S3 on :9000.
# There is no shell for a HEALTHCHECK; probe GET /healthz and /readyz from the orchestrator.

ARG RUST_VERSION=1
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot

# ---- build from source -------------------------------------------------------------------------
FROM rust:${RUST_VERSION}-alpine AS build
# ring compiles a little C/asm; musl-dev + gcc are the only native build deps (pure-Rust policy).
RUN apk add --no-cache musl-dev gcc
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p cairn-cli \
 && install -D -m 0755 target/release/cairn /out/cairn

# ---- data dir skeleton owned by the runtime user (named volumes inherit it) --------------------
# Built on the build platform: the directory is arch-independent, so no QEMU for the other arch.
FROM --platform=$BUILDPLATFORM alpine:3 AS datadir
RUN mkdir -p /data && chown 65532:65532 /data && chmod 0750 /data

# ---- release: prebuilt binary for $TARGETARCH -------------------------------------------------
FROM ${RUNTIME_IMAGE} AS release
ARG TARGETARCH
COPY --chmod=0755 dist/image/${TARGETARCH}/cairn /usr/local/bin/cairn
COPY --from=datadir --chown=65532:65532 /data /data
USER 65532:65532
VOLUME ["/data"]
EXPOSE 9000
ENV CAIRN_DATA_DIR=/data \
    CAIRN_SERVER_LISTEN=0.0.0.0:9000
ENTRYPOINT ["/usr/local/bin/cairn"]
CMD ["serve"]

# ---- runtime (default): binary built from source above -----------------------------------------
FROM ${RUNTIME_IMAGE} AS runtime
COPY --from=build /out/cairn /usr/local/bin/cairn
COPY --from=datadir --chown=65532:65532 /data /data
USER 65532:65532
VOLUME ["/data"]
EXPOSE 9000
ENV CAIRN_DATA_DIR=/data \
    CAIRN_SERVER_LISTEN=0.0.0.0:9000
ENTRYPOINT ["/usr/local/bin/cairn"]
CMD ["serve"]
