# Twofold -- multi-stage build
# Build stage: compile from source on Rust official image
# Runtime stage: minimal Debian bookworm-slim
#
# Base image digests pinned for reproducibility and supply-chain safety.
# To update: pull the new tag, get the digest with `docker inspect --format='{{index .RepoDigests 0}}'`
# and update both FROM lines below.
#
# Dependencies:
#   Build: pkg-config, libssl-dev (for reqwest / openssl-sys)
#   Runtime: libssl3, ca-certificates (reqwest TLS)
#   SQLite: compiled in via rusqlite "bundled" feature -- no system SQLite needed
#   Templates/assets: compiled in via askama + include_str! -- no runtime files

FROM rust:1.88-slim-bookworm@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89 AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      pkg-config \
      libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim@sha256:0104b334637a5f19aa9c983a91b54c89887c0984081f2068983107a6f6c21eeb

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      libssl3 \
      curl \
    && rm -rf /var/lib/apt/lists/*

# Explicit UID/GID 999 -- matches chown applied to the Docker volume during migration.
# Do NOT change without also updating the volume ownership step.
RUN groupadd -r -g 999 twofold && \
    useradd -r -u 999 -g 999 -d /data -s /sbin/nologin twofold

COPY --from=builder /build/target/release/twofold /usr/local/bin/twofold

# Data directory for SQLite DB
RUN mkdir -p /data && chown twofold:twofold /data
VOLUME /data

USER twofold

ENV TWOFOLD_BIND=0.0.0.0:3030
ENV TWOFOLD_DB_PATH=/data/twofold.db
ENV TWOFOLD_BASE_URL=https://share.hearth.observer
ENV TWOFOLD_DEFAULT_THEME=hearth

EXPOSE 3030

CMD ["twofold", "serve"]
