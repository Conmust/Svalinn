# syntax=docker/dockerfile:1

# Builds all three svalinn-server binaries (the API server, the one-shot
# migration runner, and the svalinn-admin CLI) into a single small runtime
# image. The desktop client (apps/desktop) is not part of this image -- it
# is a Tauri app your users install locally, not something you self-host.
#
# The workspace also lists apps/desktop/src-tauri as a member, so Cargo
# parses its manifest to resolve the workspace graph even though this image
# never builds it; `.dockerignore` still keeps its node_modules/, gen/ and
# other huge, irrelevant directories out of the build context.

FROM rust:1-bookworm AS build
WORKDIR /app
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build -p svalinn-server --release --bins --locked \
    && cp target/release/svalinn-server target/release/svalinn-admin target/release/run-migrations /tmp/

FROM debian:bookworm-slim AS runtime
# Needed for sqlx's rustls-based TLS to validate certificates, and for the
# Resend HTTPS calls in email_delivery.rs.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends ca-certificates

RUN addgroup --system --gid 1001 svalinn \
    && adduser --system --uid 1001 --ingroup svalinn --home /app svalinn

WORKDIR /app
COPY --from=build --chown=1001:1001 /tmp/svalinn-server /tmp/svalinn-admin /tmp/run-migrations /app/
# run-migrations looks for ./migrations relative to its working directory.
COPY --chown=1001:1001 migrations ./migrations
# Where uploaded files (avatars, server icons, message attachments) land.
# Mount a volume here in production -- see the self-hosting guide.
RUN mkdir -p /app/uploads && chown 1001:1001 /app/uploads

USER svalinn:svalinn
EXPOSE 3001
LABEL org.opencontainers.image.source="https://github.com/Conmust/Svalinn"

ENTRYPOINT ["/app/svalinn-server"]
