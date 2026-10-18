FROM rust:1.99.0-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY web ./web
RUN cargo build --locked --release --bin filevault

FROM debian:bookworm-slim
ARG BUILD_VERSION=dev
LABEL org.opencontainers.image.title="FileVault" \
      io.hass.name="FileVault" \
      org.opencontainers.image.licenses="MIT" \
      io.hass.version="${BUILD_VERSION}" \
      io.hass.type="app" \
      io.hass.arch="aarch64|amd64"
RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates gosu \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 filevault \
    && useradd --uid 10001 --gid filevault --no-create-home --shell /usr/sbin/nologin filevault \
    && install -d -o filevault -g filevault /data
COPY --from=build /src/target/release/filevault /usr/local/bin/filevault
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
WORKDIR /data
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
