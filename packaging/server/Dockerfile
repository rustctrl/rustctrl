FROM docker.io/library/rust:1.98.1-bookworm AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
ENV CARGO_BUILD_JOBS=2
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --locked --release --package rustctrl_server \
    && cp target/release/rustctrl-server /build/rustctrl-server

FROM docker.io/library/debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 rustctrl \
    && useradd --uid 10001 --gid 10001 --no-create-home rustctrl \
    && install -d -m 0700 -o 10001 -g 10001 /data /tls /pki
COPY --from=build /build/rustctrl-server /usr/local/bin/rustctrl-server
COPY config/server.compose.example.toml /etc/rustctrl/server.toml
USER 10001:10001
EXPOSE 9876
ENTRYPOINT ["rustctrl-server"]
CMD ["serve", "--config", "/etc/rustctrl/server.toml"]
