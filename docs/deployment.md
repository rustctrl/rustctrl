# Linux Server deployment

The foundation uses one headless Server container with SQLite state in a named volume. Docker Compose is the deployment interface. Podman Compose can be used for local checks; validate against Docker Compose v2 on the actual host as well.

## Initialize and start

```sh
cp .env.example .env
docker compose build server
docker compose --profile tools run --rm pki-init
docker compose up -d server
docker compose ps
docker compose exec -T server rustctrl-server healthcheck --tls-dir /tls
```

The loopback defaults are for a local smoke test. Before initializing certificates on an office host, set `.env` to the host's real internal name, reachable IP, and endpoint. For example:

```dotenv
RUSTCTRL_LISTEN_ADDRESS=10.10.10.5
RUSTCTRL_PORT=9876
RUSTCTRL_SERVER_NAME=rustctrl.office.internal
RUSTCTRL_SERVER_IP=10.10.10.5
RUSTCTRL_SERVER_ENDPOINT=https://rustctrl.office.internal:9876
```

Clients must resolve that internal name and reach the host through the office routing/firewall. The bootstrap control port is `9876/TCP`; no ADB or media ports are exposed by this foundation. Changing the port does not require issuing a new certificate, but changing the certified host names/IPs requires an appropriate certificate.

Image building and dependency acquisition require internet access initially. Once the image and generated credentials are available locally, startup, TLS, health, heartbeat, and database operations use internal resources only. For a host without internet access, build elsewhere and transfer the image:

```sh
docker save rustctrl-server:local > rustctrl-server-image.tar
# On the offline host:
docker load < rustctrl-server-image.tar
```

Then run initialization and startup with the Compose file, environment, and image already present; skip `docker compose build` on that host.

## Data and credentials

Compose creates three separate named volumes:

| Volume | Purpose | Server access |
| --- | --- | --- |
| `server-data` | SQLite database and WAL files | Read/write |
| `server-tls` | Server identity, public CA, and local healthcheck identity | Read-only |
| `admin-pki` | CA private key and generated client bundles | Not mounted in the Server |

The image runs as UID/GID 10001 with a read-only root filesystem. Initialization uses the same identity to populate writable named volumes. The Server handles SIGTERM for graceful shutdown. Compose applies a restart policy and a mutually authenticated healthcheck.

Initialization is a one-time operation and does not overwrite existing keys. Restarting the Server reuses its credentials and data. `docker compose down` retains named volumes; `docker compose down --volumes` deletes them, including the CA and database.

## Export the initial client bundles

The foundation generates one Controller identity and one Agent identity. Treat these as bootstrap credentials; per-staff login and production fleet enrollment are separate features. Distribute each bundle only to its intended holder.

```sh
mkdir -p .local/bundles
umask 077
docker compose --profile tools run --rm -T --entrypoint tar pki-init \
  -C /pki/clients -cf - controller > .local/bundles/controller.tar
docker compose --profile tools run --rm -T --entrypoint tar pki-init \
  -C /pki/clients -cf - agent > .local/bundles/agent.tar
tar -xf .local/bundles/controller.tar -C .local/bundles
tar -xf .local/bundles/agent.tar -C .local/bundles
```

Run the native Controller or Agent with the exported `config.toml`. The CA private key stays in the administrative volume. Back up it and the client identities securely. Back up the database using a SQLite-aware method or while the Server is stopped; copying a live database without its WAL state is insufficient.

An existing office CA can be used instead of the initializer. Supply a server-auth certificate with the proper DNS/IP SANs, a public CA bundle, and client-auth certificates trusted by that CA. Heartbeat clients also need a DNS SAN of `<device-id>.agent.rustctrl.internal` matching the configured UUID. Preserve the filenames and mount paths expected by `config/server.compose.example.toml`.

## Container smoke test

After installing the Rust toolchain and container engine:

```sh
scripts/smoke-compose.sh
```

The script uses a separate temporary Compose project, checks startup and TLS health, sends a real Agent heartbeat, restarts the Server, and checks that the bootstrap record persists. It removes only its own temporary containers and volumes. Set `RUSTCTRL_SKIP_IMAGE_BUILD=1` to test an image that has already been built.

Docker Compose availability, image builds, startup checks, and actual graphical/Windows validation are separate results; see [compatibility](compatibility.md).
