# Local development

## Prerequisites

Install Rust through rustup. Cargo selects the pinned toolchain and components in `rust-toolchain.toml` automatically. A C/C++ compiler and `pkg-config` are required for native dependencies. Protobuf generation uses a vendored protoc binary; a system protoc installation is unnecessary.

For the Linux GPUI Controller, provide development libraries for Fontconfig, FreeType, XCB, xkbcommon, and Wayland, together with a working graphics driver. On AlmaLinux, the relevant packages include:

```sh
sudo dnf install gcc gcc-c++ pkgconf-pkg-config fontconfig-devel freetype-devel \
  libxcb-devel libxkbcommon-devel libxkbcommon-x11-devel wayland-devel
```

Windows builds use the MSVC toolchain and Windows SDK. GPUI release builds also require the SDK's shader compiler; see [compatibility](compatibility.md).

## Start the native bootstrap

From the repository root:

```sh
cargo build --locked -p rustctrl_server -p rustctrl_agent
cargo run --locked -p rustctrl_server -- init-pki --output .local/pki
cargo run --locked -p rustctrl_server -- serve --config .local/pki/server.toml
```

The initializer creates a private CA, a Server identity, a healthcheck identity, one Controller bundle, and one Agent bundle with a generated Device ID. It refuses to overwrite an existing CA or identity. Leaf certificates expire after one year; the local CA expires after ten years. Renewal and fleet enrollment are subsequent provisioning work.

Keep the Server running, then use another terminal:

```sh
cargo run --locked -p rustctrl_agent -- console --config .local/pki/clients/agent/config.toml --once
cargo run --locked -p rustctrl_controller -- --config .local/pki/clients/controller/config.toml check
cargo run --locked -p rustctrl_controller -- --config .local/pki/clients/controller/config.toml gui
```

The GUI polls actual Server health. With the Server stopped, it reports an unavailable connection instead of displaying sample inventory. To run only the connection diagnostic on a headless machine:

```sh
cargo run --locked -p rustctrl_controller --no-default-features -- \
  --config .local/pki/clients/controller/config.toml check
```

The no-default-features build is a CLI diagnostic, not the desktop Controller. A GUI build and an actual graphical session are needed to validate the window.

Configuration paths are resolved relative to the configuration file. Generated client bundles contain their own config, certificate, key, and public CA certificate, so a bundle can be copied without changing its internal paths. Edit the endpoint and TLS domain for the host that the client will reach. Keep each Agent's Device ID paired with its issued certificate.

Use `console` without `--once` to exercise reconnect and periodic heartbeat. The console diagnostic also runs on Linux; that does not imply support for Linux endpoints in the fleet.

## Windows Service lifecycle

Build on Windows:

```powershell
cargo build --locked -p rustctrl_agent
```

Copy the Agent executable and its generated bundle to their intended locations. In an elevated PowerShell session:

```powershell
$exe = (Resolve-Path .\target\debug\rustctrl-agent.exe).Path
$config = (Resolve-Path .\.local\pki\clients\agent\config.toml).Path
$binaryPath = "`"$exe`" service --config `"$config`""
New-Service -Name RustCtrlAgent -BinaryPathName $binaryPath -StartupType Automatic
Start-Service RustCtrlAgent
Get-Service RustCtrlAgent
Stop-Service RustCtrlAgent
sc.exe delete RustCtrlAgent
```

Use absolute paths. Protect the client key with filesystem ACLs and allow the service account to read its bundle. Service mode logs to `log_file`, which defaults to `agent.log` beside the configuration. Console mode logs to stdout. Service logging is a bootstrap append-only file; configure collection and retention before long-running deployments.

The service currently maintains its authenticated heartbeat connection. Interactive desktop helpers, capture, UAC, and input handling are feature work.

## Checks

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked -p rustctrl_controller
```

The integration tests use real local TLS connections. They cover Agent identity binding, rejection of unauthenticated/untrusted clients, hostname verification, key overwrite protection, and persistence across a Server restart. Tests bind ephemeral loopback ports.

The GitHub Actions workflow separately checks Linux headless components, the AlmaLinux Controller build, Windows builds/service lifecycle, and Docker Compose startup. A configured workflow is not evidence of a completed run.
