# Compatibility and verification

## Intended foundation targets

| Component | Target | Validation |
| --- | --- | --- |
| Controller | Windows x86_64, MSVC | Native build configured in CI; graphical startup requires a desktop session. |
| Controller | AlmaLinux x86_64 | GPUI supports X11/Wayland; record the actual OS, GPU, driver, and session used for runtime tests. |
| Server | Linux x86_64, native or Compose container | Exercise real TLS, persistence, restart, and container health. |
| Agent | Windows x86_64, MSVC | Build plus Service Control Manager start/stop checks. |
| Agent console diagnostic | Linux x86_64 | Protocol testing only; Linux fleet endpoints are outside the initial brief. |

The checked-in CI configuration is a recipe for verification, not a claim that GitHub Actions has run successfully. Record actual local and CI results separately.

## GPUI version and graphics

The Controller uses `gpui-kit` 0.8.1, which supplies matching `gpui-pre` and `gpui-pre-platform` 0.3.10 dependencies. Its desktop platform enables X11 and Wayland on Linux and the native backend on Windows. The GUI command requires a graphical session; use `check` for headless connection diagnostics.

Linux builds require native font and windowing libraries. Launching the Controller also requires a usable graphical session and graphics driver. A successful `cargo check` does not prove the binary links, and a successful build does not prove a window renders.

Windows release builds of the GPUI backend require `fxc.exe` from the Windows SDK. Install that SDK or configure `GPUI_FXC_PATH` if automatic discovery fails. A Rust Windows target installed on Linux does not provide the Windows linker, SDK, or a running Windows environment.



## Feature validation remains separate

This foundation does not establish support for Android TV remote after reboot, Windows login/UAC capture and input, media relay, inter-VLAN device discovery, deployment tasks, or monitor automation. Those requirements remain in the first-release brief and need their own implementations and acceptance evidence.

Before claiming fleet compatibility, record TV model/firmware, Windows edition, AlmaLinux version, application/monitor configuration, routing/firewall rules, and performance measurements for the relevant feature tests.

## Local verification on 2026-10-23

Environment: AlmaLinux 10.2 x86_64, Rust 1.98.1, Podman 5.8.2, and podman-compose 1.5.0.

- Workspace format, strict Clippy checks, and tests passed. The two integration tests exercise real mutual TLS, identity checks, key overwrite protection, and persistent bootstrap state.
- The native GPUI Controller binary compiled and linked. The host lacked `libxkbcommon-x11-devel`; verified AlmaLinux RPMs were extracted into an ignored local directory and supplied through the linker's search path. Install the development prerequisites in `development.md` for a normal system build.
- The full GUI build's `check` command connected to a native Server over TLS. The Agent sent a heartbeat and exited successfully on Ctrl+C; the Server exited successfully on SIGTERM.
- The Server image built successfully. Compose initialized credentials, started a non-root Server, passed TLS health checks, accepted an Agent heartbeat, and retained its bootstrap record after restart. This was tested through Podman Compose, not Docker Engine.
- Stable graphical startup remains pending on a real desktop. An isolated Weston/Xwayland test reached Vulkan initialization, but the virtual compositor failed before a stable frame could be inspected. This is not a visual acceptance pass.
- Native Windows builds and Service Control Manager start/stop checks remain pending on a Windows runner. The CI workflow is configured, but was not triggered during this local setup.

## Issue #14 Verification on 2026-10-26 (Windows Agent Package & Service Lifecycle)

Environment: Linux x86_64, Rust 1.98.1 pinned toolchain.

- **Package Generation**: Verified Controller CLI (`export-agent-package`) and GUI modal overlay (`Export Package`) packaging logic. Generates compliant PKZIP 2.0 uncompressed archives and directory trees containing `rustctrl-agent.exe`, `artifact.toml`, `install.ps1`, `uninstall.ps1`, and `README.txt`.
- **Packaging and Lifecycle Tests**: `crates/rustctrl_agent/tests/enrollment.rs` (`controller_package_export_to_agent_service_lifecycle_restart_and_update`) verified:
  - Admin authentication and Installation Authorization preparation via StaffAuth gRPC.
  - Package export to `.zip` with CRC-32 verification and entry inspection.
  - Service installation and automatic enrollment via `ServiceOptions::load_or_enroll`.
  - Heartbeat and inventory appearance on Server.
  - Service restart and computer reboot simulation reusing existing `config.toml` (retaining Device ID).
  - Identity-preserving binary update (replacing executable retains local identity without duplicate inventory entries).
  - Distinct multi-PC enrollment from the same package producing distinct Device IDs in Fleet Inventory.
- **Service Management & Hardening**:
  - `install_service` enforces Windows ACLs (`*S-1-5-18`, `*S-1-5-32-544`) restricting directory access to SYSTEM and BUILTIN\Administrators.
  - `install.ps1` configures Windows service `RustCtrlAgent` with `Automatic` startup and restart failure recovery.
  - `uninstall.ps1` and `uninstall` command stop and remove the service from SCM while preserving local credentials and Device identity; endpoint remains offline in Fleet Inventory until Admin cleanup.
- **Platform Limitations & Evidence**:
  - Linux builds, tests, and headless controller diagnostics (`cargo test --locked --workspace --exclude rustctrl_controller`, `cargo test --locked -p rustctrl_controller`, `cargo clippy`, `cargo fmt`) passed locally.
  - Physical Windows PC execution with desktop GUI and interactive Windows Service Control Manager was unavailable in this Linux host and was not run locally; Windows SCM lifecycle is gated and validated via the `windows-latest` GitHub Actions workflow.

## Issue #47 verification on 2026-10-28

On Linux x86_64 with Rust 1.98.1, the Controller with GPUI Kit built and passed strict Clippy and the workspace test suite. These checks do not validate graphical rendering. Native Windows MSVC and interactive X11 and Wayland sessions were not available for this verification.
