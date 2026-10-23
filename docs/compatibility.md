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

`gpui` and `gpui_platform` use the same pinned Zed commit. Linux enables both X11 and Wayland; Windows uses its native platform backend. Avoid mixing a registry release of one package with a different Git revision of the other.

The pinned Linux platform crate does not forward the X11 flag to GPUI's compositor detection, so the Controller enables the Linux backend features on both crates explicitly. The GUI command requires a graphical session; use `check` for headless connection diagnostics.

Linux builds require native font and windowing libraries. Launching the Controller also requires a usable graphical session and graphics driver. A successful `cargo check` does not prove the binary links, and a successful build does not prove a window renders.

Windows release builds of the pinned GPUI backend require `fxc.exe` from the Windows SDK. Install that SDK or configure `GPUI_FXC_PATH` if automatic discovery fails. A Rust Windows target installed on Linux does not provide the Windows linker, SDK, or a running Windows environment.

Sources: [pinned GPUI README](https://github.com/zed-industries/zed/blob/66ed3027b8ca7fed0feeee91d1ce6346ccd4ac39/crates/gpui/README.md), [pinned Windows build script](https://github.com/zed-industries/zed/blob/66ed3027b8ca7fed0feeee91d1ce6346ccd4ac39/crates/gpui_windows/build.rs).

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
