# RustCtrl

RustCtrl is a desktop control system for an office fleet of Windows computers and Android TVs. Staff use a Rust/GPUI Controller on Windows or AlmaLinux, backed by an internal Linux Server.

This repository currently contains the **project foundation**: the Cargo workspace, a GPUI connection window, a Linux bootstrap Server, a Windows Agent service entrypoint, local CA tooling, mutually authenticated health/heartbeat RPCs, persistent bootstrap state, and a Compose deployment.

Remote desktop, Android TV integration, staff login, management tasks, package deployment, and monitor automation remain feature work. The Android, media, task, and native Windows integration crates currently define their boundaries only. All planned features remain in the first-release scope described by the initial brief.

## Getting started

- [Local development](docs/development.md): build the workspace, initialize a local CA, and run the components.
- [Server deployment](docs/deployment.md): build and run the Linux Server with Docker Compose.
- [Compatibility and verification](docs/compatibility.md): platform requirements and limits of the available tests.

The pinned toolchain is declared in `rust-toolchain.toml`. Commit `Cargo.lock` with dependency changes. The Server and Agent do not depend on GPUI.

## Project documents

- [SPEC.md](SPEC.md) is the initial project brief.
- Feature specs and implementation tickets are developed through the Matt Pocock skills and tracked in [GitHub Issues](https://github.com/rustctrl/rustctrl/issues).
- [CONTEXT.md](CONTEXT.md) defines domain vocabulary; [ADRs](docs/adr/) record consequential decisions.
- [AGENTS.md](AGENTS.md) provides the repository's agent instructions.

ADRs, context documents, READMEs, and specifications are written in English.
