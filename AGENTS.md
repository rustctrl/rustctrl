# Repository instructions

<!-- codebase-memory-mcp:start -->
For structural codebase exploration, use the installed `codebase-memory` skill.
<!-- codebase-memory-mcp:end -->

## Scope and sources

RustCtrl coordinates Windows computers and Android TVs through a Linux Server and a desktop Controller for Windows and Linux, including AlmaLinux. The current code establishes the project foundation. Keep implementation within the active request or ticket; planned capabilities in the initial brief do not authorize additional feature work.

Write repository documentation, ADRs, context documents, specifications, and issue bodies in English. Follow the user's language in conversation.

- Before domain or architecture work and codebase exploration, read [domain conventions](docs/agents/domain.md), then the relevant context and ADRs it points to. Surface conflicts with an accepted ADR.
- Before planning delivery, check `ROADMAP.md` if it exists. Use it for milestones, ordering, dependencies, and progress. Keep feature requirements and acceptance criteria in GitHub Issues, and architectural choices with their rationale in ADRs. Link to those sources instead of copying their detail into the roadmap. Create or revise the roadmap when planning work or when an accepted plan changes.
- Before locating specifications or operating on GitHub Issues, read [issue tracker conventions](docs/agents/issue-tracker.md). `SPEC.md` is the initial brief; published feature specs and implementation tickets define their current scope.
- Before triaging or changing labels, read [triage label mapping](docs/agents/triage-labels.md).

## Component boundaries

- Keep shared identities and configuration in `rustctrl_core`, wire contracts in `rustctrl_protocol`, and shared TLS client setup in `rustctrl_network`. Keep these independent of GPUI and platform APIs.
- Keep the Server and Agent headless. Isolate desktop UI in `rustctrl_controller`, Windows APIs in `rustctrl_windows_native` or Windows-gated Agent service code, and Android integration in `rustctrl_android`.
- The Agent's Linux console mode is a protocol diagnostic. Fleet endpoint support remains Windows computers and Android TVs.
- Place future media and management-task implementations in their respective crates when their tickets authorize them. Preserve empty integration crates until there is real behavior to implement.
- Edit protobuf definitions under `crates/rustctrl_protocol/proto/`; `build.rs` generates bindings into Cargo's output directory. Keep generated bindings out of source control.

## Rust and native dependencies

- Use the pinned toolchain and `--locked` Cargo commands. Keep `Cargo.lock` committed and make dependency updates intentional.
- Keep GPUI and `gpui_platform` on the same pinned revision. Linux Controller builds need X11 and Wayland features on both dependencies; consult [compatibility notes](docs/compatibility.md) before changing them.
- Keep platform-specific dependencies and APIs behind target configuration. Wrap native resources with explicit ownership and cleanup; document each unsafe block's safety requirements.
- Keep network and blocking work off the GPUI event loop. Release synchronous lock guards before awaiting and preserve cancellation during connection retries and shutdown.

## Credentials, state, and containers

- Use `.local/` for development credentials, bundles, native dependency extracts, and scratch output. Use `config/*.example.toml` and `.env.example` for sanitized templates; keep real deployment settings local.
- Preserve mutual TLS, hostname verification, and the binding between an Agent's certificate and Device ID. Component credentials do not replace staff account authentication.
- Keep the CA private key outside Server runtime mounts. Preserve the non-root container, read-only root filesystem, and separate state and credential volumes described in [deployment](docs/deployment.md).
- When changing container inputs, update `.dockerignore` with the Dockerfile. Include every workspace member needed by Cargo resolution and exclude local state and credentials. Git and Docker ignore rules are independent.

## Verification and handoff

Read [development](docs/development.md) for prerequisites and check commands. Keep the CI checks in [foundation.yml](.github/workflows/foundation.yml) aligned with documented commands when changing the build. Update its path routing when adding crates or changing which components a job validates.

- Match verification to the changed behavior. For documentation, comments, or metadata-only edits, inspect the diff and check relevant links or formatting; skip Cargo builds, tests, and application startup. For code changes, use the narrowest lint, test, or build that covers the edit. Run the affected application only when its runtime behavior or platform integration needs validation.
- Run broader package or workspace checks when changes cross crate boundaries or affect shared protocol, identity, TLS, persistence, dependencies, or build configuration. Avoid rerunning checks that do not cover the change or whose result is already established for the same unchanged inputs.
- For container changes, build the Server image and run `scripts/smoke-compose.sh`. The script uses its own temporary Compose project and removes its volumes; keep manual checks isolated from deployment data.
- Verify Controller changes with default GUI features on the affected platform. A headless diagnostic build does not validate the desktop window. Treat Windows service lifecycle checks separately from Linux console checks.
- Report checks actually run and their results. Briefly explain any relevant check skipped because the change does not affect its behavior. Distinguish Podman checks from Docker Engine checks, and builds from graphical runtime validation. Record compatibility findings in [compatibility notes](docs/compatibility.md).
- Before committing, inspect staged paths and the diff for private material, local state, and build output. Include source changes, relevant checks, and documentation together; retain unrelated working-tree edits.
