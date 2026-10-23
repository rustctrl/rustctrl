## Summary

<!-- Describe the concrete problem and resulting behavior. Explain any scope change or consequential trade-off. One or two sentences are enough for a small PR. -->

## Related issues

<!-- Use Closes #<implementation-ticket> only when its acceptance criteria are complete. Use Refs #<parent-spec> or Refs #<ticket> for partial work. For work without an issue, write None. -->

## Verification

<!-- List checks actually run, their results, and relevant checks skipped with a reason. Choose the narrowest checks that cover the change using docs/development.md and AGENTS.md. Documentation-only changes need diff, formatting, and link review; skip Cargo builds and application startup. -->

| Check or command | Environment | Result / evidence |
| --- | --- | --- |
| | | |

<!-- Controller changes: use default GUI features on the affected platform. Distinguish build success from graphical runtime validation; include screenshots or a short recording for visible changes when useful. Record OS/architecture and X11/Wayland where relevant. A headless diagnostic does not validate the desktop window. -->

<!-- Windows Agent changes: distinguish actual Windows service lifecycle evidence from Linux console diagnostics. -->

<!-- Container changes: report the Server image build and isolated scripts/smoke-compose.sh run. Name the container engine; Docker Engine and Podman results are distinct. -->

<!-- Shared identity, protocol, TLS, persistence, dependency, or build changes: include the relevant broader package/workspace checks. Describe authorization/revocation or migration behavior when changed. Never include real credentials, tokens, private keys, or local deployment settings in evidence. -->

## Compatibility and follow-up

<!-- State material risks, configuration/wire/storage compatibility changes, migration or recovery steps, and known verification gaps. Link affected ADRs, deployment docs, or compatibility findings when applicable. Link follow-up issues for remaining work. Write None if there are no relevant changes or follow-ups. -->
