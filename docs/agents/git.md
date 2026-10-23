# Git conventions

Write issue titles and bodies, branch names, commit messages, and pull requests in English. Use the domain vocabulary from `CONTEXT.md`. Apply these naming rules to new work; existing issues, branches, and commit history can keep their names.

## Issue titles

Use `<kind>: <outcome>` with the kinds below. Describe the observable result or failure in sentence case.

| Kind | Use | Example |
| --- | --- | --- |
| `Spec` | Feature specification | `Spec: self-hosted staff access and minimal Fleet Inventory` |
| `Task` | Implementation ticket | `Task: bootstrap the first Admin and sign in through the Controller` |
| `Bug` | Reported incorrect behavior | `Bug: blocked Agent can still send heartbeat` |
| `Docs` | Documentation work | `Docs: explain offline Server deployment` |
| `Chore` | Maintenance without a user-facing feature or bug | `Chore: refresh pinned native build dependencies` |

Keep an implementation ticket's parent spec, acceptance criteria, and blockers in its body and tracker relationships. Naming does not replace the label mapping or dependency rules in [issue tracker conventions](issue-tracker.md).

## Branches

Use `<type>/<issue-number>-<short-kebab-case-summary>`, for example:

- `feat/2-bootstrap-staff-login`
- `fix/10-enforce-device-block`
- `docs/42-update-deployment-guide`

Use a type from the commit table below. The issue number is the implementation ticket's number rather than its parent spec's number. For work without an issue, use `<type>/<short-kebab-case-summary>`, such as `docs/git-conventions-pr-template`; a naming rule alone does not require creating an issue.

Start a focused branch from the latest `main`. Before starting a blocked ticket, confirm its blockers are complete and their changes are present in the branch base. Use a separate branch for each implementation ticket; explain any necessary combined scope in the PR.

## Commit messages and PR titles

Use Conventional Commits-style titles:

```text
type(scope): imperative summary
```

The scope is optional. Use lowercase types and scopes, an imperative summary such as "add" or "fix", and no trailing period. Preserve canonical domain terms such as Admin, Agent, and Device ID in the summary.

| Type | Use |
| --- | --- |
| `feat` | Add user-visible behavior |
| `fix` | Correct a bug |
| `docs` | Change documentation, agent instructions, or contribution templates |
| `refactor` | Restructure code while preserving behavior |
| `test` | Add or improve tests without changing production behavior |
| `perf` | Improve performance without changing intended behavior |
| `build` | Change dependencies, toolchains, native builds, packaging, or container builds |
| `ci` | Change CI workflows or check routing |
| `chore` | Other repository maintenance |
| `revert` | Revert an earlier change |

For component-specific work, use `server`, `agent`, `controller`, `core`, `protocol`, `network`, `android`, `tasks`, `media`, or `windows-native` as the scope. Use `deps`, `packaging`, or another concise scope when that identifies the change more clearly. Omit the scope when the change spans components.

Examples:

```text
feat: bootstrap staff login through the Controller
fix(agent): retain Device ID across service restart
docs: add Git conventions and a pull request template
ci: route Controller changes to platform builds
```

Use `!` before the colon and a `BREAKING CHANGE:` footer when compatibility actually breaks. Describe the affected configuration, wire contract, or persistent data and the required migration. Do not mark every protocol or schema addition as breaking.

Keep commits focused and include the source, checks, and documentation needed for the change. Run `cargo fmt --all --check` before committing Rust changes. Put issue references in commit bodies or footers, such as `Refs #2`, rather than making issue numbers part of the title format. Preserve unrelated working-tree changes and inspect staged content before committing.

## Pull requests and merging

Target `main` and describe the final scope using the [pull request template](../../.github/pull_request_template.md). Lead with the concrete problem and resulting behavior. Keep the description short for a small change; include more detail only when it helps assess the implementation, compatibility, or verification.

Use `Closes #<implementation-ticket>` only when the PR completes that ticket's acceptance criteria. Use `Refs #<spec>` for the parent spec and `Refs` for partial work. A single implementation PR should not automatically close the parent feature spec.

Record checks actually run, their environment and results, and relevant checks skipped with a reason. Use [development checks](../development.md) and the verification rules in `AGENTS.md` to choose evidence. For documentation-only changes, inspect formatting, links, and the diff; Cargo builds and application startup are unnecessary.

Prefer squash merge for a focused implementation ticket. The final PR title should be suitable as the squash commit title. Follow the repository's enabled merge methods and required checks; documentation does not change GitHub protection settings. Update the title and body if the final scope changes, and verify issue-closing references before merging.
