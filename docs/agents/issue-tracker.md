# Issue tracker: GitHub

Feature specs and implementation tickets live in GitHub Issues for `rustctrl/rustctrl`. Use the `gh` CLI and pass `--repo rustctrl/rustctrl` for issue and PR operations.

## From initial brief to specs and tickets

`SPEC.md` is the initial project brief. Use it and the current discussion as inputs to the Matt Pocock engineering skills; refine requirements and technical details through those workflows.

- `to-spec` synthesizes the discussion into a feature spec and publishes it as a GitHub issue.
- `to-tickets` breaks a plan or spec into implementation tickets, with acceptance criteria, parent references, and blocking relationships.
- `triage` evaluates issues using the label mapping in `docs/agents/triage-labels.md`.

For a feature with a published spec, read its issue body, comments recording decisions, and linked implementation tickets. Use the current spec and ticket scope for implementation. Keep requirements traceable to their parent spec; surface conflicts between tickets, the spec, or the initial brief so they can be resolved explicitly.

The setup records these conventions. Specs and tickets are created when the corresponding workflow is invoked.

## Issue operations

Use [Git conventions](git.md) for issue titles, branch names, commit messages, and pull requests.

- Create: `gh issue create --repo rustctrl/rustctrl --title "..." --body-file /path/to/body.md`.
- Read, including comments: `gh issue view <number> --repo rustctrl/rustctrl --comments`.
- List: `gh issue list --repo rustctrl/rustctrl --state open --json number,title,body,labels,comments`, adding label and state filters as needed.
- Comment: `gh issue comment <number> --repo rustctrl/rustctrl --body-file /path/to/comment.md`.
- Apply or remove labels: `gh issue edit <number> --repo rustctrl/rustctrl --add-label "..."` or `--remove-label "..."`.
- Assign: `gh issue edit <number> --repo rustctrl/rustctrl --add-assignee @me`.
- Close: `gh issue close <number> --repo rustctrl/rustctrl`.

Write multiline bodies to a temporary UTF-8 file and pass it with `--body-file`. Read the label mapping in `docs/agents/triage-labels.md` before applying triage labels.

When a skill says "publish to the issue tracker", create a GitHub issue. When it says "fetch the relevant ticket", read the issue and its comments.

## Pull requests as a triage surface

**PRs as a request surface: no.**

If this flag is changed to `yes`, use `gh pr view`, `gh pr diff`, `gh pr list`, `gh pr comment`, `gh pr edit`, and `gh pr close` for the corresponding operations. Scope the external PR queue to authors whose `authorAssociation` is `CONTRIBUTOR`, `FIRST_TIME_CONTRIBUTOR`, or `NONE`.

GitHub issues and PRs share a number space. Resolve an ambiguous number with `gh pr view <number> --repo rustctrl/rustctrl`, falling back to `gh issue view`.

## Wayfinding operations

For skills that use a map and child tickets:

- The map is one issue labelled `wayfinder:map`, containing notes, decisions, and open questions.
- Child tickets are linked as GitHub sub-issues. If sub-issues are unavailable, add children to a task list in the map body and put `Part of #<map>` at the top of each child body.
- Child labels are `wayfinder:research`, `wayfinder:prototype`, `wayfinder:grilling`, or `wayfinder:task`.
- Represent blockers with native issue dependencies. Add a dependency using `gh api --method POST repos/rustctrl/rustctrl/issues/<child>/dependencies/blocked_by -F issue_id=<blocker-db-id>`. Fetch the blocker's database ID with `gh api repos/rustctrl/rustctrl/issues/<number> --jq .id`; use that ID rather than the issue number or node ID.
- If dependencies are unavailable, put `Blocked by: #<number>, #<number>` at the top of the child body.
- A ticket is available when it is open, unassigned, and has no open blockers. Select the first eligible ticket in map order.
- Claim by assigning the ticket to the driving developer. Resolve by posting the answer, closing the ticket, and adding a short finding with a link to the map's decisions.
