# Domain docs

This repository uses a single-context layout:

```text
CONTEXT.md
docs/adr/
```

## Before exploration and design work

Read root `CONTEXT.md` for domain terms and `docs/adr/` entries relevant to the area being changed. Read `docs/agents/issue-tracker.md` for the rules on locating current feature specs and implementation tickets.

If `CONTEXT.md` or the ADR directory does not exist, proceed silently. Create domain documents when terminology or architectural decisions are resolved through the `domain-modeling` workflow; setup does not create placeholders.

## Vocabulary

Use the terms defined in `CONTEXT.md` in issue titles, design proposals, code, and tests. If a needed concept is absent, determine whether an existing term fits. Record a genuine terminology gap for domain modeling.

## Architecture decisions

Report conflicts with an existing ADR explicitly, identifying the decision and why it needs reconsideration. Keep system decisions in root `docs/adr/`.

A future split into multiple contexts requires an explicit layout change, a root `CONTEXT-MAP.md`, and updates to these consumer rules.
