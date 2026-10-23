# Roadmap

RustCtrl is intended to be a self-hosted product, with the Server operated by its deployer. This follows the existing internal-Server architecture and offline operation decisions.

## Next milestone: staff access and fleet inventory

Status: design interview closed; consolidated scope confirmed by the user on 2026-10-23. Feature spec published as [#1](https://github.com/rustctrl/rustctrl/issues/1); a proposed 14-ticket breakdown awaits user review before publication.

Deliver staff access and the minimum Fleet Inventory through the desktop Controller and shared Server, including central activity recording. Remote Sessions, Android TV connectivity integration, and advanced audit search/filter views follow this milestone. RustCtrl operates independently of the office's separate asset inventory application. Windows Devices join automatically through trusted Agent installation; Android TVs are added manually as unverified connection targets.

Feature requirements and acceptance criteria live in [Spec: self-hosted staff access and minimal Fleet Inventory](https://github.com/rustctrl/rustctrl/issues/1). No implementation tickets have been published for this milestone yet. Implementation ticket breakdown precedes application changes.

The existing foundation follows [centralized fleet coordination](docs/adr/0001-centralize-fleet-coordination.md) and [offline local CA bootstrap](docs/adr/0002-bootstrap-an-offline-local-ca.md).

Design decisions:

- [Local first-Admin bootstrap and recovery](docs/adr/0003-bootstrap-staff-administration-locally.md).
- [Trusted automatic Agent enrollment](docs/adr/0004-enroll-agents-through-trusted-installation.md).
- [Revocable remembered staff access](docs/adr/0005-keep-remembered-staff-access-revocable.md).
- [Separate inventory cleanup and Device blocking](docs/adr/0006-separate-inventory-cleanup-from-device-blocking.md).

Domain terms are defined in [CONTEXT.md](CONTEXT.md). The [initial brief](SPEC.md) supplies background, not an implementation ticket for the entire project.
