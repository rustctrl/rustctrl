# Roadmap

RustCtrl is intended to be a self-hosted product, with the Server operated by its deployer. This follows the existing internal-Server architecture and offline operation decisions.

## Next milestone: staff access and fleet inventory

Status: design and ticket breakdown approved. Feature spec [#1](https://github.com/rustctrl/rustctrl/issues/1) and 14 implementation tickets are published; implementation has not started.

Deliver staff access and the minimum Fleet Inventory through the desktop Controller and shared Server, including central activity recording. Remote Sessions, Android TV connectivity integration, and advanced audit search/filter views follow this milestone. RustCtrl operates independently of the office's separate asset inventory application. Windows Devices join automatically through trusted Agent installation; Android TVs are added manually as unverified connection targets.

Feature requirements and acceptance criteria live in [Spec: self-hosted staff access and minimal Fleet Inventory](https://github.com/rustctrl/rustctrl/issues/1) and its implementation tickets below. Blocking relationships are recorded natively in GitHub and in each ticket body. Start with [#2](https://github.com/rustctrl/rustctrl/issues/2), then select an open, unassigned ticket whose blockers are all closed.

## Implementation tickets

1. [#2: Bootstrap the first Admin and sign in through the Controller](https://github.com/rustctrl/rustctrl/issues/2).
2. [#3: Create Staff Accounts and change roles through the Controller](https://github.com/rustctrl/rustctrl/issues/3).
3. [#4: Change passwords, reset staff access, and recover an existing Admin](https://github.com/rustctrl/rustctrl/issues/4).
4. [#5: Deactivate Staff Accounts without losing the last active Admin](https://github.com/rustctrl/rustctrl/issues/5).
5. [#6: Remember staff login across Controller restarts with independent sessions](https://github.com/rustctrl/rustctrl/issues/6).
6. [#7: Show the shared Windows Fleet Inventory with real heartbeat status](https://github.com/rustctrl/rustctrl/issues/7).
7. [#8: Edit Device display names and optional locations through the Controller](https://github.com/rustctrl/rustctrl/issues/8).
8. [#9: Manage Android TV connection targets as unverified inventory entries](https://github.com/rustctrl/rustctrl/issues/9).
9. [#10: Block and unblock Device identities while retaining visible inventory records](https://github.com/rustctrl/rustctrl/issues/10).
10. [#11: Clean offline inventory entries without revoking authorized Agent access](https://github.com/rustctrl/rustctrl/issues/11).
11. [#12: Replace an inventory entry explicitly after Device identity loss](https://github.com/rustctrl/rustctrl/issues/12).
12. [#13: Prepare Installation Authorization in the Controller and enroll distinct Agents automatically](https://github.com/rustctrl/rustctrl/issues/13).
13. [#14: Install and update Controller-generated Windows Agent packages as a service](https://github.com/rustctrl/rustctrl/issues/14).
14. [#15: Revoke and replace Installation Authorizations without interrupting enrolled Devices](https://github.com/rustctrl/rustctrl/issues/15).

## Architecture decisions

The existing foundation follows [centralized fleet coordination](docs/adr/0001-centralize-fleet-coordination.md) and [offline local CA bootstrap](docs/adr/0002-bootstrap-an-offline-local-ca.md).

Design decisions:

- [Local first-Admin bootstrap and recovery](docs/adr/0003-bootstrap-staff-administration-locally.md).
- [Trusted automatic Agent enrollment](docs/adr/0004-enroll-agents-through-trusted-installation.md).
- [Revocable remembered staff access](docs/adr/0005-keep-remembered-staff-access-revocable.md).
- [Separate inventory cleanup and Device blocking](docs/adr/0006-separate-inventory-cleanup-from-device-blocking.md).
- [Provision Agent credentials through a scoped issuing authority](docs/adr/0007-provision-agent-credentials-via-scoped-issuing-authority.md).

Domain terms are defined in [CONTEXT.md](CONTEXT.md). The [initial brief](SPEC.md) supplies background, not an implementation ticket for the entire project.
