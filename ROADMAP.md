# Roadmap

RustCtrl is intended to be a self-hosted product, with the Server operated by its deployer. This follows the existing internal-Server architecture and offline operation decisions.

## Upcoming milestones

### Next milestone: Remote Sessions and Android TV connectivity

Status: pending specification and ticket breakdown. Follows the completed staff access and Fleet Inventory milestone.

Planned capabilities:
- Unattended Remote Sessions for Windows endpoints (WebRTC media plane, screen capture, input control, single operator lock per device).
- Android TV connectivity integration (ADB and scrcpy bridge via the central Server).
- Advanced audit search and filtering.

Requirements will be synthesized into feature specifications and implementation tickets as the milestone is planned.

## Completed milestones

### Staff access and minimal Fleet Inventory

Status: completed. Feature spec [#1](https://github.com/rustctrl/rustctrl/issues/1) and all 14 implementation tickets ([#2](https://github.com/rustctrl/rustctrl/issues/2) through [#15](https://github.com/rustctrl/rustctrl/issues/15)) delivered and verified.

Delivered staff access and the minimum Fleet Inventory through the desktop Controller and shared Server, including central activity recording, trusted Windows Agent service enrollment and lifecycle management, unverified Android TV targets, and durable access controls.

#### Implementation tickets

1. [#2: Bootstrap the first Admin and sign in through the Controller](https://github.com/rustctrl/rustctrl/issues/2) (completed).
2. [#3: Create Staff Accounts and change roles through the Controller](https://github.com/rustctrl/rustctrl/issues/3) (completed).
3. [#4: Change passwords, reset staff access, and recover an existing Admin](https://github.com/rustctrl/rustctrl/issues/4) (completed).
4. [#5: Deactivate Staff Accounts without losing the last active Admin](https://github.com/rustctrl/rustctrl/issues/5) (completed).
5. [#6: Remember staff login across Controller restarts with independent sessions](https://github.com/rustctrl/rustctrl/issues/6) (completed).
6. [#7: Show the shared Windows Fleet Inventory with real heartbeat status](https://github.com/rustctrl/rustctrl/issues/7) (completed).
7. [#8: Edit Device display names and optional locations through the Controller](https://github.com/rustctrl/rustctrl/issues/8) (completed).
8. [#9: Manage Android TV connection targets as unverified inventory entries](https://github.com/rustctrl/rustctrl/issues/9) (completed).
9. [#10: Block and unblock Device identities while retaining visible inventory records](https://github.com/rustctrl/rustctrl/issues/10) (completed).
10. [#11: Clean offline inventory entries without revoking authorized Agent access](https://github.com/rustctrl/rustctrl/issues/11) (completed).
11. [#12: Replace an inventory entry explicitly after Device identity loss](https://github.com/rustctrl/rustctrl/issues/12) (completed).
12. [#13: Prepare Installation Authorization in the Controller and enroll distinct Agents automatically](https://github.com/rustctrl/rustctrl/issues/13) (completed).
13. [#14: Install and update Controller-generated Windows Agent packages as a service](https://github.com/rustctrl/rustctrl/issues/14) (completed).
14. [#15: Revoke and replace Installation Authorizations without interrupting enrolled Devices](https://github.com/rustctrl/rustctrl/issues/15) (completed).

## Architecture decisions

The existing foundation follows [centralized fleet coordination](docs/adr/0001-centralize-fleet-coordination.md) and [offline local CA bootstrap](docs/adr/0002-bootstrap-an-offline-local-ca.md).

Design decisions:

- [Local first-Admin bootstrap and recovery](docs/adr/0003-bootstrap-staff-administration-locally.md).
- [Trusted automatic Agent enrollment](docs/adr/0004-enroll-agents-through-trusted-installation.md).
- [Revocable remembered staff access](docs/adr/0005-keep-remembered-staff-access-revocable.md).
- [Separate inventory cleanup and Device blocking](docs/adr/0006-separate-inventory-cleanup-from-device-blocking.md).
- [Provision Agent credentials through a scoped issuing authority](docs/adr/0007-provision-agent-credentials-via-scoped-issuing-authority.md).

Domain terms are defined in [CONTEXT.md](CONTEXT.md). The [initial brief](SPEC.md) supplies background, not an implementation ticket for the entire project.
