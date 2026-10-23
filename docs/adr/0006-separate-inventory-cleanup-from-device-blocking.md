---
status: accepted
---

# Separate inventory cleanup from Device blocking

Windows Devices are automatically registered by their Agents, so deleting an inventory entry must not silently revoke an Agent's access. Devices remain listed while their Agents run and remain offline in the inventory when connectivity is lost; after Agent removal, an Admin cleans up the offline entry manually. If a still-authorized Agent reconnects after cleanup, the Device reappears with the same identity.

An Admin explicitly blocks a Device identity through the Controller to deny operational Agent access. The Device remains visible as blocked, and only an Admin can unblock it. Inventory Cleanup and revocation of an Installation Authorization are separate from Device blocking; cleanup does not lift a block.

Agent updates that retain the Device identity keep the existing inventory entry. Losing that identity during a Windows reinstall creates a new Device; an Admin can explicitly replace the previous entry rather than relying on hostname or IP matching.

This decision revises section 5.1 of the [initial brief](../../SPEC.md), which coupled inventory deletion with credential revocation. It preserves automatic inventory membership while giving Admins a separate control over operational access.
