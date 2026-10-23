---
status: accepted
---

# Enroll Agents through trusted installation

Self-hosted deployments need Windows Devices to appear in the Fleet Inventory after Agent installation without separate registration or Controller approval. An Admin uses the Controller to prepare a deployment-specific Agent Installation Package carrying Server configuration and installation authorization; installation establishes a distinct Device identity and automatically enrolls it with the intended Server, preserving mutual TLS and certificate-to-Device-ID binding. This places the admission decision in trusted installation rather than a later approval queue; Android TVs remain Agent-free and are added manually as connection targets.

An Admin can use the Controller to revoke an Installation Authorization and prepare a replacement package without revoking Devices already enrolled through it. Installation permission and ongoing Device access have separate lifecycles.

The staff-access and Fleet Inventory milestone stores Android TV connection targets as unverified. ADB pairing, connection verification, and scrcpy integration follow later; Windows connection status uses actual Agent heartbeat information.

Windows inventory membership and access restrictions follow [separate inventory cleanup and Device blocking](0006-separate-inventory-cleanup-from-device-blocking.md).
