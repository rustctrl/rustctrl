---
status: accepted
---

# Provision Agent credentials through a scoped issuing authority

Automatic Agent enrollment requires Windows Devices to establish distinct operational identities and credentials without manual post-installation approval or offline signing for each endpoint, while preserving mutual TLS, hostname verification, and certificate-to-Device-ID binding (`<device-id>.agent.rustctrl.internal`). At the same time, the deployment's root CA private key must remain strictly offline in the administrative PKI volume, outside Server runtime mounts and generated Agent packages.

RustCtrl resolves this by delegating leaf Agent certificate issuance to a scoped subordinate Agent Issuing CA held by the Server:

1. **Root CA custody**: The root CA private key remains offline with the administrator, outside Server runtime mounts and client packages (preserving [offline local CA bootstrap](0002-bootstrap-an-offline-local-ca.md)).
2. **Scoped issuing authority**: The root CA signs a subordinate Agent Issuing CA with path length 0. The Server holds this intermediate CA to mint operational leaf certificates restricted strictly to the `<device-id>.agent.rustctrl.internal` identity. The subordinate CA cannot issue Server certificates, Controller certificates, or further CAs.
3. **Installation artifact & authority**: An Admin exports an installation artifact through the Controller containing the Server endpoint, domain name, public CA trust certificate, an enrollment TLS credential for mutual TLS during enrollment, and an Installation Authorization secret token.
4. **Distinct endpoint identities**: When an Agent installs from the artifact, it establishes a distinct `DeviceId`, proves installation authority over mutual TLS, receives its operational certificate from the Server, and persists its credentials locally. Retries and restarts reuse the local credentials and do not create duplicate inventory entries.
5. **Separate lifecycles**: Revoking an Installation Authorization denies new enrollments while leaving previously enrolled Agent credentials and Device Blocks intact (following [trusted automatic Agent enrollment](0004-enroll-agents-through-trusted-installation.md)).

## Consequences and Trade-offs

- **Automated admission**: Endpoints join the Fleet Inventory automatically upon installation without requiring an administrator to sign individual certificates at the Server shell.
- **Contained blast radius**: If a Server is compromised, the attacker cannot compromise the root CA or forge Server/Controller identities. The Server's authority is limited to issuing leaf certificates in the Agent namespace for valid Installation Authorizations.
- **Defense in depth**: Knowledge of the Server address alone does not admit an Agent: both deployment mutual TLS and a valid, unrevoked Installation Authorization secret are required.
