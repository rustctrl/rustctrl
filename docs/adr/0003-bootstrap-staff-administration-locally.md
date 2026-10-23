---
status: accepted
---

# Bootstrap staff administration locally

The Server needs an initial staff administrator before account management through the Controller is available. A Server administrator creates the first Admin through a local Server command, rather than a default username/password or public account registration; subsequent staff account management takes place through the Controller. The last active Admin cannot be deactivated or demoted until another active Admin exists, preserving access to account management.

If the remaining Admin loses their password, a Server administrator can reset that existing account through a local command without email or an internet service. Recovery revokes the account's Staff Sessions and requires replacing the temporary password at the next login.
