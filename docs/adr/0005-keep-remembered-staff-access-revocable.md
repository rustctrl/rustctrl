---
status: accepted
---

# Keep remembered staff access revocable

Self-hosted deployments need convenient staff access without depending on an external account service. Staff can opt to remember their login across Controller restarts for a configurable duration, initially 30 days, and use separate Staff Sessions on multiple Controllers. The Server remains authoritative: logout ends the current Staff Session, while account deactivation or a password reset revokes all of that account's Staff Sessions.

Admins issue temporary passwords for new accounts and password resets, with a mandatory password change at the next login. This supports offline account administration while avoiding permanent Admin-known staff passwords.
