//! Shared domain record types, role enums, and outcome types for Server persistence.
//!
//! # Domain Scope
//! Defines all in-memory representations of persistent domain entities used across the
//! store modules, gRPC transport handlers, and CLI commands.
//!
//! # Canonical Terms (from [CONTEXT.md](../../../../CONTEXT.md))
//! - **Staff Account**: Individual IT staff member identity with Admin or Operator role.
//! - **Staff Session**: Revocable period of access to RustCtrl under a Staff Account.
//! - **Device**: A Windows computer or Android TV recorded in the fleet inventory.
//! - **Fleet Inventory**: Operational list of Devices and information needed to identify and access them.
//! - **Installation Authorization**: Admin-granted permission for new Agents to join.
//! - **Admin**: Staff member allowed to manage accounts, Devices, configuration, and Management Tasks.
//! - **Operator**: Staff member allowed to monitor the Fleet and open Remote Sessions.
//!
//! # Domain Store Records and Enums
//! - [`StaffRole`]: Privileges role (`Admin` or `Operator`) for staff members.
//! - [`StaffAccount`]: Persistent staff account entity with hashed credentials and active flag.
//! - [`StaffSession`]: Active staff session record with expiry tracking.
//! - [`DeviceRecord`]: Operational inventory record containing permanent device ID and metadata.
//! - [`TargetRecord`]: Unverified connection target for Android TV endpoints.
//! - [`DeviceReplacementRecord`]: Durable mapping between a replaced device identity and its successor.
//! - [`InstallationAuthorizationRecord`]: Pre-approved enrollment permission token record.
//! - [`RevokeAuthorizationOutcome`]: Outcome of an administrative authorization revocation request.
//! - [`DeviceEnrollmentRecord`]: Enrolled device record binding device identity to authorization.
//! - [`ActivityRecord`]: Audit log entry capturing actor, action, result, and detail.
//!
//! # Invariants and Architectural Guarantees
//! - A [`DeviceRecord`] maintains permanent identity via `device_id` regardless of `last_address` changes.
//! - A [`TargetRecord`] represents unverified connection targets and is never treated as an enrolled Agent.
//! - [`InstallationAuthorizationRecord`] and [`DeviceEnrollmentRecord`] ensure each Agent joins under explicit authorization.
//! - [`StaffSession`] tokens remain independently revocable and distinct from remote screen sessions.
//!
//! # Forbidden Anti-Patterns
//! - Never use IP address as device identity (always use canonical `device_id`).
//! - Never conflate Staff Session with Remote Session.
//! - Never treat an Android TV target as a verified Agent device record.
//!
//! # Applicable Architecture Decision Records (ADRs)
//! - [ADR 0001: Centralize Fleet Coordination](../../../../docs/adr/0001-centralize-fleet-coordination.md)
//! - [ADR 0003: Bootstrap Staff Administration Locally](../../../../docs/adr/0003-bootstrap-staff-administration-locally.md)
//! - [ADR 0004: Enroll Agents Through Trusted Installation](../../../../docs/adr/0004-enroll-agents-through-trusted-installation.md)
//! - [ADR 0005: Keep Remembered Staff Access Revocable](../../../../docs/adr/0005-keep-remembered-staff-access-revocable.md)
//! - [ADR 0006: Separate Inventory Cleanup from Device Blocking](../../../../docs/adr/0006-separate-inventory-cleanup-from-device-blocking.md)
//! - [ADR 0007: Provision Agent Credentials via Scoped Issuing Authority](../../../../docs/adr/0007-provision-agent-credentials-via-scoped-issuing-authority.md)

use anyhow::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaffRole {
    Admin,
    Operator,
}

impl StaffRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            StaffRole::Admin => "admin",
            StaffRole::Operator => "operator",
        }
    }
}

impl std::str::FromStr for StaffRole {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "admin" => Ok(StaffRole::Admin),
            "operator" => Ok(StaffRole::Operator),
            _ => anyhow::bail!("unknown role: {s}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct StaffAccount {
    pub username: String,
    pub role: StaffRole,
    pub password_hash: String,
    pub must_change_password: bool,
    pub active: bool,
    pub created_at_unix_ms: i64,
    pub updated_at_unix_ms: i64,
}

#[derive(Debug, Clone)]
pub struct StaffSession {
    pub session_id: String,
    pub username: String,
    pub role: StaffRole,
    pub must_change_password: bool,
    pub created_at_unix_ms: i64,
    pub last_seen_unix_ms: i64,
    pub revoked: bool,
}

#[derive(Debug, Clone)]
pub struct ActivityRecord {
    pub id: i64,
    pub server_time_unix_ms: i64,
    pub actor: String,
    pub action: String,
    pub result: String,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct DeviceRecord {
    pub device_id: String,
    pub name: String,
    pub agent_version: String,
    pub last_address: Option<String>,
    pub last_seen_unix_ms: i64,
    pub location: Option<String>,
    pub device_type: String,
    pub configured_address: Option<String>,
    pub blocked: bool,
}

#[derive(Debug, Clone)]
pub struct TargetRecord {
    pub target_id: String,
    pub display_name: String,
    pub target_type: String,
    pub configured_address: String,
    pub location: Option<String>,
    pub created_at_unix_ms: i64,
    pub updated_at_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceReplacementRecord {
    pub prior_device_id: String,
    pub replacement_device_id: String,
    pub replaced_at_unix_ms: i64,
    pub replaced_by: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallationAuthorizationRecord {
    pub authorization_id: String,
    pub secret_hash: String,
    pub created_at_unix_ms: i64,
    pub created_by: String,
    pub revoked_at_unix_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevokeAuthorizationOutcome {
    NotFound,
    AlreadyRevoked,
    Revoked(InstallationAuthorizationRecord),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceEnrollmentRecord {
    pub device_id: String,
    pub authorization_id: String,
    pub enrolled_at_unix_ms: i64,
    pub resumption_secret_hash: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn staff_role_as_str() {
        assert_eq!(StaffRole::Admin.as_str(), "admin");
        assert_eq!(StaffRole::Operator.as_str(), "operator");
    }

    #[test]
    fn staff_role_from_str() {
        assert_eq!(StaffRole::from_str("admin").unwrap(), StaffRole::Admin);
        assert_eq!(StaffRole::from_str("Admin").unwrap(), StaffRole::Admin);
        assert_eq!(StaffRole::from_str("ADMIN").unwrap(), StaffRole::Admin);
        assert_eq!(
            StaffRole::from_str("operator").unwrap(),
            StaffRole::Operator
        );
        assert_eq!(
            StaffRole::from_str("Operator").unwrap(),
            StaffRole::Operator
        );
        assert_eq!(
            StaffRole::from_str("OPERATOR").unwrap(),
            StaffRole::Operator
        );

        assert!(StaffRole::from_str("unknown").is_err());
        assert!(StaffRole::from_str("").is_err());
    }
}
