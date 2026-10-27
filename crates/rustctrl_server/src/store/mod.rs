//! Server persistence facade and store coordinator.
//!
//! # Domain Scope
//! This module provides the unified [`DeviceStore`] facade coordinator for all persistence
//! operations in the RustCtrl Server, including fleet inventory, staff accounts, staff sessions,
//! installation authorizations, device enrollments, and audit logging.
//!
//! # Canonical Terms (from [CONTEXT.md](../../../../CONTEXT.md))
//! - **Server**: The shared authority for staff accounts, inventory, Remote Sessions, Management Tasks, and activity history.
//! - **Device**: A Windows computer or Android TV recorded in the fleet inventory.
//! - **Fleet Inventory**: Operational list of Devices and information needed to identify and access them.
//! - **Staff Account**: Individual IT staff member identity with Admin or Operator role.
//! - **Staff Session**: Revocable period of access to RustCtrl under a Staff Account.
//! - **Installation Authorization**: Admin-granted permission for new Agents to join.
//! - **Inventory Cleanup**: Removal of an offline Device entry without revoking Agent access.
//! - **Device Block**: Denying operational Agent access while keeping Device visible in inventory.
//!
//! # Invariants and Architectural Guarantees
//! - The [`DeviceStore`] facade coordinates all persistence operations with thread-safe access.
//! - Atomic transactions guarantee consistent updates across related entities (e.g. metadata transfers, replacements).
//! - All domain types are re-exported directly from the store module root to preserve caller compatibility.
//!
//! # Forbidden Anti-Patterns
//! - Never use IP address as device identity (Devices are identified by permanent `DeviceId`).
//! - Never treat Inventory Cleanup as Device Block (Cleanup allows re-registration; Block denies access).
//! - Never conflate Staff Session with Remote Session (Staff Session is Controller access; Remote Session is screen control).
//! - Never allow shared staff accounts or Controller certificates as staff identity.
//!
//! # Applicable Architecture Decision Records (ADRs)
//! - [ADR 0001: Centralize Fleet Coordination](../../../../docs/adr/0001-centralize-fleet-coordination.md)
//! - [ADR 0003: Bootstrap Staff Administration Locally](../../../../docs/adr/0003-bootstrap-staff-administration-locally.md)
//! - [ADR 0004: Enroll Agents Through Trusted Installation](../../../../docs/adr/0004-enroll-agents-through-trusted-installation.md)
//! - [ADR 0005: Keep Remembered Staff Access Revocable](../../../../docs/adr/0005-keep-remembered-staff-access-revocable.md)
//! - [ADR 0006: Separate Inventory Cleanup from Device Blocking](../../../../docs/adr/0006-separate-inventory-cleanup-from-device-blocking.md)
//! - [ADR 0007: Provision Agent Credentials via Scoped Issuing Authority](../../../../docs/adr/0007-provision-agent-credentials-via-scoped-issuing-authority.md)

pub(crate) mod accounts;
pub(crate) mod audit;
pub(crate) mod enrollment;
pub(crate) mod fleet;
pub(crate) mod helpers;
pub(crate) mod schema;
pub(crate) mod sessions;
pub mod types;

pub use types::{
    ActivityRecord, DeviceEnrollmentRecord, DeviceRecord, DeviceReplacementRecord,
    InstallationAuthorizationRecord, RevokeAuthorizationOutcome, StaffAccount, StaffRole,
    StaffSession, TargetRecord,
};

use anyhow::Result;
use rusqlite::Connection;
use std::{
    path::Path,
    sync::{Arc, Mutex},
};

#[derive(Clone)]
pub struct DeviceStore(pub(crate) Arc<Mutex<Connection>>);

impl DeviceStore {
    pub fn open(path: &Path) -> Result<Self> {
        let connection = schema::open_connection(path)?;
        Ok(Self(Arc::new(Mutex::new(connection))))
    }
}
