//! Central activity log persistence operations for the RustCtrl Server.
//!
//! # Domain Scope
//! This module implements persistence operations for the central activity log, including recording
//! operational events (staff logins, credential changes, account creation, deactivations, device
//! blocks, device replacements, inventory cleanups, and target management) and querying durable audit history.
//!
//! # Canonical Terms (from [CONTEXT.md](../../../../CONTEXT.md))
//! - **Server**: The shared authority for staff accounts, inventory, Remote Sessions, Management Tasks,
//!   and activity history.
//! - **Staff Account**: Individual IT staff member identity with Admin or Operator role.
//! - **Device**: A Windows computer or Android TV recorded in the fleet inventory.
//! - **Installation Authorization**: Admin-granted permission for new Agents to join.
//! - **Admin**: A staff member allowed to manage accounts, Devices, configuration, and Management Tasks.
//! - **Operator**: A staff member allowed to monitor the Fleet and open Remote Sessions using an individual account.
//!
//! # Invariants and Architectural Guarantees
//! - **Exclusion of Secrets**: Passwords, session tokens, and raw authorization secrets are strictly
//!   excluded from the activity log. Only actor identity, action type, outcome result, and sanitized
//!   detail strings are stored.
//! - **Chronological Audit Trail**: Activity log records include server timestamp (`server_time_unix_ms`)
//!   and auto-incrementing sequential identifier `id` guaranteeing deterministic chronological ordering.
//! - **Attribution Preservation**: Historical activity log records retain original device and staff
//!   identities even when devices are replaced or accounts are deactivated.
//!
//! # Forbidden Anti-Patterns
//! - Never log raw passwords, session tokens, or sensitive credentials in the activity log.
//! - Never rewrite or re-attribute historical activity log entries upon device replacement.
//! - Never allow unauthenticated callers to query the activity log.
//!
//! # Applicable Architecture Decision Records (ADRs)
//! - [ADR 0001: Centralize Fleet Coordination](../../../../docs/adr/0001-centralize-fleet-coordination.md)
//! - [ADR 0003: Bootstrap Staff Administration Locally](../../../../docs/adr/0003-bootstrap-staff-administration-locally.md)
//! - [ADR 0005: Keep Remembered Staff Access Revocable](../../../../docs/adr/0005-keep-remembered-staff-access-revocable.md)
//! - [ADR 0006: Separate Inventory Cleanup from Device Blocking](../../../../docs/adr/0006-separate-inventory-cleanup-from-device-blocking.md)
//! - [ADR 0007: Provision Agent Credentials via Scoped Issuing Authority](../../../../docs/adr/0007-provision-agent-credentials-via-scoped-issuing-authority.md)

use super::{DeviceStore, helpers::current_time_ms, types::ActivityRecord};
use anyhow::Result;
use rusqlite::params;

impl DeviceStore {
    /// Records a system, staff, or agent activity entry in the durable central activity log.
    ///
    /// Excludes secrets and credentials from the stored record.
    pub async fn record_activity(
        &self,
        actor: String,
        action: String,
        result: String,
        detail: String,
    ) -> Result<()> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let now = current_time_ms()?;
            let connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            connection.execute(
                "INSERT INTO activity_log (server_time_unix_ms, actor, action, result, detail) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![now, actor, action, result, detail],
            )?;
            Ok(())
        })
        .await?
    }

    /// Lists all central activity log entries in ascending chronological order.
    pub async fn list_activity(&self) -> Result<Vec<ActivityRecord>> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            let mut stmt = connection.prepare(
                "SELECT id, server_time_unix_ms, actor, action, result, detail FROM activity_log ORDER BY id ASC",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(ActivityRecord {
                    id: row.get(0)?,
                    server_time_unix_ms: row.get(1)?,
                    actor: row.get(2)?,
                    action: row.get(3)?,
                    result: row.get(4)?,
                    detail: row.get(5)?,
                })
            })?;
            let mut list = Vec::new();
            for r in rows {
                list.push(r?);
            }
            Ok(list)
        })
        .await?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn record_and_list_activity_chronological_order() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let store = DeviceStore::open(&temp.path().join("store.db"))?;

        assert!(store.list_activity().await?.is_empty());

        store
            .record_activity(
                "alice".into(),
                "login".into(),
                "success".into(),
                "staff session started".into(),
            )
            .await?;

        store
            .record_activity(
                "alice".into(),
                "block_device".into(),
                "success".into(),
                "device blocked".into(),
            )
            .await?;

        let activities = store.list_activity().await?;
        assert_eq!(activities.len(), 2);

        assert_eq!(activities[0].actor, "alice");
        assert_eq!(activities[0].action, "login");
        assert_eq!(activities[0].result, "success");
        assert_eq!(activities[0].detail, "staff session started");
        assert!(activities[0].server_time_unix_ms > 0);

        assert_eq!(activities[1].actor, "alice");
        assert_eq!(activities[1].action, "block_device");
        assert_eq!(activities[1].result, "success");
        assert_eq!(activities[1].detail, "device blocked");
        assert!(activities[1].id > activities[0].id);

        Ok(())
    }
}
