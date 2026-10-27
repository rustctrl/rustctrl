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

pub(crate) mod helpers;
pub(crate) mod schema;
pub mod types;

pub use types::{
    ActivityRecord, DeviceEnrollmentRecord, DeviceRecord, DeviceReplacementRecord,
    InstallationAuthorizationRecord, RevokeAuthorizationOutcome, StaffAccount, StaffRole,
    StaffSession, TargetRecord,
};

use anyhow::Result;
use helpers::{current_time_ms, reset_account_password_to_temporary, validate_username};
use rusqlite::{Connection, OptionalExtension, params};
use rustctrl_core::DeviceId;
use std::{
    path::Path,
    sync::{Arc, Mutex},
};

#[derive(Clone)]
pub struct DeviceStore(Arc<Mutex<Connection>>);

impl DeviceStore {
    pub fn open(path: &Path) -> Result<Self> {
        let connection = schema::open_connection(path)?;
        Ok(Self(Arc::new(Mutex::new(connection))))
    }

    pub async fn heartbeat(
        &self,
        id: DeviceId,
        name: String,
        version: String,
        remote_address: Option<String>,
    ) -> Result<i64> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let now = current_time_ms()?;
            let connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            let is_replaced: i64 = connection.query_row(
                "SELECT COUNT(*) FROM device_replacements WHERE prior_device_id = ?1",
                params![id.to_string()],
                |row| row.get(0),
            )?;
            if is_replaced > 0 {
                anyhow::bail!("device '{}' has been replaced", id);
            }
            let is_blocked: i64 = connection.query_row(
                "SELECT COUNT(*) FROM blocked_devices WHERE device_id = ?1",
                params![id.to_string()],
                |row| row.get(0),
            )?;
            if is_blocked > 0 {
                anyhow::bail!("device '{}' is blocked", id);
            }
            connection.execute(
                "INSERT INTO bootstrap_devices (device_id, name, agent_version, last_address, last_seen_unix_ms) VALUES (?1, ?2, ?3, ?4, ?5)
                ON CONFLICT(device_id) DO UPDATE SET name=excluded.name,
                agent_version=excluded.agent_version, last_address=excluded.last_address, last_seen_unix_ms=excluded.last_seen_unix_ms",
                params![id.to_string(), name, version, remote_address, now],
            )?;
            let _ = connection.execute(
                "INSERT OR IGNORE INTO known_device_identities (device_id) VALUES (?1)",
                params![id.to_string()],
            );
            Ok(now)
        })
        .await?
    }

    pub async fn list_devices(&self) -> Result<Vec<DeviceRecord>> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            let mut stmt = connection.prepare(
                "SELECT b.device_id, COALESCE(m.display_name, b.name) AS display_name, b.agent_version, b.last_address, b.last_seen_unix_ms, m.location, 'windows', NULL, CASE WHEN bl.device_id IS NOT NULL THEN 1 ELSE 0 END
                 FROM bootstrap_devices b
                 LEFT JOIN device_metadata m ON b.device_id = m.device_id
                 LEFT JOIN blocked_devices bl ON b.device_id = bl.device_id
                 UNION ALL
                 SELECT t.target_id, t.display_name, '', NULL, 0, t.location, t.target_type, t.configured_address, 0
                 FROM connection_targets t
                 ORDER BY 5 DESC, 2 ASC, 1 ASC",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(DeviceRecord {
                    device_id: row.get(0)?,
                    name: row.get(1)?,
                    agent_version: row.get(2)?,
                    last_address: row.get(3)?,
                    last_seen_unix_ms: row.get(4)?,
                    location: row.get(5)?,
                    device_type: row.get(6)?,
                    configured_address: row.get(7)?,
                    blocked: row.get::<_, i64>(8)? != 0,
                })
            })?;
            let mut devices = Vec::new();
            for row in rows {
                devices.push(row?);
            }
            Ok(devices)
        })
        .await?
    }

    pub async fn get_device(&self, device_id: &str) -> Result<Option<DeviceRecord>> {
        let store = self.clone();
        let device_id = device_id.to_string();
        tokio::task::spawn_blocking(move || {
            let connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            let mut stmt = connection.prepare(
                "SELECT b.device_id, COALESCE(m.display_name, b.name), b.agent_version, b.last_address, b.last_seen_unix_ms, m.location, 'windows', NULL, CASE WHEN bl.device_id IS NOT NULL THEN 1 ELSE 0 END
                 FROM bootstrap_devices b
                 LEFT JOIN device_metadata m ON b.device_id = m.device_id
                 LEFT JOIN blocked_devices bl ON b.device_id = bl.device_id
                 WHERE b.device_id = ?1
                 UNION ALL
                 SELECT t.target_id, t.display_name, '', NULL, 0, t.location, t.target_type, t.configured_address, 0
                 FROM connection_targets t
                 WHERE t.target_id = ?1",
            )?;
            let mut rows = stmt.query(params![device_id])?;
            if let Some(row) = rows.next()? {
                Ok(Some(DeviceRecord {
                    device_id: row.get(0)?,
                    name: row.get(1)?,
                    agent_version: row.get(2)?,
                    last_address: row.get(3)?,
                    last_seen_unix_ms: row.get(4)?,
                    location: row.get(5)?,
                    device_type: row.get(6)?,
                    configured_address: row.get(7)?,
                    blocked: row.get::<_, i64>(8)? != 0,
                }))
            } else {
                Ok(None)
            }
        })
        .await?
    }

    pub async fn update_device_metadata(
        &self,
        device_id: &str,
        display_name: &str,
        location: Option<&str>,
    ) -> Result<DeviceRecord> {
        let device_id = device_id.trim();
        let _: DeviceId = device_id
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid device_id"))?;
        let display_name = display_name.trim();
        anyhow::ensure!(!display_name.is_empty(), "display name cannot be empty");
        anyhow::ensure!(
            display_name.len() <= 128,
            "display name must contain at most 128 characters"
        );
        let location = location
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .map(|l| l.to_string());
        if let Some(loc) = &location {
            anyhow::ensure!(
                loc.len() <= 128,
                "location must contain at most 128 characters"
            );
        }

        let store = self.clone();
        let device_id = device_id.to_string();
        let display_name = display_name.to_string();
        tokio::task::spawn_blocking(move || {
            let now = current_time_ms()?;
            let connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;

            let exists: i64 = connection.query_row(
                "SELECT COUNT(*) FROM bootstrap_devices WHERE device_id = ?1",
                params![device_id],
                |row| row.get(0),
            )?;
            if exists == 0 {
                anyhow::bail!("device '{device_id}' not found");
            }

            connection.execute(
                "INSERT INTO device_metadata (device_id, display_name, location, updated_at_unix_ms)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(device_id) DO UPDATE SET
                     display_name = excluded.display_name,
                     location = excluded.location,
                     updated_at_unix_ms = excluded.updated_at_unix_ms",
                params![device_id, display_name, location, now],
            )?;

            let record = connection.query_row(
                "SELECT b.device_id, COALESCE(m.display_name, b.name), b.agent_version, b.last_address, b.last_seen_unix_ms, m.location, 'windows', NULL, CASE WHEN bl.device_id IS NOT NULL THEN 1 ELSE 0 END
                 FROM bootstrap_devices b
                 LEFT JOIN device_metadata m ON b.device_id = m.device_id
                 LEFT JOIN blocked_devices bl ON b.device_id = bl.device_id
                 WHERE b.device_id = ?1",
                params![device_id],
                |row| {
                    Ok(DeviceRecord {
                        device_id: row.get(0)?,
                        name: row.get(1)?,
                        agent_version: row.get(2)?,
                        last_address: row.get(3)?,
                        last_seen_unix_ms: row.get(4)?,
                        location: row.get(5)?,
                        device_type: row.get(6)?,
                        configured_address: row.get(7)?,
                        blocked: row.get::<_, i64>(8)? != 0,
                    })
                },
            )?;

            Ok(record)
        })
        .await?
    }

    pub async fn is_device_blocked(&self, device_id: &str) -> Result<bool> {
        let store = self.clone();
        let device_id = device_id.trim().to_string();
        tokio::task::spawn_blocking(move || {
            let connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            let count: i64 = connection.query_row(
                "SELECT COUNT(*) FROM blocked_devices WHERE device_id = ?1",
                params![device_id],
                |row| row.get(0),
            )?;
            Ok(count > 0)
        })
        .await?
    }

    pub async fn block_device(&self, device_id: &str, blocked_by: &str) -> Result<DeviceRecord> {
        let device_id = device_id.trim();
        let _: DeviceId = device_id
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid device_id"))?;
        let store = self.clone();
        let device_id = device_id.to_string();
        let blocked_by = blocked_by.trim().to_string();
        tokio::task::spawn_blocking(move || {
            let now = current_time_ms()?;
            let connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;

            let exists: i64 = connection.query_row(
                "SELECT COUNT(*) FROM bootstrap_devices WHERE device_id = ?1",
                params![device_id],
                |row| row.get(0),
            )?;
            if exists == 0 {
                anyhow::bail!("device '{device_id}' not found");
            }

            let is_blocked: i64 = connection.query_row(
                "SELECT COUNT(*) FROM blocked_devices WHERE device_id = ?1",
                params![device_id],
                |row| row.get(0),
            )?;
            if is_blocked > 0 {
                anyhow::bail!("device '{device_id}' is already blocked");
            }

            connection.execute(
                "INSERT INTO blocked_devices (device_id, blocked_at_unix_ms, blocked_by) VALUES (?1, ?2, ?3)",
                params![device_id, now, blocked_by],
            )?;

            let record = connection.query_row(
                "SELECT b.device_id, COALESCE(m.display_name, b.name), b.agent_version, b.last_address, b.last_seen_unix_ms, m.location, 'windows', NULL, 1
                 FROM bootstrap_devices b
                 LEFT JOIN device_metadata m ON b.device_id = m.device_id
                 WHERE b.device_id = ?1",
                params![device_id],
                |row| {
                    Ok(DeviceRecord {
                        device_id: row.get(0)?,
                        name: row.get(1)?,
                        agent_version: row.get(2)?,
                        last_address: row.get(3)?,
                        last_seen_unix_ms: row.get(4)?,
                        location: row.get(5)?,
                        device_type: row.get(6)?,
                        configured_address: row.get(7)?,
                        blocked: true,
                    })
                },
            )?;

            Ok(record)
        })
        .await?
    }

    pub async fn unblock_device(&self, device_id: &str) -> Result<DeviceRecord> {
        let device_id = device_id.trim();
        let _: DeviceId = device_id
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid device_id"))?;
        let store = self.clone();
        let device_id = device_id.to_string();
        tokio::task::spawn_blocking(move || {
            let connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;

            let exists: i64 = connection.query_row(
                "SELECT COUNT(*) FROM bootstrap_devices WHERE device_id = ?1",
                params![device_id],
                |row| row.get(0),
            )?;
            if exists == 0 {
                anyhow::bail!("device '{device_id}' not found");
            }

            let is_blocked: i64 = connection.query_row(
                "SELECT COUNT(*) FROM blocked_devices WHERE device_id = ?1",
                params![device_id],
                |row| row.get(0),
            )?;
            if is_blocked == 0 {
                anyhow::bail!("device '{device_id}' is not blocked");
            }

            connection.execute(
                "DELETE FROM blocked_devices WHERE device_id = ?1",
                params![device_id],
            )?;

            let record = connection.query_row(
                "SELECT b.device_id, COALESCE(m.display_name, b.name), b.agent_version, b.last_address, b.last_seen_unix_ms, m.location, 'windows', NULL, 0
                 FROM bootstrap_devices b
                 LEFT JOIN device_metadata m ON b.device_id = m.device_id
                 WHERE b.device_id = ?1",
                params![device_id],
                |row| {
                    Ok(DeviceRecord {
                        device_id: row.get(0)?,
                        name: row.get(1)?,
                        agent_version: row.get(2)?,
                        last_address: row.get(3)?,
                        last_seen_unix_ms: row.get(4)?,
                        location: row.get(5)?,
                        device_type: row.get(6)?,
                        configured_address: row.get(7)?,
                        blocked: false,
                    })
                },
            )?;

            Ok(record)
        })
        .await?
    }

    pub async fn clean_offline_device(
        &self,
        device_id: &str,
        offline_after_secs: u64,
    ) -> Result<String> {
        let device_id = device_id.trim();
        let _: DeviceId = device_id
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid device_id"))?;
        let store = self.clone();
        let device_id = device_id.to_string();
        tokio::task::spawn_blocking(move || {
            let now = current_time_ms()?;
            let mut connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;

            let last_seen_unix_ms: i64 = match connection.query_row(
                "SELECT last_seen_unix_ms FROM bootstrap_devices WHERE device_id = ?1",
                params![device_id],
                |row| row.get(0),
            ) {
                Ok(ms) => ms,
                Err(rusqlite::Error::QueryReturnedNoRows) => {
                    let is_target: i64 = connection.query_row(
                        "SELECT COUNT(*) FROM connection_targets WHERE target_id = ?1",
                        params![device_id],
                        |row| row.get(0),
                    )?;
                    if is_target > 0 {
                        anyhow::bail!(
                            "device '{device_id}' is a connection target; use remove-target instead"
                        );
                    }
                    anyhow::bail!("device '{device_id}' not found");
                }
                Err(e) => return Err(e.into()),
            };

            let is_blocked: i64 = connection.query_row(
                "SELECT COUNT(*) FROM blocked_devices WHERE device_id = ?1",
                params![device_id],
                |row| row.get(0),
            )?;
            if is_blocked > 0 {
                anyhow::bail!("cannot clean up blocked device '{device_id}'");
            }

            let window_ms =
                i64::try_from(offline_after_secs.saturating_mul(1000)).unwrap_or(i64::MAX);
            if now.saturating_sub(last_seen_unix_ms) <= window_ms {
                anyhow::bail!("cannot clean up online device '{device_id}'");
            }

            let tx = connection.transaction()?;
            tx.execute(
                "DELETE FROM device_metadata WHERE device_id = ?1",
                params![device_id],
            )?;
            tx.execute(
                "DELETE FROM bootstrap_devices WHERE device_id = ?1",
                params![device_id],
            )?;
            tx.commit()?;

            Ok(device_id)
        })
        .await?
    }

    pub async fn replace_device(
        &self,
        prior_device_id: &str,
        replacement_device_id: &str,
        replaced_by: &str,
    ) -> Result<DeviceRecord> {
        let prior_device_id = prior_device_id.trim();
        let _: DeviceId = prior_device_id
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid prior_device_id"))?;
        let replacement_device_id = replacement_device_id.trim();
        let _: DeviceId = replacement_device_id
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid replacement_device_id"))?;
        anyhow::ensure!(
            prior_device_id != replacement_device_id,
            "prior and replacement device identities must be different"
        );
        let replaced_by = replaced_by.trim();
        anyhow::ensure!(!replaced_by.is_empty(), "replaced_by cannot be empty");

        let store = self.clone();
        let prior_device_id = prior_device_id.to_string();
        let replacement_device_id = replacement_device_id.to_string();
        let replaced_by = replaced_by.to_string();

        tokio::task::spawn_blocking(move || {
            let now = current_time_ms()?;
            let mut connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;

            // 1. Check if either is a connection target
            let prior_is_target: i64 = connection.query_row(
                "SELECT COUNT(*) FROM connection_targets WHERE target_id = ?1",
                params![prior_device_id],
                |row| row.get(0),
            )?;
            if prior_is_target > 0 {
                anyhow::bail!(
                    "prior device '{prior_device_id}' is a connection target; replacement applies only to Windows fleet devices"
                );
            }
            let replacement_is_target: i64 = connection.query_row(
                "SELECT COUNT(*) FROM connection_targets WHERE target_id = ?1",
                params![replacement_device_id],
                |row| row.get(0),
            )?;
            if replacement_is_target > 0 {
                anyhow::bail!(
                    "replacement device '{replacement_device_id}' is a connection target; replacement applies only to Windows fleet devices"
                );
            }

            // 2. Check prior device existence in bootstrap_devices
            let prior_exists: i64 = connection.query_row(
                "SELECT COUNT(*) FROM bootstrap_devices WHERE device_id = ?1",
                params![prior_device_id],
                |row| row.get(0),
            )?;
            if prior_exists == 0 {
                let was_replaced: i64 = connection.query_row(
                    "SELECT COUNT(*) FROM device_replacements WHERE prior_device_id = ?1",
                    params![prior_device_id],
                    |row| row.get(0),
                )?;
                if was_replaced > 0 {
                    anyhow::bail!("prior device '{prior_device_id}' has already been replaced");
                }
                anyhow::bail!("prior device '{prior_device_id}' not found");
            }

            // 3. Check replacement device existence in bootstrap_devices
            let replacement_exists: i64 = connection.query_row(
                "SELECT COUNT(*) FROM bootstrap_devices WHERE device_id = ?1",
                params![replacement_device_id],
                |row| row.get(0),
            )?;
            if replacement_exists == 0 {
                let was_replaced: i64 = connection.query_row(
                    "SELECT COUNT(*) FROM device_replacements WHERE prior_device_id = ?1",
                    params![replacement_device_id],
                    |row| row.get(0),
                )?;
                if was_replaced > 0 {
                    anyhow::bail!(
                        "replacement device '{replacement_device_id}' has already been replaced"
                    );
                }
                anyhow::bail!("replacement device '{replacement_device_id}' not found");
            }

            // 4. Ensure replacement has not been recorded as already replaced
            let replacement_was_replaced: i64 = connection.query_row(
                "SELECT COUNT(*) FROM device_replacements WHERE prior_device_id = ?1",
                params![replacement_device_id],
                |row| row.get(0),
            )?;
            if replacement_was_replaced > 0 {
                anyhow::bail!(
                    "replacement device '{replacement_device_id}' has already been replaced"
                );
            }

            // 5. Read prior's curated metadata or bootstrap name
            let (prior_display_name, prior_location): (String, Option<String>) = match connection
                .query_row(
                    "SELECT display_name, location FROM device_metadata WHERE device_id = ?1",
                    params![prior_device_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                ) {
                Ok((name, loc)) => (name, loc),
                Err(rusqlite::Error::QueryReturnedNoRows) => {
                    let name: String = connection.query_row(
                        "SELECT name FROM bootstrap_devices WHERE device_id = ?1",
                        params![prior_device_id],
                        |row| row.get(0),
                    )?;
                    (name, None)
                }
                Err(e) => return Err(e.into()),
            };

            // 6. Check if prior is blocked
            let prior_block: Option<(i64, String)> = connection
                .query_row(
                    "SELECT blocked_at_unix_ms, blocked_by FROM blocked_devices WHERE device_id = ?1",
                    params![prior_device_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;

            // 7. Atomic transaction
            let tx = connection.transaction()?;

            // Transfer curated metadata to replacement device
            tx.execute(
                "INSERT INTO device_metadata (device_id, display_name, location, updated_at_unix_ms)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(device_id) DO UPDATE SET
                     display_name = excluded.display_name,
                     location = excluded.location,
                     updated_at_unix_ms = excluded.updated_at_unix_ms",
                params![
                    replacement_device_id,
                    prior_display_name,
                    prior_location,
                    now
                ],
            )?;

            // If prior was blocked, preserve the block on replacement device
            if let Some((blocked_at, blocked_by)) = prior_block {
                tx.execute(
                    "INSERT INTO blocked_devices (device_id, blocked_at_unix_ms, blocked_by)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT(device_id) DO NOTHING",
                    params![replacement_device_id, blocked_at, blocked_by],
                )?;
            }

            // Record replacement association
            tx.execute(
                "INSERT INTO device_replacements (prior_device_id, replacement_device_id, replaced_at_unix_ms, replaced_by)
                 VALUES (?1, ?2, ?3, ?4)",
                params![prior_device_id, replacement_device_id, now, replaced_by],
            )?;

            // Remove prior from device_metadata and bootstrap_devices (reconciling inventory)
            tx.execute(
                "DELETE FROM device_metadata WHERE device_id = ?1",
                params![prior_device_id],
            )?;
            tx.execute(
                "DELETE FROM bootstrap_devices WHERE device_id = ?1",
                params![prior_device_id],
            )?;

            tx.commit()?;

            // Fetch and return the reconciled replacement DeviceRecord
            let record = connection.query_row(
                "SELECT b.device_id, COALESCE(m.display_name, b.name), b.agent_version, b.last_address, b.last_seen_unix_ms, m.location, 'windows', NULL, CASE WHEN bl.device_id IS NOT NULL THEN 1 ELSE 0 END
                 FROM bootstrap_devices b
                 LEFT JOIN device_metadata m ON b.device_id = m.device_id
                 LEFT JOIN blocked_devices bl ON b.device_id = bl.device_id
                 WHERE b.device_id = ?1",
                params![replacement_device_id],
                |row| {
                    Ok(DeviceRecord {
                        device_id: row.get(0)?,
                        name: row.get(1)?,
                        agent_version: row.get(2)?,
                        last_address: row.get(3)?,
                        last_seen_unix_ms: row.get(4)?,
                        location: row.get(5)?,
                        device_type: row.get(6)?,
                        configured_address: row.get(7)?,
                        blocked: row.get::<_, i64>(8)? != 0,
                    })
                },
            )?;

            Ok(record)
        })
        .await?
    }

    pub async fn get_device_replacement(
        &self,
        prior_device_id: &str,
    ) -> Result<Option<DeviceReplacementRecord>> {
        let prior_device_id = prior_device_id.trim().to_string();
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            let mut stmt = connection.prepare(
                "SELECT prior_device_id, replacement_device_id, replaced_at_unix_ms, replaced_by
                 FROM device_replacements WHERE prior_device_id = ?1",
            )?;
            let mut rows = stmt.query(params![prior_device_id])?;
            if let Some(row) = rows.next()? {
                Ok(Some(DeviceReplacementRecord {
                    prior_device_id: row.get(0)?,
                    replacement_device_id: row.get(1)?,
                    replaced_at_unix_ms: row.get(2)?,
                    replaced_by: row.get(3)?,
                }))
            } else {
                Ok(None)
            }
        })
        .await?
    }

    pub async fn create_target(
        &self,
        display_name: &str,
        address: &str,
        target_type: Option<&str>,
        location: Option<&str>,
    ) -> Result<TargetRecord> {
        let display_name = display_name.trim();
        anyhow::ensure!(!display_name.is_empty(), "display name cannot be empty");
        anyhow::ensure!(
            display_name.len() <= 128,
            "display name must contain at most 128 characters"
        );

        let address = address.trim();
        anyhow::ensure!(!address.is_empty(), "configured address cannot be empty");
        anyhow::ensure!(
            address.len() <= 128,
            "configured address must contain at most 128 characters"
        );

        let target_type = match target_type.unwrap_or("android_tv").trim() {
            "" | "android_tv" => "android_tv",
            other => anyhow::bail!("unsupported target type '{other}'"),
        };

        let location = location
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .map(|l| l.to_string());
        if let Some(loc) = &location {
            anyhow::ensure!(
                loc.len() <= 128,
                "location must contain at most 128 characters"
            );
        }

        let store = self.clone();
        let display_name = display_name.to_string();
        let address = address.to_string();
        let target_type = target_type.to_string();
        tokio::task::spawn_blocking(move || {
            let target_id = DeviceId::new().to_string();
            let now = current_time_ms()?;
            let connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;

            connection.execute(
                "INSERT INTO connection_targets (target_id, display_name, target_type, configured_address, location, created_at_unix_ms, updated_at_unix_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![target_id, display_name, target_type, address, location, now, now],
            )?;

            Ok(TargetRecord {
                target_id,
                display_name,
                target_type,
                configured_address: address,
                location,
                created_at_unix_ms: now,
                updated_at_unix_ms: now,
            })
        })
        .await?
    }

    pub async fn update_target(
        &self,
        target_id: &str,
        display_name: &str,
        address: &str,
        location: Option<&str>,
    ) -> Result<TargetRecord> {
        let target_id = target_id.trim();
        let _: DeviceId = target_id
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid target_id"))?;

        let display_name = display_name.trim();
        anyhow::ensure!(!display_name.is_empty(), "display name cannot be empty");
        anyhow::ensure!(
            display_name.len() <= 128,
            "display name must contain at most 128 characters"
        );

        let address = address.trim();
        anyhow::ensure!(!address.is_empty(), "configured address cannot be empty");
        anyhow::ensure!(
            address.len() <= 128,
            "configured address must contain at most 128 characters"
        );

        let location = location
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .map(|l| l.to_string());
        if let Some(loc) = &location {
            anyhow::ensure!(
                loc.len() <= 128,
                "location must contain at most 128 characters"
            );
        }

        let store = self.clone();
        let target_id = target_id.to_string();
        let display_name = display_name.to_string();
        let address = address.to_string();
        tokio::task::spawn_blocking(move || {
            let now = current_time_ms()?;
            let connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;

            let changed = connection.execute(
                "UPDATE connection_targets
                 SET display_name = ?1, configured_address = ?2, location = ?3, updated_at_unix_ms = ?4
                 WHERE target_id = ?5",
                params![display_name, address, location, now, target_id],
            )?;
            if changed == 0 {
                anyhow::bail!("target '{target_id}' not found");
            }

            let record = connection.query_row(
                "SELECT target_id, display_name, target_type, configured_address, location, created_at_unix_ms, updated_at_unix_ms
                 FROM connection_targets
                 WHERE target_id = ?1",
                params![target_id],
                |row| {
                    Ok(TargetRecord {
                        target_id: row.get(0)?,
                        display_name: row.get(1)?,
                        target_type: row.get(2)?,
                        configured_address: row.get(3)?,
                        location: row.get(4)?,
                        created_at_unix_ms: row.get(5)?,
                        updated_at_unix_ms: row.get(6)?,
                    })
                },
            )?;

            Ok(record)
        })
        .await?
    }

    pub async fn remove_target(&self, target_id: &str) -> Result<String> {
        let target_id = target_id.trim();
        let _: DeviceId = target_id
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid target_id"))?;

        let store = self.clone();
        let target_id = target_id.to_string();
        tokio::task::spawn_blocking(move || {
            let connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;

            let changed = connection.execute(
                "DELETE FROM connection_targets WHERE target_id = ?1",
                params![target_id],
            )?;
            if changed == 0 {
                anyhow::bail!("target '{target_id}' not found");
            }

            Ok(target_id)
        })
        .await?
    }

    pub async fn count(&self) -> Result<u64> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            let count: i64 = connection.query_row(
                "SELECT (SELECT COUNT(*) FROM bootstrap_devices) + (SELECT COUNT(*) FROM connection_targets)",
                [],
                |row| row.get(0),
            )?;
            Ok(u64::try_from(count)?)
        })
        .await?
    }

    pub async fn bootstrap_admin(
        &self,
        username: String,
        temporary_password: String,
    ) -> Result<()> {
        let username = validate_username(&username)?;
        let hash = crate::password::hash_password(&temporary_password)?;
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let now = current_time_ms()?;
            let connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            let admin_count: i64 = connection.query_row(
                "SELECT COUNT(*) FROM staff_accounts WHERE role = 'admin'",
                [],
                |row| row.get(0),
            )?;
            if admin_count > 0 {
                let _ = connection.execute(
                    "INSERT INTO activity_log (server_time_unix_ms, actor, action, result, detail) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        now,
                        "local",
                        "bootstrap_admin",
                        "rejected",
                        "an admin account already exists; repeated bootstrap is not allowed"
                    ],
                );
                anyhow::bail!("an admin account already exists; repeated bootstrap is not allowed");
            }
            connection.execute(
                "INSERT INTO staff_accounts (username, role, password_hash, must_change_password, created_at_unix_ms, updated_at_unix_ms) VALUES (?1, 'admin', ?2, 1, ?3, ?3)",
                params![username, hash, now],
            )?;
            connection.execute(
                "INSERT INTO activity_log (server_time_unix_ms, actor, action, result, detail) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    now,
                    "local",
                    "bootstrap_admin",
                    "success",
                    format!("initial admin '{username}' created with temporary password")
                ],
            )?;
            Ok(())
        })
        .await?
    }

    pub async fn get_staff_account(&self, username: &str) -> Result<Option<StaffAccount>> {
        let store = self.clone();
        let username = username.to_string();
        tokio::task::spawn_blocking(move || {
            let connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            let mut stmt = connection.prepare(
                "SELECT username, role, password_hash, must_change_password, active, created_at_unix_ms, updated_at_unix_ms FROM staff_accounts WHERE username = ?1",
            )?;
            let mut rows = stmt.query(params![username])?;
            if let Some(row) = rows.next()? {
                let role_str: String = row.get(1)?;
                let role: StaffRole = role_str.parse()?;
                let must_change: i64 = row.get(3)?;
                let active: i64 = row.get(4)?;
                Ok(Some(StaffAccount {
                    username: row.get(0)?,
                    role,
                    password_hash: row.get(2)?,
                    must_change_password: must_change != 0,
                    active: active != 0,
                    created_at_unix_ms: row.get(5)?,
                    updated_at_unix_ms: row.get(6)?,
                }))
            } else {
                Ok(None)
            }
        })
        .await?
    }

    pub async fn update_password(
        &self,
        username: &str,
        new_password_hash: String,
        must_change_password: bool,
    ) -> Result<()> {
        let store = self.clone();
        let username = username.to_string();
        tokio::task::spawn_blocking(move || {
            let now = current_time_ms()?;
            let connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            let changed = connection.execute(
                "UPDATE staff_accounts SET password_hash = ?1, must_change_password = ?2, updated_at_unix_ms = ?3 WHERE username = ?4",
                params![new_password_hash, if must_change_password { 1 } else { 0 }, now, username],
            )?;
            if changed == 0 {
                anyhow::bail!("account '{username}' not found");
            }
            // Update active sessions for this account to reflect password change status
            connection.execute(
                "UPDATE staff_sessions SET must_change_password = ?1 WHERE username = ?2 AND revoked = 0",
                params![if must_change_password { 1 } else { 0 }, username],
            )?;
            Ok(())
        })
        .await?
    }

    pub async fn reset_staff_password(
        &self,
        username: &str,
        temporary_password: String,
    ) -> Result<StaffAccount> {
        let hash = crate::password::hash_password(&temporary_password)?;
        let store = self.clone();
        let username = username.to_string();
        tokio::task::spawn_blocking(move || {
            let now = current_time_ms()?;
            let mut connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            let tx = connection.transaction()?;
            let (role, active, created_at_unix_ms) = {
                let mut stmt = tx.prepare(
                    "SELECT role, active, created_at_unix_ms FROM staff_accounts WHERE username = ?1",
                )?;
                let mut rows = stmt.query(params![username])?;
                if let Some(row) = rows.next()? {
                    let role_str: String = row.get(0)?;
                    let active: i64 = row.get(1)?;
                    (role_str.parse()?, active != 0, row.get(2)?)
                } else {
                    anyhow::bail!("account '{username}' not found");
                }
            };
            reset_account_password_to_temporary(&tx, &username, &hash, now)?;
            tx.commit()?;
            Ok(StaffAccount {
                username,
                role,
                password_hash: hash,
                must_change_password: true,
                active,
                created_at_unix_ms,
                updated_at_unix_ms: now,
            })
        })
        .await?
    }

    pub async fn change_own_password(
        &self,
        username: &str,
        current_password: String,
        new_password_hash: String,
    ) -> Result<()> {
        let store = self.clone();
        let username = username.to_string();
        tokio::task::spawn_blocking(move || {
            let now = current_time_ms()?;
            let mut connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            let tx = connection.transaction()?;
            let stored_hash: String = {
                let mut stmt =
                    tx.prepare("SELECT password_hash FROM staff_accounts WHERE username = ?1")?;
                let mut rows = stmt.query(params![username])?;
                if let Some(row) = rows.next()? {
                    row.get(0)?
                } else {
                    anyhow::bail!("account '{username}' not found");
                }
            };
            anyhow::ensure!(
                crate::password::verify_password(&current_password, &stored_hash),
                "current password is incorrect"
            );
            // Guard on the verified hash so a concurrent reset that already committed
            // cannot be silently overwritten by this change.
            let changed = tx.execute(
                "UPDATE staff_accounts SET password_hash = ?1, must_change_password = 0, updated_at_unix_ms = ?2 WHERE username = ?3 AND password_hash = ?4",
                params![new_password_hash, now, username, stored_hash],
            )?;
            anyhow::ensure!(
                changed == 1,
                "password was reset concurrently; sign in again"
            );
            tx.execute(
                "UPDATE staff_sessions SET must_change_password = 0 WHERE username = ?1 AND revoked = 0",
                params![username],
            )?;
            tx.commit()?;
            Ok(())
        })
        .await?
    }

    pub async fn recover_admin(&self, username: String, temporary_password: String) -> Result<()> {
        let username = validate_username(&username)?;
        let hash = crate::password::hash_password(&temporary_password)?;
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let now = current_time_ms()?;
            let mut connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            let tx = connection.transaction()?;
            let role: String = {
                let mut stmt = tx.prepare(
                    "SELECT role FROM staff_accounts WHERE username = ?1",
                )?;
                let mut rows = stmt.query(params![username])?;
                if let Some(row) = rows.next()? {
                    row.get(0)?
                } else {
                    anyhow::bail!("account '{username}' not found");
                }
            };
            anyhow::ensure!(
                role == StaffRole::Admin.as_str(),
                "account '{username}' is not an admin account; local recovery applies to existing admin accounts only"
            );
            reset_account_password_to_temporary(&tx, &username, &hash, now)?;
            tx.execute(
                "INSERT INTO activity_log (server_time_unix_ms, actor, action, result, detail) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    now,
                    "local",
                    "recover_admin",
                    "success",
                    format!("admin account '{username}' reset to a temporary password and its staff sessions revoked")
                ],
            )?;
            tx.commit()?;
            Ok(())
        })
        .await?
    }

    pub async fn list_staff_accounts(&self) -> Result<Vec<StaffAccount>> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            let mut stmt = connection.prepare(
                "SELECT username, role, password_hash, must_change_password, active, created_at_unix_ms, updated_at_unix_ms FROM staff_accounts ORDER BY username ASC",
            )?;
            let rows = stmt.query_map([], |row| {
                let role_str: String = row.get(1)?;
                let role: StaffRole = role_str.parse().map_err(|e: anyhow::Error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Text,
                        Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())),
                    )
                })?;
                let must_change: i64 = row.get(3)?;
                let active: i64 = row.get(4)?;
                Ok(StaffAccount {
                    username: row.get(0)?,
                    role,
                    password_hash: row.get(2)?,
                    must_change_password: must_change != 0,
                    active: active != 0,
                    created_at_unix_ms: row.get(5)?,
                    updated_at_unix_ms: row.get(6)?,
                })
            })?;
            let mut accounts = Vec::new();
            for r in rows {
                accounts.push(r?);
            }
            Ok(accounts)
        })
        .await?
    }

    pub async fn create_staff_account(
        &self,
        username: String,
        role: StaffRole,
        temporary_password: String,
    ) -> Result<StaffAccount> {
        let username = validate_username(&username)?;
        let hash = crate::password::hash_password(&temporary_password)?;
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let now = current_time_ms()?;
            let connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            let exists: i64 = connection.query_row(
                "SELECT COUNT(*) FROM staff_accounts WHERE username = ?1",
                params![username],
                |row| row.get(0),
            )?;
            if exists > 0 {
                anyhow::bail!("staff account '{username}' already exists");
            }
            connection.execute(
                "INSERT INTO staff_accounts (username, role, password_hash, must_change_password, active, created_at_unix_ms, updated_at_unix_ms) VALUES (?1, ?2, ?3, 1, 1, ?4, ?4)",
                params![username, role.as_str(), hash, now],
            )?;
            Ok(StaffAccount {
                username,
                role,
                password_hash: hash,
                must_change_password: true,
                active: true,
                created_at_unix_ms: now,
                updated_at_unix_ms: now,
            })
        })
        .await?
    }

    pub async fn change_staff_role(
        &self,
        username: &str,
        new_role: StaffRole,
    ) -> Result<StaffAccount> {
        let store = self.clone();
        let username = username.to_string();
        tokio::task::spawn_blocking(move || {
            let now = current_time_ms()?;
            let mut connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            let tx = connection.transaction()?;
            let (current_role, password_hash, must_change_password, active, created_at_unix_ms) = {
                let mut stmt = tx.prepare(
                    "SELECT role, password_hash, must_change_password, active, created_at_unix_ms FROM staff_accounts WHERE username = ?1",
                )?;
                let mut rows = stmt.query(params![username])?;
                if let Some(row) = rows.next()? {
                    let role_str: String = row.get(0)?;
                    let role: StaffRole = role_str.parse()?;
                    let must_change: i64 = row.get(2)?;
                    let active: i64 = row.get(3)?;
                    (role, row.get(1)?, must_change != 0, active != 0, row.get(4)?)
                } else {
                    anyhow::bail!("account '{username}' not found");
                }
            };

            if current_role == StaffRole::Admin && new_role == StaffRole::Operator && active {
                let admin_count: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM staff_accounts WHERE role = 'admin' AND active = 1",
                    [],
                    |row| row.get(0),
                )?;
                if admin_count <= 1 {
                    anyhow::bail!("cannot demote the last active admin");
                }
            }

            tx.execute(
                "UPDATE staff_accounts SET role = ?1, updated_at_unix_ms = ?2 WHERE username = ?3",
                params![new_role.as_str(), now, username],
            )?;

            tx.execute(
                "UPDATE staff_sessions SET role = ?1 WHERE username = ?2 AND revoked = 0",
                params![new_role.as_str(), username],
            )?;

            tx.commit()?;

            Ok(StaffAccount {
                username,
                role: new_role,
                password_hash,
                must_change_password,
                active,
                created_at_unix_ms,
                updated_at_unix_ms: now,
            })
        })
        .await?
    }

    pub async fn deactivate_staff_account(&self, username: &str) -> Result<StaffAccount> {
        let store = self.clone();
        let username = username.to_string();
        tokio::task::spawn_blocking(move || {
            let now = current_time_ms()?;
            let mut connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            let tx = connection.transaction()?;
            let (role, password_hash, must_change_password, active, created_at_unix_ms) = {
                let mut stmt = tx.prepare(
                    "SELECT role, password_hash, must_change_password, active, created_at_unix_ms FROM staff_accounts WHERE username = ?1",
                )?;
                let mut rows = stmt.query(params![username])?;
                if let Some(row) = rows.next()? {
                    let role_str: String = row.get(0)?;
                    let role: StaffRole = role_str.parse()?;
                    let must_change: i64 = row.get(2)?;
                    let active: i64 = row.get(3)?;
                    (
                        role,
                        row.get(1)?,
                        must_change != 0,
                        active != 0,
                        row.get(4)?,
                    )
                } else {
                    anyhow::bail!("account '{username}' not found");
                }
            };
            anyhow::ensure!(active, "account '{username}' is already deactivated");
            if role == StaffRole::Admin {
                let admin_count: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM staff_accounts WHERE role = 'admin' AND active = 1",
                    [],
                    |row| row.get(0),
                )?;
                anyhow::ensure!(
                    admin_count > 1,
                    "cannot deactivate the last active admin"
                );
            }
            tx.execute(
                "UPDATE staff_accounts SET active = 0, updated_at_unix_ms = ?1 WHERE username = ?2",
                params![now, username],
            )?;
            tx.execute(
                "UPDATE staff_sessions SET revoked = 1 WHERE username = ?1 AND revoked = 0",
                params![username],
            )?;
            tx.commit()?;
            Ok(StaffAccount {
                username,
                role,
                password_hash,
                must_change_password,
                active: false,
                created_at_unix_ms,
                updated_at_unix_ms: now,
            })
        })
        .await?
    }

    // Creates the login session only when the password hash the caller verified is
    // still the account's current hash, atomically with the insert. A reset or
    // self-change that commits first either fails this check or, when it commits
    // after, revokes the freshly inserted session. Remembered sessions carry a
    // finite expiry that get_session enforces on every validation.
    pub async fn create_login_session(
        &self,
        session_id: String,
        username: String,
        verified_password_hash: String,
        expires_at_unix_ms: Option<i64>,
    ) -> Result<Option<StaffSession>> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let now = current_time_ms()?;
            let mut connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            let tx = connection.transaction()?;
            let (password_hash, role_str, must_change, active): (String, String, bool, bool) = {
                let mut stmt = tx.prepare(
                    "SELECT password_hash, role, must_change_password, active FROM staff_accounts WHERE username = ?1",
                )?;
                let mut rows = stmt.query(params![username])?;
                if let Some(row) = rows.next()? {
                    let must_change: i64 = row.get(2)?;
                    let active: i64 = row.get(3)?;
                    (row.get(0)?, row.get(1)?, must_change != 0, active != 0)
                } else {
                    return Ok(None);
                }
            };
            // Deactivated accounts never start sessions, even with valid credentials.
            if !active {
                return Ok(None);
            }
            if password_hash != verified_password_hash {
                return Ok(None);
            }
            let role: StaffRole = role_str.parse()?;
            tx.execute(
                "INSERT INTO staff_sessions (session_id, username, role, must_change_password, created_at_unix_ms, last_seen_unix_ms, revoked, expires_at_unix_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?5, 0, ?6)",
                params![
                    session_id,
                    username,
                    role.as_str(),
                    if must_change { 1 } else { 0 },
                    now,
                    expires_at_unix_ms
                ],
            )?;
            tx.commit()?;
            Ok(Some(StaffSession {
                session_id,
                username,
                role,
                must_change_password: must_change,
                created_at_unix_ms: now,
                last_seen_unix_ms: now,
                revoked: false,
            }))
        })
        .await?
    }

    pub async fn get_session(&self, session_id: &str) -> Result<Option<StaffSession>> {
        let store = self.clone();
        let session_id = session_id.to_string();
        tokio::task::spawn_blocking(move || {
            let now = current_time_ms()?;
            let connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            let mut stmt = connection.prepare(
                "SELECT s.session_id, s.username, a.role, s.must_change_password, s.created_at_unix_ms, s.last_seen_unix_ms, s.revoked, a.active, s.expires_at_unix_ms FROM staff_sessions s JOIN staff_accounts a ON s.username = a.username WHERE s.session_id = ?1",
            )?;
            let mut rows = stmt.query(params![session_id])?;
            if let Some(row) = rows.next()? {
                let role_str: String = row.get(2)?;
                let role: StaffRole = role_str.parse()?;
                let must_change: i64 = row.get(3)?;
                let revoked: i64 = row.get(6)?;
                let active: i64 = row.get(7)?;
                let expires_at: Option<i64> = row.get(8)?;
                let session = StaffSession {
                    session_id: row.get(0)?,
                    username: row.get(1)?,
                    role,
                    must_change_password: must_change != 0,
                    created_at_unix_ms: row.get(4)?,
                    last_seen_unix_ms: row.get(5)?,
                    revoked: revoked != 0
                        || active == 0
                        || expires_at.is_some_and(|deadline| deadline <= now),
                };
                if !session.revoked {
                    let _ = connection.execute(
                        "UPDATE staff_sessions SET last_seen_unix_ms = ?1 WHERE session_id = ?2",
                        params![now, session_id],
                    );
                }
                Ok(Some(session))
            } else {
                Ok(None)
            }
        })
        .await?
    }

    pub async fn revoke_session(&self, session_id: &str) -> Result<bool> {
        let store = self.clone();
        let session_id = session_id.to_string();
        tokio::task::spawn_blocking(move || {
            let connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            let updated = connection.execute(
                "UPDATE staff_sessions SET revoked = 1 WHERE session_id = ?1 AND revoked = 0",
                params![session_id],
            )?;
            Ok(updated > 0)
        })
        .await?
    }

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

    pub async fn create_installation_authorization(
        &self,
        authorization_id: String,
        secret_hash: String,
        created_by: String,
    ) -> Result<InstallationAuthorizationRecord> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let now = current_time_ms()?;
            let connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            connection.execute(
                "INSERT INTO installation_authorizations (authorization_id, secret_hash, created_at_unix_ms, created_by, revoked_at_unix_ms) VALUES (?1, ?2, ?3, ?4, NULL)",
                params![authorization_id, secret_hash, now, created_by],
            )?;
            Ok(InstallationAuthorizationRecord {
                authorization_id,
                secret_hash,
                created_at_unix_ms: now,
                created_by,
                revoked_at_unix_ms: None,
            })
        })
        .await?
    }

    pub async fn get_installation_authorization(
        &self,
        authorization_id: &str,
    ) -> Result<Option<InstallationAuthorizationRecord>> {
        let store = self.clone();
        let authorization_id = authorization_id.to_string();
        tokio::task::spawn_blocking(move || {
            let connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            let mut stmt = connection.prepare(
                "SELECT authorization_id, secret_hash, created_at_unix_ms, created_by, revoked_at_unix_ms FROM installation_authorizations WHERE authorization_id = ?1",
            )?;
            let mut rows = stmt.query(params![authorization_id])?;
            if let Some(row) = rows.next()? {
                Ok(Some(InstallationAuthorizationRecord {
                    authorization_id: row.get(0)?,
                    secret_hash: row.get(1)?,
                    created_at_unix_ms: row.get(2)?,
                    created_by: row.get(3)?,
                    revoked_at_unix_ms: row.get(4)?,
                }))
            } else {
                Ok(None)
            }
        })
        .await?
    }

    pub async fn find_installation_authorization_by_hash(
        &self,
        secret_hash: &str,
    ) -> Result<Option<InstallationAuthorizationRecord>> {
        let store = self.clone();
        let secret_hash = secret_hash.to_string();
        tokio::task::spawn_blocking(move || {
            let connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            let mut stmt = connection.prepare(
                "SELECT authorization_id, secret_hash, created_at_unix_ms, created_by, revoked_at_unix_ms FROM installation_authorizations WHERE secret_hash = ?1",
            )?;
            let mut rows = stmt.query(params![secret_hash])?;
            if let Some(row) = rows.next()? {
                Ok(Some(InstallationAuthorizationRecord {
                    authorization_id: row.get(0)?,
                    secret_hash: row.get(1)?,
                    created_at_unix_ms: row.get(2)?,
                    created_by: row.get(3)?,
                    revoked_at_unix_ms: row.get(4)?,
                }))
            } else {
                Ok(None)
            }
        })
        .await?
    }

    pub async fn revoke_installation_authorization(
        &self,
        authorization_id: &str,
    ) -> Result<RevokeAuthorizationOutcome> {
        let store = self.clone();
        let authorization_id = authorization_id.to_string();
        tokio::task::spawn_blocking(move || {
            let connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;

            let mut stmt = connection.prepare(
                "SELECT authorization_id, secret_hash, created_at_unix_ms, created_by, revoked_at_unix_ms FROM installation_authorizations WHERE authorization_id = ?1",
            )?;
            let mut rows = stmt.query(params![authorization_id])?;
            let record = match rows.next()? {
                Some(row) => InstallationAuthorizationRecord {
                    authorization_id: row.get(0)?,
                    secret_hash: row.get(1)?,
                    created_at_unix_ms: row.get(2)?,
                    created_by: row.get(3)?,
                    revoked_at_unix_ms: row.get(4)?,
                },
                None => return Ok(RevokeAuthorizationOutcome::NotFound),
            };

            if record.revoked_at_unix_ms.is_some() {
                return Ok(RevokeAuthorizationOutcome::AlreadyRevoked);
            }

            let now = current_time_ms()?;
            connection.execute(
                "UPDATE installation_authorizations SET revoked_at_unix_ms = ?1 WHERE authorization_id = ?2 AND revoked_at_unix_ms IS NULL",
                params![now, authorization_id],
            )?;

            Ok(RevokeAuthorizationOutcome::Revoked(
                InstallationAuthorizationRecord {
                    revoked_at_unix_ms: Some(now),
                    ..record
                },
            ))
        })
        .await?
    }

    pub async fn list_installation_authorizations(
        &self,
    ) -> Result<Vec<InstallationAuthorizationRecord>> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            let mut stmt = connection.prepare(
                "SELECT authorization_id, secret_hash, created_at_unix_ms, created_by, revoked_at_unix_ms FROM installation_authorizations ORDER BY created_at_unix_ms DESC",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(InstallationAuthorizationRecord {
                    authorization_id: row.get(0)?,
                    secret_hash: row.get(1)?,
                    created_at_unix_ms: row.get(2)?,
                    created_by: row.get(3)?,
                    revoked_at_unix_ms: row.get(4)?,
                })
            })?;
            let mut auths = Vec::new();
            for r in rows {
                auths.push(r?);
            }
            Ok(auths)
        })
        .await?
    }

    pub async fn record_device_enrollment(
        &self,
        device_id: DeviceId,
        authorization_id: String,
        name: String,
        agent_version: String,
        remote_address: Option<String>,
        resumption_secret_hash: String,
    ) -> Result<i64> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let mut connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            let now = current_time_ms()?;
            let tx = connection.transaction()?;

            let is_replaced: i64 = tx.query_row(
                "SELECT COUNT(*) FROM device_replacements WHERE prior_device_id = ?1",
                params![device_id.to_string()],
                |row| row.get(0),
            )?;
            if is_replaced > 0 {
                anyhow::bail!("device '{}' has been replaced", device_id);
            }

            let is_blocked: i64 = tx.query_row(
                "SELECT COUNT(*) FROM blocked_devices WHERE device_id = ?1",
                params![device_id.to_string()],
                |row| row.get(0),
            )?;
            if is_blocked > 0 {
                anyhow::bail!("device '{}' is blocked", device_id);
            }

            let existing: Option<(String, Option<String>)> = tx
                .query_row(
                    "SELECT authorization_id, resumption_secret_hash FROM device_enrollments WHERE device_id = ?1",
                    params![device_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;

            if let Some((enrolled_auth, stored_resumption_hash)) = &existing {
                if enrolled_auth != &authorization_id {
                    anyhow::bail!(
                        "device '{}' is already enrolled under a different authorization",
                        device_id
                    );
                }
                match stored_resumption_hash {
                    Some(expected) if expected == &resumption_secret_hash => {}
                    _ => {
                        anyhow::bail!(
                            "resumption secret does not match enrolled device '{}'",
                            device_id
                        );
                    }
                }
            } else {
                let is_bootstrap: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM bootstrap_devices WHERE device_id = ?1",
                    params![device_id.to_string()],
                    |row| row.get(0),
                )?;
                if is_bootstrap > 0 {
                    anyhow::bail!(
                        "device '{}' already exists in inventory as a bootstrap device",
                        device_id
                    );
                }

                let is_known: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM known_device_identities WHERE device_id = ?1",
                    params![device_id.to_string()],
                    |row| row.get(0),
                )?;
                if is_known > 0 {
                    anyhow::bail!("device '{}' already exists in inventory", device_id);
                }

                let is_revoked: Option<Option<i64>> = tx
                    .query_row(
                        "SELECT revoked_at_unix_ms FROM installation_authorizations WHERE authorization_id = ?1",
                        params![authorization_id],
                        |row| row.get(0),
                    )
                    .optional()?;
                match is_revoked {
                    None => anyhow::bail!("installation authorization not found"),
                    Some(Some(_)) => anyhow::bail!("installation authorization has been revoked"),
                    Some(None) => {}
                }

                tx.execute(
                    "INSERT INTO device_enrollments (device_id, authorization_id, enrolled_at_unix_ms, resumption_secret_hash) VALUES (?1, ?2, ?3, ?4)",
                    params![device_id.to_string(), authorization_id, now, resumption_secret_hash],
                )?;

                tx.execute(
                    "INSERT OR IGNORE INTO known_device_identities (device_id) VALUES (?1)",
                    params![device_id.to_string()],
                )?;
            }

            tx.execute(
                "INSERT INTO bootstrap_devices (device_id, name, agent_version, last_address, last_seen_unix_ms) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(device_id) DO UPDATE SET name = excluded.name, agent_version = excluded.agent_version, last_address = excluded.last_address, last_seen_unix_ms = excluded.last_seen_unix_ms",
                params![device_id.to_string(), name, agent_version, remote_address, now],
            )?;

            tx.commit()?;
            Ok(now)
        })
        .await?
    }

    pub async fn get_device_enrollment(
        &self,
        device_id: &str,
    ) -> Result<Option<DeviceEnrollmentRecord>> {
        let store = self.clone();
        let device_id = device_id.to_string();
        tokio::task::spawn_blocking(move || {
            let connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            let mut stmt = connection.prepare(
                "SELECT device_id, authorization_id, enrolled_at_unix_ms, resumption_secret_hash FROM device_enrollments WHERE device_id = ?1",
            )?;
            let mut rows = stmt.query(params![device_id])?;
            if let Some(row) = rows.next()? {
                Ok(Some(DeviceEnrollmentRecord {
                    device_id: row.get(0)?,
                    authorization_id: row.get(1)?,
                    enrolled_at_unix_ms: row.get(2)?,
                    resumption_secret_hash: row.get(3)?,
                }))
            } else {
                Ok(None)
            }
        })
        .await?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn login_session_rejects_credentials_superseded_by_a_password_change() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let store = DeviceStore::open(&temp.path().join("store.db"))?;
        store
            .bootstrap_admin("alice".into(), "TempPass1234!".into())
            .await?;

        let account = store
            .get_staff_account("alice")
            .await?
            .expect("bootstrapped account");
        let session = store
            .create_login_session(
                "s1".into(),
                "alice".into(),
                account.password_hash.clone(),
                None,
            )
            .await?;
        let session = session.expect("current hash yields a session");
        assert!(session.must_change_password);
        assert_eq!(session.role, StaffRole::Admin);

        // A password change supersedes the verified hash; a login that verified
        // the old hash must not produce a session.
        let new_hash = crate::password::hash_password("NewPermanent123!")?;
        store
            .update_password("alice", new_hash.clone(), false)
            .await?;
        let stale = store
            .create_login_session("s2".into(), "alice".into(), account.password_hash, None)
            .await?;
        assert!(stale.is_none(), "stale hash must not create a session");

        // The new hash still yields one, reflecting the fresh account state.
        let fresh = store
            .create_login_session("s3".into(), "alice".into(), new_hash, None)
            .await?
            .expect("current hash yields a session");
        assert!(!fresh.must_change_password);

        // Unknown accounts never yield a session.
        let unknown = store
            .create_login_session("s4".into(), "ghost".into(), "irrelevant".into(), None)
            .await?;
        assert!(unknown.is_none());

        // A remembered session with a past deadline is treated as revoked.
        let past = store
            .create_login_session(
                "s5".into(),
                "alice".into(),
                store
                    .get_staff_account("alice")
                    .await?
                    .expect("account")
                    .password_hash,
                Some(1),
            )
            .await?
            .expect("session created");
        assert!(past.created_at_unix_ms > 1);
        let expired = store.get_session("s5").await?.expect("row exists");
        assert!(
            expired.revoked,
            "expired remembered session must be invalid"
        );

        Ok(())
    }

    #[tokio::test]
    async fn device_metadata_curation_survives_subsequent_heartbeats() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let store = DeviceStore::open(&temp.path().join("store.db"))?;
        let dev_id = DeviceId::new();

        // 1. A newly seen device starts with its reported hostname and no location.
        store
            .heartbeat(
                dev_id,
                "DESKTOP-ABC1234".into(),
                "1.0.0".into(),
                Some("192.168.1.50:5000".into()),
            )
            .await?;

        let dev = store
            .get_device(&dev_id.to_string())
            .await?
            .expect("device exists");
        assert_eq!(dev.name, "DESKTOP-ABC1234");
        assert_eq!(dev.location, None);
        assert_eq!(dev.last_address, Some("192.168.1.50:5000".into()));

        let list = store.list_devices().await?;
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "DESKTOP-ABC1234");
        assert_eq!(list[0].location, None);

        // 2. Admin edits display name and adds location.
        let updated = store
            .update_device_metadata(
                &dev_id.to_string(),
                "Reception Front Desk",
                Some("Building A - Floor 1"),
            )
            .await?;
        assert_eq!(updated.name, "Reception Front Desk");
        assert_eq!(updated.location, Some("Building A - Floor 1".into()));

        // 3. Subsequent heartbeats report new IP, newer version, or even a different hostname.
        // Observed data updates, but curated metadata must NOT be overwritten!
        store
            .heartbeat(
                dev_id,
                "DESKTOP-ABC1234-RENAMED".into(),
                "1.1.0".into(),
                Some("192.168.1.99:5000".into()),
            )
            .await?;

        let dev_after = store
            .get_device(&dev_id.to_string())
            .await?
            .expect("device exists");
        assert_eq!(dev_after.name, "Reception Front Desk");
        assert_eq!(dev_after.location, Some("Building A - Floor 1".into()));
        assert_eq!(dev_after.agent_version, "1.1.0");
        assert_eq!(dev_after.last_address, Some("192.168.1.99:5000".into()));

        // 4. Admin clears the location (sets to None or whitespace).
        let cleared = store
            .update_device_metadata(&dev_id.to_string(), "Reception Front Desk", Some("   "))
            .await?;
        assert_eq!(cleared.name, "Reception Front Desk");
        assert_eq!(cleared.location, None);

        // 5. Validation checks:
        // Empty display name rejected
        assert!(
            store
                .update_device_metadata(&dev_id.to_string(), "   ", None)
                .await
                .is_err()
        );
        // Non-existent device rejected
        let fake_id = DeviceId::new();
        assert!(
            store
                .update_device_metadata(&fake_id.to_string(), "Valid Name", None)
                .await
                .is_err()
        );

        Ok(())
    }

    #[tokio::test]
    async fn device_blocking_and_unblocking_restricts_heartbeat_and_persists() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let db_path = temp.path().join("store.db");
        let store = DeviceStore::open(&db_path)?;
        let dev_id = DeviceId::new();

        // 1. Initial heartbeat registers the device as unblocked.
        store
            .heartbeat(
                dev_id,
                "DESKTOP-TEST".into(),
                "1.0.0".into(),
                Some("192.168.1.100:5000".into()),
            )
            .await?;

        let dev = store
            .get_device(&dev_id.to_string())
            .await?
            .expect("device exists");
        assert!(!dev.blocked, "newly registered device must not be blocked");
        assert!(
            !store.is_device_blocked(&dev_id.to_string()).await?,
            "is_device_blocked must return false"
        );

        // 2. Admin blocks the device.
        let blocked_record = store.block_device(&dev_id.to_string(), "alice").await?;
        assert!(blocked_record.blocked, "record must be blocked");
        assert!(
            store.is_device_blocked(&dev_id.to_string()).await?,
            "is_device_blocked must return true"
        );

        let dev_blocked = store
            .get_device(&dev_id.to_string())
            .await?
            .expect("device exists");
        assert!(dev_blocked.blocked, "get_device must show blocked");

        let list = store.list_devices().await?;
        assert_eq!(list.len(), 1);
        assert!(list[0].blocked, "list_devices must show blocked");

        // 3. Heartbeat for blocked device must fail.
        let hb_err = store
            .heartbeat(
                dev_id,
                "DESKTOP-TEST".into(),
                "1.0.0".into(),
                Some("192.168.1.101:5000".into()),
            )
            .await
            .unwrap_err();
        assert!(
            hb_err.to_string().contains("is blocked"),
            "heartbeat error must indicate device is blocked: {hb_err}"
        );

        // 4. Blocking an already-blocked device must fail.
        let already_blocked_err = store
            .block_device(&dev_id.to_string(), "alice")
            .await
            .unwrap_err();
        assert!(
            already_blocked_err.to_string().contains("already blocked"),
            "error must indicate already blocked: {already_blocked_err}"
        );

        // 5. Blocking persists across store reopen.
        drop(store);
        let store2 = DeviceStore::open(&db_path)?;
        assert!(
            store2.is_device_blocked(&dev_id.to_string()).await?,
            "is_device_blocked must persist across restart"
        );
        let list2 = store2.list_devices().await?;
        assert!(list2[0].blocked, "list_devices must persist blocked");

        // 6. Admin unblocks the device.
        let unblocked_record = store2.unblock_device(&dev_id.to_string()).await?;
        assert!(!unblocked_record.blocked, "record must be unblocked");
        assert!(
            !store2.is_device_blocked(&dev_id.to_string()).await?,
            "is_device_blocked must return false after unblock"
        );

        // 7. Unblocking a non-blocked device must fail.
        let not_blocked_err = store2
            .unblock_device(&dev_id.to_string())
            .await
            .unwrap_err();
        assert!(
            not_blocked_err.to_string().contains("not blocked"),
            "error must indicate not blocked: {not_blocked_err}"
        );

        // 8. Subsequent heartbeat succeeds.
        store2
            .heartbeat(
                dev_id,
                "DESKTOP-TEST".into(),
                "1.0.1".into(),
                Some("192.168.1.102:5000".into()),
            )
            .await?;
        let dev_restored = store2
            .get_device(&dev_id.to_string())
            .await?
            .expect("device exists");
        assert_eq!(dev_restored.agent_version, "1.0.1");
        assert!(!dev_restored.blocked);

        // 9. Edge cases: non-existent device and invalid device ID.
        let non_existent = DeviceId::new();
        let not_found_err = store2
            .block_device(&non_existent.to_string(), "alice")
            .await
            .unwrap_err();
        assert!(not_found_err.to_string().contains("not found"));

        let invalid_id_err = store2
            .block_device("not-a-uuid", "alice")
            .await
            .unwrap_err();
        assert!(invalid_id_err.to_string().contains("invalid device_id"));

        Ok(())
    }

    #[tokio::test]
    async fn clean_offline_device_removes_entry_without_revoking_access_and_preserves_attribution()
    -> Result<()> {
        let temp = tempfile::tempdir()?;
        let db_path = temp.path().join("store.db");
        let store = DeviceStore::open(&db_path)?;
        let dev_id = DeviceId::new();

        // 1. Invalid device ID fails.
        let invalid_err = store
            .clean_offline_device("not-a-uuid", 60)
            .await
            .unwrap_err();
        assert!(invalid_err.to_string().contains("invalid device_id"));

        // 2. Non-existent device fails.
        let not_found_err = store
            .clean_offline_device(&dev_id.to_string(), 60)
            .await
            .unwrap_err();
        assert!(not_found_err.to_string().contains("not found"));

        // 3. Connection target cannot be cleaned via clean_offline_device.
        let target = store
            .create_target(
                "Boardroom TV",
                "192.168.1.50:5555",
                Some("android_tv"),
                None,
            )
            .await?;
        let target_clean_err = store
            .clean_offline_device(&target.target_id, 60)
            .await
            .unwrap_err();
        assert!(
            target_clean_err.to_string().contains("connection target"),
            "cleaning a connection target must fail: {target_clean_err}"
        );

        // 4. Register a Windows device and update metadata.
        store
            .heartbeat(
                dev_id,
                "WORKSTATION-01".into(),
                "1.0.0".into(),
                Some("192.168.1.100:5000".into()),
            )
            .await?;
        store
            .update_device_metadata(&dev_id.to_string(), "Finance PC", Some("Floor 2"))
            .await?;
        store
            .record_activity(
                "alice".into(),
                "test_action".into(),
                "success".into(),
                format!("attributed to device '{dev_id}'"),
            )
            .await?;

        // 5. Attempting to clean online device fails.
        let online_clean_err = store
            .clean_offline_device(&dev_id.to_string(), 60)
            .await
            .unwrap_err();
        assert!(
            online_clean_err.to_string().contains("online"),
            "online device must not be cleaned: {online_clean_err}"
        );

        // 6. Block device: even if offline window is 0, cleaning a blocked device must fail.
        store.block_device(&dev_id.to_string(), "alice").await?;
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let blocked_clean_err = store
            .clean_offline_device(&dev_id.to_string(), 0)
            .await
            .unwrap_err();
        assert!(
            blocked_clean_err.to_string().contains("blocked"),
            "blocked device cannot be cleaned up: {blocked_clean_err}"
        );

        // 7. Unblock device.
        store.unblock_device(&dev_id.to_string()).await?;

        // 8. Offline cleanup succeeds with window = 0 after brief sleep.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let cleaned_id = store.clean_offline_device(&dev_id.to_string(), 0).await?;
        assert_eq!(cleaned_id, dev_id.to_string());

        // 9. Entry is removed from inventory and metadata.
        assert!(
            store.get_device(&dev_id.to_string()).await?.is_none(),
            "cleaned device must not be returned by get_device"
        );
        let list_after_clean = store.list_devices().await?;
        assert!(
            !list_after_clean
                .iter()
                .any(|d| d.device_id == dev_id.to_string()),
            "cleaned device must not be in list_devices"
        );

        // 10. Removal persists across store reopen.
        drop(store);
        let store2 = DeviceStore::open(&db_path)?;
        assert!(
            store2.get_device(&dev_id.to_string()).await?.is_none(),
            "cleaned device must remain removed across restart"
        );

        // 11. Still-authorized agent reconnects and restores entry under SAME identity without duplicate.
        store2
            .heartbeat(
                dev_id,
                "WORKSTATION-01".into(),
                "1.0.0".into(),
                Some("192.168.1.105:5000".into()),
            )
            .await?;
        let restored_dev = store2
            .get_device(&dev_id.to_string())
            .await?
            .expect("restored device must exist");
        assert_eq!(restored_dev.device_id, dev_id.to_string());
        assert_eq!(restored_dev.name, "WORKSTATION-01");
        assert!(!restored_dev.blocked);

        let list_restored = store2.list_devices().await?;
        let matching: Vec<_> = list_restored
            .iter()
            .filter(|d| d.device_id == dev_id.to_string())
            .collect();
        assert_eq!(matching.len(), 1, "exactly one device record must exist");

        // 12. Historical activity attribution remains intact.
        let activities = store2.list_activity().await?;
        assert!(
            activities
                .iter()
                .any(|a| a.detail.contains(&dev_id.to_string()) && a.action == "test_action"),
            "historical activity attribution must be preserved after cleanup and restoration"
        );

        Ok(())
    }

    #[tokio::test]
    async fn replace_device_reconciles_inventory_transfers_metadata_preserves_blocks_and_association()
    -> Result<()> {
        let temp = tempfile::tempdir()?;
        let db_path = temp.path().join("store.db");
        let store = DeviceStore::open(&db_path)?;
        let prior_id = DeviceId::new();
        let replacement_id = DeviceId::new();

        // 1. Invalid prior or replacement device ID fails.
        let invalid_err = store
            .replace_device("not-a-uuid", &replacement_id.to_string(), "alice")
            .await
            .unwrap_err();
        assert!(invalid_err.to_string().contains("invalid prior_device_id"));

        let invalid_rep_err = store
            .replace_device(&prior_id.to_string(), "not-a-uuid", "alice")
            .await
            .unwrap_err();
        assert!(
            invalid_rep_err
                .to_string()
                .contains("invalid replacement_device_id")
        );

        // 2. Same device ID fails.
        let same_err = store
            .replace_device(&prior_id.to_string(), &prior_id.to_string(), "alice")
            .await
            .unwrap_err();
        assert!(same_err.to_string().contains("must be different"));

        // 3. Non-existent prior or replacement fails.
        let not_found_prior = store
            .replace_device(&prior_id.to_string(), &replacement_id.to_string(), "alice")
            .await
            .unwrap_err();
        assert!(
            not_found_prior.to_string().contains("prior device")
                && not_found_prior.to_string().contains("not found")
        );

        // Register prior device.
        store
            .heartbeat(
                prior_id,
                "OLD-HOSTNAME".into(),
                "1.0.0".into(),
                Some("192.168.1.50:5000".into()),
            )
            .await?;
        store
            .update_device_metadata(
                &prior_id.to_string(),
                "Reception PC",
                Some("Floor 1 Reception"),
            )
            .await?;

        // Prior device has audit history.
        store
            .record_activity(
                "alice".into(),
                "update_fleet_device".into(),
                "success".into(),
                format!("updated device '{prior_id}' display name"),
            )
            .await?;

        let not_found_rep = store
            .replace_device(&prior_id.to_string(), &replacement_id.to_string(), "alice")
            .await
            .unwrap_err();
        assert!(
            not_found_rep.to_string().contains("replacement device")
                && not_found_rep.to_string().contains("not found")
        );

        // 4. Connection target cannot be replaced or used as replacement.
        let target = store
            .create_target("Lobby TV", "192.168.1.60:5555", Some("android_tv"), None)
            .await?;
        let target_prior_err = store
            .replace_device(&target.target_id, &replacement_id.to_string(), "alice")
            .await
            .unwrap_err();
        assert!(target_prior_err.to_string().contains("connection target"));

        // Register replacement device with same hostname/address as the reinstalled machine.
        store
            .heartbeat(
                replacement_id,
                "OLD-HOSTNAME".into(),
                "1.0.0".into(),
                Some("192.168.1.50:5000".into()),
            )
            .await?;

        let target_rep_err = store
            .replace_device(&prior_id.to_string(), &target.target_id, "alice")
            .await
            .unwrap_err();
        assert!(target_rep_err.to_string().contains("connection target"));

        // 5. Block prior device to test that block is preserved across replacement.
        store.block_device(&prior_id.to_string(), "alice").await?;

        // Both devices currently exist distinctly before replacement (no auto-merge).
        let list_before = store.list_devices().await?;
        assert_eq!(
            list_before
                .iter()
                .filter(|d| d.device_id == prior_id.to_string()
                    || d.device_id == replacement_id.to_string())
                .count(),
            2,
            "both prior and replacement devices must exist distinctly before replacement"
        );

        // 6. Explicit replacement.
        let reconciled = store
            .replace_device(&prior_id.to_string(), &replacement_id.to_string(), "alice")
            .await?;
        assert_eq!(reconciled.device_id, replacement_id.to_string());
        assert_eq!(
            reconciled.name, "Reception PC",
            "curated display name must transfer to replacement"
        );
        assert_eq!(
            reconciled.location.as_deref(),
            Some("Floor 1 Reception"),
            "location must transfer"
        );
        assert!(
            reconciled.blocked,
            "block must be preserved on replacement device"
        );

        // 7. Prior device is removed from visible inventory, replacement is present.
        assert!(store.get_device(&prior_id.to_string()).await?.is_none());
        let list_after = store.list_devices().await?;
        assert!(
            !list_after
                .iter()
                .any(|d| d.device_id == prior_id.to_string()),
            "prior device must not appear in list_devices"
        );
        let rep_in_list = list_after
            .iter()
            .find(|d| d.device_id == replacement_id.to_string())
            .expect("replacement device must be in list_devices");
        assert_eq!(rep_in_list.name, "Reception PC");
        assert!(rep_in_list.blocked);

        // 8. Replaced prior device cannot reconnect/send heartbeat.
        let heartbeat_err = store
            .heartbeat(
                prior_id,
                "OLD-HOSTNAME".into(),
                "1.0.0".into(),
                Some("192.168.1.50:5000".into()),
            )
            .await
            .unwrap_err();
        assert!(
            heartbeat_err.to_string().contains("replaced"),
            "replaced prior device must not be able to heartbeat: {heartbeat_err}"
        );

        // 9. Association is preserved and queryable.
        let repl_record = store
            .get_device_replacement(&prior_id.to_string())
            .await?
            .expect("replacement association must exist");
        assert_eq!(repl_record.prior_device_id, prior_id.to_string());
        assert_eq!(
            repl_record.replacement_device_id,
            replacement_id.to_string()
        );
        assert_eq!(repl_record.replaced_by, "alice");

        // 10. Replaced device cannot be replaced again.
        let already_repl_err = store
            .replace_device(&prior_id.to_string(), &replacement_id.to_string(), "alice")
            .await
            .unwrap_err();
        assert!(
            already_repl_err
                .to_string()
                .contains("already been replaced")
                || already_repl_err.to_string().contains("not found")
        );

        // 11. Historical activity attribution is not rewritten.
        let activities = store.list_activity().await?;
        assert!(
            activities
                .iter()
                .any(|a| a.detail.contains(&prior_id.to_string())
                    && a.action == "update_fleet_device"),
            "past activity must retain prior_device_id attribution"
        );
        assert!(
            !activities
                .iter()
                .any(|a| a.detail.contains(&replacement_id.to_string())
                    && a.action == "update_fleet_device"),
            "past activity must not be rewritten to replacement_device_id"
        );

        // 12. Result and association persist across Server restart.
        drop(store);
        let store2 = DeviceStore::open(&db_path)?;

        assert!(store2.get_device(&prior_id.to_string()).await?.is_none());
        let rep_restarted = store2
            .get_device(&replacement_id.to_string())
            .await?
            .expect("replacement device must persist");
        assert_eq!(rep_restarted.name, "Reception PC");
        assert_eq!(rep_restarted.location.as_deref(), Some("Floor 1 Reception"));
        assert!(rep_restarted.blocked);

        let repl_persisted = store2
            .get_device_replacement(&prior_id.to_string())
            .await?
            .expect("replacement association must persist across restart");
        assert_eq!(repl_persisted.prior_device_id, prior_id.to_string());
        assert_eq!(
            repl_persisted.replacement_device_id,
            replacement_id.to_string()
        );
        assert_eq!(repl_persisted.replaced_by, "alice");

        let heartbeat_err2 = store2
            .heartbeat(
                prior_id,
                "OLD-HOSTNAME".into(),
                "1.0.0".into(),
                Some("192.168.1.50:5000".into()),
            )
            .await
            .unwrap_err();
        assert!(heartbeat_err2.to_string().contains("replaced"));

        Ok(())
    }

    #[tokio::test]
    async fn installation_authorization_and_device_enrollment_lifecycle() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let db_path = dir.path().join("test.db");
        let store = DeviceStore::open(&db_path)?;

        // 1. Create installation authorization
        let auth_id = "auth-123";
        let secret_hash = "hash-abc-def";
        let auth = store
            .create_installation_authorization(
                auth_id.into(),
                secret_hash.into(),
                "admin_user".into(),
            )
            .await?;
        assert_eq!(auth.authorization_id, auth_id);
        assert_eq!(auth.secret_hash, secret_hash);
        assert_eq!(auth.created_by, "admin_user");
        assert!(auth.revoked_at_unix_ms.is_none());

        // 2. Query authorization by ID and by hash
        let found = store
            .get_installation_authorization(auth_id)
            .await?
            .expect("should find by id");
        assert_eq!(found.authorization_id, auth_id);

        let found_hash = store
            .find_installation_authorization_by_hash(secret_hash)
            .await?
            .expect("should find by hash");
        assert_eq!(found_hash.authorization_id, auth_id);

        // 3. Enroll device 1
        let dev1_id = DeviceId::new();
        let dev1_resumption_hash = "dev1_secret_hash".to_string();
        store
            .record_device_enrollment(
                dev1_id,
                auth_id.into(),
                "Dev 1".into(),
                "0.1.0".into(),
                Some("10.0.0.1".into()),
                dev1_resumption_hash.clone(),
            )
            .await?;

        let dev1_rec = store
            .get_device(&dev1_id.to_string())
            .await?
            .expect("dev1 must exist");
        assert_eq!(dev1_rec.name, "Dev 1");
        assert_eq!(dev1_rec.last_address.as_deref(), Some("10.0.0.1"));

        let dev1_enroll = store
            .get_device_enrollment(&dev1_id.to_string())
            .await?
            .expect("dev1 enrollment must exist");
        assert_eq!(dev1_enroll.device_id, dev1_id.to_string());
        assert_eq!(dev1_enroll.authorization_id, auth_id);
        assert_eq!(
            dev1_enroll.resumption_secret_hash.as_deref(),
            Some("dev1_secret_hash")
        );

        // 4. Enroll device 2 under same authorization
        let dev2_id = DeviceId::new();
        let dev2_resumption_hash = "dev2_secret_hash".to_string();
        store
            .record_device_enrollment(
                dev2_id,
                auth_id.into(),
                "Dev 2".into(),
                "0.1.0".into(),
                Some("10.0.0.2".into()),
                dev2_resumption_hash,
            )
            .await?;
        let dev2_rec = store
            .get_device(&dev2_id.to_string())
            .await?
            .expect("dev2 must exist");
        assert_eq!(dev2_rec.name, "Dev 2");

        // 5. Resuming enrollment for dev1 with matching resumption secret succeeds
        store
            .record_device_enrollment(
                dev1_id,
                auth_id.into(),
                "Dev 1 Renamed".into(),
                "0.1.1".into(),
                Some("10.0.0.1".into()),
                dev1_resumption_hash.clone(),
            )
            .await?;
        let dev1_resumed = store
            .get_device(&dev1_id.to_string())
            .await?
            .expect("dev1 must exist");
        assert_eq!(dev1_resumed.name, "Dev 1 Renamed");

        // 5b. Resuming dev1 with wrong resumption secret fails (imposter cannot hijack)
        let imposter_err = store
            .record_device_enrollment(
                dev1_id,
                auth_id.into(),
                "Dev 1 Imposter".into(),
                "0.1.1".into(),
                None,
                "wrong_secret_hash".into(),
            )
            .await
            .unwrap_err();
        assert!(
            imposter_err
                .to_string()
                .contains("resumption secret does not match")
        );

        // 5c. Enrolling dev1 under a different authorization fails
        let diff_auth_id = "diff-auth-uuid";
        store
            .create_installation_authorization(
                diff_auth_id.into(),
                "diff_hash".into(),
                "admin_user".into(),
            )
            .await?;
        let diff_enroll_err = store
            .record_device_enrollment(
                dev1_id,
                diff_auth_id.into(),
                "Dev 1 Hijack".into(),
                "0.1.1".into(),
                None,
                "any_secret_hash".into(),
            )
            .await
            .unwrap_err();
        assert!(
            diff_enroll_err
                .to_string()
                .contains("already enrolled under a different authorization")
        );

        // 5d. Enrolling a bootstrap device identity fails
        let boot_id = DeviceId::new();
        store
            .heartbeat(boot_id, "Boot PC".into(), "1.0.0".into(), None)
            .await?;
        let boot_enroll_err = store
            .record_device_enrollment(
                boot_id,
                diff_auth_id.into(),
                "Boot Clone".into(),
                "1.0.0".into(),
                None,
                "any_secret_hash".into(),
            )
            .await
            .unwrap_err();
        assert!(
            boot_enroll_err
                .to_string()
                .contains("already exists in inventory")
        );

        // 6. Persistence across restart
        drop(store);
        let store2 = DeviceStore::open(&db_path)?;

        let auth_persisted = store2
            .get_installation_authorization(auth_id)
            .await?
            .expect("auth must persist");
        assert_eq!(auth_persisted.authorization_id, auth_id);
        assert!(auth_persisted.revoked_at_unix_ms.is_none());

        let dev1_persisted = store2
            .get_device(&dev1_id.to_string())
            .await?
            .expect("dev1 must persist");
        assert_eq!(dev1_persisted.name, "Dev 1 Renamed");

        // 7. Revoke authorization
        let outcome = store2.revoke_installation_authorization(auth_id).await?;
        assert!(matches!(outcome, RevokeAuthorizationOutcome::Revoked(_)));
        let outcome_repeat = store2.revoke_installation_authorization(auth_id).await?;
        assert_eq!(outcome_repeat, RevokeAuthorizationOutcome::AlreadyRevoked);

        let auth_revoked = store2
            .get_installation_authorization(auth_id)
            .await?
            .expect("auth must exist");
        assert!(auth_revoked.revoked_at_unix_ms.is_some());

        // 8. Enrolling new device with revoked authorization fails
        let dev3_id = DeviceId::new();
        let enroll_err = store2
            .record_device_enrollment(
                dev3_id,
                auth_id.into(),
                "Dev 3".into(),
                "0.1.0".into(),
                None,
                "dev3_secret_hash".into(),
            )
            .await
            .unwrap_err();
        assert!(enroll_err.to_string().contains("revoked"));

        // 8b. Resuming previously enrolled dev1 with matching resumption secret under revoked authorization succeeds
        store2
            .record_device_enrollment(
                dev1_id,
                auth_id.into(),
                "Dev 1 After Revoke".into(),
                "0.1.2".into(),
                Some("10.0.0.1".into()),
                dev1_resumption_hash.clone(),
            )
            .await?;

        // 8c. Resuming previously enrolled dev1 with wrong secret fails even under revoked authorization
        let revoke_imposter_err = store2
            .record_device_enrollment(
                dev1_id,
                auth_id.into(),
                "Dev 1 After Revoke Imposter".into(),
                "0.1.2".into(),
                Some("10.0.0.1".into()),
                "wrong_secret_hash".into(),
            )
            .await
            .unwrap_err();
        assert!(
            revoke_imposter_err
                .to_string()
                .contains("resumption secret does not match")
        );

        // 9. List installation authorizations returns all created authorizations
        let all_auths = store2.list_installation_authorizations().await?;
        assert_eq!(all_auths.len(), 2);
        let listed_auth1 = all_auths
            .iter()
            .find(|a| a.authorization_id == auth_id)
            .unwrap();
        assert!(listed_auth1.revoked_at_unix_ms.is_some());
        assert_eq!(listed_auth1.created_by, "admin_user");
        let listed_auth2 = all_auths
            .iter()
            .find(|a| a.authorization_id == diff_auth_id)
            .unwrap();
        assert!(listed_auth2.revoked_at_unix_ms.is_none());
        assert_eq!(listed_auth2.created_by, "admin_user");

        Ok(())
    }
}
