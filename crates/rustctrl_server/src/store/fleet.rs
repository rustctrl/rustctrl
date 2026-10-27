//! Fleet inventory and device lifecycle persistence operations for the RustCtrl Server.
//!
//! # Domain Scope
//! This module implements persistence operations for the Fleet Inventory, including device
//! heartbeat recording, device enumeration and retrieval, curated metadata management (display names
//! and physical locations), offline inventory cleanup, explicit device replacement reconciliation,
//! durable device blocking and unblocking, and unverified connection target management (such as
//! Android TVs).
//!
//! # Canonical Terms (from [CONTEXT.md](../../../../CONTEXT.md))
//! - **Device**: A Windows computer or Android TV recorded in the fleet inventory. Its identity
//!   remains the same when its network address changes.
//! - **Fleet**: All Devices managed by the IT team through RustCtrl.
//! - **Fleet Inventory**: RustCtrl's operational list of Devices and the information needed to
//!   identify and access them.
//! - **Inventory Cleanup**: An Admin's removal of an offline Device entry from the Fleet Inventory
//!   without revoking its Agent's access. A still-authorized Agent can restore the entry by connecting again.
//! - **Device Block**: An Admin-imposed restriction on a Device identity that denies operational
//!   Agent access while keeping the Device visible in the Fleet Inventory.
//! - **Admin**: A staff member allowed to manage accounts, Devices, configuration, and Management Tasks.
//! - **Operator**: A staff member allowed to monitor the Fleet and open Remote Sessions using an individual account.
//!
//! # Invariants and Architectural Guarantees
//! - **Permanent Identity**: Devices are identified strictly by their permanent `DeviceId` UUID, never
//!   by transient network properties such as IP address or hostname.
//! - **Curated Metadata Preservation**: Administrator-assigned display names and locations stored in
//!   `device_metadata` survive subsequent heartbeats and server restarts.
//! - **Separation of Cleanup and Block (ADR 0006)**: Inventory Cleanup removes an offline Device entry
//!   from the operational list without revoking Agent credentials or authorization. When an Agent reconnects,
//!   its identity reappears. Conversely, Device Block explicitly denies operational Agent access while
//!   keeping the entry visible in the inventory. Cleanup cannot be performed on blocked or online devices,
//!   and cleanup does not lift a block.
//! - **Explicit Device Replacement Reconciliation**: When an endpoint loses its identity (e.g. following
//!   a Windows reinstall), an Admin explicitly binds the prior Device identity to the replacement Device
//!   identity. This atomically transfers curated metadata, preserves blocks, marks the prior identity as
//!   replaced, removes the prior entry from visible inventory, and permanently rejects future heartbeats
//!   from the prior identity, without rewriting historical audit attribution.
//! - **Connection Targets**: Android TV targets are registered as unverified inventory entries with
//!   pre-configured addresses and locations, distinct from automatically enrolling Windows Agents.
//!
//! # Forbidden Anti-Patterns
//! - Never use IP address or hostname as device identity.
//! - Never treat Inventory Cleanup as Device Block (Cleanup allows re-registration; Block denies operational access).
//! - Never allow blocked or replaced devices to submit heartbeats or re-register.
//! - Never rewrite historical activity log entries during device replacement.
//!
//! # Applicable Architecture Decision Records (ADRs)
//! - [ADR 0001: Centralize Fleet Coordination](../../../../docs/adr/0001-centralize-fleet-coordination.md)
//! - [ADR 0006: Separate Inventory Cleanup from Device Blocking](../../../../docs/adr/0006-separate-inventory-cleanup-from-device-blocking.md)
//! - [ADR 0007: Provision Agent Credentials via Scoped Issuing Authority](../../../../docs/adr/0007-provision-agent-credentials-via-scoped-issuing-authority.md)

use super::{
    DeviceStore,
    helpers::current_time_ms,
    types::{DeviceRecord, DeviceReplacementRecord, TargetRecord},
};
use anyhow::Result;
use rusqlite::{OptionalExtension, params};
use rustctrl_core::DeviceId;

impl DeviceStore {
    /// Records a heartbeat from an active Agent, updating its last seen timestamp, agent version,
    /// and observed network address.
    ///
    /// Fails if the device has been replaced or blocked.
    pub async fn record_heartbeat(
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

    /// Alias for [`Self::record_heartbeat`] preserving caller compatibility.
    pub async fn heartbeat(
        &self,
        id: DeviceId,
        name: String,
        version: String,
        remote_address: Option<String>,
    ) -> Result<i64> {
        self.record_heartbeat(id, name, version, remote_address)
            .await
    }

    /// Lists all devices in the fleet inventory, combining Windows bootstrap devices and
    /// unverified connection targets ordered by freshness and display name.
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

    /// Retrieves an individual device record by ID, checking both Windows devices and connection targets.
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

    /// Updates curated display name and physical location for a Windows fleet device.
    ///
    /// Preserves values across subsequent Agent heartbeats.
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

    /// Checks if a device is currently blocked from operational Agent access.
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

    /// Blocks a device identity, denying future heartbeats and operational Agent operations
    /// while retaining the device visible in inventory.
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

    /// Lifts an administrative block on a device, restoring operational Agent connectivity.
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

    /// Removes an offline device entry from the fleet inventory without revoking Agent credentials.
    ///
    /// Fails if the device is currently online or blocked. If the Agent later reconnects,
    /// it reappears in the inventory.
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

    /// Explicitly reconciles a device replacement between a prior Device and a replacement Device.
    ///
    /// Transfers curated metadata, preserves blocks, records the replacement relationship,
    /// and deletes the prior device from visible inventory.
    pub async fn replace_fleet_device(
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

    /// Alias for [`Self::replace_fleet_device`] preserving caller compatibility.
    pub async fn replace_device(
        &self,
        prior_device_id: &str,
        replacement_device_id: &str,
        replaced_by: &str,
    ) -> Result<DeviceRecord> {
        self.replace_fleet_device(prior_device_id, replacement_device_id, replaced_by)
            .await
    }

    /// Retrieves an explicit device replacement record by prior device ID.
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

    /// Creates an unverified connection target entry (e.g. Android TV).
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

    /// Updates display name, address, or location for an existing connection target.
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

    /// Removes a connection target from the fleet inventory.
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

    /// Lists all connection targets in the inventory.
    pub async fn list_targets(&self) -> Result<Vec<TargetRecord>> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            let mut stmt = connection.prepare(
                "SELECT target_id, display_name, target_type, configured_address, location, created_at_unix_ms, updated_at_unix_ms
                 FROM connection_targets
                 ORDER BY created_at_unix_ms ASC, display_name ASC",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(TargetRecord {
                    target_id: row.get(0)?,
                    display_name: row.get(1)?,
                    target_type: row.get(2)?,
                    configured_address: row.get(3)?,
                    location: row.get(4)?,
                    created_at_unix_ms: row.get(5)?,
                    updated_at_unix_ms: row.get(6)?,
                })
            })?;
            let mut targets = Vec::new();
            for row in rows {
                targets.push(row?);
            }
            Ok(targets)
        })
        .await?
    }

    /// Counts total devices in inventory (Windows bootstrap devices plus connection targets).
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
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let dev = store
            .get_device(&dev_id.to_string())
            .await?
            .expect("device exists");
        assert_eq!(dev.name, "Reception Front Desk");
        assert_eq!(dev.location, Some("Building A - Floor 1".into()));

        let list = store.list_devices().await?;
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "Reception Front Desk");
        assert_eq!(list[0].location, Some("Building A - Floor 1".into()));

        // 3. Subsequent heartbeats from the Agent must preserve the curated display
        // name and location, while updating last_seen and last_address.
        store
            .heartbeat(
                dev_id,
                "DESKTOP-ABC1234".into(),
                "1.0.1".into(),
                Some("192.168.1.55:5000".into()),
            )
            .await?;

        let dev = store
            .get_device(&dev_id.to_string())
            .await?
            .expect("device exists");
        assert_eq!(
            dev.name, "Reception Front Desk",
            "curated display name must survive heartbeats"
        );
        assert_eq!(
            dev.location,
            Some("Building A - Floor 1".into()),
            "curated location must survive heartbeats"
        );
        assert_eq!(dev.agent_version, "1.0.1");
        assert_eq!(dev.last_address, Some("192.168.1.55:5000".into()));

        // 4. Clearing location by passing None.
        let cleared = store
            .update_device_metadata(&dev_id.to_string(), "Reception Front Desk", None)
            .await?;
        assert_eq!(cleared.location, None);

        let dev = store
            .get_device(&dev_id.to_string())
            .await?
            .expect("device exists");
        assert_eq!(dev.location, None);

        // 5. Updating an unknown device fails.
        let ghost_id = DeviceId::new();
        assert!(
            store
                .update_device_metadata(&ghost_id.to_string(), "Ghost", None)
                .await
                .is_err()
        );

        // 6. Validation: empty display name fails.
        assert!(
            store
                .update_device_metadata(&dev_id.to_string(), "   ", None)
                .await
                .is_err()
        );

        Ok(())
    }

    #[tokio::test]
    async fn device_blocking_and_unblocking_restricts_heartbeat_and_persists() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let store = DeviceStore::open(&temp.path().join("store.db"))?;
        let dev_id = DeviceId::new();

        // Register device via initial heartbeat
        store
            .heartbeat(
                dev_id,
                "WIN-BLOCKED-TEST".into(),
                "1.0.0".into(),
                Some("10.0.0.1:5000".into()),
            )
            .await?;

        let dev = store
            .get_device(&dev_id.to_string())
            .await?
            .expect("device exists");
        assert!(!dev.blocked);
        assert!(!store.is_device_blocked(&dev_id.to_string()).await?);

        // Block the device
        let blocked = store
            .block_device(&dev_id.to_string(), "admin_alice")
            .await?;
        assert!(blocked.blocked);
        assert!(store.is_device_blocked(&dev_id.to_string()).await?);

        let dev = store
            .get_device(&dev_id.to_string())
            .await?
            .expect("device exists");
        assert!(
            dev.blocked,
            "device must be marked blocked in inventory record"
        );

        let list = store.list_devices().await?;
        assert_eq!(list.len(), 1);
        assert!(list[0].blocked);

        // Subsequent heartbeat must be rejected
        let hb_err = store
            .heartbeat(
                dev_id,
                "WIN-BLOCKED-TEST".into(),
                "1.0.0".into(),
                Some("10.0.0.1:5000".into()),
            )
            .await
            .unwrap_err();
        assert!(
            hb_err.to_string().contains("blocked"),
            "heartbeat must be rejected when blocked: {hb_err}"
        );

        // Attempting to block an already blocked device fails
        assert!(
            store
                .block_device(&dev_id.to_string(), "admin_alice")
                .await
                .is_err()
        );

        // Blocking an unknown device fails
        let ghost_id = DeviceId::new();
        assert!(
            store
                .block_device(&ghost_id.to_string(), "admin_alice")
                .await
                .is_err()
        );

        // Block survives store restart / new connection
        drop(store);
        let store2 = DeviceStore::open(&temp.path().join("store.db"))?;
        assert!(store2.is_device_blocked(&dev_id.to_string()).await?);
        let dev2 = store2
            .get_device(&dev_id.to_string())
            .await?
            .expect("device exists");
        assert!(dev2.blocked);

        // Unblock the device
        let unblocked = store2.unblock_device(&dev_id.to_string()).await?;
        assert!(!unblocked.blocked);
        assert!(!store2.is_device_blocked(&dev_id.to_string()).await?);

        let dev_unblocked = store2
            .get_device(&dev_id.to_string())
            .await?
            .expect("device exists");
        assert!(!dev_unblocked.blocked);

        // Heartbeats are now accepted again
        let new_hb = store2
            .heartbeat(
                dev_id,
                "WIN-BLOCKED-TEST".into(),
                "1.0.1".into(),
                Some("10.0.0.2:5000".into()),
            )
            .await?;
        assert!(new_hb > 0);

        // Unblocking a non-blocked device fails
        assert!(store2.unblock_device(&dev_id.to_string()).await.is_err());

        // Unblocking an unknown device fails
        assert!(store2.unblock_device(&ghost_id.to_string()).await.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn clean_offline_device_removes_entry_without_revoking_access_and_preserves_attribution()
    -> Result<()> {
        let temp = tempfile::tempdir()?;
        let store = DeviceStore::open(&temp.path().join("store.db"))?;
        let dev_id = DeviceId::new();

        // 1. Device registers via heartbeat with curated metadata
        store
            .heartbeat(
                dev_id,
                "WIN-CLEANUP-TEST".into(),
                "1.0.0".into(),
                Some("192.168.1.100:5000".into()),
            )
            .await?;
        store
            .update_device_metadata(&dev_id.to_string(), "Conference Room PC", Some("Floor 2"))
            .await?;

        // 2. Attempting to clean up an online device (heartbeat within window) fails
        let err = store
            .clean_offline_device(&dev_id.to_string(), 3600)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("cannot clean up online device"),
            "online device cleanup must be rejected: {err}"
        );

        // 3. Attempting to clean up an unknown device fails
        let ghost = DeviceId::new();
        assert!(
            store
                .clean_offline_device(&ghost.to_string(), 0)
                .await
                .is_err()
        );

        // 4. Attempting to clean up a blocked device fails
        store
            .block_device(&dev_id.to_string(), "admin_alice")
            .await?;
        let block_err = store
            .clean_offline_device(&dev_id.to_string(), 0)
            .await
            .unwrap_err();
        assert!(
            block_err
                .to_string()
                .contains("cannot clean up blocked device"),
            "blocked device cleanup must be rejected: {block_err}"
        );
        store.unblock_device(&dev_id.to_string()).await?;

        // 5. Clean up the offline device with offline_after_secs = 0 (instant timeout)
        let cleaned = store.clean_offline_device(&dev_id.to_string(), 0).await?;
        assert_eq!(cleaned, dev_id.to_string());

        // Device is no longer in inventory
        assert!(store.get_device(&dev_id.to_string()).await?.is_none());
        assert!(store.list_devices().await?.is_empty());

        // 6. When the still-authorized Agent reconnects, it automatically reappears
        store
            .heartbeat(
                dev_id,
                "WIN-CLEANUP-TEST".into(),
                "1.0.0".into(),
                Some("192.168.1.101:5000".into()),
            )
            .await?;

        let restored = store
            .get_device(&dev_id.to_string())
            .await?
            .expect("device restored on reconnect");
        assert_eq!(restored.device_id, dev_id.to_string());
        // Curated metadata was removed on cleanup, so it resets to reported name
        assert_eq!(restored.name, "WIN-CLEANUP-TEST");
        assert_eq!(restored.location, None);
        assert!(!restored.blocked);

        // 7. Cleanup survives store restart
        store.clean_offline_device(&dev_id.to_string(), 0).await?;
        drop(store);

        let store2 = DeviceStore::open(&temp.path().join("store.db"))?;
        assert!(store2.get_device(&dev_id.to_string()).await?.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn replace_device_reconciles_inventory_transfers_metadata_preserves_blocks_and_association()
    -> Result<()> {
        let temp = tempfile::tempdir()?;
        let store = DeviceStore::open(&temp.path().join("store.db"))?;

        let prior_id = DeviceId::new();
        let replacement_id = DeviceId::new();

        // 1. Invalid input validation
        assert!(
            store
                .replace_device("not-a-uuid", &replacement_id.to_string(), "alice")
                .await
                .is_err()
        );
        assert!(
            store
                .replace_device(&prior_id.to_string(), "not-a-uuid", "alice")
                .await
                .is_err()
        );
        assert!(
            store
                .replace_device(&prior_id.to_string(), &replacement_id.to_string(), "")
                .await
                .is_err()
        );
        assert!(
            store
                .replace_device(&prior_id.to_string(), &prior_id.to_string(), "alice")
                .await
                .is_err()
        );

        // Devices do not exist yet
        assert!(
            store
                .replace_device(&prior_id.to_string(), &replacement_id.to_string(), "alice")
                .await
                .is_err()
        );

        // 2. Setup prior device with curated metadata and block
        store
            .heartbeat(
                prior_id,
                "OLD-HOSTNAME".into(),
                "1.0.0".into(),
                Some("10.0.0.1:5000".into()),
            )
            .await?;
        store
            .update_device_metadata(&prior_id.to_string(), "Executive Laptop", Some("Room 401"))
            .await?;
        store.block_device(&prior_id.to_string(), "alice").await?;

        // Replacement device still does not exist
        assert!(
            store
                .replace_device(&prior_id.to_string(), &replacement_id.to_string(), "alice")
                .await
                .is_err()
        );

        // Cannot replace connection targets
        let target = store
            .create_target("Meeting TV", "192.168.1.200", None, None)
            .await?;
        assert!(
            store
                .replace_device(&target.target_id, &replacement_id.to_string(), "alice")
                .await
                .is_err()
        );

        // Setup replacement device via fresh heartbeat
        store
            .heartbeat(
                replacement_id,
                "NEW-HOSTNAME".into(),
                "1.0.1".into(),
                Some("10.0.0.2:5000".into()),
            )
            .await?;

        assert!(
            store
                .replace_device(&prior_id.to_string(), &target.target_id, "alice")
                .await
                .is_err()
        );

        // 3. Successful replacement
        let replaced_record = store
            .replace_device(&prior_id.to_string(), &replacement_id.to_string(), "alice")
            .await?;

        assert_eq!(replaced_record.device_id, replacement_id.to_string());
        assert_eq!(
            replaced_record.name, "Executive Laptop",
            "curated display name must transfer to replacement"
        );
        assert_eq!(
            replaced_record.location,
            Some("Room 401".into()),
            "curated location must transfer to replacement"
        );
        assert!(
            replaced_record.blocked,
            "block status from prior must transfer to replacement"
        );
        assert_eq!(replaced_record.agent_version, "1.0.1");

        // 4. Verify prior device is gone from inventory
        assert!(store.get_device(&prior_id.to_string()).await?.is_none());

        // 5. Verify replacement device in inventory
        let dev = store
            .get_device(&replacement_id.to_string())
            .await?
            .expect("replacement exists");
        assert_eq!(dev.name, "Executive Laptop");
        assert_eq!(dev.location, Some("Room 401".into()));
        assert!(dev.blocked);

        let list = store.list_devices().await?;
        // Target + replacement = 2 devices
        assert_eq!(list.len(), 2);
        assert!(!list.iter().any(|d| d.device_id == prior_id.to_string()));

        // 6. Verify association query
        let assoc = store
            .get_device_replacement(&prior_id.to_string())
            .await?
            .expect("replacement association exists");
        assert_eq!(assoc.prior_device_id, prior_id.to_string());
        assert_eq!(assoc.replacement_device_id, replacement_id.to_string());
        assert_eq!(assoc.replaced_by, "alice");
        assert!(assoc.replaced_at_unix_ms > 0);

        assert_eq!(
            store
                .get_device_replacement(&replacement_id.to_string())
                .await?,
            None
        );

        // 7. Repeated replacement of already replaced prior fails
        assert!(
            store
                .replace_device(&prior_id.to_string(), &replacement_id.to_string(), "alice")
                .await
                .is_err()
        );

        // 8. Reconnecting heartbeat from prior device is rejected
        let hb_err = store
            .heartbeat(
                prior_id,
                "OLD-HOSTNAME".into(),
                "1.0.0".into(),
                Some("10.0.0.1:5000".into()),
            )
            .await
            .unwrap_err();
        assert!(
            hb_err.to_string().contains("replaced"),
            "heartbeat from replaced device must be rejected: {hb_err}"
        );

        // 9. Persistence across restart
        drop(store);
        let store2 = DeviceStore::open(&temp.path().join("store.db"))?;

        assert!(store2.get_device(&prior_id.to_string()).await?.is_none());
        let dev2 = store2
            .get_device(&replacement_id.to_string())
            .await?
            .expect("replacement exists after restart");
        assert_eq!(dev2.name, "Executive Laptop");
        assert_eq!(dev2.location, Some("Room 401".into()));
        assert!(dev2.blocked);

        let assoc2 = store2
            .get_device_replacement(&prior_id.to_string())
            .await?
            .expect("replacement association survives restart");
        assert_eq!(assoc2.prior_device_id, prior_id.to_string());
        assert_eq!(assoc2.replacement_device_id, replacement_id.to_string());

        let hb2_err = store2
            .heartbeat(
                prior_id,
                "OLD-HOSTNAME".into(),
                "1.0.0".into(),
                Some("10.0.0.1:5000".into()),
            )
            .await
            .unwrap_err();
        assert!(hb2_err.to_string().contains("replaced"));

        Ok(())
    }

    #[tokio::test]
    async fn target_management_and_counting() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let store = DeviceStore::open(&temp.path().join("store.db"))?;

        assert_eq!(store.count().await?, 0);

        let t1 = store
            .create_target(
                "Boardroom TV",
                "10.0.0.50:5555",
                Some("android_tv"),
                Some("Floor 3"),
            )
            .await?;
        assert_eq!(t1.display_name, "Boardroom TV");
        assert_eq!(t1.target_type, "android_tv");
        assert_eq!(t1.configured_address, "10.0.0.50:5555");
        assert_eq!(t1.location, Some("Floor 3".into()));

        assert_eq!(store.count().await?, 1);

        let list = store.list_targets().await?;
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].target_id, t1.target_id);

        let updated = store
            .update_target(
                &t1.target_id,
                "Executive Boardroom TV",
                "10.0.0.51:5555",
                Some("Floor 4"),
            )
            .await?;
        assert_eq!(updated.display_name, "Executive Boardroom TV");
        assert_eq!(updated.configured_address, "10.0.0.51:5555");
        assert_eq!(updated.location, Some("Floor 4".into()));

        let removed = store.remove_target(&t1.target_id).await?;
        assert_eq!(removed, t1.target_id);
        assert_eq!(store.count().await?, 0);
        assert!(store.list_targets().await?.is_empty());

        Ok(())
    }
}
