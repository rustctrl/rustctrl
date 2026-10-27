//! Installation authorization and agent enrollment persistence operations for the RustCtrl Server.
//!
//! # Domain Scope
//! This module implements persistence operations for installation authorizations and agent
//! enrollment lifecycle, including preparing installation authorizations, revoking authorizations
//! without interrupting enrolled devices, agent enrollment verification, resumption secret validation,
//! and enrollment record retrieval.
//!
//! # Canonical Terms (from [CONTEXT.md](../../../../CONTEXT.md))
//! - **Installation Authorization**: An Admin-granted permission for new Agents to join a specific
//!   RustCtrl Server through an Agent Installation Package. It is distinct from an already enrolled
//!   Device's permission to connect.
//! - **Agent Installation Package**: A deployment-specific package containing the configuration and
//!   installation authorization needed for an Agent to join its intended RustCtrl Server automatically.
//! - **Device**: A Windows computer or Android TV recorded in the fleet inventory.
//! - **Fleet Inventory**: RustCtrl's operational list of Devices and information needed to identify and access them.
//! - **Device Block**: Denying operational Agent access while keeping Device visible in inventory.
//! - **Admin**: A staff member allowed to manage accounts, Devices, configuration, and Management Tasks.
//!
//! # Invariants and Architectural Guarantees
//! - **Scoped Agent Authority (ADR 0007)**: Agent credentials are provisioned via a scoped subordinate
//!   issuing authority under the Server, requiring a valid, unrevoked Installation Authorization secret.
//! - **Authorization Revocation (ADR 0004, ADR 0007)**: Revoking an Installation Authorization immediately
//!   denies new agent enrollments attempting to use that authorization, while leaving already-enrolled
//!   Device credentials and operations completely uninterrupted.
//! - **Resumption Secret Idempotency**: Each agent generates a per-installation resumption secret prior
//!   to initial RPC enrollment. Retrying an enrollment or resuming after interruption requires presenting
//!   the matching resumption secret hash, preventing third parties holding the installation artifact from
//!   hijacking or re-issuing credentials for existing devices.
//! - **Blocked and Replaced Exclusions**: Devices that have been blocked or replaced can never be enrolled
//!   or resumed.
//! - **Bootstrap Device Exclusion**: A device ID that already exists as a bootstrap device cannot be enrolled
//!   under an installation authorization.
//!
//! # Forbidden Anti-Patterns
//! - Never allow revoked installation authorizations to enroll new devices.
//! - Never interrupt or invalidate already enrolled devices upon authorization revocation.
//! - Never allow enrollment resumption with a mismatched or missing resumption secret.
//! - Never permit blocked or replaced devices to enroll.
//!
//! # Applicable Architecture Decision Records (ADRs)
//! - [ADR 0004: Enroll Agents Through Trusted Installation](../../../../docs/adr/0004-enroll-agents-through-trusted-installation.md)
//! - [ADR 0006: Separate Inventory Cleanup from Device Blocking](../../../../docs/adr/0006-separate-inventory-cleanup-from-device-blocking.md)
//! - [ADR 0007: Provision Agent Credentials via Scoped Issuing Authority](../../../../docs/adr/0007-provision-agent-credentials-via-scoped-issuing-authority.md)

use super::{
    DeviceStore,
    helpers::current_time_ms,
    types::{DeviceEnrollmentRecord, InstallationAuthorizationRecord, RevokeAuthorizationOutcome},
};
use anyhow::Result;
use rusqlite::{OptionalExtension, params};
use rustctrl_core::DeviceId;

impl DeviceStore {
    /// Prepares a new installation authorization entry with hashed secret and administrator attribution.
    pub async fn prepare_installation_authorization(
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

    /// Alias for [`Self::prepare_installation_authorization`] preserving caller compatibility.
    pub async fn create_installation_authorization(
        &self,
        authorization_id: String,
        secret_hash: String,
        created_by: String,
    ) -> Result<InstallationAuthorizationRecord> {
        self.prepare_installation_authorization(authorization_id, secret_hash, created_by)
            .await
    }

    /// Retrieves an installation authorization record by its unique authorization ID.
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

    /// Finds an unrevoked or revoked installation authorization by secret hash.
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

    /// Revokes an installation authorization, preventing new agent enrollments without
    /// affecting previously enrolled devices.
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

    /// Lists all installation authorization records ordered by creation timestamp descending.
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

    /// Records an initial agent enrollment or validates resumption for an existing device.
    ///
    /// Checks for replaced or blocked status, verifies resumption secret hash idempotency,
    /// and atomically inserts enrollment and bootstrap records.
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

    /// Enrolls an agent under an installation authorization.
    pub async fn enroll_agent(
        &self,
        device_id: DeviceId,
        authorization_id: String,
        name: String,
        agent_version: String,
        remote_address: Option<String>,
        resumption_secret_hash: String,
    ) -> Result<i64> {
        self.record_device_enrollment(
            device_id,
            authorization_id,
            name,
            agent_version,
            remote_address,
            resumption_secret_hash,
        )
        .await
    }

    /// Resumes an agent enrollment using its verified resumption secret.
    ///
    /// Fails if the device is not already enrolled.
    pub async fn resume_enrollment(
        &self,
        device_id: DeviceId,
        authorization_id: String,
        name: String,
        agent_version: String,
        remote_address: Option<String>,
        resumption_secret_hash: String,
    ) -> Result<i64> {
        let existing = self.get_device_enrollment(&device_id.to_string()).await?;
        if existing.is_none() {
            anyhow::bail!(
                "device '{}' has no existing enrollment to resume",
                device_id
            );
        }
        self.record_device_enrollment(
            device_id,
            authorization_id,
            name,
            agent_version,
            remote_address,
            resumption_secret_hash,
        )
        .await
    }

    /// Retrieves an enrollment record by device ID.
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

    #[tokio::test]
    async fn prepare_authorization_and_enroll_agent_wrappers() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let db_path = dir.path().join("wrapper_test.db");
        let store = DeviceStore::open(&db_path)?;

        let auth = store
            .prepare_installation_authorization(
                "auth-wrap-1".into(),
                "hash-wrap-1".into(),
                "admin1".into(),
            )
            .await?;
        assert_eq!(auth.authorization_id, "auth-wrap-1");

        let dev_id = DeviceId::new();
        let res_hash = "secret-wrap-1".to_string();

        let enrolled_at = store
            .enroll_agent(
                dev_id,
                "auth-wrap-1".into(),
                "PC-WRAP".into(),
                "1.0.0".into(),
                Some("192.168.1.20".into()),
                res_hash.clone(),
            )
            .await?;
        assert!(enrolled_at > 0);

        let resumed_at = store
            .resume_enrollment(
                dev_id,
                "auth-wrap-1".into(),
                "PC-WRAP-UPDATED".into(),
                "1.0.1".into(),
                Some("192.168.1.21".into()),
                res_hash,
            )
            .await?;
        assert!(resumed_at >= enrolled_at);

        let dev = store
            .get_device(&dev_id.to_string())
            .await?
            .expect("device exists");
        assert_eq!(dev.name, "PC-WRAP-UPDATED");
        assert_eq!(dev.agent_version, "1.0.1");

        // Resuming a non-enrolled device identity fails
        let ghost_id = DeviceId::new();
        let ghost_err = store
            .resume_enrollment(
                ghost_id,
                "auth-wrap-1".into(),
                "Ghost".into(),
                "1.0.0".into(),
                None,
                "any-hash".into(),
            )
            .await
            .unwrap_err();
        assert!(ghost_err.to_string().contains("no existing enrollment"));

        Ok(())
    }
}
