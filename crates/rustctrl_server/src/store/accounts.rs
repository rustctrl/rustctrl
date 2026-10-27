//! Staff account administration persistence operations for the RustCtrl Server.
//!
//! # Domain Scope
//! This module implements persistence operations for staff account management, including
//! initial administrator bootstrap, local administrator recovery, staff account creation,
//! credential updates (password replacement and resets), role modifications, and account
//! deactivation.
//!
//! # Canonical Terms (from [CONTEXT.md](../../../../CONTEXT.md))
//! - **Staff Account**: An individual IT staff member's identity in RustCtrl, with an Admin or Operator role.
//!   It is distinct from a component's connection identity.
//! - **Staff Session**: A revocable period of access to RustCtrl through the Controller under a Staff Account.
//! - **Admin**: A staff member allowed to manage accounts, Devices, configuration, and Management Tasks.
//! - **Operator**: A staff member allowed to monitor the Fleet and open Remote Sessions using an individual account.
//!
//! # Invariants and Architectural Guarantees
//! - **Initial Admin Bootstrap**: The first administrator is bootstrapped via a local Server command.
//!   Repeated bootstrap attempts are rejected once an Admin exists.
//! - **Local Admin Recovery**: An existing Admin account can be reset to a temporary password via a local
//!   Server command without internet or external email dependencies. Recovery immediately revokes all active
//!   Staff Sessions for that account and requires a password change upon next login.
//! - **Last Active Admin Protection**: The last active Admin account cannot be deactivated or demoted to
//!   Operator, guaranteeing continuous administrative access to the system.
//! - **Mandatory Password Change**: Newly created staff accounts and accounts subjected to an administrative
//!   reset are flagged with `must_change_password = true`, requiring replacement at next login.
//! - **Transaction Atomicity**: Account mutations, role modifications, session revocations, and activity log
//!   records commit atomically within single SQLite transactions.
//!
//! # Forbidden Anti-Patterns
//! - Never allow shared staff accounts or Controller certificates as staff identity.
//! - Never deactivate or demote the last active Admin account.
//! - Never conflate Staff Session with Remote Session.
//! - Never permit concurrent password changes to overwrite an administrative reset silently.
//!
//! # Applicable Architecture Decision Records (ADRs)
//! - [ADR 0003: Bootstrap Staff Administration Locally](../../../../docs/adr/0003-bootstrap-staff-administration-locally.md)
//! - [ADR 0005: Keep Remembered Staff Access Revocable](../../../../docs/adr/0005-keep-remembered-staff-access-revocable.md)

use super::{
    DeviceStore,
    helpers::{current_time_ms, reset_account_password_to_temporary, validate_username},
    types::{StaffAccount, StaffRole},
};
use anyhow::Result;
use rusqlite::params;

impl DeviceStore {
    /// Bootstraps the first administrator account with a temporary password.
    ///
    /// Fails if any admin account already exists in the store. Records success or rejection
    /// in the activity log.
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

    /// Fetches a staff account by username.
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

    /// Updates password hash and temporary flag for a staff account, updating active sessions.
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

    /// Replaces a temporary password with a permanent one (sets `must_change_password = false`).
    pub async fn replace_temporary_password(
        &self,
        username: &str,
        new_password_hash: String,
    ) -> Result<()> {
        self.update_password(username, new_password_hash, false)
            .await
    }

    /// Resets a staff member's password to a temporary password, revoking existing sessions.
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

    /// Alias for [`reset_staff_password`](Self::reset_staff_password).
    pub async fn reset_password(
        &self,
        username: &str,
        temporary_password: String,
    ) -> Result<StaffAccount> {
        self.reset_staff_password(username, temporary_password)
            .await
    }

    /// Changes a staff member's own password after verifying their current password.
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

    /// Alias for [`change_own_password`](Self::change_own_password).
    pub async fn change_password(
        &self,
        username: &str,
        current_password: String,
        new_password_hash: String,
    ) -> Result<()> {
        self.change_own_password(username, current_password, new_password_hash)
            .await
    }

    /// Recovers an existing administrator account by setting a temporary password.
    ///
    /// Revokes all active sessions for the recovered administrator account. Fails if the
    /// account does not exist or is not an administrator.
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

    /// Lists all staff accounts ordered by username ascending.
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

    /// Creates a new staff account with an initial temporary password.
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

    /// Changes a staff account's role, strictly enforcing last-active-admin protection.
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

    /// Alias for [`change_staff_role`](Self::change_staff_role).
    pub async fn change_role(&self, username: &str, new_role: StaffRole) -> Result<StaffAccount> {
        self.change_staff_role(username, new_role).await
    }

    /// Deactivates a staff account and revokes all of its active sessions.
    ///
    /// Strictly prevents deactivation of the last active administrator.
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

    /// Alias for [`deactivate_staff_account`](Self::deactivate_staff_account).
    pub async fn deactivate_account(&self, username: &str) -> Result<StaffAccount> {
        self.deactivate_staff_account(username).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bootstrap_admin_and_prevent_duplicate() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let store = DeviceStore::open(&temp.path().join("accounts_test.db"))?;

        store
            .bootstrap_admin("admin_alice".into(), "InitialPass123!".into())
            .await?;

        let account = store
            .get_staff_account("admin_alice")
            .await?
            .expect("admin account must exist");
        assert_eq!(account.username, "admin_alice");
        assert_eq!(account.role, StaffRole::Admin);
        assert!(account.must_change_password);
        assert!(account.active);

        // Repeated bootstrap must be rejected
        let repeat_err = store
            .bootstrap_admin("admin_bob".into(), "OtherPass123!".into())
            .await
            .unwrap_err();
        assert!(repeat_err.to_string().contains("already exists"));

        Ok(())
    }

    #[tokio::test]
    async fn create_staff_account_and_role_change_protects_last_admin() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let store = DeviceStore::open(&temp.path().join("accounts_test2.db"))?;

        store
            .bootstrap_admin("root_admin".into(), "InitialPass123!".into())
            .await?;

        // Demoting the only admin must fail
        let demote_err = store
            .change_role("root_admin", StaffRole::Operator)
            .await
            .unwrap_err();
        assert!(
            demote_err
                .to_string()
                .contains("cannot demote the last active admin")
        );

        // Create an operator account
        let operator = store
            .create_staff_account("op_user".into(), StaffRole::Operator, "OpTemp123!".into())
            .await?;
        assert_eq!(operator.role, StaffRole::Operator);
        assert!(operator.must_change_password);

        // Promote operator to admin
        let promoted = store.change_role("op_user", StaffRole::Admin).await?;
        assert_eq!(promoted.role, StaffRole::Admin);

        // Now demoting root_admin succeeds because op_user is an active admin
        let demoted = store.change_role("root_admin", StaffRole::Operator).await?;
        assert_eq!(demoted.role, StaffRole::Operator);

        // Demoting op_user now fails as they are the last active admin
        let demote_last_err = store
            .change_role("op_user", StaffRole::Operator)
            .await
            .unwrap_err();
        assert!(
            demote_last_err
                .to_string()
                .contains("cannot demote the last active admin")
        );

        Ok(())
    }

    #[tokio::test]
    async fn deactivation_protects_last_admin_and_marks_inactive() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let store = DeviceStore::open(&temp.path().join("accounts_test3.db"))?;

        store
            .bootstrap_admin("sole_admin".into(), "InitialPass123!".into())
            .await?;

        // Cannot deactivate the only admin
        let deact_err = store.deactivate_account("sole_admin").await.unwrap_err();
        assert!(
            deact_err
                .to_string()
                .contains("cannot deactivate the last active admin")
        );

        // Create second admin
        store
            .create_staff_account(
                "second_admin".into(),
                StaffRole::Admin,
                "AdminPass123!".into(),
            )
            .await?;

        // Now first admin can be deactivated
        let deactivated = store.deactivate_account("sole_admin").await?;
        assert!(!deactivated.active);

        // Cannot deactivate already deactivated account
        let repeat_err = store.deactivate_account("sole_admin").await.unwrap_err();
        assert!(repeat_err.to_string().contains("already deactivated"));

        // Second admin is now the last active admin, cannot be deactivated
        let deact_second_err = store.deactivate_account("second_admin").await.unwrap_err();
        assert!(
            deact_second_err
                .to_string()
                .contains("cannot deactivate the last active admin")
        );

        Ok(())
    }

    #[tokio::test]
    async fn password_replacement_and_reset_flow() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let store = DeviceStore::open(&temp.path().join("accounts_test4.db"))?;

        store
            .bootstrap_admin("admin_user".into(), "TempPass123!".into())
            .await?;

        let new_hash = crate::password::hash_password("PermanentPass123!")?;
        store
            .replace_temporary_password("admin_user", new_hash.clone())
            .await?;

        let account = store.get_staff_account("admin_user").await?.unwrap();
        assert!(!account.must_change_password);
        assert_eq!(account.password_hash, new_hash);

        // Change password using current password verification
        let next_hash = crate::password::hash_password("SuperSecret456!")?;
        store
            .change_password("admin_user", "PermanentPass123!".into(), next_hash.clone())
            .await?;

        let account_after = store.get_staff_account("admin_user").await?.unwrap();
        assert_eq!(account_after.password_hash, next_hash);

        // Administrative reset sets must_change_password back to true
        let reset_account = store
            .reset_password("admin_user", "ResetTemp789!".into())
            .await?;
        assert!(reset_account.must_change_password);

        // Admin recovery resets password
        store
            .recover_admin("admin_user".into(), "RecoveredPass321!".into())
            .await?;
        let recovered = store.get_staff_account("admin_user").await?.unwrap();
        assert!(recovered.must_change_password);

        Ok(())
    }
}
