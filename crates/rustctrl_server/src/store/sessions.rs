//! Staff session lifecycle persistence operations for the RustCtrl Server.
//!
//! # Domain Scope
//! This module implements persistence operations for staff session management, including
//! session creation, token validation and retrieval, activity touching (`last_seen` timestamp updates),
//! individual and bulk session revocation, and deterministic expiry cleanup.
//!
//! # Canonical Terms (from [CONTEXT.md](../../../../CONTEXT.md))
//! - **Staff Session**: A revocable period of access to RustCtrl through the Controller under a Staff Account.
//!   It is distinct from a Remote Session with a Device.
//! - **Staff Account**: An individual IT staff member's identity in RustCtrl, with an Admin or Operator role.
//!   It is distinct from a component's connection identity.
//! - **Admin**: A staff member allowed to manage accounts, Devices, configuration, and Management Tasks.
//! - **Operator**: A staff member allowed to monitor the Fleet and open Remote Sessions using an individual account.
//! - **Remote Session**: A period during which one staff member can view and control a Device's screen.
//!
//! # Invariants and Architectural Guarantees
//! - **Atomicity of Session Creation**: Login sessions are created atomically only when the verified password
//!   hash matches the account's current hash in the database.
//! - **Deactivated Account Invariant**: Deactivated staff accounts can never start sessions, even if valid credentials
//!   are presented.
//! - **Session Revocation**: A session can be explicitly revoked individually, or bulk-revoked by username
//!   when passwords are reset or accounts are deactivated.
//! - **Deterministic Expiry**: Remembered sessions carry an optional deadline (`expires_at_unix_ms`). Any
//!   session whose deadline is in the past is treated as revoked on validation.
//! - **Activity Touching**: Accessing or explicitly touching an active, valid session updates its `last_seen_unix_ms`.
//!
//! # Forbidden Anti-Patterns
//! - Never conflate Staff Session (Controller access period) with Remote Session (screen control).
//! - Never treat Controller certificate as staff identity (Staff Sessions authenticate staff members).
//! - Never allow expired or revoked sessions to authenticate administrative operations.
//!
//! # Applicable Architecture Decision Records (ADRs)
//! - [ADR 0003: Bootstrap Staff Administration Locally](../../../../docs/adr/0003-bootstrap-staff-administration-locally.md)
//! - [ADR 0005: Keep Remembered Staff Access Revocable](../../../../docs/adr/0005-keep-remembered-staff-access-revocable.md)

use super::{
    DeviceStore,
    helpers::current_time_ms,
    types::{StaffRole, StaffSession},
};
use anyhow::Result;
use rusqlite::params;

impl DeviceStore {
    /// Creates a new login session for a staff member.
    ///
    /// The session is created only when the password hash verified by the caller is still
    /// the account's current hash, atomically with the insert. A reset or password change that
    /// commits first either fails this check or, when it commits after, revokes the freshly
    /// inserted session. Remembered sessions carry an optional finite expiry.
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

    /// Alias for [`create_login_session`](Self::create_login_session).
    pub async fn create_session(
        &self,
        session_id: String,
        username: String,
        verified_password_hash: String,
        expires_at_unix_ms: Option<i64>,
    ) -> Result<Option<StaffSession>> {
        self.create_login_session(
            session_id,
            username,
            verified_password_hash,
            expires_at_unix_ms,
        )
        .await
    }

    /// Retrieves and validates a staff session by session ID.
    ///
    /// Returns the session with `revoked = true` if the session was explicitly revoked,
    /// if the associated account is deactivated, or if the session's expiry deadline has passed.
    /// If valid and active, updates `last_seen_unix_ms` to the current time.
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

    /// Updates the `last_seen_unix_ms` timestamp for an active, unrevoked session.
    ///
    /// Returns `Ok(true)` if the session was found, active, and updated; `Ok(false)` otherwise.
    pub async fn touch_session(&self, session_id: &str) -> Result<bool> {
        let store = self.clone();
        let session_id = session_id.to_string();
        tokio::task::spawn_blocking(move || {
            let now = current_time_ms()?;
            let connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            let mut stmt = connection.prepare(
                "SELECT s.revoked, a.active, s.expires_at_unix_ms FROM staff_sessions s JOIN staff_accounts a ON s.username = a.username WHERE s.session_id = ?1",
            )?;
            let mut rows = stmt.query(params![session_id])?;
            if let Some(row) = rows.next()? {
                let revoked: i64 = row.get(0)?;
                let active: i64 = row.get(1)?;
                let expires_at: Option<i64> = row.get(2)?;
                let is_revoked = revoked != 0
                    || active == 0
                    || expires_at.is_some_and(|deadline| deadline <= now);
                if !is_revoked {
                    let updated = connection.execute(
                        "UPDATE staff_sessions SET last_seen_unix_ms = ?1 WHERE session_id = ?2",
                        params![now, session_id],
                    )?;
                    return Ok(updated > 0);
                }
            }
            Ok(false)
        })
        .await?
    }

    /// Explicitly revokes a single session by session ID.
    ///
    /// Returns `true` if an active session was revoked, `false` if already revoked or not found.
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

    /// Revokes all active sessions belonging to the given username.
    ///
    /// Returns the number of sessions revoked.
    pub async fn revoke_all_sessions(&self, username: &str) -> Result<usize> {
        let store = self.clone();
        let username = username.to_string();
        tokio::task::spawn_blocking(move || {
            let connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            let updated = connection.execute(
                "UPDATE staff_sessions SET revoked = 1 WHERE username = ?1 AND revoked = 0",
                params![username],
            )?;
            Ok(updated)
        })
        .await?
    }

    /// Cleans up expired remembered sessions from persistence.
    ///
    /// Deletes sessions whose `expires_at_unix_ms` timestamp is in the past.
    /// Returns the number of deleted session records.
    pub async fn clean_expired_sessions(&self) -> Result<usize> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let now = current_time_ms()?;
            let connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            let deleted = connection.execute(
                "DELETE FROM staff_sessions WHERE expires_at_unix_ms IS NOT NULL AND expires_at_unix_ms <= ?1",
                params![now],
            )?;
            Ok(deleted)
        })
        .await?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn session_lifecycle_touch_and_revocation() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let store = DeviceStore::open(&temp.path().join("sessions_test.db"))?;

        store
            .bootstrap_admin("sess_admin".into(), "AdminPass123!".into())
            .await?;
        let admin = store.get_staff_account("sess_admin").await?.unwrap();

        // Create session
        let session = store
            .create_session(
                "s_test_1".into(),
                "sess_admin".into(),
                admin.password_hash.clone(),
                None,
            )
            .await?
            .expect("session created");
        assert_eq!(session.session_id, "s_test_1");
        assert!(!session.revoked);

        // Touch session
        let touched = store.touch_session("s_test_1").await?;
        assert!(touched);

        // Revoke single session
        let revoked = store.revoke_session("s_test_1").await?;
        assert!(revoked);

        // Touching revoked session fails
        let touch_revoked = store.touch_session("s_test_1").await?;
        assert!(!touch_revoked);

        // get_session returns revoked = true
        let fetched = store.get_session("s_test_1").await?.unwrap();
        assert!(fetched.revoked);

        Ok(())
    }

    #[tokio::test]
    async fn revoke_all_sessions_and_clean_expired() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let store = DeviceStore::open(&temp.path().join("sessions_test2.db"))?;

        store
            .bootstrap_admin("multi_admin".into(), "MultiPass123!".into())
            .await?;
        let admin = store.get_staff_account("multi_admin").await?.unwrap();

        // Create multiple sessions
        store
            .create_session(
                "s_m1".into(),
                "multi_admin".into(),
                admin.password_hash.clone(),
                None,
            )
            .await?;
        store
            .create_session(
                "s_m2".into(),
                "multi_admin".into(),
                admin.password_hash.clone(),
                None,
            )
            .await?;

        // Revoke all
        let count = store.revoke_all_sessions("multi_admin").await?;
        assert_eq!(count, 2);

        let s1 = store.get_session("s_m1").await?.unwrap();
        let s2 = store.get_session("s_m2").await?.unwrap();
        assert!(s1.revoked);
        assert!(s2.revoked);

        // Test expired sessions cleanup
        store
            .create_session(
                "s_exp1".into(),
                "multi_admin".into(),
                admin.password_hash.clone(),
                Some(1), // already expired
            )
            .await?;

        let cleaned = store.clean_expired_sessions().await?;
        assert_eq!(cleaned, 1);

        // After deletion, get_session returns None
        assert!(store.get_session("s_exp1").await?.is_none());

        Ok(())
    }

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
}
