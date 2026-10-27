//! Shared validation, timestamp, and account mutation utility functions for Server persistence.
//!
//! # Domain Scope
//! Provides validation, time-calculation, and internal transactional helpers used across the
//! persistence store, ensuring consistent validation rules (e.g. username formatting), timestamp
//! resolution, and atomic password reset state transitions.
//!
//! # Canonical Terms (from [CONTEXT.md](../../../../CONTEXT.md))
//! - **Staff Account**: Validates individual staff usernames according to canonical naming constraints.
//! - **Staff Session**: Revokes existing sessions during administrative password reset.
//!
//! # Invariants and Architectural Guarantees
//! - `validate_username` enforces 1 to 64 character length and alphanumeric, '.', '_', '-' characters.
//! - `current_time_ms` provides millisecond unix timestamps for consistent audit and event tracking.
//! - `reset_account_password_to_temporary` requires an open transaction caller so password reset
//!   and activity audit logs commit atomically.
//!
//! # Forbidden Anti-Patterns
//! - Never allow empty or whitespace-only usernames.
//! - Never bypass username character restrictions.
//!
//! # Applicable Architecture Decision Records (ADRs)
//! - [ADR 0003: Bootstrap Staff Administration Locally](../../../../docs/adr/0003-bootstrap-staff-administration-locally.md)
//! - [ADR 0005: Keep Remembered Staff Access Revocable](../../../../docs/adr/0005-keep-remembered-staff-access-revocable.md)

use anyhow::Result;
use rusqlite::params;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn current_time_ms() -> Result<i64> {
    Ok(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

pub fn validate_username(username: &str) -> Result<String> {
    let username = username.trim().to_string();
    anyhow::ensure!(
        !username.is_empty() && username.len() <= 64,
        "username must contain 1 to 64 characters"
    );
    anyhow::ensure!(
        username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'),
        "username may only contain alphanumeric characters, '.', '_', or '-'"
    );
    Ok(username)
}

// Caller keeps the transaction open so reset and its activity record commit together.
pub(crate) fn reset_account_password_to_temporary(
    tx: &rusqlite::Transaction<'_>,
    username: &str,
    password_hash: &str,
    now: i64,
) -> Result<()> {
    let changed = tx.execute(
        "UPDATE staff_accounts SET password_hash = ?1, must_change_password = 1, updated_at_unix_ms = ?2 WHERE username = ?3",
        params![password_hash, now, username],
    )?;
    anyhow::ensure!(changed == 1, "account '{username}' not found");
    tx.execute(
        "UPDATE staff_sessions SET revoked = 1 WHERE username = ?1 AND revoked = 0",
        params![username],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn current_time_ms_returns_positive_timestamp() {
        let ts = current_time_ms().expect("current time should be valid unix timestamp");
        assert!(ts > 0);
    }

    #[test]
    fn validate_username_accepts_valid_names() {
        assert_eq!(validate_username("alice").unwrap(), "alice");
        assert_eq!(validate_username("  bob.smith  ").unwrap(), "bob.smith");
        assert_eq!(validate_username("user-1_test").unwrap(), "user-1_test");
    }

    #[test]
    fn validate_username_rejects_empty_or_whitespace() {
        assert!(validate_username("").is_err());
        assert!(validate_username("   ").is_err());
    }

    #[test]
    fn validate_username_rejects_names_exceeding_64_chars() {
        let long_name = "a".repeat(65);
        assert!(validate_username(&long_name).is_err());
        let exact_name = "a".repeat(64);
        assert_eq!(validate_username(&exact_name).unwrap(), exact_name);
    }

    #[test]
    fn validate_username_rejects_illegal_characters() {
        assert!(validate_username("user@domain").is_err());
        assert!(validate_username("user#1").is_err());
        assert!(validate_username("user$name").is_err());
        assert!(validate_username("alice/admin").is_err());
    }

    #[test]
    fn reset_account_password_to_temporary_updates_account_and_revokes_sessions() -> Result<()> {
        let mut conn = Connection::open_in_memory()?;
        conn.execute_batch(
            "CREATE TABLE staff_accounts (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                must_change_password INTEGER NOT NULL DEFAULT 0,
                updated_at_unix_ms INTEGER NOT NULL
            );
            CREATE TABLE staff_sessions (
                session_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0
            );
            INSERT INTO staff_accounts VALUES ('alice', 'old_hash', 0, 100);
            INSERT INTO staff_sessions VALUES ('s1', 'alice', 0), ('s2', 'bob', 0);",
        )?;

        let tx = conn.transaction()?;
        reset_account_password_to_temporary(&tx, "alice", "new_temp_hash", 200)?;
        tx.commit()?;

        let (hash, must_change, updated_at): (String, bool, i64) = conn.query_row(
            "SELECT password_hash, must_change_password, updated_at_unix_ms FROM staff_accounts WHERE username = 'alice'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        assert_eq!(hash, "new_temp_hash");
        assert!(must_change);
        assert_eq!(updated_at, 200);

        let alice_revoked: bool = conn.query_row(
            "SELECT revoked FROM staff_sessions WHERE session_id = 's1'",
            [],
            |r| r.get(0),
        )?;
        assert!(alice_revoked);

        let bob_revoked: bool = conn.query_row(
            "SELECT revoked FROM staff_sessions WHERE session_id = 's2'",
            [],
            |r| r.get(0),
        )?;
        assert!(!bob_revoked);

        Ok(())
    }
}
