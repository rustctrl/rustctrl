//! SQLite persistence schema initialization, connection pragmas, and schema migrations.
//!
//! # Domain Scope
//! Manages low-level SQLite database setup, connection configuration (WAL journal mode,
//! busy timeout), table creation DDL, index creation, and additive column migrations for
//! existing databases.
//!
//! # Canonical Terms (from [CONTEXT.md](../../../../CONTEXT.md))
//! - **Server**: The central persistent authority backing fleet coordination and accounts.
//! - **Fleet Inventory**: Persisted across tables `bootstrap_devices`, `device_metadata`,
//!   `blocked_devices`, `device_replacements`, and `connection_targets`.
//! - **Staff Account** and **Staff Session**: Persisted in `staff_accounts` and `staff_sessions`.
//! - **Installation Authorization** and **Device Enrollment**: Persisted in `installation_authorizations`
//!   and `device_enrollments`.
//!
//! # Invariants and Architectural Guarantees
//! - WAL mode (`PRAGMA journal_mode=WAL`) and a 5-second busy timeout are strictly enforced on open.
//! - Foreign key constraints and additive column migrations guarantee backwards compatibility
//!   with existing on-disk SQLite databases without data loss.
//! - Tables and indexes are created idempotently (`CREATE TABLE IF NOT EXISTS`, `CREATE INDEX IF NOT EXISTS`).
//!
//! # Forbidden Anti-Patterns
//! - Never drop tables or delete persistent data during startup or migrations.
//! - Never rely on SQLite default rollback journal mode (WAL mode is required for concurrency).
//!
//! # Applicable Architecture Decision Records (ADRs)
//! - [ADR 0001: Centralize Fleet Coordination](../../../../docs/adr/0001-centralize-fleet-coordination.md)
//! - [ADR 0003: Bootstrap Staff Administration Locally](../../../../docs/adr/0003-bootstrap-staff-administration-locally.md)
//! - [ADR 0005: Keep Remembered Staff Access Revocable](../../../../docs/adr/0005-keep-remembered-staff-access-revocable.md)
//! - [ADR 0006: Separate Inventory Cleanup from Device Blocking](../../../../docs/adr/0006-separate-inventory-cleanup-from-device-blocking.md)

use anyhow::{Context, Result};
use rusqlite::Connection;
use std::path::Path;

/// Configure connection-level pragmas including WAL mode and busy timeout.
pub(crate) fn configure_connection(connection: &Connection) -> Result<()> {
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(())
}

/// Create all required tables, indices, and seed known device identities.
pub(crate) fn initialize_schema(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS bootstrap_devices (
            device_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            agent_version TEXT NOT NULL,
            last_address TEXT,
            last_seen_unix_ms INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS staff_accounts (
            username TEXT PRIMARY KEY,
            role TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            must_change_password INTEGER NOT NULL DEFAULT 0,
            active INTEGER NOT NULL DEFAULT 1,
            created_at_unix_ms INTEGER NOT NULL,
            updated_at_unix_ms INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS staff_sessions (
            session_id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            must_change_password INTEGER NOT NULL,
            created_at_unix_ms INTEGER NOT NULL,
            last_seen_unix_ms INTEGER NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0,
            expires_at_unix_ms INTEGER,
            FOREIGN KEY(username) REFERENCES staff_accounts(username)
        );
        CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_time_unix_ms INTEGER NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            result TEXT NOT NULL,
            detail TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS device_metadata (
            device_id TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            location TEXT,
            updated_at_unix_ms INTEGER NOT NULL,
            FOREIGN KEY(device_id) REFERENCES bootstrap_devices(device_id)
        );
        CREATE TABLE IF NOT EXISTS connection_targets (
            target_id TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            target_type TEXT NOT NULL,
            configured_address TEXT NOT NULL,
            location TEXT,
            created_at_unix_ms INTEGER NOT NULL,
            updated_at_unix_ms INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS blocked_devices (
            device_id TEXT PRIMARY KEY,
            blocked_at_unix_ms INTEGER NOT NULL,
            blocked_by TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS device_replacements (
            prior_device_id TEXT PRIMARY KEY,
            replacement_device_id TEXT NOT NULL,
            replaced_at_unix_ms INTEGER NOT NULL,
            replaced_by TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS installation_authorizations (
            authorization_id TEXT PRIMARY KEY,
            secret_hash TEXT NOT NULL,
            created_at_unix_ms INTEGER NOT NULL,
            created_by TEXT NOT NULL,
            revoked_at_unix_ms INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_installation_authorizations_secret_hash ON installation_authorizations(secret_hash);
        CREATE TABLE IF NOT EXISTS device_enrollments (
            device_id TEXT PRIMARY KEY,
            authorization_id TEXT NOT NULL,
            enrolled_at_unix_ms INTEGER NOT NULL,
            resumption_secret_hash TEXT,
            FOREIGN KEY(authorization_id) REFERENCES installation_authorizations(authorization_id)
        );
        CREATE TABLE IF NOT EXISTS known_device_identities (
            device_id TEXT PRIMARY KEY
        );
        INSERT OR IGNORE INTO known_device_identities (device_id) SELECT device_id FROM bootstrap_devices;
        INSERT OR IGNORE INTO known_device_identities (device_id) SELECT device_id FROM device_enrollments;",
    )?;
    Ok(())
}

fn ensure_column(connection: &Connection, table: &str, column: &str, col_def: &str) -> Result<()> {
    let pragma_query = format!("SELECT name FROM pragma_table_info('{table}')");
    let columns: Vec<String> = connection
        .prepare(&pragma_query)?
        .query_map([], |row| row.get(0))?
        .collect::<std::result::Result<_, _>>()?;
    if !columns.iter().any(|name| name == column) {
        connection.execute_batch(&format!(
            "ALTER TABLE {table} ADD COLUMN {column} {col_def};"
        ))?;
    }
    Ok(())
}

/// Apply additive column migrations for existing databases that predate new features.
pub(crate) fn run_migrations(connection: &Connection) -> Result<()> {
    // Existing databases predate account deactivation, remembered-session
    // expiry, and observed device addresses; add missing columns in place.
    ensure_column(connection, "bootstrap_devices", "last_address", "TEXT")?;
    ensure_column(
        connection,
        "staff_accounts",
        "active",
        "INTEGER NOT NULL DEFAULT 1",
    )?;
    ensure_column(
        connection,
        "staff_sessions",
        "expires_at_unix_ms",
        "INTEGER",
    )?;
    ensure_column(
        connection,
        "device_enrollments",
        "resumption_secret_hash",
        "TEXT",
    )?;
    Ok(())
}

/// Open and fully configure an SQLite database connection at the given path.
pub(crate) fn open_connection(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let connection = Connection::open(path).context("open inventory database")?;
    configure_connection(&connection)?;
    initialize_schema(&connection)?;
    run_migrations(&connection)?;
    Ok(connection)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_connection_creates_tables_and_pragmas() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let db_path = temp.path().join("subdir").join("test.db");
        let conn = open_connection(&db_path)?;

        // Verify WAL mode
        let journal_mode: String = conn.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
        assert_eq!(journal_mode.to_lowercase(), "wal");

        // Verify tables exist
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")?
            .query_map([], |row| row.get(0))?
            .collect::<std::result::Result<_, _>>()?;

        assert!(tables.contains(&"bootstrap_devices".to_string()));
        assert!(tables.contains(&"staff_accounts".to_string()));
        assert!(tables.contains(&"staff_sessions".to_string()));
        assert!(tables.contains(&"activity_log".to_string()));
        assert!(tables.contains(&"device_metadata".to_string()));
        assert!(tables.contains(&"connection_targets".to_string()));
        assert!(tables.contains(&"blocked_devices".to_string()));
        assert!(tables.contains(&"device_replacements".to_string()));
        assert!(tables.contains(&"installation_authorizations".to_string()));
        assert!(tables.contains(&"device_enrollments".to_string()));
        assert!(tables.contains(&"known_device_identities".to_string()));

        Ok(())
    }

    #[test]
    fn run_migrations_adds_missing_columns_to_legacy_schema() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let db_path = temp.path().join("legacy.db");
        let conn = Connection::open(&db_path)?;

        // Simulate legacy schema lacking last_address, active, expires_at_unix_ms, resumption_secret_hash
        conn.execute_batch(
            "CREATE TABLE bootstrap_devices (
                device_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                agent_version TEXT NOT NULL,
                last_seen_unix_ms INTEGER NOT NULL
            );
            CREATE TABLE staff_accounts (
                username TEXT PRIMARY KEY,
                role TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                must_change_password INTEGER NOT NULL DEFAULT 0,
                created_at_unix_ms INTEGER NOT NULL,
                updated_at_unix_ms INTEGER NOT NULL
            );
            CREATE TABLE staff_sessions (
                session_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                role TEXT NOT NULL,
                must_change_password INTEGER NOT NULL,
                created_at_unix_ms INTEGER NOT NULL,
                last_seen_unix_ms INTEGER NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE installation_authorizations (
                authorization_id TEXT PRIMARY KEY,
                secret_hash TEXT NOT NULL,
                created_at_unix_ms INTEGER NOT NULL,
                created_by TEXT NOT NULL,
                revoked_at_unix_ms INTEGER
            );
            CREATE TABLE device_enrollments (
                device_id TEXT PRIMARY KEY,
                authorization_id TEXT NOT NULL,
                enrolled_at_unix_ms INTEGER NOT NULL
            );",
        )?;

        // Run migrations
        run_migrations(&conn)?;

        // Verify all 4 columns were added
        let device_cols: Vec<String> = conn
            .prepare("SELECT name FROM pragma_table_info('bootstrap_devices')")?
            .query_map([], |row| row.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        assert!(device_cols.contains(&"last_address".to_string()));

        let staff_cols: Vec<String> = conn
            .prepare("SELECT name FROM pragma_table_info('staff_accounts')")?
            .query_map([], |row| row.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        assert!(staff_cols.contains(&"active".to_string()));

        let session_cols: Vec<String> = conn
            .prepare("SELECT name FROM pragma_table_info('staff_sessions')")?
            .query_map([], |row| row.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        assert!(session_cols.contains(&"expires_at_unix_ms".to_string()));

        let enrollment_cols: Vec<String> = conn
            .prepare("SELECT name FROM pragma_table_info('device_enrollments')")?
            .query_map([], |row| row.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        assert!(enrollment_cols.contains(&"resumption_secret_hash".to_string()));

        Ok(())
    }
}
