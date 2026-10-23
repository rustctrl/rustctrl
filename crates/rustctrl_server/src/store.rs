use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use rustctrl_core::DeviceId;
use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

fn current_time_ms() -> Result<i64> {
    Ok(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

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

#[derive(Clone)]
pub struct DeviceStore(Arc<Mutex<Connection>>);

impl DeviceStore {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let connection = Connection::open(path).context("open inventory database")?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS bootstrap_devices (
                device_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                agent_version TEXT NOT NULL,
                last_seen_unix_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS staff_accounts (
                username TEXT PRIMARY KEY,
                role TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                must_change_password INTEGER NOT NULL DEFAULT 0,
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
                FOREIGN KEY(username) REFERENCES staff_accounts(username)
            );
            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_time_unix_ms INTEGER NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                result TEXT NOT NULL,
                detail TEXT NOT NULL
            );",
        )?;
        Ok(Self(Arc::new(Mutex::new(connection))))
    }

    pub async fn heartbeat(&self, id: DeviceId, name: String, version: String) -> Result<i64> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let now = current_time_ms()?;
            let connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            connection.execute(
                "INSERT INTO bootstrap_devices VALUES (?1, ?2, ?3, ?4)
                ON CONFLICT(device_id) DO UPDATE SET name=excluded.name,
                agent_version=excluded.agent_version, last_seen_unix_ms=excluded.last_seen_unix_ms",
                params![id.to_string(), name, version, now],
            )?;
            Ok(now)
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
            let count: i64 =
                connection.query_row("SELECT COUNT(*) FROM bootstrap_devices", [], |row| {
                    row.get(0)
                })?;
            Ok(u64::try_from(count)?)
        })
        .await?
    }

    pub async fn bootstrap_admin(
        &self,
        username: String,
        temporary_password: String,
    ) -> Result<()> {
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
                "SELECT username, role, password_hash, must_change_password, created_at_unix_ms, updated_at_unix_ms FROM staff_accounts WHERE username = ?1",
            )?;
            let mut rows = stmt.query(params![username])?;
            if let Some(row) = rows.next()? {
                let role_str: String = row.get(1)?;
                let role: StaffRole = role_str.parse()?;
                let must_change: i64 = row.get(3)?;
                Ok(Some(StaffAccount {
                    username: row.get(0)?,
                    role,
                    password_hash: row.get(2)?,
                    must_change_password: must_change != 0,
                    created_at_unix_ms: row.get(4)?,
                    updated_at_unix_ms: row.get(5)?,
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

    pub async fn create_session(
        &self,
        session_id: String,
        username: String,
        role: StaffRole,
        must_change_password: bool,
    ) -> Result<StaffSession> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let now = current_time_ms()?;
            let connection = store
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            connection.execute(
                "INSERT INTO staff_sessions (session_id, username, role, must_change_password, created_at_unix_ms, last_seen_unix_ms, revoked) VALUES (?1, ?2, ?3, ?4, ?5, ?5, 0)",
                params![session_id, username, role.as_str(), if must_change_password { 1 } else { 0 }, now],
            )?;
            Ok(StaffSession {
                session_id,
                username,
                role,
                must_change_password,
                created_at_unix_ms: now,
                last_seen_unix_ms: now,
                revoked: false,
            })
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
                "SELECT session_id, username, role, must_change_password, created_at_unix_ms, last_seen_unix_ms, revoked FROM staff_sessions WHERE session_id = ?1",
            )?;
            let mut rows = stmt.query(params![session_id])?;
            if let Some(row) = rows.next()? {
                let role_str: String = row.get(2)?;
                let role: StaffRole = role_str.parse()?;
                let must_change: i64 = row.get(3)?;
                let revoked: i64 = row.get(6)?;
                let session = StaffSession {
                    session_id: row.get(0)?,
                    username: row.get(1)?,
                    role,
                    must_change_password: must_change != 0,
                    created_at_unix_ms: row.get(4)?,
                    last_seen_unix_ms: row.get(5)?,
                    revoked: revoked != 0,
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
}
