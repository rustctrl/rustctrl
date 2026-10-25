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

fn validate_username(username: &str) -> Result<String> {
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
fn reset_account_password_to_temporary(
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
    pub active: bool,
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

#[derive(Debug, Clone)]
pub struct DeviceRecord {
    pub device_id: String,
    pub name: String,
    pub agent_version: String,
    pub last_address: Option<String>,
    pub last_seen_unix_ms: i64,
    pub location: Option<String>,
    pub device_type: String,
    pub configured_address: Option<String>,
    pub blocked: bool,
}

#[derive(Debug, Clone)]
pub struct TargetRecord {
    pub target_id: String,
    pub display_name: String,
    pub target_type: String,
    pub configured_address: String,
    pub location: Option<String>,
    pub created_at_unix_ms: i64,
    pub updated_at_unix_ms: i64,
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
            );",
        )?;
        // Existing databases predate account deactivation, remembered-session
        // expiry, and observed device addresses; add missing columns in place.
        let device_columns: Vec<String> = connection
            .prepare("SELECT name FROM pragma_table_info('bootstrap_devices')")?
            .query_map([], |row| row.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        if !device_columns.iter().any(|name| name == "last_address") {
            connection
                .execute_batch("ALTER TABLE bootstrap_devices ADD COLUMN last_address TEXT;")?;
        }
        let staff_columns: Vec<String> = connection
            .prepare("SELECT name FROM pragma_table_info('staff_accounts')")?
            .query_map([], |row| row.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        if !staff_columns.iter().any(|name| name == "active") {
            connection.execute_batch(
                "ALTER TABLE staff_accounts ADD COLUMN active INTEGER NOT NULL DEFAULT 1;",
            )?;
        }
        let session_columns: Vec<String> = connection
            .prepare("SELECT name FROM pragma_table_info('staff_sessions')")?
            .query_map([], |row| row.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        if !session_columns
            .iter()
            .any(|name| name == "expires_at_unix_ms")
        {
            connection.execute_batch(
                "ALTER TABLE staff_sessions ADD COLUMN expires_at_unix_ms INTEGER;",
            )?;
        }
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
}
