use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use rustctrl_core::DeviceId;
use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

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
        );",
        )?;
        Ok(Self(Arc::new(Mutex::new(connection))))
    }
    pub async fn heartbeat(&self, id: DeviceId, name: String, version: String) -> Result<i64> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
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
}
