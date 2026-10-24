//! Locally stored remembered Staff Session credential.
//!
//! Only the Server-issued session token is stored, never the staff password.
//! The file is scoped to the deployment it was issued for and protected with
//! user-only filesystem permissions on Unix.

use anyhow::{Context, Result};
use rustctrl_core::ClientConfig;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedStaffSession {
    pub endpoint: String,
    pub domain_name: String,
    pub username: String,
    pub session_token: String,
}

impl SavedStaffSession {
    pub fn matches_deployment(&self, server: &ClientConfig) -> bool {
        self.endpoint == server.endpoint && self.domain_name == server.domain_name
    }
}

pub fn session_file_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("session.toml")
}

pub fn save(path: &Path, session: &SavedStaffSession) -> Result<()> {
    let body = toml::to_string_pretty(session).context("serialize saved staff session")?;
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        // Create with mode 0600 so no credential byte is ever observable
        // through a more permissive file, regardless of the process umask.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("create {}", path.display()))?;
        file.write_all(body.as_bytes())
            .with_context(|| format!("write {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, &body).with_context(|| format!("write {}", path.display()))?;
    }
    // Tighten a pre-existing file that may carry looser permissions.
    restrict_permissions(path)
}

pub fn load(path: &Path) -> Result<Option<SavedStaffSession>> {
    match std::fs::read_to_string(path) {
        Ok(body) => Ok(Some(
            toml::from_str(&body).context("parse saved staff session")?,
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(anyhow::Error::new(error)).with_context(|| format!("read {}", path.display()))
        }
    }
}

pub fn clear(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(anyhow::Error::new(error)).with_context(|| format!("remove {}", path.display()))
        }
    }
}

fn restrict_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("restrict permissions on {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}
