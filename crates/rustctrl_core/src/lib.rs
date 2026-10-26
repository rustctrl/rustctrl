//! Shared identities and configuration for the RustCtrl bootstrap.
#![forbid(unsafe_code)]

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    fmt, fs,
    path::{Path, PathBuf},
    str::FromStr,
};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeviceId(Uuid);

impl DeviceId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
    pub fn certificate_name(self) -> String {
        format!("{self}.agent.rustctrl.internal")
    }
}
impl Default for DeviceId {
    fn default() -> Self {
        Self::new()
    }
}
impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl FromStr for DeviceId {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        let id = Uuid::parse_str(value).context("device_id must be a UUID")?;
        ensure!(!id.is_nil(), "device_id must not be the nil UUID");
        Ok(Self(id))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub endpoint: String,
    pub domain_name: String,
    pub ca_certificate: PathBuf,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
}
impl ClientConfig {
    pub fn resolve_paths(&mut self, base: &Path) {
        resolve(base, &mut self.ca_certificate);
        resolve(base, &mut self.certificate);
        resolve(base, &mut self.private_key);
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.endpoint.starts_with("https://"),
            "server endpoint must use https://"
        );
        ensure!(
            !self.domain_name.trim().is_empty(),
            "TLS domain_name is required"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerConfig {
    pub server: ClientConfig,
}
impl ControllerConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let mut config: Self = read_config(path)?;
        config.server.resolve_paths(config_base(path));
        config.server.validate()?;
        Ok(config)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    pub device_id: DeviceId,
    pub name: String,
    #[serde(default = "default_heartbeat_seconds")]
    pub heartbeat_seconds: u64,
    #[serde(default = "default_log_file")]
    pub log_file: PathBuf,
    pub server: ClientConfig,
}
fn default_heartbeat_seconds() -> u64 {
    10
}
fn default_log_file() -> PathBuf {
    PathBuf::from("agent.log")
}
impl AgentConfig {
    pub fn save(&self, path: &Path) -> Result<()> {
        let content = toml::to_string_pretty(self).context("serialize agent config to toml")?;
        fs::write(path, content).context("write agent config file")?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let mut config: Self = read_config(path)?;
        ensure!(
            !config.device_id.0.is_nil(),
            "device_id must not be the nil UUID"
        );
        ensure!(
            !config.name.trim().is_empty() && config.name.len() <= 128,
            "name must contain 1 to 128 bytes"
        );
        ensure!(
            (1..=3600).contains(&config.heartbeat_seconds),
            "heartbeat_seconds must be between 1 and 3600"
        );
        config.server.resolve_paths(config_base(path));
        resolve(config_base(path), &mut config.log_file);
        config.server.validate()?;
        Ok(config)
    }
}

/// A deployment-specific installation artifact prepared by an Admin through the Controller.
///
/// Contains the server configuration, public trust material, an enrollment TLS credential,
/// and an Installation Authorization secret token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentInstallationArtifact {
    pub server_endpoint: String,
    pub domain_name: String,
    pub ca_certificate: String,
    pub enrollment_certificate: String,
    pub enrollment_private_key: String,
    pub authorization_id: String,
    pub installation_secret: String,
    pub created_at_unix_ms: i64,
}

impl AgentInstallationArtifact {
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let content =
            toml::to_string_pretty(self).context("serialize installation artifact to toml")?;
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, content.as_bytes())
            .with_context(|| format!("write installation artifact to {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    pub fn load_from_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("read installation artifact from {}", path.display()))?;
        toml::from_str::<Self>(&content)
            .with_context(|| format!("parse installation artifact from {}", path.display()))
    }
}

pub fn read_config<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let body = fs::read_to_string(path)
        .with_context(|| format!("read configuration {}", path.display()))?;
    toml::from_str(&body).with_context(|| format!("parse configuration {}", path.display()))
}
pub fn config_base(path: &Path) -> &Path {
    path.parent().unwrap_or_else(|| Path::new("."))
}
pub fn resolve(base: &Path, path: &mut PathBuf) {
    if path.is_relative() {
        *path = base.join(&*path);
    }
}
pub fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

pub fn init_file_logging(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open service log {}", path.display()))?;
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .with_writer(std::sync::Arc::new(file))
        .try_init()
        .map_err(|error| anyhow::anyhow!("initialize service logging: {error}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_config_save_and_load_escapes_special_characters() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("config.toml");
        let id = DeviceId::new();
        let special_name = r#"Office "Reception" \ A"#;

        let config = AgentConfig {
            device_id: id,
            name: special_name.into(),
            heartbeat_seconds: 15,
            log_file: PathBuf::from("agent.log"),
            server: ClientConfig {
                endpoint: "https://localhost:9876".into(),
                domain_name: "localhost".into(),
                ca_certificate: PathBuf::from("ca.pem"),
                certificate: PathBuf::from("cert.pem"),
                private_key: PathBuf::from("key.pem"),
            },
        };

        config.save(&path)?;

        let loaded = AgentConfig::load(&path)?;
        assert_eq!(loaded.device_id, id);
        assert_eq!(loaded.name, special_name);
        assert_eq!(loaded.heartbeat_seconds, 15);
        Ok(())
    }
}
