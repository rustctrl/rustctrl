use anyhow::Result;
use rustctrl_core::{config_base, read_config, resolve};
use serde::Deserialize;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub database: PathBuf,
    pub tls: TlsConfig,
    #[serde(default)]
    pub staff_session: StaffSessionConfig,
    #[serde(default)]
    pub fleet: FleetConfig,
    #[serde(default)]
    pub enrollment: EnrollmentConfig,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub client_ca: PathBuf,
}
/// Finite lifetime for remembered Staff Sessions, enforced by the Server.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaffSessionConfig {
    #[serde(default = "default_remembered_lifetime_secs")]
    pub remembered_lifetime_secs: u64,
}
impl Default for StaffSessionConfig {
    fn default() -> Self {
        Self {
            remembered_lifetime_secs: default_remembered_lifetime_secs(),
        }
    }
}
pub fn default_remembered_lifetime_secs() -> u64 {
    30 * 24 * 60 * 60
}
/// Heartbeat freshness window used to derive Device online status.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetConfig {
    #[serde(default = "default_offline_after_secs")]
    pub offline_after_secs: u64,
}
impl Default for FleetConfig {
    fn default() -> Self {
        Self {
            offline_after_secs: default_offline_after_secs(),
        }
    }
}
pub fn default_offline_after_secs() -> u64 {
    60
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentConfig {
    pub server_endpoint: Option<String>,
    pub domain_name: Option<String>,
    pub agent_issuer_certificate: Option<PathBuf>,
    pub agent_issuer_private_key: Option<PathBuf>,
    pub enrollment_certificate: Option<PathBuf>,
    pub enrollment_private_key: Option<PathBuf>,
}

impl ServerConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let mut config: Self = read_config(path)?;
        let base = config_base(path);
        resolve(base, &mut config.database);
        resolve(base, &mut config.tls.certificate);
        resolve(base, &mut config.tls.private_key);
        resolve(base, &mut config.tls.client_ca);
        if let Some(ref mut p) = config.enrollment.agent_issuer_certificate {
            resolve(base, p);
        }
        if let Some(ref mut p) = config.enrollment.agent_issuer_private_key {
            resolve(base, p);
        }
        if let Some(ref mut p) = config.enrollment.enrollment_certificate {
            resolve(base, p);
        }
        if let Some(ref mut p) = config.enrollment.enrollment_private_key {
            resolve(base, p);
        }
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_config(path: &Path, body: &str) {
        std::fs::write(path, body).unwrap();
    }

    #[test]
    fn staff_session_defaults_to_30_days_and_accepts_override() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("server.toml");
        write_config(
            &path,
            "listen = \"127.0.0.1:9876\"\ndatabase = \"db.sqlite\"\n\n[tls]\ncertificate = \"c\"\nprivate_key = \"k\"\nclient_ca = \"ca\"\n",
        );
        let config = ServerConfig::load(&path)?;
        assert_eq!(config.staff_session.remembered_lifetime_secs, 2_592_000);

        write_config(
            &path,
            "listen = \"127.0.0.1:9876\"\ndatabase = \"db.sqlite\"\n\n[tls]\ncertificate = \"c\"\nprivate_key = \"k\"\nclient_ca = \"ca\"\n\n[staff_session]\nremembered_lifetime_secs = 90\n",
        );
        let config = ServerConfig::load(&path)?;
        assert_eq!(config.staff_session.remembered_lifetime_secs, 90);
        Ok(())
    }
}
