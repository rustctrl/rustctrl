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
impl ServerConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let mut config: Self = read_config(path)?;
        let base = config_base(path);
        resolve(base, &mut config.database);
        resolve(base, &mut config.tls.certificate);
        resolve(base, &mut config.tls.private_key);
        resolve(base, &mut config.tls.client_ca);
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
