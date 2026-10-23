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
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub client_ca: PathBuf,
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
