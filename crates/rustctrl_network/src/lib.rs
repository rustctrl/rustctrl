//! TLS control-plane client shared by the Controller and Agent.
#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use rustctrl_core::ClientConfig;
use rustctrl_protocol::bootstrap::bootstrap_client::BootstrapClient;
use std::{fs, time::Duration};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

pub async fn connect(config: &ClientConfig) -> Result<BootstrapClient<Channel>> {
    initialize_tls();
    config.validate()?;
    let ca = fs::read(&config.ca_certificate).context("read CA certificate")?;
    let cert = fs::read(&config.certificate).context("read client certificate")?;
    let key = fs::read(&config.private_key).context("read client private key")?;
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(ca))
        .identity(Identity::from_pem(cert, key))
        .domain_name(&config.domain_name);
    let channel = Endpoint::from_shared(config.endpoint.clone())?
        .tls_config(tls)?
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(5))
        .connect()
        .await
        .context("connect to RustCtrl server over mutual TLS")?;
    Ok(BootstrapClient::new(channel))
}

pub fn initialize_tls() {
    // GPUI dependencies may enable another provider; choose one before building TLS configs.
    let _ = rustls::crypto::ring::default_provider().install_default();
}
