//! TLS control-plane client shared by the Controller and Agent.
#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use rustctrl_core::ClientConfig;
use rustctrl_protocol::bootstrap::bootstrap_client::BootstrapClient;
use std::{fs, time::Duration};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

pub async fn connect_channel_from_pem(
    endpoint: &str,
    domain_name: &str,
    ca_pem: &[u8],
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<Channel> {
    initialize_tls();
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(ca_pem))
        .identity(Identity::from_pem(cert_pem, key_pem))
        .domain_name(domain_name);
    let channel = Endpoint::from_shared(endpoint.to_string())?
        .tls_config(tls)?
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(5))
        .connect()
        .await
        .context("connect to RustCtrl server over mutual TLS")?;
    Ok(channel)
}

pub async fn connect_from_pem(
    endpoint: &str,
    domain_name: &str,
    ca_pem: &[u8],
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<BootstrapClient<Channel>> {
    let channel =
        connect_channel_from_pem(endpoint, domain_name, ca_pem, cert_pem, key_pem).await?;
    Ok(BootstrapClient::new(channel))
}

pub async fn connect_channel(config: &ClientConfig) -> Result<Channel> {
    config.validate()?;
    let ca = fs::read(&config.ca_certificate).context("read CA certificate")?;
    let cert = fs::read(&config.certificate).context("read client certificate")?;
    let key = fs::read(&config.private_key).context("read client private key")?;
    connect_channel_from_pem(&config.endpoint, &config.domain_name, &ca, &cert, &key).await
}

pub async fn connect(config: &ClientConfig) -> Result<BootstrapClient<Channel>> {
    let channel = connect_channel(config).await?;
    Ok(BootstrapClient::new(channel))
}

pub async fn connect_staff_auth(
    config: &ClientConfig,
) -> Result<rustctrl_protocol::auth::staff_auth_client::StaffAuthClient<Channel>> {
    let channel = connect_channel(config).await?;
    Ok(rustctrl_protocol::auth::staff_auth_client::StaffAuthClient::new(channel))
}

pub fn initialize_tls() {
    // GPUI dependencies may enable another provider; choose one before building TLS configs.
    let _ = rustls::crypto::ring::default_provider().install_default();
}
