use crate::{config::ServerConfig, store::DeviceStore};
use anyhow::{Context, Result};
use rustctrl_core::DeviceId;
use rustctrl_protocol::bootstrap::{
    HealthReply, HealthRequest, HeartbeatReply, HeartbeatRequest,
    bootstrap_server::{Bootstrap, BootstrapServer},
};
use std::{fs, future::Future};
use tonic::{
    Request, Response, Status,
    transport::{Certificate, Identity, Server, ServerTlsConfig},
};
use x509_parser::{extensions::GeneralName, parse_x509_certificate};

pub struct BootstrapService {
    store: DeviceStore,
}
impl BootstrapService {
    pub fn new(store: DeviceStore) -> Self {
        Self { store }
    }
}

#[tonic::async_trait]
impl Bootstrap for BootstrapService {
    async fn get_health(
        &self,
        _request: Request<HealthRequest>,
    ) -> Result<Response<HealthReply>, Status> {
        let count = self.store.count().await.map_err(database_error)?;
        Ok(Response::new(HealthReply {
            version: env!("CARGO_PKG_VERSION").into(),
            registered_devices: count,
        }))
    }
    async fn send_heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatReply>, Status> {
        let body = request.get_ref();
        let id: DeviceId = body
            .device_id
            .parse()
            .map_err(|_| Status::invalid_argument("invalid device_id"))?;
        if body.name.trim().is_empty()
            || body.name.len() > 128
            || body.agent_version.is_empty()
            || body.agent_version.len() > 64
        {
            return Err(Status::invalid_argument("invalid name or agent_version"));
        }
        let certs = request
            .peer_certs()
            .ok_or_else(|| Status::unauthenticated("client certificate required"))?;
        let leaf = certs
            .first()
            .ok_or_else(|| Status::unauthenticated("client certificate required"))?;
        let (_, cert) = parse_x509_certificate(leaf.as_ref())
            .map_err(|_| Status::unauthenticated("invalid client certificate"))?;
        let expected = id.certificate_name();
        let san = cert
            .subject_alternative_name()
            .map_err(|_| Status::unauthenticated("invalid certificate SAN"))?;
        let matches = san.is_some_and(|extension| {
            extension
                .value
                .general_names
                .iter()
                .any(|name| matches!(name, GeneralName::DNSName(value) if *value == expected))
        });
        if !matches {
            return Err(Status::permission_denied(
                "certificate does not identify this device",
            ));
        }
        let body = request.into_inner();
        let timestamp = self
            .store
            .heartbeat(id, body.name, body.agent_version)
            .await
            .map_err(database_error)?;
        tracing::debug!(device_id = %id, "heartbeat stored");
        Ok(Response::new(HeartbeatReply {
            received_at_unix_ms: timestamp,
        }))
    }
}
fn database_error(error: anyhow::Error) -> Status {
    tracing::error!(%error, "inventory operation failed");
    Status::internal("inventory operation failed")
}

pub async fn serve(
    config: ServerConfig,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .context("bind server listener")?;
    serve_on(config, listener, shutdown).await
}

pub async fn serve_on(
    config: ServerConfig,
    listener: tokio::net::TcpListener,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<()> {
    rustctrl_network::initialize_tls();
    let store = DeviceStore::open(&config.database)?;
    let certificate = fs::read(&config.tls.certificate).context("read server certificate")?;
    let private_key = fs::read(&config.tls.private_key).context("read server private key")?;
    let ca = fs::read(&config.tls.client_ca).context("read client CA certificate")?;
    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(certificate, private_key))
        .client_ca_root(Certificate::from_pem(ca));
    tracing::info!(listen = %config.listen, "starting RustCtrl bootstrap server with required client certificates");
    Server::builder()
        .tls_config(tls)?
        .add_service(BootstrapServer::new(BootstrapService::new(store)))
        .serve_with_incoming_shutdown(
            tokio_stream::wrappers::TcpListenerStream::new(listener),
            shutdown,
        )
        .await?;
    Ok(())
}
