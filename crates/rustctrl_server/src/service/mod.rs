//! gRPC transport services, TLS configuration, and server startup for the RustCtrl Server.
//!
//! # Domain Scope
//! This module coordinates the gRPC transport architecture for the RustCtrl Server. It binds
//! transport security (`tls`), staff session authorization middleware (`middleware`),
//! agent bootstrap and enrollment services (`bootstrap`), and staff administration and fleet
//! inventory services (`staff_auth`), exposing the main server entrypoints (`serve` and `serve_on`).
//!
//! # Canonical Terms (from [CONTEXT.md](../../../../CONTEXT.md))
//! - **Server**: The shared authority for staff accounts, inventory, Remote Sessions,
//!   Management Tasks, and activity history. Avoid: Controller.
//! - **Device**: A Windows computer or Android TV recorded in the fleet inventory. Its identity
//!   remains the same when its network address changes. Avoid: IP address as device identity.
//! - **Fleet**: All Devices managed by the IT team through RustCtrl. Avoid: IP list.
//! - **Controller**: The staff application for accessing the Fleet and performing actions allowed
//!   by the staff member's role. Avoid: Server, Agent.
//! - **Agent**: The RustCtrl component representing a Windows Device in the Fleet. Avoid: Controller.
//! - **Staff Account**: An individual IT staff member's identity in RustCtrl, with an Admin or
//!   Operator role. It is distinct from a component's connection identity. Avoid: shared account,
//!   Controller certificate as staff identity.
//! - **Staff Session**: A revocable period of access to RustCtrl through the Controller under a
//!   Staff Account. Avoid: Remote Session, Agent connection.
//! - **Installation Authorization**: An Admin-granted permission for new Agents to join a specific
//!   RustCtrl Server through an Agent Installation Package. Avoid: Device credentials.
//! - **Provisioning**: The initial preparation that establishes a Device's identity and access
//!   within RustCtrl. Avoid: per-session approval.
//!
//! # Invariants and Architectural Guarantees
//! - **Mutual TLS (ADR 0002)**: All connections require mutual TLS verification distinguishing
//!   enrolled Agents, enrollment bootstrap clients, and Controllers.
//! - **Role-Based Authorization (ADR 0003, ADR 0005)**: Staff operations strictly enforce
//!   role permissions and revocable session validity.
//! - **Subordinate Agent CA (ADR 0007)**: Leaf agent credentials are provisioned through a scoped
//!   issuing authority without exposing the root CA private key.
//!
//! # Forbidden Anti-Patterns
//! - Never allow unauthenticated or unauthorized access to staff RPCs.
//! - Never use IP addresses as durable device identities.
//! - Never conflate Staff Sessions with Remote Sessions.
//!
//! # Applicable Architecture Decision Records (ADRs)
//! - [ADR 0001: Centralize Fleet Coordination](../../../../docs/adr/0001-centralize-fleet-coordination.md)
//! - [ADR 0002: Bootstrap an Offline Local CA](../../../../docs/adr/0002-bootstrap-an-offline-local-ca.md)
//! - [ADR 0003: Bootstrap Staff Administration Locally](../../../../docs/adr/0003-bootstrap-staff-administration-locally.md)
//! - [ADR 0004: Enroll Agents Through Trusted Installation](../../../../docs/adr/0004-enroll-agents-through-trusted-installation.md)
//! - [ADR 0005: Keep Remembered Staff Access Revocable](../../../../docs/adr/0005-keep-remembered-staff-access-revocable.md)
//! - [ADR 0006: Separate Inventory Cleanup From Device Blocking](../../../../docs/adr/0006-separate-inventory-cleanup-from-device-blocking.md)
//! - [ADR 0007: Provision Agent Credentials via Scoped Issuing Authority](../../../../docs/adr/0007-provision-agent-credentials-via-scoped-issuing-authority.md)

pub mod bootstrap;
pub mod middleware;
pub mod staff_auth;
pub mod tls;

pub use bootstrap::BootstrapService;
pub use staff_auth::StaffAuthService;

use crate::{config::ServerConfig, issuer::AgentIssuer, store::DeviceStore};
use anyhow::{Context, Result};
use rustctrl_protocol::{
    auth::staff_auth_server::StaffAuthServer, bootstrap::bootstrap_server::BootstrapServer,
};
use std::{fs, future::Future, sync::Arc};
use tonic::{
    Status,
    transport::{Certificate, Identity, Server, ServerTlsConfig},
};

pub(crate) fn hash_secret(secret: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, secret.as_bytes());
    digest.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn database_error(error: anyhow::Error) -> Status {
    tracing::error!(%error, "inventory operation failed");
    Status::internal("inventory operation failed")
}

/// Starts the RustCtrl Server by binding a new TCP listener to the configured socket address.
pub async fn serve(
    config: ServerConfig,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .context("bind server listener")?;
    serve_on(config, listener, shutdown).await
}

/// Starts the RustCtrl Server on an existing TCP listener, setting up mTLS, store, and services.
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

    let tls_dir = config
        .tls
        .certificate
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let agent_ca_cert_path = config
        .enrollment
        .agent_issuer_certificate
        .clone()
        .unwrap_or_else(|| tls_dir.join("agent-ca/cert.pem"));
    let agent_ca_key_path = config
        .enrollment
        .agent_issuer_private_key
        .clone()
        .unwrap_or_else(|| tls_dir.join("agent-ca/key.pem"));
    let enrollment_cert_path = config
        .enrollment
        .enrollment_certificate
        .clone()
        .unwrap_or_else(|| tls_dir.join("enrollment/cert.pem"));
    let enrollment_key_path = config
        .enrollment
        .enrollment_private_key
        .clone()
        .unwrap_or_else(|| tls_dir.join("enrollment/key.pem"));

    let agent_issuer = if agent_ca_cert_path.exists()
        && agent_ca_key_path.exists()
        && enrollment_cert_path.exists()
        && enrollment_key_path.exists()
    {
        let ca_cert_pem = fs::read_to_string(&config.tls.client_ca).context("read client CA")?;
        let issuer_cert_pem =
            fs::read_to_string(&agent_ca_cert_path).context("read agent CA cert")?;
        let issuer_key_pem = fs::read_to_string(&agent_ca_key_path).context("read agent CA key")?;
        let enrollment_cert_pem =
            fs::read_to_string(&enrollment_cert_path).context("read enrollment cert")?;
        let enrollment_key_pem =
            fs::read_to_string(&enrollment_key_path).context("read enrollment key")?;
        let mut server_endpoint = config.enrollment.server_endpoint.clone();
        let mut domain_name = config.enrollment.domain_name.clone();

        if server_endpoint.is_none() {
            server_endpoint = std::env::var("RUSTCTRL_SERVER_ENDPOINT").ok();
        }
        if domain_name.is_none() {
            domain_name = std::env::var("RUSTCTRL_SERVER_NAME").ok();
        }

        let enrollment_toml_path = tls_dir.join("enrollment.toml");
        let parsed_deployment = if (server_endpoint.is_none() || domain_name.is_none())
            && enrollment_toml_path.exists()
        {
            fs::read_to_string(&enrollment_toml_path)
                .ok()
                .and_then(|c| toml::from_str::<toml::Value>(&c).ok())
        } else {
            None
        };
        if let Some(parsed) = parsed_deployment {
            if server_endpoint.is_none() {
                server_endpoint = parsed
                    .get("server_endpoint")
                    .and_then(|v| v.as_str())
                    .map(ToString::to_string);
            }
            if domain_name.is_none() {
                domain_name = parsed
                    .get("domain_name")
                    .and_then(|v| v.as_str())
                    .map(ToString::to_string);
            }
        }

        let server_endpoint = server_endpoint
            .unwrap_or_else(|| format!("https://localhost:{}", config.listen.port()));
        let domain_name = domain_name.unwrap_or_else(|| "localhost".into());

        Some(Arc::new(AgentIssuer::new(
            server_endpoint,
            domain_name,
            ca_cert_pem,
            issuer_cert_pem,
            issuer_key_pem,
            enrollment_cert_pem,
            enrollment_key_pem,
        )))
    } else {
        None
    };

    let bootstrap_service = match &agent_issuer {
        Some(issuer) => BootstrapService::with_issuer(store.clone(), issuer.clone()),
        None => BootstrapService::new(store.clone()),
    };
    let staff_auth_service = match &agent_issuer {
        Some(issuer) => StaffAuthService::with_issuer(
            store,
            config.staff_session.remembered_lifetime_secs,
            config.fleet.offline_after_secs,
            issuer.clone(),
        ),
        None => StaffAuthService::new(
            store,
            config.staff_session.remembered_lifetime_secs,
            config.fleet.offline_after_secs,
        ),
    };

    Server::builder()
        .tls_config(tls)?
        .add_service(BootstrapServer::new(bootstrap_service))
        .add_service(StaffAuthServer::new(staff_auth_service))
        .serve_with_incoming_shutdown(
            tokio_stream::wrappers::TcpListenerStream::new(listener),
            shutdown,
        )
        .await?;
    Ok(())
}
