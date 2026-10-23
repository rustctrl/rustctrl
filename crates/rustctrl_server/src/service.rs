use crate::{config::ServerConfig, store::DeviceStore};
use anyhow::{Context, Result};
use rustctrl_core::DeviceId;
use rustctrl_protocol::auth::{
    LoginReply, LoginRequest, LogoutReply, LogoutRequest, ReplaceTemporaryPasswordReply,
    ReplaceTemporaryPasswordRequest, StaffStatusReply, StaffStatusRequest,
    staff_auth_server::{StaffAuth, StaffAuthServer},
};
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

pub struct StaffAuthService {
    store: DeviceStore,
}

impl StaffAuthService {
    pub fn new(store: DeviceStore) -> Self {
        Self { store }
    }

    async fn authenticate_request<T>(
        &self,
        request: &Request<T>,
    ) -> Result<crate::store::StaffSession, Status> {
        let token = request
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.strip_prefix("Bearer ").unwrap_or(s).trim())
            .or_else(|| {
                request
                    .metadata()
                    .get("session-token")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.trim())
            });

        let token = match token {
            Some(t) if !t.is_empty() => t,
            _ => return Err(Status::unauthenticated("staff session required")),
        };

        match self.store.get_session(token).await {
            Ok(Some(session)) if !session.revoked => Ok(session),
            _ => Err(Status::unauthenticated("invalid or revoked staff session")),
        }
    }
}

#[tonic::async_trait]
impl StaffAuth for StaffAuthService {
    async fn login(&self, request: Request<LoginRequest>) -> Result<Response<LoginReply>, Status> {
        let body = request.into_inner();
        let username = body.username.trim();
        if username.is_empty() || body.password.is_empty() {
            return Err(Status::invalid_argument(
                "username and password are required",
            ));
        }

        let account = self
            .store
            .get_staff_account(username)
            .await
            .map_err(database_error)?;

        let valid = match &account {
            Some(acc) => crate::password::verify_password(&body.password, &acc.password_hash),
            None => false,
        };

        if !valid {
            let _ = self
                .store
                .record_activity(
                    username.to_string(),
                    "login".into(),
                    "failed".into(),
                    "invalid username or password".into(),
                )
                .await;
            return Err(Status::unauthenticated("invalid username or password"));
        }

        let account = account.unwrap();
        let session_id = uuid::Uuid::new_v4().to_string();
        let session = self
            .store
            .create_session(
                session_id,
                account.username.clone(),
                account.role,
                account.must_change_password,
            )
            .await
            .map_err(database_error)?;

        let _ = self
            .store
            .record_activity(
                account.username.clone(),
                "login".into(),
                "success".into(),
                format!("staff session started for role {}", account.role.as_str()),
            )
            .await;

        Ok(Response::new(LoginReply {
            session_token: session.session_id,
            username: account.username,
            role: account.role.as_str().into(),
            must_change_password: account.must_change_password,
            server_time_unix_ms: session.created_at_unix_ms,
        }))
    }

    async fn replace_temporary_password(
        &self,
        request: Request<ReplaceTemporaryPasswordRequest>,
    ) -> Result<Response<ReplaceTemporaryPasswordReply>, Status> {
        let session = self.authenticate_request(&request).await?;
        let body = request.into_inner();
        let new_hash = crate::password::hash_password(&body.new_password)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        self.store
            .update_password(&session.username, new_hash, false)
            .await
            .map_err(database_error)?;

        let _ = self
            .store
            .record_activity(
                session.username.clone(),
                "replace_temporary_password".into(),
                "success".into(),
                "temporary password replaced with permanent password".into(),
            )
            .await;

        Ok(Response::new(ReplaceTemporaryPasswordReply {
            success: true,
        }))
    }

    async fn logout(
        &self,
        request: Request<LogoutRequest>,
    ) -> Result<Response<LogoutReply>, Status> {
        let session = self.authenticate_request(&request).await?;
        self.store
            .revoke_session(&session.session_id)
            .await
            .map_err(database_error)?;

        let _ = self
            .store
            .record_activity(
                session.username,
                "logout".into(),
                "success".into(),
                "staff session terminated".into(),
            )
            .await;

        Ok(Response::new(LogoutReply { success: true }))
    }

    async fn get_staff_status(
        &self,
        request: Request<StaffStatusRequest>,
    ) -> Result<Response<StaffStatusReply>, Status> {
        let session = self.authenticate_request(&request).await?;
        if session.must_change_password {
            return Err(Status::permission_denied(
                "password change required before accessing protected operations",
            ));
        }

        let count = self.store.count().await.map_err(database_error)?;
        Ok(Response::new(StaffStatusReply {
            username: session.username,
            role: session.role.as_str().into(),
            authenticated: true,
            registered_devices: count,
            server_version: env!("CARGO_PKG_VERSION").into(),
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
        .add_service(BootstrapServer::new(BootstrapService::new(store.clone())))
        .add_service(StaffAuthServer::new(StaffAuthService::new(store)))
        .serve_with_incoming_shutdown(
            tokio_stream::wrappers::TcpListenerStream::new(listener),
            shutdown,
        )
        .await?;
    Ok(())
}
