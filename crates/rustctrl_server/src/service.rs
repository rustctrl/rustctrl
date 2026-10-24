use crate::{config::ServerConfig, store::DeviceStore};
use anyhow::{Context, Result};
use rustctrl_core::DeviceId;
use rustctrl_protocol::auth::{
    ChangeOwnPasswordReply, ChangeOwnPasswordRequest, ChangeStaffRoleReply, ChangeStaffRoleRequest,
    CreateStaffAccountReply, CreateStaffAccountRequest, ListStaffAccountsReply,
    ListStaffAccountsRequest, LoginReply, LoginRequest, LogoutReply, LogoutRequest,
    ReplaceTemporaryPasswordReply, ReplaceTemporaryPasswordRequest, ResetStaffPasswordReply,
    ResetStaffPasswordRequest, StaffAccountEntry, StaffStatusReply, StaffStatusRequest,
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

    async fn authenticate_admin<T>(
        &self,
        request: &Request<T>,
        action: &str,
        target: Option<&str>,
    ) -> Result<crate::store::StaffSession, Status> {
        let session = self.authenticate_request(request).await?;
        if session.must_change_password {
            return Err(Status::permission_denied(
                "password change required before accessing protected operations",
            ));
        }
        if session.role != crate::store::StaffRole::Admin {
            let detail = if let Some(tgt) = target {
                format!("operator cannot perform '{action}' on target '{tgt}'")
            } else {
                format!("operator cannot perform '{action}'")
            };
            let _ = self
                .store
                .record_activity(
                    session.username.clone(),
                    action.into(),
                    "rejected".into(),
                    detail,
                )
                .await;
            return Err(Status::permission_denied("admin role required"));
        }
        Ok(session)
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
            .create_login_session(
                session_id,
                account.username.clone(),
                account.password_hash.clone(),
            )
            .await
            .map_err(database_error)?;
        let session = match session {
            Some(session) => session,
            None => {
                // The password was reset or changed after verification; the
                // credentials this login verified are no longer current.
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
        };

        let _ = self
            .store
            .record_activity(
                session.username.clone(),
                "login".into(),
                "success".into(),
                format!("staff session started for role {}", session.role.as_str()),
            )
            .await;

        Ok(Response::new(LoginReply {
            session_token: session.session_id.clone(),
            username: session.username,
            role: session.role.as_str().into(),
            must_change_password: session.must_change_password,
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

    async fn change_own_password(
        &self,
        request: Request<ChangeOwnPasswordRequest>,
    ) -> Result<Response<ChangeOwnPasswordReply>, Status> {
        let session = self.authenticate_request(&request).await?;
        if session.must_change_password {
            return Err(Status::permission_denied(
                "password change required: replace the temporary password first",
            ));
        }
        let body = request.into_inner();
        if body.current_password.is_empty() || body.new_password.is_empty() {
            return Err(Status::invalid_argument(
                "current and new passwords are required",
            ));
        }
        let new_hash = crate::password::hash_password(&body.new_password)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        if let Err(e) = self
            .store
            .change_own_password(&session.username, body.current_password, new_hash)
            .await
        {
            let err_msg = e.to_string();
            let recognized = err_msg.contains("current password")
                || err_msg.contains("concurrently")
                || err_msg.contains("not found");
            let _ = self
                .store
                .record_activity(
                    session.username.clone(),
                    "change_own_password".into(),
                    "rejected".into(),
                    if recognized {
                        err_msg.clone()
                    } else {
                        "password change failed".into()
                    },
                )
                .await;
            if err_msg.contains("current password") {
                return Err(Status::invalid_argument(err_msg));
            }
            if err_msg.contains("concurrently") {
                return Err(Status::aborted(
                    "password was reset concurrently; sign in again",
                ));
            }
            if err_msg.contains("not found") {
                return Err(Status::not_found(err_msg));
            }
            return Err(database_error(e));
        }

        let _ = self
            .store
            .record_activity(
                session.username.clone(),
                "change_own_password".into(),
                "success".into(),
                "staff member changed their own password".into(),
            )
            .await;

        Ok(Response::new(ChangeOwnPasswordReply { success: true }))
    }

    async fn reset_staff_password(
        &self,
        request: Request<ResetStaffPasswordRequest>,
    ) -> Result<Response<ResetStaffPasswordReply>, Status> {
        let body = request.get_ref();
        let target_username = body.username.trim().to_string();
        let session = self
            .authenticate_admin(&request, "reset_staff_password", Some(&target_username))
            .await?;

        if body.temporary_password.len() < 8 {
            let _ = self
                .store
                .record_activity(
                    session.username.clone(),
                    "reset_staff_password".into(),
                    "rejected".into(),
                    format!("failed to reset password of '{target_username}': password must contain at least 8 characters"),
                )
                .await;
            return Err(Status::invalid_argument(
                "temporary password must contain at least 8 characters",
            ));
        }

        match self
            .store
            .reset_staff_password(&target_username, body.temporary_password.clone())
            .await
        {
            Ok(account) => {
                let _ = self
                    .store
                    .record_activity(
                        session.username.clone(),
                        "reset_staff_password".into(),
                        "success".into(),
                        format!(
                            "reset password of '{target_username}' to a temporary password and revoked its staff sessions"
                        ),
                    )
                    .await;
                Ok(Response::new(ResetStaffPasswordReply {
                    account: Some(StaffAccountEntry {
                        username: account.username,
                        role: account.role.as_str().into(),
                        must_change_password: account.must_change_password,
                        created_at_unix_ms: account.created_at_unix_ms,
                        updated_at_unix_ms: account.updated_at_unix_ms,
                    }),
                }))
            }
            Err(e) => {
                let err_msg = e.to_string();
                let _ = self
                    .store
                    .record_activity(
                        session.username.clone(),
                        "reset_staff_password".into(),
                        "rejected".into(),
                        format!("failed to reset password of '{target_username}': {err_msg}"),
                    )
                    .await;
                if err_msg.contains("not found") {
                    Err(Status::not_found(err_msg))
                } else {
                    Err(Status::invalid_argument(err_msg))
                }
            }
        }
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

    async fn list_staff_accounts(
        &self,
        request: Request<ListStaffAccountsRequest>,
    ) -> Result<Response<ListStaffAccountsReply>, Status> {
        let _session = self
            .authenticate_admin(&request, "list_staff_accounts", None)
            .await?;
        let accounts = self
            .store
            .list_staff_accounts()
            .await
            .map_err(database_error)?;
        let entries = accounts
            .into_iter()
            .map(|acc| StaffAccountEntry {
                username: acc.username,
                role: acc.role.as_str().into(),
                must_change_password: acc.must_change_password,
                created_at_unix_ms: acc.created_at_unix_ms,
                updated_at_unix_ms: acc.updated_at_unix_ms,
            })
            .collect();
        Ok(Response::new(ListStaffAccountsReply { accounts: entries }))
    }

    async fn create_staff_account(
        &self,
        request: Request<CreateStaffAccountRequest>,
    ) -> Result<Response<CreateStaffAccountReply>, Status> {
        let body = request.get_ref();
        let target_username = body.username.trim().to_string();
        let role_str = body.role.trim().to_string();
        let target_role: crate::store::StaffRole = match role_str.parse() {
            Ok(r) => r,
            Err(_) => {
                return Err(Status::invalid_argument(format!(
                    "invalid role: {role_str}"
                )));
            }
        };
        let session = self
            .authenticate_admin(&request, "create_staff_account", Some(&target_username))
            .await?;

        let temporary_password = body.temporary_password.clone();
        if temporary_password.len() < 8 {
            let _ = self
                .store
                .record_activity(
                    session.username.clone(),
                    "create_staff_account".into(),
                    "rejected".into(),
                    format!("failed to create staff account '{target_username}': password must contain at least 8 characters"),
                )
                .await;
            return Err(Status::invalid_argument(
                "temporary password must contain at least 8 characters",
            ));
        }

        match self
            .store
            .create_staff_account(target_username.clone(), target_role, temporary_password)
            .await
        {
            Ok(account) => {
                let _ = self
                    .store
                    .record_activity(
                        session.username.clone(),
                        "create_staff_account".into(),
                        "success".into(),
                        format!(
                            "created staff account '{target_username}' with role '{}'",
                            target_role.as_str()
                        ),
                    )
                    .await;
                Ok(Response::new(CreateStaffAccountReply {
                    account: Some(StaffAccountEntry {
                        username: account.username,
                        role: account.role.as_str().into(),
                        must_change_password: account.must_change_password,
                        created_at_unix_ms: account.created_at_unix_ms,
                        updated_at_unix_ms: account.updated_at_unix_ms,
                    }),
                }))
            }
            Err(e) => {
                let err_msg = e.to_string();
                let _ = self
                    .store
                    .record_activity(
                        session.username.clone(),
                        "create_staff_account".into(),
                        "rejected".into(),
                        format!("failed to create staff account '{target_username}': {err_msg}"),
                    )
                    .await;
                if err_msg.contains("already exists") {
                    Err(Status::already_exists(err_msg))
                } else {
                    Err(Status::invalid_argument(err_msg))
                }
            }
        }
    }

    async fn change_staff_role(
        &self,
        request: Request<ChangeStaffRoleRequest>,
    ) -> Result<Response<ChangeStaffRoleReply>, Status> {
        let body = request.get_ref();
        let target_username = body.username.trim().to_string();
        let new_role_str = body.new_role.trim().to_string();
        let new_role: crate::store::StaffRole = match new_role_str.parse() {
            Ok(r) => r,
            Err(_) => {
                return Err(Status::invalid_argument(format!(
                    "invalid role: {new_role_str}"
                )));
            }
        };
        let session = self
            .authenticate_admin(&request, "change_staff_role", Some(&target_username))
            .await?;

        match self
            .store
            .change_staff_role(&target_username, new_role)
            .await
        {
            Ok(account) => {
                let _ = self
                    .store
                    .record_activity(
                        session.username.clone(),
                        "change_staff_role".into(),
                        "success".into(),
                        format!(
                            "changed role of '{target_username}' to '{}'",
                            new_role.as_str()
                        ),
                    )
                    .await;
                Ok(Response::new(ChangeStaffRoleReply {
                    username: account.username,
                    role: account.role.as_str().into(),
                    updated_at_unix_ms: account.updated_at_unix_ms,
                }))
            }
            Err(e) => {
                let err_msg = e.to_string();
                let _ = self
                    .store
                    .record_activity(
                        session.username.clone(),
                        "change_staff_role".into(),
                        "rejected".into(),
                        format!("failed to change role of '{target_username}': {err_msg}"),
                    )
                    .await;
                if err_msg.contains("last active admin") {
                    Err(Status::failed_precondition(err_msg))
                } else if err_msg.contains("not found") {
                    Err(Status::not_found(err_msg))
                } else {
                    Err(Status::invalid_argument(err_msg))
                }
            }
        }
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
