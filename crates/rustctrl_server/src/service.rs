use crate::{
    config::ServerConfig,
    store::{DeviceRecord, DeviceStore, TargetRecord},
};
use anyhow::{Context, Result};
use rustctrl_core::DeviceId;
use rustctrl_protocol::auth::{
    BlockDeviceReply, BlockDeviceRequest, ChangeOwnPasswordReply, ChangeOwnPasswordRequest,
    ChangeStaffRoleReply, ChangeStaffRoleRequest, CleanOfflineDeviceReply,
    CleanOfflineDeviceRequest, CreateStaffAccountReply, CreateStaffAccountRequest,
    CreateTargetReply, CreateTargetRequest, DeactivateStaffAccountReply,
    DeactivateStaffAccountRequest, FleetDeviceEntry, ListFleetDevicesReply,
    ListFleetDevicesRequest, ListStaffAccountsReply, ListStaffAccountsRequest, LoginReply,
    LoginRequest, LogoutReply, LogoutRequest, RemoveTargetReply, RemoveTargetRequest,
    ReplaceTemporaryPasswordReply, ReplaceTemporaryPasswordRequest, ResetStaffPasswordReply,
    ResetStaffPasswordRequest, StaffAccountEntry, StaffStatusReply, StaffStatusRequest,
    UnblockDeviceReply, UnblockDeviceRequest, UpdateFleetDeviceReply, UpdateFleetDeviceRequest,
    UpdateTargetReply, UpdateTargetRequest,
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

        if self
            .store
            .is_device_blocked(&id.to_string())
            .await
            .map_err(database_error)?
        {
            return Err(Status::permission_denied("device is blocked"));
        }

        let remote_address = request.remote_addr().map(|addr| addr.to_string());
        let body = request.into_inner();
        let timestamp = self
            .store
            .heartbeat(id, body.name, body.agent_version, remote_address)
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
    remembered_lifetime_secs: u64,
    offline_after_secs: u64,
}

impl StaffAuthService {
    pub fn new(store: DeviceStore, remembered_lifetime_secs: u64, offline_after_secs: u64) -> Self {
        Self {
            store,
            remembered_lifetime_secs,
            offline_after_secs,
        }
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

    async fn authenticate_staff<T>(
        &self,
        request: &Request<T>,
    ) -> Result<crate::store::StaffSession, Status> {
        let session = self.authenticate_request(request).await?;
        if session.must_change_password {
            return Err(Status::permission_denied(
                "password change required before accessing protected operations",
            ));
        }
        Ok(session)
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
        let expires_at_unix_ms = if body.remember {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or_default();
            let lifetime_ms = i64::try_from(self.remembered_lifetime_secs.saturating_mul(1000))
                .unwrap_or(i64::MAX);
            Some(now_ms.saturating_add(lifetime_ms))
        } else {
            None
        };
        let session = self
            .store
            .create_login_session(
                session_id,
                account.username.clone(),
                account.password_hash.clone(),
                expires_at_unix_ms,
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
                format!(
                    "staff session started for role {}{}",
                    session.role.as_str(),
                    if body.remember { " (remembered)" } else { "" }
                ),
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
                        active: account.active,
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

    async fn deactivate_staff_account(
        &self,
        request: Request<DeactivateStaffAccountRequest>,
    ) -> Result<Response<DeactivateStaffAccountReply>, Status> {
        let body = request.get_ref();
        let target_username = body.username.trim().to_string();
        let session = self
            .authenticate_admin(&request, "deactivate_staff_account", Some(&target_username))
            .await?;

        match self.store.deactivate_staff_account(&target_username).await {
            Ok(account) => {
                let _ = self
                    .store
                    .record_activity(
                        session.username.clone(),
                        "deactivate_staff_account".into(),
                        "success".into(),
                        format!(
                            "deactivated staff account '{target_username}' and revoked its staff sessions"
                        ),
                    )
                    .await;
                Ok(Response::new(DeactivateStaffAccountReply {
                    account: Some(StaffAccountEntry {
                        username: account.username,
                        role: account.role.as_str().into(),
                        must_change_password: account.must_change_password,
                        created_at_unix_ms: account.created_at_unix_ms,
                        updated_at_unix_ms: account.updated_at_unix_ms,
                        active: account.active,
                    }),
                }))
            }
            Err(e) => {
                let err_msg = e.to_string();
                let _ = self
                    .store
                    .record_activity(
                        session.username.clone(),
                        "deactivate_staff_account".into(),
                        "rejected".into(),
                        format!(
                            "failed to deactivate staff account '{target_username}': {err_msg}"
                        ),
                    )
                    .await;
                if err_msg.contains("not found") {
                    Err(Status::not_found(err_msg))
                } else if err_msg.contains("already deactivated")
                    || err_msg.contains("last active admin")
                {
                    Err(Status::failed_precondition(err_msg))
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
        let session = self.authenticate_staff(&request).await?;

        let count = self.store.count().await.map_err(database_error)?;
        Ok(Response::new(StaffStatusReply {
            username: session.username,
            role: session.role.as_str().into(),
            authenticated: true,
            registered_devices: count,
            server_version: env!("CARGO_PKG_VERSION").into(),
        }))
    }

    async fn list_fleet_devices(
        &self,
        request: Request<ListFleetDevicesRequest>,
    ) -> Result<Response<ListFleetDevicesReply>, Status> {
        // Both roles read the complete Fleet Inventory; only a valid,
        // non-temporary Staff Session is required.
        self.authenticate_staff(&request).await?;

        let devices = self.store.list_devices().await.map_err(database_error)?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or_default();
        let window_ms =
            i64::try_from(self.offline_after_secs.saturating_mul(1000)).unwrap_or(i64::MAX);
        let entries = devices
            .into_iter()
            .map(|device| to_fleet_device_entry(device, now_ms, window_ms))
            .collect();
        Ok(Response::new(ListFleetDevicesReply { devices: entries }))
    }

    async fn create_target(
        &self,
        request: Request<CreateTargetRequest>,
    ) -> Result<Response<CreateTargetReply>, Status> {
        let session = self
            .authenticate_admin(&request, "create_target", None)
            .await?;
        let body = request.into_inner();
        let display_name = body.display_name.trim();
        let address = body.address.trim();
        let target_type = body.target_type.as_deref();
        let location = body.location.as_deref();

        match self
            .store
            .create_target(display_name, address, target_type, location)
            .await
        {
            Ok(target) => {
                let _ = self
                    .store
                    .record_activity(
                        session.username.clone(),
                        "create_target".into(),
                        "success".into(),
                        format!(
                            "created target '{}' (name='{}', address='{}', type='{}')",
                            target.target_id,
                            target.display_name,
                            target.configured_address,
                            target.target_type
                        ),
                    )
                    .await;
                Ok(Response::new(CreateTargetReply {
                    target: Some(target_to_fleet_device_entry(target)),
                }))
            }
            Err(e) => {
                let err_msg = e.to_string();
                let _ = self
                    .store
                    .record_activity(
                        session.username.clone(),
                        "create_target".into(),
                        "rejected".into(),
                        format!("failed to create target: {err_msg}"),
                    )
                    .await;
                Err(Status::invalid_argument(err_msg))
            }
        }
    }

    async fn update_target(
        &self,
        request: Request<UpdateTargetRequest>,
    ) -> Result<Response<UpdateTargetReply>, Status> {
        let body = request.get_ref();
        let target_id = body.target_id.trim().to_string();
        let session = self
            .authenticate_admin(&request, "update_target", Some(&target_id))
            .await?;
        let body = request.into_inner();
        let display_name = body.display_name.trim();
        let address = body.address.trim();
        let location = body.location.as_deref();

        match self
            .store
            .update_target(&target_id, display_name, address, location)
            .await
        {
            Ok(target) => {
                let location_desc = match &target.location {
                    Some(loc) => format!("'{loc}'"),
                    None => "none".into(),
                };
                let _ = self
                    .store
                    .record_activity(
                        session.username.clone(),
                        "update_target".into(),
                        "success".into(),
                        format!(
                            "updated target '{target_id}' (name='{}', address='{}', location={location_desc})",
                            target.display_name, target.configured_address
                        ),
                    )
                    .await;
                Ok(Response::new(UpdateTargetReply {
                    target: Some(target_to_fleet_device_entry(target)),
                }))
            }
            Err(e) => {
                let err_msg = e.to_string();
                let _ = self
                    .store
                    .record_activity(
                        session.username.clone(),
                        "update_target".into(),
                        "rejected".into(),
                        format!("failed to update target '{target_id}': {err_msg}"),
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

    async fn remove_target(
        &self,
        request: Request<RemoveTargetRequest>,
    ) -> Result<Response<RemoveTargetReply>, Status> {
        let body = request.get_ref();
        let target_id = body.target_id.trim().to_string();
        let session = self
            .authenticate_admin(&request, "remove_target", Some(&target_id))
            .await?;

        match self.store.remove_target(&target_id).await {
            Ok(removed_id) => {
                let _ = self
                    .store
                    .record_activity(
                        session.username.clone(),
                        "remove_target".into(),
                        "success".into(),
                        format!("removed target '{target_id}'"),
                    )
                    .await;
                Ok(Response::new(RemoveTargetReply {
                    success: true,
                    target_id: removed_id,
                }))
            }
            Err(e) => {
                let err_msg = e.to_string();
                let _ = self
                    .store
                    .record_activity(
                        session.username.clone(),
                        "remove_target".into(),
                        "rejected".into(),
                        format!("failed to remove target '{target_id}': {err_msg}"),
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

    async fn update_fleet_device(
        &self,
        request: Request<UpdateFleetDeviceRequest>,
    ) -> Result<Response<UpdateFleetDeviceReply>, Status> {
        let body = request.get_ref();
        let target_device_id = body.device_id.trim().to_string();
        let session = self
            .authenticate_admin(&request, "update_fleet_device", Some(&target_device_id))
            .await?;

        let display_name = body.display_name.trim();
        let location = body.location.as_deref();

        match self
            .store
            .update_device_metadata(&target_device_id, display_name, location)
            .await
        {
            Ok(updated) => {
                let location_desc = match &updated.location {
                    Some(loc) => format!("'{loc}'"),
                    None => "none".into(),
                };
                let _ = self
                    .store
                    .record_activity(
                        session.username.clone(),
                        "update_fleet_device".into(),
                        "success".into(),
                        format!(
                            "updated device '{target_device_id}' display name to '{}' and location to {location_desc}",
                            updated.name
                        ),
                    )
                    .await;
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as i64)
                    .unwrap_or_default();
                let window_ms =
                    i64::try_from(self.offline_after_secs.saturating_mul(1000)).unwrap_or(i64::MAX);
                Ok(Response::new(UpdateFleetDeviceReply {
                    device: Some(to_fleet_device_entry(updated, now_ms, window_ms)),
                }))
            }
            Err(e) => {
                let err_msg = e.to_string();
                let _ = self
                    .store
                    .record_activity(
                        session.username.clone(),
                        "update_fleet_device".into(),
                        "rejected".into(),
                        format!("failed to update device '{target_device_id}' metadata: {err_msg}"),
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

    async fn block_device(
        &self,
        request: Request<BlockDeviceRequest>,
    ) -> Result<Response<BlockDeviceReply>, Status> {
        let body = request.get_ref();
        let target_device_id = body.device_id.trim().to_string();
        let session = self
            .authenticate_admin(&request, "block_device", Some(&target_device_id))
            .await?;

        match self
            .store
            .block_device(&target_device_id, &session.username)
            .await
        {
            Ok(blocked) => {
                let _ = self
                    .store
                    .record_activity(
                        session.username.clone(),
                        "block_device".into(),
                        "success".into(),
                        format!("blocked device '{target_device_id}'"),
                    )
                    .await;
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as i64)
                    .unwrap_or_default();
                let window_ms =
                    i64::try_from(self.offline_after_secs.saturating_mul(1000)).unwrap_or(i64::MAX);
                Ok(Response::new(BlockDeviceReply {
                    device: Some(to_fleet_device_entry(blocked, now_ms, window_ms)),
                }))
            }
            Err(e) => {
                let err_msg = e.to_string();
                let _ = self
                    .store
                    .record_activity(
                        session.username.clone(),
                        "block_device".into(),
                        "rejected".into(),
                        format!("failed to block device '{target_device_id}': {err_msg}"),
                    )
                    .await;
                if err_msg.contains("not found") {
                    Err(Status::not_found(err_msg))
                } else if err_msg.contains("already blocked") {
                    Err(Status::failed_precondition(err_msg))
                } else {
                    Err(Status::invalid_argument(err_msg))
                }
            }
        }
    }

    async fn unblock_device(
        &self,
        request: Request<UnblockDeviceRequest>,
    ) -> Result<Response<UnblockDeviceReply>, Status> {
        let body = request.get_ref();
        let target_device_id = body.device_id.trim().to_string();
        let session = self
            .authenticate_admin(&request, "unblock_device", Some(&target_device_id))
            .await?;

        match self.store.unblock_device(&target_device_id).await {
            Ok(unblocked) => {
                let _ = self
                    .store
                    .record_activity(
                        session.username.clone(),
                        "unblock_device".into(),
                        "success".into(),
                        format!("unblocked device '{target_device_id}'"),
                    )
                    .await;
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as i64)
                    .unwrap_or_default();
                let window_ms =
                    i64::try_from(self.offline_after_secs.saturating_mul(1000)).unwrap_or(i64::MAX);
                Ok(Response::new(UnblockDeviceReply {
                    device: Some(to_fleet_device_entry(unblocked, now_ms, window_ms)),
                }))
            }
            Err(e) => {
                let err_msg = e.to_string();
                let _ = self
                    .store
                    .record_activity(
                        session.username.clone(),
                        "unblock_device".into(),
                        "rejected".into(),
                        format!("failed to unblock device '{target_device_id}': {err_msg}"),
                    )
                    .await;
                if err_msg.contains("not found") {
                    Err(Status::not_found(err_msg))
                } else if err_msg.contains("not blocked") {
                    Err(Status::failed_precondition(err_msg))
                } else {
                    Err(Status::invalid_argument(err_msg))
                }
            }
        }
    }

    async fn clean_offline_device(
        &self,
        request: Request<CleanOfflineDeviceRequest>,
    ) -> Result<Response<CleanOfflineDeviceReply>, Status> {
        let body = request.get_ref();
        let target_device_id = body.device_id.trim().to_string();
        let session = self
            .authenticate_admin(&request, "clean_offline_device", Some(&target_device_id))
            .await?;

        match self
            .store
            .clean_offline_device(&target_device_id, self.offline_after_secs)
            .await
        {
            Ok(cleaned_id) => {
                let _ = self
                    .store
                    .record_activity(
                        session.username.clone(),
                        "clean_offline_device".into(),
                        "success".into(),
                        format!("cleaned offline device '{target_device_id}'"),
                    )
                    .await;
                Ok(Response::new(CleanOfflineDeviceReply {
                    success: true,
                    device_id: cleaned_id,
                }))
            }
            Err(e) => {
                let err_msg = e.to_string();
                let _ = self
                    .store
                    .record_activity(
                        session.username.clone(),
                        "clean_offline_device".into(),
                        "rejected".into(),
                        format!("failed to clean offline device '{target_device_id}': {err_msg}"),
                    )
                    .await;
                if err_msg.contains("not found") {
                    Err(Status::not_found(err_msg))
                } else if err_msg.contains("blocked") || err_msg.contains("online") {
                    Err(Status::failed_precondition(err_msg))
                } else {
                    Err(Status::invalid_argument(err_msg))
                }
            }
        }
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
                active: acc.active,
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
                        active: account.active,
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

fn to_fleet_device_entry(device: DeviceRecord, now_ms: i64, window_ms: i64) -> FleetDeviceEntry {
    let is_windows = device.device_type == "windows";
    let online = if is_windows && !device.blocked {
        now_ms.saturating_sub(device.last_seen_unix_ms) <= window_ms
    } else {
        false
    };
    let status = if device.blocked {
        "blocked".into()
    } else if !is_windows {
        "unverified".into()
    } else if online {
        "online".into()
    } else {
        "offline".into()
    };
    FleetDeviceEntry {
        device_id: device.device_id,
        display_name: device.name,
        device_type: device.device_type,
        last_address: device.last_address.unwrap_or_default(),
        online,
        last_seen_unix_ms: device.last_seen_unix_ms,
        location: device.location,
        configured_address: device.configured_address,
        status,
        blocked: device.blocked,
    }
}

fn target_to_fleet_device_entry(target: TargetRecord) -> FleetDeviceEntry {
    FleetDeviceEntry {
        device_id: target.target_id,
        display_name: target.display_name,
        device_type: target.target_type,
        last_address: String::new(),
        online: false,
        last_seen_unix_ms: 0,
        location: target.location,
        configured_address: Some(target.configured_address),
        status: "unverified".into(),
        blocked: false,
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
        .add_service(StaffAuthServer::new(StaffAuthService::new(
            store,
            config.staff_session.remembered_lifetime_secs,
            config.fleet.offline_after_secs,
        )))
        .serve_with_incoming_shutdown(
            tokio_stream::wrappers::TcpListenerStream::new(listener),
            shutdown,
        )
        .await?;
    Ok(())
}
