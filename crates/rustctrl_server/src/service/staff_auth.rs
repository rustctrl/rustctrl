//! Staff authentication, administration, and inventory curation gRPC service handlers.
//!
//! # Domain Scope
//! This module implements the staff-facing `StaffAuth` gRPC service. It coordinates staff
//! identity authentication (`login`, `logout`, `get_staff_status`), password lifecycle
//! (`change_own_password`, `replace_temporary_password`, `reset_staff_password`), staff account
//! administration (`list_staff_accounts`, `create_staff_account`, `change_staff_role`,
//! `deactivate_staff_account`), fleet inventory curation (`list_fleet_devices`, `update_fleet_device`,
//! `clean_offline_device`, `replace_fleet_device`, `block_device`, `unblock_device`), target management
//! (`create_target`, `update_target`, `remove_target`), and installation authorization management
//! (`prepare_installation_artifact`, `list_installation_authorizations`, `revoke_installation_authorization`).
//!
//! # Canonical Terms (from [CONTEXT.md](../../../../CONTEXT.md))
//! - **Staff Account**: An individual IT staff member's identity in RustCtrl, with an Admin or
//!   Operator role. It is distinct from a component's connection identity. Avoid: shared account,
//!   Controller certificate as staff identity.
//! - **Staff Session**: A revocable period of access to RustCtrl through the Controller under a
//!   Staff Account. It is distinct from a Remote Session with a Device. Avoid: Remote Session,
//!   Agent connection.
//! - **Admin**: A staff member allowed to manage accounts, Devices, configuration, and Management
//!   Tasks, as well as open Remote Sessions. Avoid: shared account.
//! - **Operator**: A staff member allowed to monitor the Fleet and open Remote Sessions using an
//!   individual account. Avoid: endpoint user.
//! - **Device**: A Windows computer or Android TV recorded in the fleet inventory. Its identity
//!   remains the same when its network address changes. Avoid: IP address as device identity.
//! - **Fleet**: All Devices managed by the IT team through RustCtrl. Avoid: IP list.
//! - **Fleet Inventory**: RustCtrl's operational list of Devices and the information needed to
//!   identify and access them. Avoid: asset register, external inventory mirror.
//! - **Inventory Cleanup**: An Admin's removal of an offline Device entry from the Fleet Inventory
//!   without revoking its Agent's access. Avoid: Device Block, uninstall.
//! - **Device Block**: An Admin-imposed restriction on a Device identity that denies operational
//!   Agent access while keeping the Device visible in the Fleet Inventory. Avoid: Inventory Cleanup.
//! - **Installation Authorization**: An Admin-granted permission for new Agents to join a specific
//!   RustCtrl Server through an Agent Installation Package. Avoid: Device credentials, Staff Session.
//! - **Remote Session**: A period during which one staff member can view and control a Device's
//!   screen. Distinct from a Staff Session.
//!
//! # Invariants and Architectural Guarantees
//! - **Role-Based Authorization (ADR 0003, ADR 0005)**: Staff operations strictly enforce
//!   role permissions (Admin vs Operator) and valid unrevoked sessions.
//! - **Last Active Admin Protection (ADR 0003)**: Deactivation or role demotion that would leave zero
//!   active Admins is rejected with precondition failure.
//! - **Mandatory Password Change Gate**: Accounts marked with temporary passwords must replace them
//!   before invoking any protected administrative operations.
//! - **Separate Inventory Cleanup From Device Blocking (ADR 0006)**: Cleanup removes offline inventory
//!   entries without blocking or revoking credentials; blocking denies agent communication while
//!   retaining the visible inventory record.
//! - **Device Replacement Continuity (ADR 0006)**: Replaces an inventory entry after identity loss,
//!   transferring metadata, preserving blocks, and recording audit attribution.
//! - **Installation Authorization Lifecycle (ADR 0004, ADR 0007)**: Admins prepare scoped installation
//!   authorizations and can revoke them without invalidating already enrolled devices.
//!
//! # Forbidden Anti-Patterns
//! - Never allow deactivation or demotion of the last active Admin.
//! - Never treat an inventory cleanup as a device block or credential revocation.
//! - Never conflate a Staff Session with a Remote Session or Agent connection.
//! - Never use an IP address as a device's durable identity.
//!
//! # Applicable Architecture Decision Records (ADRs)
//! - [ADR 0001: Centralize Fleet Coordination](../../../../docs/adr/0001-centralize-fleet-coordination.md)
//! - [ADR 0003: Bootstrap Staff Administration Locally](../../../../docs/adr/0003-bootstrap-staff-administration-locally.md)
//! - [ADR 0004: Enroll Agents Through Trusted Installation](../../../../docs/adr/0004-enroll-agents-through-trusted-installation.md)
//! - [ADR 0005: Keep Remembered Staff Access Revocable](../../../../docs/adr/0005-keep-remembered-staff-access-revocable.md)
//! - [ADR 0006: Separate Inventory Cleanup From Device Blocking](../../../../docs/adr/0006-separate-inventory-cleanup-from-device-blocking.md)
//! - [ADR 0007: Provision Agent Credentials via Scoped Issuing Authority](../../../../docs/adr/0007-provision-agent-credentials-via-scoped-issuing-authority.md)

use super::{database_error, hash_secret};
use crate::{
    issuer::AgentIssuer,
    service::middleware,
    store::{DeviceRecord, DeviceStore, RevokeAuthorizationOutcome, TargetRecord},
};
use ring::rand::SecureRandom;
use rustctrl_protocol::auth::{
    BlockDeviceReply, BlockDeviceRequest, ChangeOwnPasswordReply, ChangeOwnPasswordRequest,
    ChangeStaffRoleReply, ChangeStaffRoleRequest, CleanOfflineDeviceReply,
    CleanOfflineDeviceRequest, CreateStaffAccountReply, CreateStaffAccountRequest,
    CreateTargetReply, CreateTargetRequest, DeactivateStaffAccountReply,
    DeactivateStaffAccountRequest, FleetDeviceEntry, InstallationAuthorizationEntry,
    ListFleetDevicesReply, ListFleetDevicesRequest, ListInstallationAuthorizationsReply,
    ListInstallationAuthorizationsRequest, ListStaffAccountsReply, ListStaffAccountsRequest,
    LoginReply, LoginRequest, LogoutReply, LogoutRequest, PrepareInstallationArtifactReply,
    PrepareInstallationArtifactRequest, RemoveTargetReply, RemoveTargetRequest,
    ReplaceFleetDeviceReply, ReplaceFleetDeviceRequest, ReplaceTemporaryPasswordReply,
    ReplaceTemporaryPasswordRequest, ResetStaffPasswordReply, ResetStaffPasswordRequest,
    RevokeInstallationAuthorizationReply, RevokeInstallationAuthorizationRequest,
    StaffAccountEntry, StaffStatusReply, StaffStatusRequest, UnblockDeviceReply,
    UnblockDeviceRequest, UpdateFleetDeviceReply, UpdateFleetDeviceRequest, UpdateTargetReply,
    UpdateTargetRequest, staff_auth_server::StaffAuth,
};
use std::sync::Arc;
use tonic::{Request, Response, Status};

fn generate_secret() -> Result<String, Status> {
    let mut bytes = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| Status::internal("failed to generate random secret"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
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

/// Service implementing the gRPC `StaffAuth` protocol for staff administration and fleet management.
pub struct StaffAuthService {
    store: DeviceStore,
    remembered_lifetime_secs: u64,
    offline_after_secs: u64,
    issuer: Option<Arc<AgentIssuer>>,
}

impl StaffAuthService {
    /// Creates a new `StaffAuthService` instance without an agent certificate issuer.
    pub fn new(store: DeviceStore, remembered_lifetime_secs: u64, offline_after_secs: u64) -> Self {
        Self {
            store,
            remembered_lifetime_secs,
            offline_after_secs,
            issuer: None,
        }
    }

    /// Creates a new `StaffAuthService` instance with an agent certificate issuer for preparing installation packages.
    pub fn with_issuer(
        store: DeviceStore,
        remembered_lifetime_secs: u64,
        offline_after_secs: u64,
        issuer: Arc<AgentIssuer>,
    ) -> Self {
        Self {
            store,
            remembered_lifetime_secs,
            offline_after_secs,
            issuer: Some(issuer),
        }
    }

    async fn authenticate_request<T>(
        &self,
        request: &Request<T>,
    ) -> Result<crate::store::StaffSession, Status> {
        middleware::authenticate_request(&self.store, request).await
    }

    async fn authenticate_staff<T>(
        &self,
        request: &Request<T>,
    ) -> Result<crate::store::StaffSession, Status> {
        middleware::authenticate_staff(&self.store, request).await
    }

    async fn authenticate_admin<T>(
        &self,
        request: &Request<T>,
        action: &str,
        target: Option<&str>,
    ) -> Result<crate::store::StaffSession, Status> {
        middleware::authenticate_admin(&self.store, request, action, target).await
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

    async fn replace_fleet_device(
        &self,
        request: Request<ReplaceFleetDeviceRequest>,
    ) -> Result<Response<ReplaceFleetDeviceReply>, Status> {
        let body = request.get_ref();
        let prior_device_id = body.prior_device_id.trim().to_string();
        let replacement_device_id = body.replacement_device_id.trim().to_string();
        let target_label = format!("{prior_device_id} -> {replacement_device_id}");
        let session = self
            .authenticate_admin(&request, "replace_fleet_device", Some(&target_label))
            .await?;

        match self
            .store
            .replace_device(&prior_device_id, &replacement_device_id, &session.username)
            .await
        {
            Ok(reconciled) => {
                let _ = self
                    .store
                    .record_activity(
                        session.username.clone(),
                        "replace_fleet_device".into(),
                        "success".into(),
                        format!(
                            "replaced prior device '{prior_device_id}' with replacement device '{replacement_device_id}'"
                        ),
                    )
                    .await;
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as i64)
                    .unwrap_or_default();
                let window_ms =
                    i64::try_from(self.offline_after_secs.saturating_mul(1000)).unwrap_or(i64::MAX);
                Ok(Response::new(ReplaceFleetDeviceReply {
                    device: Some(to_fleet_device_entry(reconciled, now_ms, window_ms)),
                    prior_device_id,
                    replacement_device_id,
                }))
            }
            Err(e) => {
                let err_msg = e.to_string();
                let _ = self
                    .store
                    .record_activity(
                        session.username.clone(),
                        "replace_fleet_device".into(),
                        "rejected".into(),
                        format!(
                            "failed to replace prior device '{prior_device_id}' with replacement device '{replacement_device_id}': {err_msg}"
                        ),
                    )
                    .await;
                if err_msg.contains("not found") {
                    Err(Status::not_found(err_msg))
                } else if err_msg.contains("already been replaced")
                    || err_msg.contains("connection target")
                {
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

    async fn prepare_installation_artifact(
        &self,
        request: Request<PrepareInstallationArtifactRequest>,
    ) -> Result<Response<PrepareInstallationArtifactReply>, Status> {
        let session = self
            .authenticate_admin(&request, "prepare_installation_artifact", None)
            .await?;

        let issuer = self
            .issuer
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("agent issuer not configured"))?;

        let authorization_id = uuid::Uuid::new_v4().to_string();
        let installation_secret = generate_secret()?;
        let secret_hash = hash_secret(&installation_secret);

        let auth = self
            .store
            .create_installation_authorization(
                authorization_id.clone(),
                secret_hash,
                session.username.clone(),
            )
            .await
            .map_err(database_error)?;

        let _ = self
            .store
            .record_activity(
                session.username,
                "create_installation_authorization".into(),
                "success".into(),
                format!("created installation authorization '{authorization_id}'"),
            )
            .await;

        Ok(Response::new(PrepareInstallationArtifactReply {
            authorization_id,
            server_endpoint: issuer.server_endpoint.clone(),
            domain_name: issuer.domain_name.clone(),
            ca_certificate: issuer.ca_cert_pem.clone(),
            enrollment_certificate: issuer.enrollment_cert_pem.clone(),
            enrollment_private_key: issuer.enrollment_key_pem.clone(),
            installation_secret,
            created_at_unix_ms: auth.created_at_unix_ms,
        }))
    }

    async fn list_installation_authorizations(
        &self,
        request: Request<ListInstallationAuthorizationsRequest>,
    ) -> Result<Response<ListInstallationAuthorizationsReply>, Status> {
        let _session = self
            .authenticate_admin(&request, "list_installation_authorizations", None)
            .await?;

        let auths = self
            .store
            .list_installation_authorizations()
            .await
            .map_err(database_error)?;

        let entries = auths
            .into_iter()
            .map(|a| InstallationAuthorizationEntry {
                authorization_id: a.authorization_id,
                created_at_unix_ms: a.created_at_unix_ms,
                created_by: a.created_by,
                revoked_at_unix_ms: a.revoked_at_unix_ms,
            })
            .collect();

        Ok(Response::new(ListInstallationAuthorizationsReply {
            authorizations: entries,
        }))
    }

    async fn revoke_installation_authorization(
        &self,
        request: Request<RevokeInstallationAuthorizationRequest>,
    ) -> Result<Response<RevokeInstallationAuthorizationReply>, Status> {
        let body = request.get_ref();
        let authorization_id = body.authorization_id.trim().to_string();
        if authorization_id.is_empty() {
            return Err(Status::invalid_argument("authorization_id is required"));
        }

        let session = self
            .authenticate_admin(
                &request,
                "revoke_installation_authorization",
                Some(&authorization_id),
            )
            .await?;

        let outcome = self
            .store
            .revoke_installation_authorization(&authorization_id)
            .await
            .map_err(database_error)?;

        match outcome {
            RevokeAuthorizationOutcome::NotFound => {
                let _ = self
                    .store
                    .record_activity(
                        session.username.clone(),
                        "revoke_installation_authorization".into(),
                        "rejected".into(),
                        format!(
                            "failed to revoke installation authorization '{authorization_id}': not found"
                        ),
                    )
                    .await;
                Err(Status::not_found(format!(
                    "installation authorization '{authorization_id}' not found"
                )))
            }
            RevokeAuthorizationOutcome::AlreadyRevoked => {
                let _ = self
                    .store
                    .record_activity(
                        session.username.clone(),
                        "revoke_installation_authorization".into(),
                        "rejected".into(),
                        format!(
                            "failed to revoke installation authorization '{authorization_id}': already revoked"
                        ),
                    )
                    .await;
                Err(Status::failed_precondition(format!(
                    "installation authorization '{authorization_id}' is already revoked"
                )))
            }
            RevokeAuthorizationOutcome::Revoked(record) => {
                let _ = self
                    .store
                    .record_activity(
                        session.username.clone(),
                        "revoke_installation_authorization".into(),
                        "success".into(),
                        format!("revoked installation authorization '{authorization_id}'"),
                    )
                    .await;

                Ok(Response::new(RevokeInstallationAuthorizationReply {
                    success: true,
                    authorization_id: record.authorization_id,
                    revoked_at_unix_ms: record.revoked_at_unix_ms.unwrap_or(0),
                }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn create_test_store() -> DeviceStore {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        DeviceStore::open(&db_path).unwrap()
    }

    #[tokio::test]
    async fn login_rejects_empty_credentials() {
        let store = create_test_store().await;
        let service = StaffAuthService::new(store, 3600, 300);

        let err = service
            .login(Request::new(LoginRequest {
                username: "".into(),
                password: "password123".into(),
                remember: false,
            }))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(err.message(), "username and password are required");

        let err2 = service
            .login(Request::new(LoginRequest {
                username: "admin".into(),
                password: "".into(),
                remember: false,
            }))
            .await
            .unwrap_err();

        assert_eq!(err2.code(), tonic::Code::InvalidArgument);
        assert_eq!(err2.message(), "username and password are required");
    }

    #[tokio::test]
    async fn login_rejects_invalid_credentials() {
        let store = create_test_store().await;
        let service = StaffAuthService::new(store, 3600, 300);

        let err = service
            .login(Request::new(LoginRequest {
                username: "nonexistent".into(),
                password: "password123".into(),
                remember: false,
            }))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert_eq!(err.message(), "invalid username or password");
    }

    #[test]
    fn target_to_fleet_device_entry_maps_fields_correctly() {
        let target = TargetRecord {
            target_id: "android-tv-1".into(),
            display_name: "Meeting Room TV".into(),
            configured_address: "192.168.1.100:5555".into(),
            target_type: "android_tv".into(),
            location: Some("Floor 2".into()),
            created_at_unix_ms: 123456789,
            updated_at_unix_ms: 123456789,
        };

        let entry = target_to_fleet_device_entry(target);
        assert_eq!(entry.device_id, "android-tv-1");
        assert_eq!(entry.display_name, "Meeting Room TV");
        assert_eq!(entry.device_type, "android_tv");
        assert_eq!(entry.configured_address, Some("192.168.1.100:5555".into()));
        assert_eq!(entry.location, Some("Floor 2".into()));
        assert_eq!(entry.status, "unverified");
        assert!(!entry.online);
        assert!(!entry.blocked);
    }
}
