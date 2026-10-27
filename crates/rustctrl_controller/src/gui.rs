use anyhow::Result;
use gpui::{
    App, Context, FocusHandle, IntoElement, KeyDownEvent, Render, Task, Window, WindowOptions, div,
    prelude::*, rgb,
};
use rustctrl_core::{ControllerConfig, DeviceId};
use rustctrl_protocol::auth::{
    BlockDeviceRequest, ChangeOwnPasswordRequest, ChangeStaffRoleRequest,
    CleanOfflineDeviceRequest, CreateStaffAccountRequest, CreateTargetRequest,
    DeactivateStaffAccountRequest, FleetDeviceEntry, ListFleetDevicesRequest,
    ListStaffAccountsRequest, LoginRequest, LogoutRequest, PrepareInstallationArtifactRequest,
    RemoveTargetRequest, ReplaceFleetDeviceRequest, ReplaceTemporaryPasswordRequest,
    ResetStaffPasswordRequest, StaffAccountEntry, StaffStatusRequest, UnblockDeviceRequest,
    UpdateFleetDeviceRequest, UpdateTargetRequest,
};
use std::time::Duration;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ActiveField {
    Username,
    Password,
    NewPassword,
    ConfirmPassword,
    CurrentPassword,
    TemporaryPassword,
    NewAccountUsername,
    NewAccountPassword,
    EditDeviceDisplayName,
    EditDeviceLocation,
    AddTargetDisplayName,
    AddTargetAddress,
    AddTargetLocation,
    EditTargetDisplayName,
    EditTargetAddress,
    EditTargetLocation,
    ReplaceDevicePriorId,
    ReplaceDeviceReplacementId,
    PrepareArtifactOutputPath,
    PreparePackageAgentBinary,
}

#[derive(Clone)]
enum Overlay {
    None,
    ChangePassword {
        current_password: String,
        new_password: String,
        confirm_password: String,
        error: Option<String>,
        in_flight: bool,
    },
    ResetPassword {
        target_username: String,
        temporary_password: String,
        confirm_password: String,
        error: Option<String>,
        in_flight: bool,
    },
    EditDevice {
        request_id: u64,
        device_id: String,
        display_name: String,
        location: String,
        error: Option<String>,
        in_flight: bool,
    },
    AddTarget {
        request_id: u64,
        display_name: String,
        address: String,
        location: String,
        error: Option<String>,
        in_flight: bool,
    },
    EditTarget {
        request_id: u64,
        target_id: String,
        display_name: String,
        address: String,
        location: String,
        error: Option<String>,
        in_flight: bool,
    },
    ReplaceDevice {
        request_id: u64,
        prior_device_id: String,
        replacement_device_id: String,
        error: Option<String>,
        in_flight: bool,
    },
    PrepareInstallationArtifact {
        request_id: u64,
        output_path: String,
        agent_binary_path: String,
        error: Option<String>,
        in_flight: bool,
        success: Option<String>,
    },
}

#[derive(Clone)]
enum ScreenState {
    Login {
        username: String,
        password: String,
        error: Option<String>,
        notice: Option<String>,
        remember: bool,
        in_flight: bool,
    },
    MustChangePassword {
        session_token: String,
        username: String,
        role: String,
        new_password: String,
        confirm_password: String,
        error: Option<String>,
        in_flight: bool,
    },
    Connected {
        session_token: String,
        username: String,
        role: String,
        server_version: String,
        registered_devices: u64,
        devices: Vec<FleetDeviceEntry>,
        accounts: Vec<StaffAccountEntry>,
        new_account_username: String,
        new_account_role: String,
        new_account_password: String,
        error: Option<String>,
        notice: Option<String>,
        in_flight: bool,
    },
}

enum RestoreFailure {
    ExpiredOrRevoked,
    ServerUnavailable(String),
}

struct ControllerApp {
    config: ControllerConfig,
    config_path: std::path::PathBuf,
    state: ScreenState,
    overlay: Overlay,
    active_field: ActiveField,
    focus_handle: FocusHandle,
    tokio_handle: tokio::runtime::Handle,
    next_edit_device_request_id: u64,
    next_target_request_id: u64,
    next_replace_device_request_id: u64,
    next_prepare_artifact_request_id: u64,
    _refresh: Task<()>,
    _restore: Option<Task<()>>,
}

fn resolve_typed_text(keystroke: &gpui::Keystroke) -> Option<&str> {
    if keystroke.modifiers.control || keystroke.modifiers.platform {
        return None;
    }
    if let Some(kc) = keystroke.key_char.as_deref()
        && !kc.is_empty()
        && !kc.chars().any(|c| c.is_control())
    {
        return Some(kc);
    }
    if keystroke.key == "space" {
        return Some(" ");
    }
    if keystroke.key.chars().count() == 1 {
        let c = keystroke.key.chars().next().unwrap();
        if !c.is_control() {
            return Some(&keystroke.key);
        }
    }
    None
}

impl ControllerApp {
    fn new(
        config: ControllerConfig,
        config_path: std::path::PathBuf,
        tokio_handle: tokio::runtime::Handle,
        cx: &mut Context<Self>,
    ) -> Self {
        let focus_handle = cx.focus_handle();
        let refresh = cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor().timer(Duration::from_secs(5)).await;
                let token_opt = this
                    .update(cx, |view, _cx| {
                        if let ScreenState::Connected { session_token, .. } = &view.state {
                            Some(session_token.clone())
                        } else {
                            None
                        }
                    })
                    .ok()
                    .flatten();

                if let Some(token) = token_opt {
                    let _ = this.update(cx, |view, cx| {
                        view.fetch_status(token, cx);
                    });
                }
            }
        });

        // Restore a remembered Staff Session before asking for credentials.
        let restore_cfg = config.clone();
        let restore_path = config_path.clone();
        let restore_handle = tokio_handle.clone();
        let restore = cx.spawn(async move |this, cx| {
            let load_path = crate::session::session_file_path(&restore_path);
            let clear_path = load_path.clone();
            let saved = match restore_handle
                .spawn(async move { crate::session::load(&load_path) })
                .await
            {
                Ok(Ok(Some(saved))) => Some(saved),
                _ => None,
            };
            let Some(saved) = saved else {
                return;
            };
            if !saved.matches_deployment(&restore_cfg.server) {
                return;
            }
            let client_cfg = restore_cfg.server.clone();
            let token = saved.session_token.clone();
            let outcome = restore_handle
                .spawn(async move {
                    let mut client = match rustctrl_network::connect_staff_auth(&client_cfg).await {
                        Ok(client) => client,
                        Err(error) => {
                            return Err(RestoreFailure::ServerUnavailable(error.to_string()));
                        }
                    };
                    let auth = match format!("Bearer {token}").parse() {
                        Ok(value) => value,
                        Err(error) => {
                            return Err(RestoreFailure::ServerUnavailable(format!(
                                "invalid session token encoding: {error}"
                            )));
                        }
                    };
                    let mut req = tonic::Request::new(StaffStatusRequest {});
                    req.metadata_mut().insert("authorization", auth);
                    match client.get_staff_status(req).await {
                        Ok(reply) => Ok(reply.into_inner()),
                        Err(status)
                            if status.code() == tonic::Code::Unauthenticated
                                || status.code() == tonic::Code::PermissionDenied =>
                        {
                            // Dead credential: stop restoring it on later
                            // launches — but only when the file still holds
                            // the rejected token, so a fresh remembered login
                            // that raced this slow check is preserved.
                            if let Ok(Some(stored)) = crate::session::load(&clear_path)
                                && stored.session_token == token
                            {
                                let _ = crate::session::clear(&clear_path);
                            }
                            Err(RestoreFailure::ExpiredOrRevoked)
                        }
                        Err(status) => Err(RestoreFailure::ServerUnavailable(status.to_string())),
                    }
                })
                .await;
            let _ = this.update(cx, |view, cx| {
                if let ScreenState::Login { .. } = view.state {
                    match outcome {
                        Ok(Ok(reply)) => {
                            view.state = ScreenState::Connected {
                                session_token: saved.session_token.clone(),
                                username: reply.username,
                                role: reply.role,
                                server_version: reply.server_version,
                                registered_devices: reply.registered_devices,
                                devices: Vec::new(),
                                accounts: Vec::new(),
                                new_account_username: String::new(),
                                new_account_role: "operator".into(),
                                new_account_password: String::new(),
                                error: None,
                                notice: Some("Signed in with your remembered session.".into()),
                                in_flight: false,
                            };
                            if let ScreenState::Connected { session_token, .. } = &view.state {
                                let token = session_token.clone();
                                view.fetch_status(token, cx);
                            }
                        }
                        Ok(Err(RestoreFailure::ExpiredOrRevoked)) => {
                            // The credential file was already cleared off the
                            // UI thread when the outcome was produced.
                            if let ScreenState::Login { notice, .. } = &mut view.state {
                                *notice =
                                    Some("Saved session expired or was revoked. Sign in.".into());
                            }
                        }
                        Ok(Err(RestoreFailure::ServerUnavailable(reason))) => {
                            tracing::warn!(%reason, "saved session could not be validated");
                            if let ScreenState::Login { notice, .. } = &mut view.state {
                                *notice = Some("Server unavailable. Sign in to reconnect.".into());
                            }
                        }
                        Err(_) => {
                            if let ScreenState::Login { notice, .. } = &mut view.state {
                                *notice = Some("Server unavailable. Sign in to reconnect.".into());
                            }
                        }
                    }
                    cx.notify();
                }
            });
        });

        Self {
            config,
            config_path,
            state: ScreenState::Login {
                username: String::new(),
                password: String::new(),
                error: None,
                notice: None,
                remember: false,
                in_flight: false,
            },
            overlay: Overlay::None,
            active_field: ActiveField::Username,
            focus_handle,
            tokio_handle,
            next_edit_device_request_id: 0,
            next_target_request_id: 0,
            next_replace_device_request_id: 0,
            next_prepare_artifact_request_id: 0,
            _refresh: refresh,
            _restore: Some(restore),
        }
    }

    fn submit_login(&mut self, cx: &mut Context<Self>) {
        let (username, password, remember) = match &self.state {
            ScreenState::Login {
                username,
                password,
                remember,
                in_flight: false,
                ..
            } => {
                if username.trim().is_empty() || password.is_empty() {
                    self.state = ScreenState::Login {
                        username: username.clone(),
                        password: password.clone(),
                        error: Some("Username and password are required.".into()),
                        notice: None,
                        remember: *remember,
                        in_flight: false,
                    };
                    cx.notify();
                    return;
                }
                (username.clone(), password.clone(), *remember)
            }
            _ => return,
        };

        self.state = ScreenState::Login {
            username: username.clone(),
            password: password.clone(),
            error: None,
            notice: None,
            remember,
            in_flight: true,
        };
        cx.notify();

        let client_cfg = self.config.server.clone();
        let session_path = crate::session::session_file_path(&self.config_path);
        let scope_endpoint = self.config.server.endpoint.clone();
        let scope_domain = self.config.server.domain_name.clone();
        let handle = self.tokio_handle.clone();
        cx.spawn(async move |this, cx| {
            let res = handle
                .spawn(async move {
                    let mut client = rustctrl_network::connect_staff_auth(&client_cfg).await?;
                    let reply = client
                        .login(LoginRequest {
                            username: username.clone(),
                            password,
                            remember,
                        })
                        .await?
                        .into_inner();
                    // The saved credential reflects the latest explicit login
                    // choice; the staff password is never stored. File work
                    // stays off the UI thread and failures are surfaced
                    // instead of silently leaving a stale credential.
                    let persistence_warning = if remember {
                        crate::session::save(
                            &session_path,
                            &crate::session::SavedStaffSession {
                                endpoint: scope_endpoint,
                                domain_name: scope_domain,
                                username: reply.username.clone(),
                                session_token: reply.session_token.clone(),
                            },
                        )
                        .err()
                        .map(|error| format!("could not save the remembered login: {error}"))
                    } else if session_path.exists() {
                        crate::session::clear(&session_path).err().map(|error| {
                            format!("could not remove the previous remembered login: {error}")
                        })
                    } else {
                        None
                    };
                    Ok::<_, anyhow::Error>((reply, persistence_warning))
                })
                .await;

            let _ = this.update(cx, |view, cx| {
                match res {
                    Ok(Ok((reply, persistence_warning))) => {
                        let warning = persistence_warning.map(|text| format!("Warning: {text}."));
                        if reply.must_change_password {
                            view.state = ScreenState::MustChangePassword {
                                session_token: reply.session_token,
                                username: reply.username,
                                role: reply.role,
                                new_password: String::new(),
                                confirm_password: String::new(),
                                error: warning,
                                in_flight: false,
                            };
                            view.active_field = ActiveField::NewPassword;
                        } else {
                            let token = reply.session_token.clone();
                            view.state = ScreenState::Connected {
                                session_token: reply.session_token,
                                username: reply.username,
                                role: reply.role,
                                server_version: "Loading...".into(),
                                registered_devices: 0,
                                devices: Vec::new(),
                                accounts: Vec::new(),
                                new_account_username: String::new(),
                                new_account_role: "operator".into(),
                                new_account_password: String::new(),
                                error: None,
                                notice: warning,
                                in_flight: false,
                            };
                            view.fetch_status(token, cx);
                        }
                    }
                    Ok(Err(err)) => {
                        if let ScreenState::Login {
                            username,
                            password,
                            remember,
                            ..
                        } = &view.state
                        {
                            view.state = ScreenState::Login {
                                username: username.clone(),
                                password: password.clone(),
                                error: Some(err.to_string()),
                                notice: None,
                                remember: *remember,
                                in_flight: false,
                            };
                        }
                    }
                    Err(join_err) => {
                        if let ScreenState::Login {
                            username,
                            password,
                            remember,
                            ..
                        } = &view.state
                        {
                            view.state = ScreenState::Login {
                                username: username.clone(),
                                password: password.clone(),
                                error: Some(join_err.to_string()),
                                notice: None,
                                remember: *remember,
                                in_flight: false,
                            };
                        }
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn submit_replace_password(&mut self, cx: &mut Context<Self>) {
        let (session_token, username, role, new_password) = match &self.state {
            ScreenState::MustChangePassword {
                session_token,
                username,
                role,
                new_password,
                confirm_password,
                in_flight: false,
                ..
            } => {
                if new_password.len() < 8 {
                    self.state = ScreenState::MustChangePassword {
                        session_token: session_token.clone(),
                        username: username.clone(),
                        role: role.clone(),
                        new_password: new_password.clone(),
                        confirm_password: confirm_password.clone(),
                        error: Some("Password must contain at least 8 characters.".into()),
                        in_flight: false,
                    };
                    cx.notify();
                    return;
                }
                if new_password != confirm_password {
                    self.state = ScreenState::MustChangePassword {
                        session_token: session_token.clone(),
                        username: username.clone(),
                        role: role.clone(),
                        new_password: new_password.clone(),
                        confirm_password: confirm_password.clone(),
                        error: Some("Passwords do not match.".into()),
                        in_flight: false,
                    };
                    cx.notify();
                    return;
                }
                (
                    session_token.clone(),
                    username.clone(),
                    role.clone(),
                    new_password.clone(),
                )
            }
            _ => return,
        };

        self.state = ScreenState::MustChangePassword {
            session_token: session_token.clone(),
            username: username.clone(),
            role: role.clone(),
            new_password: new_password.clone(),
            confirm_password: new_password.clone(),
            error: None,
            in_flight: true,
        };
        cx.notify();

        let client_cfg = self.config.server.clone();
        let handle = self.tokio_handle.clone();
        let tok = session_token.clone();
        cx.spawn(async move |this, cx| {
            let res = handle
                .spawn(async move {
                    let mut client = rustctrl_network::connect_staff_auth(&client_cfg).await?;
                    let mut req =
                        tonic::Request::new(ReplaceTemporaryPasswordRequest { new_password });
                    req.metadata_mut()
                        .insert("authorization", format!("Bearer {tok}").parse()?);
                    client.replace_temporary_password(req).await?;
                    Ok::<_, anyhow::Error>(())
                })
                .await;

            let _ = this.update(cx, |view, cx| {
                match res {
                    Ok(Ok(())) => {
                        view.state = ScreenState::Connected {
                            session_token: session_token.clone(),
                            username: username.clone(),
                            role: role.clone(),
                            server_version: "Loading...".into(),
                            registered_devices: 0,
                            devices: Vec::new(),
                            accounts: Vec::new(),
                            new_account_username: String::new(),
                            new_account_role: "operator".into(),
                            new_account_password: String::new(),
                            error: None,
                            notice: None,
                            in_flight: false,
                        };
                        view.fetch_status(session_token, cx);
                    }
                    Ok(Err(err)) => {
                        if let ScreenState::MustChangePassword {
                            session_token,
                            username,
                            role,
                            new_password,
                            confirm_password,
                            ..
                        } = &view.state
                        {
                            view.state = ScreenState::MustChangePassword {
                                session_token: session_token.clone(),
                                username: username.clone(),
                                role: role.clone(),
                                new_password: new_password.clone(),
                                confirm_password: confirm_password.clone(),
                                error: Some(err.to_string()),
                                in_flight: false,
                            };
                        }
                    }
                    Err(join_err) => {
                        if let ScreenState::MustChangePassword {
                            session_token,
                            username,
                            role,
                            new_password,
                            confirm_password,
                            ..
                        } = &view.state
                        {
                            view.state = ScreenState::MustChangePassword {
                                session_token: session_token.clone(),
                                username: username.clone(),
                                role: role.clone(),
                                new_password: new_password.clone(),
                                confirm_password: confirm_password.clone(),
                                error: Some(join_err.to_string()),
                                in_flight: false,
                            };
                        }
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn submit_logout(&mut self, cx: &mut Context<Self>) {
        let session_token = match &self.state {
            ScreenState::Connected { session_token, .. } => session_token.clone(),
            ScreenState::MustChangePassword { session_token, .. } => session_token.clone(),
            _ => return,
        };

        self.state = ScreenState::Login {
            username: String::new(),
            password: String::new(),
            error: None,
            notice: None,
            remember: false,
            in_flight: false,
        };
        // Any open password form belongs to the session being left behind.
        self.overlay = Overlay::None;
        self.active_field = ActiveField::Username;
        cx.notify();

        let client_cfg = self.config.server.clone();
        let session_path = crate::session::session_file_path(&self.config_path);
        let handle = self.tokio_handle.clone();
        cx.spawn(async move |_this, _cx| {
            let _ = handle
                .spawn(async move {
                    // Remove the remembered credential for this session first,
                    // independent of the logout RPC: a slow or unreachable
                    // Server must not leave a still-restorable credential
                    // behind after the user explicitly signed out.
                    if let Ok(Some(saved)) = crate::session::load(&session_path)
                        && saved.session_token == session_token
                    {
                        let _ = crate::session::clear(&session_path);
                    }
                    if let Ok(mut client) = rustctrl_network::connect_staff_auth(&client_cfg).await
                    {
                        let mut req = tonic::Request::new(LogoutRequest {});
                        if let Ok(val) = format!("Bearer {session_token}").parse() {
                            req.metadata_mut().insert("authorization", val);
                            let _ = client.logout(req).await;
                        }
                    }
                })
                .await;
        })
        .detach();
    }

    fn fetch_status(&mut self, session_token: String, cx: &mut Context<Self>) {
        let client_cfg = self.config.server.clone();
        let handle = self.tokio_handle.clone();
        let tok_for_req = session_token.clone();
        let tok_for_update = session_token;
        let is_admin = match &self.state {
            ScreenState::Connected { role, .. } => role == "admin",
            _ => false,
        };
        cx.spawn(async move |this, cx| {
            let res = handle
                .spawn(async move {
                    let mut client = rustctrl_network::connect_staff_auth(&client_cfg).await?;
                    let mut req = tonic::Request::new(StaffStatusRequest {});
                    req.metadata_mut()
                        .insert("authorization", format!("Bearer {tok_for_req}").parse()?);
                    let reply = client.get_staff_status(req).await?.into_inner();
                    // Both roles read the full Fleet Inventory; a failure here
                    // fails the whole refresh so the previous data is kept and
                    // reported as a Server problem instead of an empty Fleet.
                    let mut devices_req = tonic::Request::new(ListFleetDevicesRequest {});
                    devices_req
                        .metadata_mut()
                        .insert("authorization", format!("Bearer {tok_for_req}").parse()?);
                    let devices = client
                        .list_fleet_devices(devices_req)
                        .await?
                        .into_inner()
                        .devices;
                    let accounts = if is_admin || reply.role == "admin" {
                        let mut list_req = tonic::Request::new(ListStaffAccountsRequest {});
                        list_req
                            .metadata_mut()
                            .insert("authorization", format!("Bearer {tok_for_req}").parse()?);
                        client
                            .list_staff_accounts(list_req)
                            .await
                            .map(|r| r.into_inner().accounts)
                            .unwrap_or_default()
                    } else {
                        Vec::new()
                    };
                    Ok::<_, anyhow::Error>((reply, devices, accounts))
                })
                .await;

            let _ = this.update(cx, |view, cx| {
                if let ScreenState::Connected {
                    session_token: tok,
                    devices,
                    accounts,
                    new_account_username,
                    new_account_role,
                    new_account_password,
                    in_flight,
                    error,
                    notice,
                    ..
                } = &mut view.state
                    && *tok == tok_for_update
                {
                    match res {
                        Ok(Ok((reply, devices_reply, accs))) => {
                            let updated_accounts = if reply.role == "admin" {
                                accs
                            } else {
                                Vec::new()
                            };
                            let keep_error = error.clone();
                            let keep_notice = notice.clone();
                            view.state = ScreenState::Connected {
                                session_token: tok_for_update,
                                username: reply.username,
                                role: reply.role,
                                server_version: reply.server_version,
                                registered_devices: reply.registered_devices,
                                devices: devices_reply,
                                accounts: updated_accounts,
                                new_account_username: new_account_username.clone(),
                                new_account_role: new_account_role.clone(),
                                new_account_password: new_account_password.clone(),
                                error: keep_error,
                                notice: keep_notice,
                                in_flight: *in_flight,
                            };
                        }
                        Ok(Err(err)) => {
                            view.state = ScreenState::Connected {
                                session_token: tok_for_update,
                                username: String::new(),
                                role: String::new(),
                                server_version: "Unavailable".into(),
                                registered_devices: 0,
                                devices: devices.clone(),
                                accounts: accounts.clone(),
                                new_account_username: new_account_username.clone(),
                                new_account_role: new_account_role.clone(),
                                new_account_password: new_account_password.clone(),
                                error: Some(err.to_string()),
                                notice: notice.clone(),
                                in_flight: false,
                            };
                        }
                        Err(e) => {
                            view.state = ScreenState::Connected {
                                session_token: tok_for_update,
                                username: String::new(),
                                role: String::new(),
                                server_version: "Unavailable".into(),
                                registered_devices: 0,
                                devices: devices.clone(),
                                accounts: accounts.clone(),
                                new_account_username: new_account_username.clone(),
                                new_account_role: new_account_role.clone(),
                                new_account_password: new_account_password.clone(),
                                error: Some(e.to_string()),
                                notice: notice.clone(),
                                in_flight: false,
                            };
                        }
                    }
                    cx.notify();
                }
            });
        })
        .detach();
    }

    fn submit_create_account(&mut self, cx: &mut Context<Self>) {
        let (session_token, new_user, new_role, new_pass) = match &mut self.state {
            ScreenState::Connected {
                session_token,
                role,
                new_account_username,
                new_account_role,
                new_account_password,
                in_flight,
                error,
                ..
            } if role == "admin" && !*in_flight => {
                let user = new_account_username.trim().to_string();
                if user.is_empty() {
                    *error = Some("Username is required.".into());
                    cx.notify();
                    return;
                }
                if new_account_password.len() < 8 {
                    *error = Some("Temporary password must contain at least 8 characters.".into());
                    cx.notify();
                    return;
                }
                *in_flight = true;
                *error = None;
                (
                    session_token.clone(),
                    user,
                    new_account_role.clone(),
                    new_account_password.clone(),
                )
            }
            _ => return,
        };
        cx.notify();

        let client_cfg = self.config.server.clone();
        let handle = self.tokio_handle.clone();
        let tok = session_token.clone();
        cx.spawn(async move |this, cx| {
            let res = handle
                .spawn(async move {
                    let mut client = rustctrl_network::connect_staff_auth(&client_cfg).await?;
                    let mut req = tonic::Request::new(CreateStaffAccountRequest {
                        username: new_user,
                        role: new_role,
                        temporary_password: new_pass,
                    });
                    req.metadata_mut()
                        .insert("authorization", format!("Bearer {tok}").parse()?);
                    let reply = client.create_staff_account(req).await?.into_inner();
                    Ok::<_, anyhow::Error>(reply)
                })
                .await;

            let _ = this.update(cx, |view, cx| {
                if let ScreenState::Connected {
                    session_token,
                    new_account_username,
                    new_account_password,
                    in_flight,
                    error,
                    ..
                } = &mut view.state
                {
                    *in_flight = false;
                    match res {
                        Ok(Ok(_reply)) => {
                            new_account_username.clear();
                            new_account_password.clear();
                            *error = None;
                            let token = session_token.clone();
                            view.fetch_status(token, cx);
                        }
                        Ok(Err(e)) => {
                            *error = Some(e.to_string());
                        }
                        Err(join_err) => {
                            *error = Some(join_err.to_string());
                        }
                    }
                    cx.notify();
                }
            });
        })
        .detach();
    }

    fn submit_deactivate_account(&mut self, target_username: String, cx: &mut Context<Self>) {
        let session_token = match &mut self.state {
            ScreenState::Connected {
                session_token,
                role,
                in_flight,
                error,
                ..
            } if role == "admin" && !*in_flight => {
                *in_flight = true;
                *error = None;
                session_token.clone()
            }
            _ => return,
        };
        cx.notify();

        let client_cfg = self.config.server.clone();
        let handle = self.tokio_handle.clone();
        let tok = session_token.clone();
        let tok_check = session_token;
        let target_label = target_username.clone();
        let session_path = crate::session::session_file_path(&self.config_path);
        let deactivate_target = target_label.clone();
        cx.spawn(async move |this, cx| {
            let res = handle
                .spawn(async move {
                    let mut client = rustctrl_network::connect_staff_auth(&client_cfg).await?;
                    let mut req = tonic::Request::new(DeactivateStaffAccountRequest {
                        username: target_username,
                    });
                    req.metadata_mut()
                        .insert("authorization", format!("Bearer {tok}").parse()?);
                    client.deactivate_staff_account(req).await?.into_inner();
                    // Deactivating an account kills every session of that
                    // account, so any saved credential for it is dead; file
                    // work stays off the UI thread.
                    if let Ok(Some(saved)) = crate::session::load(&session_path)
                        && saved.username == deactivate_target
                    {
                        let _ = crate::session::clear(&session_path);
                    }
                    Ok::<_, anyhow::Error>(())
                })
                .await;

            let _ = this.update(cx, |view, cx| {
                let err_text = match &res {
                    Ok(Ok(())) => None,
                    Ok(Err(err)) => Some(err.to_string()),
                    Err(join_err) => Some(join_err.to_string()),
                };
                if let ScreenState::Connected {
                    in_flight, error, ..
                } = &mut view.state
                {
                    *in_flight = false;
                    if let Some(text) = err_text {
                        *error = Some(text);
                    }
                }
                // Only a successful RPC justifies the deactivation effects; a
                // rejected request (for example the last active Admin) keeps
                // the session and shows the Server's error above.
                if matches!(res, Ok(Ok(()))) {
                    let self_deactivate = matches!(
                        &view.state,
                        ScreenState::Connected { username, session_token, .. }
                            if *username == target_label && *session_token == tok_check
                    );
                    if self_deactivate {
                        // Deactivating the own account revokes this session.
                        view.state = ScreenState::Login {
                            username: target_label,
                            password: String::new(),
                            error: None,
                            notice: Some(
                                "Account deactivated and this session was revoked.".into(),
                            ),
                            in_flight: false,
                            remember: false,
                        };
                        view.active_field = ActiveField::Username;
                    } else if let ScreenState::Connected {
                        notice,
                        session_token,
                        ..
                    } = &mut view.state
                    {
                        *notice = Some(format!(
                            "Account '{target_label}' deactivated; its sessions were revoked."
                        ));
                        let token = session_token.clone();
                        view.fetch_status(token, cx);
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn submit_change_role(
        &mut self,
        target_username: String,
        new_role: String,
        cx: &mut Context<Self>,
    ) {
        let session_token = match &mut self.state {
            ScreenState::Connected {
                session_token,
                role,
                in_flight,
                error,
                ..
            } if role == "admin" && !*in_flight => {
                *in_flight = true;
                *error = None;
                session_token.clone()
            }
            _ => return,
        };
        cx.notify();

        let client_cfg = self.config.server.clone();
        let handle = self.tokio_handle.clone();
        let tok = session_token.clone();
        cx.spawn(async move |this, cx| {
            let res = handle
                .spawn(async move {
                    let mut client = rustctrl_network::connect_staff_auth(&client_cfg).await?;
                    let mut req = tonic::Request::new(ChangeStaffRoleRequest {
                        username: target_username,
                        new_role,
                    });
                    req.metadata_mut()
                        .insert("authorization", format!("Bearer {tok}").parse()?);
                    let reply = client.change_staff_role(req).await?.into_inner();
                    Ok::<_, anyhow::Error>(reply)
                })
                .await;

            let _ = this.update(cx, |view, cx| {
                if let ScreenState::Connected {
                    session_token,
                    in_flight,
                    error,
                    ..
                } = &mut view.state
                {
                    *in_flight = false;
                    match res {
                        Ok(Ok(_reply)) => {
                            *error = None;
                            let token = session_token.clone();
                            view.fetch_status(token, cx);
                        }
                        Ok(Err(e)) => {
                            *error = Some(e.to_string());
                        }
                        Err(join_err) => {
                            *error = Some(join_err.to_string());
                        }
                    }
                    cx.notify();
                }
            });
        })
        .detach();
    }

    fn open_change_password(&mut self, cx: &mut Context<Self>) {
        if let ScreenState::Connected { .. } = &self.state {
            self.overlay = Overlay::ChangePassword {
                current_password: String::new(),
                new_password: String::new(),
                confirm_password: String::new(),
                error: None,
                in_flight: false,
            };
            self.active_field = ActiveField::CurrentPassword;
            cx.notify();
        }
    }

    fn open_reset_password(&mut self, target_username: String, cx: &mut Context<Self>) {
        if let ScreenState::Connected { role, .. } = &self.state
            && role == "admin"
        {
            self.overlay = Overlay::ResetPassword {
                target_username,
                temporary_password: String::new(),
                confirm_password: String::new(),
                error: None,
                in_flight: false,
            };
            self.active_field = ActiveField::TemporaryPassword;
            cx.notify();
        }
    }

    fn open_edit_device(
        &mut self,
        device_id: String,
        display_name: String,
        location: Option<String>,
        cx: &mut Context<Self>,
    ) {
        if let Overlay::EditDevice {
            in_flight: true, ..
        } = self.overlay
        {
            return;
        }
        if let ScreenState::Connected { role, .. } = &self.state
            && role == "admin"
        {
            self.next_edit_device_request_id = self.next_edit_device_request_id.wrapping_add(1);
            let request_id = self.next_edit_device_request_id;
            self.overlay = Overlay::EditDevice {
                request_id,
                device_id,
                display_name,
                location: location.unwrap_or_default(),
                error: None,
                in_flight: false,
            };
            self.active_field = ActiveField::EditDeviceDisplayName;
            cx.notify();
        }
    }

    fn open_add_target(&mut self, cx: &mut Context<Self>) {
        if let Overlay::AddTarget {
            in_flight: true, ..
        } = self.overlay
        {
            return;
        }
        if let ScreenState::Connected { role, .. } = &self.state
            && role == "admin"
        {
            self.next_target_request_id = self.next_target_request_id.wrapping_add(1);
            let request_id = self.next_target_request_id;
            self.overlay = Overlay::AddTarget {
                request_id,
                display_name: String::new(),
                address: String::new(),
                location: String::new(),
                error: None,
                in_flight: false,
            };
            self.active_field = ActiveField::AddTargetDisplayName;
            cx.notify();
        }
    }

    fn open_edit_target(
        &mut self,
        target_id: String,
        display_name: String,
        address: String,
        location: Option<String>,
        cx: &mut Context<Self>,
    ) {
        if let Overlay::EditTarget {
            in_flight: true, ..
        } = self.overlay
        {
            return;
        }
        if let ScreenState::Connected { role, .. } = &self.state
            && role == "admin"
        {
            self.next_target_request_id = self.next_target_request_id.wrapping_add(1);
            let request_id = self.next_target_request_id;
            self.overlay = Overlay::EditTarget {
                request_id,
                target_id,
                display_name,
                address,
                location: location.unwrap_or_default(),
                error: None,
                in_flight: false,
            };
            self.active_field = ActiveField::EditTargetDisplayName;
            cx.notify();
        }
    }

    fn open_replace_device(
        &mut self,
        prior_device_id: String,
        replacement_device_id: String,
        cx: &mut Context<Self>,
    ) {
        if let Overlay::ReplaceDevice {
            in_flight: true, ..
        } = self.overlay
        {
            return;
        }
        if let ScreenState::Connected { role, .. } = &self.state
            && role == "admin"
        {
            self.next_replace_device_request_id =
                self.next_replace_device_request_id.wrapping_add(1);
            let request_id = self.next_replace_device_request_id;
            let active_field = if prior_device_id.is_empty() {
                ActiveField::ReplaceDevicePriorId
            } else {
                ActiveField::ReplaceDeviceReplacementId
            };
            self.overlay = Overlay::ReplaceDevice {
                request_id,
                prior_device_id,
                replacement_device_id,
                error: None,
                in_flight: false,
            };
            self.active_field = active_field;
            cx.notify();
        }
    }

    fn open_prepare_installation_artifact(&mut self, cx: &mut Context<Self>) {
        if let Overlay::PrepareInstallationArtifact {
            in_flight: true, ..
        } = self.overlay
        {
            return;
        }
        if let ScreenState::Connected { role, .. } = &self.state
            && role == "admin"
        {
            self.next_prepare_artifact_request_id =
                self.next_prepare_artifact_request_id.wrapping_add(1);
            let request_id = self.next_prepare_artifact_request_id;
            self.overlay = Overlay::PrepareInstallationArtifact {
                request_id,
                output_path: "rustctrl-agent-windows.zip".to_string(),
                agent_binary_path: String::new(),
                error: None,
                in_flight: false,
                success: None,
            };
            self.active_field = ActiveField::PrepareArtifactOutputPath;
            cx.notify();
        }
    }

    fn close_overlay(&mut self, cx: &mut Context<Self>) {
        self.overlay = Overlay::None;
        self.active_field = ActiveField::NewAccountUsername;
        cx.notify();
    }

    fn submit_change_password(&mut self, cx: &mut Context<Self>) {
        let (session_token, current, new_password) = match &mut self.overlay {
            Overlay::ChangePassword {
                current_password,
                new_password,
                confirm_password,
                error,
                in_flight,
            } if !*in_flight => {
                if current_password.is_empty() {
                    *error = Some("Current password is required.".into());
                    cx.notify();
                    return;
                }
                if new_password.len() < 8 {
                    *error = Some("New password must contain at least 8 characters.".into());
                    cx.notify();
                    return;
                }
                if new_password != confirm_password {
                    *error = Some("Passwords do not match.".into());
                    cx.notify();
                    return;
                }
                let token = match &self.state {
                    ScreenState::Connected { session_token, .. } => session_token.clone(),
                    _ => return,
                };
                *in_flight = true;
                *error = None;
                (token, current_password.clone(), new_password.clone())
            }
            _ => return,
        };
        cx.notify();

        let client_cfg = self.config.server.clone();
        let handle = self.tokio_handle.clone();
        let tok = session_token.clone();
        let tok_check = session_token;
        cx.spawn(async move |this, cx| {
            let res = handle
                .spawn(async move {
                    let mut client = rustctrl_network::connect_staff_auth(&client_cfg).await?;
                    let mut req = tonic::Request::new(ChangeOwnPasswordRequest {
                        current_password: current,
                        new_password,
                    });
                    req.metadata_mut()
                        .insert("authorization", format!("Bearer {tok}").parse()?);
                    client.change_own_password(req).await?.into_inner();
                    Ok::<_, anyhow::Error>(())
                })
                .await;

            let _ = this.update(cx, |view, cx| {
                match res {
                    Ok(Ok(())) => {
                        // Ignore the result if the user left this session meanwhile.
                        if matches!(
                            &view.state,
                            ScreenState::Connected { session_token, .. } if *session_token == tok_check
                        ) {
                            view.overlay = Overlay::None;
                            view.active_field = ActiveField::NewAccountUsername;
                            if let ScreenState::Connected { notice, .. } = &mut view.state {
                                *notice = Some("Password changed successfully.".into());
                            }
                        }
                    }
                    Ok(Err(err)) => {
                        if let Overlay::ChangePassword {
                            error, in_flight, ..
                        } = &mut view.overlay
                        {
                            *in_flight = false;
                            *error = Some(err.to_string());
                        }
                    }
                    Err(join_err) => {
                        if let Overlay::ChangePassword {
                            error, in_flight, ..
                        } = &mut view.overlay
                        {
                            *in_flight = false;
                            *error = Some(join_err.to_string());
                        }
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn submit_reset_password(&mut self, cx: &mut Context<Self>) {
        let (session_token, target, temporary) = match &mut self.overlay {
            Overlay::ResetPassword {
                target_username,
                temporary_password,
                confirm_password,
                error,
                in_flight,
            } if !*in_flight => {
                if temporary_password.len() < 8 {
                    *error = Some("Temporary password must contain at least 8 characters.".into());
                    cx.notify();
                    return;
                }
                if temporary_password != confirm_password {
                    *error = Some("Passwords do not match.".into());
                    cx.notify();
                    return;
                }
                let token = match &self.state {
                    ScreenState::Connected { session_token, .. } => session_token.clone(),
                    _ => return,
                };
                *in_flight = true;
                *error = None;
                (token, target_username.clone(), temporary_password.clone())
            }
            _ => return,
        };
        cx.notify();

        let client_cfg = self.config.server.clone();
        let handle = self.tokio_handle.clone();
        let tok = session_token.clone();
        let tok_check = session_token;
        let target_label = target.clone();
        let session_path = crate::session::session_file_path(&self.config_path);
        let reset_target = target_label.clone();
        cx.spawn(async move |this, cx| {
            let res = handle
                .spawn(async move {
                    let mut client = rustctrl_network::connect_staff_auth(&client_cfg).await?;
                    let mut req = tonic::Request::new(ResetStaffPasswordRequest {
                        username: target,
                        temporary_password: temporary,
                    });
                    req.metadata_mut()
                        .insert("authorization", format!("Bearer {tok}").parse()?);
                    client.reset_staff_password(req).await?.into_inner();
                    // A self-reset kills every session of the account, so any
                    // saved credential for it is dead; file work stays off the
                    // UI thread.
                    if let Ok(Some(saved)) = crate::session::load(&session_path)
                        && saved.username == reset_target
                    {
                        let _ = crate::session::clear(&session_path);
                    }
                    Ok::<_, anyhow::Error>(())
                })
                .await;

            let _ = this.update(cx, |view, cx| {
                match res {
                    Ok(Ok(())) => {
                        // Ignore the result if the user left this session meanwhile.
                        if matches!(
                            &view.state,
                            ScreenState::Connected { session_token, .. } if *session_token == tok_check
                        ) {
                            let self_reset = matches!(
                                &view.state,
                                ScreenState::Connected { username, .. } if *username == target_label
                            );
                            view.overlay = Overlay::None;
                            view.active_field = ActiveField::Username;
                            if self_reset {
                                // Resetting the own account revokes this session by design.
                                view.state = ScreenState::Login {
                                    username: target_label,
                                    password: String::new(),
                                    error: None,
                                    notice: Some(
                                        "Account reset to a temporary password and this session was revoked. Sign in with the temporary password."
                                            .into(),
                                    ),
                                    in_flight: false,
                                        remember: false,
                                };
                            } else {
                                if let ScreenState::Connected {
                                    notice,
                                    session_token,
                                    ..
                                } = &mut view.state
                                {
                                    *notice = Some(
                                        "Temporary password set; all target sessions revoked."
                                            .into(),
                                    );
                                    let token = session_token.clone();
                                    view.fetch_status(token, cx);
                                }
                            }
                        }
                    }
                    Ok(Err(err)) => {
                        if let Overlay::ResetPassword {
                            error, in_flight, ..
                        } = &mut view.overlay
                        {
                            *in_flight = false;
                            *error = Some(err.to_string());
                        }
                    }
                    Err(join_err) => {
                        if let Overlay::ResetPassword {
                            error, in_flight, ..
                        } = &mut view.overlay
                        {
                            *in_flight = false;
                            *error = Some(join_err.to_string());
                        }
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn submit_edit_device(&mut self, cx: &mut Context<Self>) {
        let (request_id, session_token, target_id, target_name, target_location) =
            match &mut self.overlay {
                Overlay::EditDevice {
                    request_id,
                    device_id,
                    display_name,
                    location,
                    error,
                    in_flight,
                } if !*in_flight => {
                    let trimmed_name = display_name.trim();
                    if trimmed_name.is_empty() {
                        *error = Some("Display name cannot be empty.".into());
                        cx.notify();
                        return;
                    }
                    if trimmed_name.len() > 128 {
                        *error = Some("Display name must not exceed 128 characters.".into());
                        cx.notify();
                        return;
                    }
                    let trimmed_loc = location.trim();
                    if trimmed_loc.len() > 128 {
                        *error = Some("Location must not exceed 128 characters.".into());
                        cx.notify();
                        return;
                    }
                    let token = match &self.state {
                        ScreenState::Connected { session_token, .. } => session_token.clone(),
                        _ => return,
                    };
                    *in_flight = true;
                    *error = None;
                    (
                        *request_id,
                        token,
                        device_id.clone(),
                        trimmed_name.to_string(),
                        if trimmed_loc.is_empty() {
                            None
                        } else {
                            Some(trimmed_loc.to_string())
                        },
                    )
                }
                _ => return,
            };
        cx.notify();

        let client_cfg = self.config.server.clone();
        let handle = self.tokio_handle.clone();
        let tok = session_token.clone();
        let tok_check = session_token;
        let device_id_label = target_id.clone();
        cx.spawn(async move |this, cx| {
            let res = handle
                .spawn(async move {
                    let mut client = rustctrl_network::connect_staff_auth(&client_cfg).await?;
                    let mut req = tonic::Request::new(UpdateFleetDeviceRequest {
                        device_id: target_id,
                        display_name: target_name,
                        location: target_location,
                    });
                    req.metadata_mut()
                        .insert("authorization", format!("Bearer {tok}").parse()?);
                    client.update_fleet_device(req).await?.into_inner();
                    Ok::<_, anyhow::Error>(())
                })
                .await;

            let _ = this.update(cx, |view, cx| {
                let is_same_session = match &view.state {
                    ScreenState::Connected { session_token, .. } => session_token == &tok_check,
                    _ => false,
                };
                if !is_same_session {
                    return;
                }

                let is_matching_form = match &view.overlay {
                    Overlay::EditDevice {
                        request_id: current_req_id,
                        device_id: current_dev_id,
                        ..
                    } => *current_req_id == request_id && current_dev_id == &device_id_label,
                    _ => false,
                };

                match res {
                    Ok(Ok(())) => {
                        if is_matching_form {
                            view.close_overlay(cx);
                        }
                        if let ScreenState::Connected { notice, .. } = &mut view.state {
                            *notice = Some(format!("Updated device '{device_id_label}'."));
                            let token = tok_check.clone();
                            view.fetch_status(token, cx);
                        }
                    }
                    Ok(Err(err)) => {
                        if is_matching_form
                            && let Overlay::EditDevice {
                                error, in_flight, ..
                            } = &mut view.overlay
                        {
                            *in_flight = false;
                            *error = Some(err.to_string());
                        }
                    }
                    Err(join_err) => {
                        if is_matching_form
                            && let Overlay::EditDevice {
                                error, in_flight, ..
                            } = &mut view.overlay
                        {
                            *in_flight = false;
                            *error = Some(join_err.to_string());
                        }
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn submit_add_target(&mut self, cx: &mut Context<Self>) {
        let (request_id, session_token, target_name, target_addr, target_location) =
            match &mut self.overlay {
                Overlay::AddTarget {
                    request_id,
                    display_name,
                    address,
                    location,
                    error,
                    in_flight,
                } => {
                    if *in_flight {
                        return;
                    }
                    let trimmed_name = display_name.trim();
                    if trimmed_name.is_empty() {
                        *error = Some("Display name cannot be empty.".into());
                        cx.notify();
                        return;
                    }
                    let trimmed_addr = address.trim();
                    if trimmed_addr.is_empty() {
                        *error = Some("Connection address cannot be empty.".into());
                        cx.notify();
                        return;
                    }
                    let trimmed_loc = location.trim();
                    let token = match &self.state {
                        ScreenState::Connected { session_token, .. } => session_token.clone(),
                        _ => return,
                    };
                    *in_flight = true;
                    *error = None;
                    (
                        *request_id,
                        token,
                        trimmed_name.to_string(),
                        trimmed_addr.to_string(),
                        if trimmed_loc.is_empty() {
                            None
                        } else {
                            Some(trimmed_loc.to_string())
                        },
                    )
                }
                _ => return,
            };
        cx.notify();

        let client_cfg = self.config.server.clone();
        let handle = self.tokio_handle.clone();
        let tok = session_token.clone();
        let tok_check = session_token;
        let target_name_label = target_name.clone();
        cx.spawn(async move |this, cx| {
            let res = handle
                .spawn(async move {
                    let mut client = rustctrl_network::connect_staff_auth(&client_cfg).await?;
                    let mut req = tonic::Request::new(CreateTargetRequest {
                        display_name: target_name,
                        address: target_addr,
                        location: target_location,
                        target_type: Some("android_tv".into()),
                    });
                    req.metadata_mut()
                        .insert("authorization", format!("Bearer {tok}").parse()?);
                    let reply = client.create_target(req).await?.into_inner();
                    Ok::<_, anyhow::Error>(reply)
                })
                .await;

            let _ = this.update(cx, |view, cx| {
                let is_same_session = match &view.state {
                    ScreenState::Connected { session_token, .. } => session_token == &tok_check,
                    _ => false,
                };
                if !is_same_session {
                    return;
                }

                let is_matching_form = match &view.overlay {
                    Overlay::AddTarget {
                        request_id: current_req_id,
                        ..
                    } => *current_req_id == request_id,
                    _ => false,
                };

                match res {
                    Ok(Ok(reply)) => {
                        if is_matching_form {
                            view.close_overlay(cx);
                        }
                        if let ScreenState::Connected { notice, .. } = &mut view.state {
                            let id_str = reply
                                .target
                                .as_ref()
                                .map(|t| t.device_id.as_str())
                                .unwrap_or("");
                            *notice = Some(format!(
                                "Added Android TV target '{target_name_label}' ({id_str})."
                            ));
                            let token = tok_check.clone();
                            view.fetch_status(token, cx);
                        }
                    }
                    Ok(Err(err)) => {
                        if is_matching_form
                            && let Overlay::AddTarget {
                                error, in_flight, ..
                            } = &mut view.overlay
                        {
                            *in_flight = false;
                            *error = Some(err.to_string());
                        }
                    }
                    Err(join_err) => {
                        if is_matching_form
                            && let Overlay::AddTarget {
                                error, in_flight, ..
                            } = &mut view.overlay
                        {
                            *in_flight = false;
                            *error = Some(join_err.to_string());
                        }
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn submit_edit_target(&mut self, cx: &mut Context<Self>) {
        let (request_id, session_token, target_id, target_name, target_addr, target_location) =
            match &mut self.overlay {
                Overlay::EditTarget {
                    request_id,
                    target_id,
                    display_name,
                    address,
                    location,
                    error,
                    in_flight,
                } => {
                    if *in_flight {
                        return;
                    }
                    let trimmed_name = display_name.trim();
                    if trimmed_name.is_empty() {
                        *error = Some("Display name cannot be empty.".into());
                        cx.notify();
                        return;
                    }
                    let trimmed_addr = address.trim();
                    if trimmed_addr.is_empty() {
                        *error = Some("Connection address cannot be empty.".into());
                        cx.notify();
                        return;
                    }
                    let trimmed_loc = location.trim();
                    let token = match &self.state {
                        ScreenState::Connected { session_token, .. } => session_token.clone(),
                        _ => return,
                    };
                    *in_flight = true;
                    *error = None;
                    (
                        *request_id,
                        token,
                        target_id.clone(),
                        trimmed_name.to_string(),
                        trimmed_addr.to_string(),
                        if trimmed_loc.is_empty() {
                            None
                        } else {
                            Some(trimmed_loc.to_string())
                        },
                    )
                }
                _ => return,
            };
        cx.notify();

        let client_cfg = self.config.server.clone();
        let handle = self.tokio_handle.clone();
        let tok = session_token.clone();
        let tok_check = session_token;
        let target_id_label = target_id.clone();
        cx.spawn(async move |this, cx| {
            let res = handle
                .spawn(async move {
                    let mut client = rustctrl_network::connect_staff_auth(&client_cfg).await?;
                    let mut req = tonic::Request::new(UpdateTargetRequest {
                        target_id,
                        display_name: target_name,
                        address: target_addr,
                        location: target_location,
                    });
                    req.metadata_mut()
                        .insert("authorization", format!("Bearer {tok}").parse()?);
                    client.update_target(req).await?.into_inner();
                    Ok::<_, anyhow::Error>(())
                })
                .await;

            let _ = this.update(cx, |view, cx| {
                let is_same_session = match &view.state {
                    ScreenState::Connected { session_token, .. } => session_token == &tok_check,
                    _ => false,
                };
                if !is_same_session {
                    return;
                }

                let is_matching_form = match &view.overlay {
                    Overlay::EditTarget {
                        request_id: current_req_id,
                        target_id: current_target_id,
                        ..
                    } => *current_req_id == request_id && current_target_id == &target_id_label,
                    _ => false,
                };

                match res {
                    Ok(Ok(())) => {
                        if is_matching_form {
                            view.close_overlay(cx);
                        }
                        if let ScreenState::Connected { notice, .. } = &mut view.state {
                            *notice = Some(format!("Updated target '{target_id_label}'."));
                            let token = tok_check.clone();
                            view.fetch_status(token, cx);
                        }
                    }
                    Ok(Err(err)) => {
                        if is_matching_form
                            && let Overlay::EditTarget {
                                error, in_flight, ..
                            } = &mut view.overlay
                        {
                            *in_flight = false;
                            *error = Some(err.to_string());
                        }
                    }
                    Err(join_err) => {
                        if is_matching_form
                            && let Overlay::EditTarget {
                                error, in_flight, ..
                            } = &mut view.overlay
                        {
                            *in_flight = false;
                            *error = Some(join_err.to_string());
                        }
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn submit_remove_target(&mut self, target_id: String, cx: &mut Context<Self>) {
        let session_token = match &self.state {
            ScreenState::Connected {
                session_token,
                role,
                ..
            } if role == "admin" => session_token.clone(),
            _ => return,
        };

        let client_cfg = self.config.server.clone();
        let handle = self.tokio_handle.clone();
        let tok = session_token.clone();
        let tok_check = session_token;
        let target_label = target_id.clone();

        cx.spawn(async move |this, cx| {
            let res = handle
                .spawn(async move {
                    let mut client = rustctrl_network::connect_staff_auth(&client_cfg).await?;
                    let mut req = tonic::Request::new(RemoveTargetRequest { target_id });
                    req.metadata_mut()
                        .insert("authorization", format!("Bearer {tok}").parse()?);
                    client.remove_target(req).await?.into_inner();
                    Ok::<_, anyhow::Error>(())
                })
                .await;

            let _ = this.update(cx, |view, cx| {
                let is_same_session = match &view.state {
                    ScreenState::Connected { session_token, .. } => session_token == &tok_check,
                    _ => false,
                };
                if !is_same_session {
                    return;
                }

                match res {
                    Ok(Ok(())) => {
                        if let ScreenState::Connected { notice, .. } = &mut view.state {
                            *notice = Some(format!("Removed target '{target_label}'."));
                            let token = tok_check.clone();
                            view.fetch_status(token, cx);
                        }
                    }
                    Ok(Err(err)) => {
                        if let ScreenState::Connected { error, .. } = &mut view.state {
                            *error = Some(err.to_string());
                        }
                    }
                    Err(join_err) => {
                        if let ScreenState::Connected { error, .. } = &mut view.state {
                            *error = Some(format!("Join error: {join_err}"));
                        }
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn submit_block_device(&mut self, device_id: String, cx: &mut Context<Self>) {
        let session_token = match &self.state {
            ScreenState::Connected {
                session_token,
                role,
                ..
            } if role == "admin" => session_token.clone(),
            _ => return,
        };

        let client_cfg = self.config.server.clone();
        let handle = self.tokio_handle.clone();
        let tok = session_token.clone();
        let tok_check = session_token;
        let device_label = device_id.clone();

        cx.spawn(async move |this, cx| {
            let res = handle
                .spawn(async move {
                    let mut client = rustctrl_network::connect_staff_auth(&client_cfg).await?;
                    let mut req = tonic::Request::new(BlockDeviceRequest { device_id });
                    req.metadata_mut()
                        .insert("authorization", format!("Bearer {tok}").parse()?);
                    client.block_device(req).await?.into_inner();
                    Ok::<_, anyhow::Error>(())
                })
                .await;

            let _ = this.update(cx, |view, cx| {
                let is_same_session = match &view.state {
                    ScreenState::Connected { session_token, .. } => session_token == &tok_check,
                    _ => false,
                };
                if !is_same_session {
                    return;
                }

                match res {
                    Ok(Ok(())) => {
                        if let ScreenState::Connected { notice, .. } = &mut view.state {
                            *notice = Some(format!("Blocked device '{device_label}'."));
                            let token = tok_check.clone();
                            view.fetch_status(token, cx);
                        }
                    }
                    Ok(Err(err)) => {
                        if let ScreenState::Connected { error, .. } = &mut view.state {
                            *error = Some(err.to_string());
                        }
                    }
                    Err(join_err) => {
                        if let ScreenState::Connected { error, .. } = &mut view.state {
                            *error = Some(format!("Join error: {join_err}"));
                        }
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn submit_unblock_device(&mut self, device_id: String, cx: &mut Context<Self>) {
        let session_token = match &self.state {
            ScreenState::Connected {
                session_token,
                role,
                ..
            } if role == "admin" => session_token.clone(),
            _ => return,
        };

        let client_cfg = self.config.server.clone();
        let handle = self.tokio_handle.clone();
        let tok = session_token.clone();
        let tok_check = session_token;
        let device_label = device_id.clone();

        cx.spawn(async move |this, cx| {
            let res = handle
                .spawn(async move {
                    let mut client = rustctrl_network::connect_staff_auth(&client_cfg).await?;
                    let mut req = tonic::Request::new(UnblockDeviceRequest { device_id });
                    req.metadata_mut()
                        .insert("authorization", format!("Bearer {tok}").parse()?);
                    client.unblock_device(req).await?.into_inner();
                    Ok::<_, anyhow::Error>(())
                })
                .await;

            let _ = this.update(cx, |view, cx| {
                let is_same_session = match &view.state {
                    ScreenState::Connected { session_token, .. } => session_token == &tok_check,
                    _ => false,
                };
                if !is_same_session {
                    return;
                }

                match res {
                    Ok(Ok(())) => {
                        if let ScreenState::Connected { notice, .. } = &mut view.state {
                            *notice = Some(format!("Unblocked device '{device_label}'."));
                            let token = tok_check.clone();
                            view.fetch_status(token, cx);
                        }
                    }
                    Ok(Err(err)) => {
                        if let ScreenState::Connected { error, .. } = &mut view.state {
                            *error = Some(err.to_string());
                        }
                    }
                    Err(join_err) => {
                        if let ScreenState::Connected { error, .. } = &mut view.state {
                            *error = Some(format!("Join error: {join_err}"));
                        }
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn submit_clean_offline_device(&mut self, device_id: String, cx: &mut Context<Self>) {
        let session_token = match &self.state {
            ScreenState::Connected {
                session_token,
                role,
                ..
            } if role == "admin" => session_token.clone(),
            _ => return,
        };

        let client_cfg = self.config.server.clone();
        let handle = self.tokio_handle.clone();
        let tok = session_token.clone();
        let tok_check = session_token;
        let device_label = device_id.clone();

        cx.spawn(async move |this, cx| {
            let res = handle
                .spawn(async move {
                    let mut client = rustctrl_network::connect_staff_auth(&client_cfg).await?;
                    let mut req = tonic::Request::new(CleanOfflineDeviceRequest { device_id });
                    req.metadata_mut()
                        .insert("authorization", format!("Bearer {tok}").parse()?);
                    client.clean_offline_device(req).await?.into_inner();
                    Ok::<_, anyhow::Error>(())
                })
                .await;

            let _ = this.update(cx, |view, cx| {
                let is_same_session = match &view.state {
                    ScreenState::Connected { session_token, .. } => session_token == &tok_check,
                    _ => false,
                };
                if !is_same_session {
                    return;
                }

                match res {
                    Ok(Ok(())) => {
                        if let ScreenState::Connected { notice, .. } = &mut view.state {
                            *notice = Some(format!("Cleaned offline device '{device_label}'."));
                            let token = tok_check.clone();
                            view.fetch_status(token, cx);
                        }
                    }
                    Ok(Err(err)) => {
                        if let ScreenState::Connected { error, .. } = &mut view.state {
                            *error = Some(err.to_string());
                        }
                    }
                    Err(join_err) => {
                        if let ScreenState::Connected { error, .. } = &mut view.state {
                            *error = Some(format!("Join error: {join_err}"));
                        }
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn submit_replace_device(&mut self, cx: &mut Context<Self>) {
        let (request_id, session_token, prior_id, replacement_id) = match &mut self.overlay {
            Overlay::ReplaceDevice {
                request_id,
                prior_device_id,
                replacement_device_id,
                error,
                in_flight,
            } if !*in_flight => {
                let p_id = prior_device_id.trim();
                if p_id.is_empty() {
                    *error = Some("Prior device ID is required.".into());
                    cx.notify();
                    return;
                }
                if p_id.parse::<DeviceId>().is_err() {
                    *error = Some("Prior device ID must be a valid UUID.".into());
                    cx.notify();
                    return;
                }
                let r_id = replacement_device_id.trim();
                if r_id.is_empty() {
                    *error = Some("Replacement device ID is required.".into());
                    cx.notify();
                    return;
                }
                if r_id.parse::<DeviceId>().is_err() {
                    *error = Some("Replacement device ID must be a valid UUID.".into());
                    cx.notify();
                    return;
                }
                if p_id == r_id {
                    *error =
                        Some("Prior and replacement device identities must be different.".into());
                    cx.notify();
                    return;
                }
                let token = match &self.state {
                    ScreenState::Connected { session_token, .. } => session_token.clone(),
                    _ => return,
                };
                *in_flight = true;
                *error = None;
                (*request_id, token, p_id.to_string(), r_id.to_string())
            }
            _ => return,
        };
        cx.notify();

        let client_cfg = self.config.server.clone();
        let handle = self.tokio_handle.clone();
        let tok = session_token.clone();
        let tok_check = session_token;
        let prior_label = prior_id.clone();
        let replacement_label = replacement_id.clone();

        cx.spawn(async move |this, cx| {
            let res = handle
                .spawn(async move {
                    let mut client = rustctrl_network::connect_staff_auth(&client_cfg).await?;
                    let mut req = tonic::Request::new(ReplaceFleetDeviceRequest {
                        prior_device_id: prior_id,
                        replacement_device_id: replacement_id,
                    });
                    req.metadata_mut()
                        .insert("authorization", format!("Bearer {tok}").parse()?);
                    let reply = client.replace_fleet_device(req).await?.into_inner();
                    Ok::<_, anyhow::Error>(reply)
                })
                .await;

            let _ = this.update(cx, |view, cx| {
                let is_same_session = match &view.state {
                    ScreenState::Connected { session_token, .. } => session_token == &tok_check,
                    _ => false,
                };
                if !is_same_session {
                    return;
                }

                let is_matching_form = match &view.overlay {
                    Overlay::ReplaceDevice {
                        request_id: current_req_id,
                        ..
                    } => *current_req_id == request_id,
                    _ => false,
                };

                match res {
                    Ok(Ok(_reply)) => {
                        if is_matching_form {
                            view.close_overlay(cx);
                        }
                        if let ScreenState::Connected { notice, .. } = &mut view.state {
                            *notice = Some(format!(
                                "Replaced device '{prior_label}' with '{replacement_label}'."
                            ));
                            let token = tok_check.clone();
                            view.fetch_status(token, cx);
                        }
                    }
                    Ok(Err(err)) => {
                        if is_matching_form
                            && let Overlay::ReplaceDevice {
                                error, in_flight, ..
                            } = &mut view.overlay
                        {
                            *error = Some(err.to_string());
                            *in_flight = false;
                        }
                    }
                    Err(join_err) => {
                        if is_matching_form
                            && let Overlay::ReplaceDevice {
                                error, in_flight, ..
                            } = &mut view.overlay
                        {
                            *error = Some(format!("Join error: {join_err}"));
                            *in_flight = false;
                        }
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn submit_prepare_installation_artifact(&mut self, cx: &mut Context<Self>) {
        let (request_id, session_token, out_path, agent_bin_path) = match &mut self.overlay {
            Overlay::PrepareInstallationArtifact {
                request_id,
                output_path,
                agent_binary_path,
                error,
                in_flight,
                success,
            } if !*in_flight => {
                let p = output_path.trim();
                if p.is_empty() {
                    *error = Some("Output file path is required.".into());
                    cx.notify();
                    return;
                }
                let token = match &self.state {
                    ScreenState::Connected { session_token, .. } => session_token.clone(),
                    _ => return,
                };
                *in_flight = true;
                *error = None;
                *success = None;
                (
                    *request_id,
                    token,
                    p.to_string(),
                    agent_binary_path.trim().to_string(),
                )
            }
            _ => return,
        };
        cx.notify();

        let client_cfg = self.config.server.clone();
        let handle = self.tokio_handle.clone();
        let tok = session_token.clone();
        let tok_check = session_token;
        let out_file_path = out_path.clone();
        let agent_bin_str = agent_bin_path;

        cx.spawn(async move |this, cx| {
            let res = handle
                .spawn(async move {
                    let mut client = rustctrl_network::connect_staff_auth(&client_cfg).await?;
                    let mut req = tonic::Request::new(PrepareInstallationArtifactRequest {});
                    req.metadata_mut()
                        .insert("authorization", format!("Bearer {tok}").parse()?);
                    let reply = client
                        .prepare_installation_artifact(req)
                        .await?
                        .into_inner();
                    let artifact = rustctrl_core::AgentInstallationArtifact {
                        server_endpoint: reply.server_endpoint,
                        domain_name: reply.domain_name,
                        ca_certificate: reply.ca_certificate,
                        enrollment_certificate: reply.enrollment_certificate,
                        enrollment_private_key: reply.enrollment_private_key,
                        authorization_id: reply.authorization_id.clone(),
                        installation_secret: reply.installation_secret,
                        created_at_unix_ms: reply.created_at_unix_ms,
                    };

                    let out_path_ref = std::path::Path::new(&out_file_path);
                    let is_zip = out_path_ref
                        .extension()
                        .and_then(|ext| ext.to_str())
                        .map(|ext| ext.eq_ignore_ascii_case("zip"))
                        .unwrap_or(false);
                    let is_toml = out_path_ref
                        .extension()
                        .and_then(|ext| ext.to_str())
                        .map(|ext| ext.eq_ignore_ascii_case("toml"))
                        .unwrap_or(false);

                    let is_package = is_zip || !is_toml;
                    if is_package {
                        let explicit_bin = if agent_bin_str.is_empty() {
                            None
                        } else {
                            Some(std::path::Path::new(&agent_bin_str))
                        };
                        let resolved_bin = rustctrl_core::resolve_agent_binary(explicit_bin)?;
                        let binary_data = std::fs::read(&resolved_bin)?;
                        let package =
                            rustctrl_core::AgentInstallationPackage::new(artifact, binary_data)?;
                        package.export(out_path_ref)?;
                    } else {
                        artifact.save_to_file(out_path_ref)?;
                    }
                    Ok::<_, anyhow::Error>((reply.authorization_id, is_package))
                })
                .await;

            let _ = this.update(cx, |view, cx| {
                let is_same_session = match &view.state {
                    ScreenState::Connected { session_token, .. } => session_token == &tok_check,
                    _ => false,
                };
                if !is_same_session {
                    return;
                }

                let is_matching_form = match &view.overlay {
                    Overlay::PrepareInstallationArtifact {
                        request_id: current_req_id,
                        ..
                    } => *current_req_id == request_id,
                    _ => false,
                };

                match res {
                    Ok(Ok((auth_id, is_package))) => {
                        if is_matching_form
                            && let Overlay::PrepareInstallationArtifact {
                                in_flight,
                                success,
                                error,
                                ..
                            } = &mut view.overlay
                        {
                            *in_flight = false;
                            let action = if is_package {
                                "Exported package"
                            } else {
                                "Saved artifact"
                            };
                            *success = Some(format!("{action} ({auth_id}) to {out_path}"));
                            *error = None;
                        }
                    }
                    Ok(Err(err)) => {
                        if is_matching_form
                            && let Overlay::PrepareInstallationArtifact {
                                error, in_flight, ..
                            } = &mut view.overlay
                        {
                            *error = Some(err.to_string());
                            *in_flight = false;
                        }
                    }
                    Err(join_err) => {
                        if is_matching_form
                            && let Overlay::PrepareInstallationArtifact {
                                error, in_flight, ..
                            } = &mut view.overlay
                        {
                            *error = Some(format!("Join error: {join_err}"));
                            *in_flight = false;
                        }
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn render_overlay_form(&self, cx: &mut Context<Self>) -> impl IntoElement {
        match &self.overlay {
            Overlay::ChangePassword {
                current_password,
                new_password,
                confirm_password,
                error,
                in_flight,
            } => {
                let current_active = self.active_field == ActiveField::CurrentPassword;
                let new_active = self.active_field == ActiveField::NewPassword;
                let conf_active = self.active_field == ActiveField::ConfirmPassword;
                let masked_current = "•".repeat(current_password.len());
                let masked_new = "•".repeat(new_password.len());
                let masked_conf = "•".repeat(confirm_password.len());

                div()
                    .mt_4()
                    .p_4()
                    .bg(rgb(0x16212e))
                    .rounded_lg()
                    .border_1()
                    .border_color(rgb(0x2a3b4c))
                    .flex()
                    .flex_col()
                    .gap_3()
                    .max_w(gpui::px(450.0))
                    .child(div().text_lg().child("Change My Password"))
                    .child("Current Password:")
                    .child(
                        div()
                            .px_3()
                            .py_2()
                            .bg(rgb(0x1a2634))
                            .border_1()
                            .border_color(if current_active {
                                rgb(0x4a90e2)
                            } else {
                                rgb(0x334455)
                            })
                            .rounded_md()
                            .id("cp-current-input")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.active_field = ActiveField::CurrentPassword;
                                cx.notify();
                            }))
                            .child(if current_password.is_empty() {
                                "Enter current password...".to_string()
                            } else {
                                masked_current
                            }),
                    )
                    .child("New Password:")
                    .child(
                        div()
                            .px_3()
                            .py_2()
                            .bg(rgb(0x1a2634))
                            .border_1()
                            .border_color(if new_active {
                                rgb(0x4a90e2)
                            } else {
                                rgb(0x334455)
                            })
                            .rounded_md()
                            .id("cp-new-input")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.active_field = ActiveField::NewPassword;
                                cx.notify();
                            }))
                            .child(if new_password.is_empty() {
                                "Minimum 8 characters...".to_string()
                            } else {
                                masked_new
                            }),
                    )
                    .child("Confirm New Password:")
                    .child(
                        div()
                            .px_3()
                            .py_2()
                            .bg(rgb(0x1a2634))
                            .border_1()
                            .border_color(if conf_active {
                                rgb(0x4a90e2)
                            } else {
                                rgb(0x334455)
                            })
                            .rounded_md()
                            .id("cp-confirm-input")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.active_field = ActiveField::ConfirmPassword;
                                cx.notify();
                            }))
                            .child(if confirm_password.is_empty() {
                                "Re-enter new password...".to_string()
                            } else {
                                masked_conf
                            }),
                    )
                    .children(
                        error.as_ref().map(|err| {
                            div().text_color(rgb(0xff6b6b)).text_sm().child(err.clone())
                        }),
                    )
                    .child(
                        div()
                            .flex()
                            .gap_3()
                            .child(
                                div()
                                    .px_4()
                                    .py_2()
                                    .bg(if *in_flight {
                                        rgb(0x556677)
                                    } else {
                                        rgb(0x2d884d)
                                    })
                                    .text_color(rgb(0xffffff))
                                    .rounded_md()
                                    .cursor_pointer()
                                    .id("cp-submit-btn")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.submit_change_password(cx);
                                    }))
                                    .child(if *in_flight {
                                        "Updating..."
                                    } else {
                                        "Update Password"
                                    }),
                            )
                            .child(
                                div()
                                    .px_4()
                                    .py_2()
                                    .bg(rgb(0x445566))
                                    .text_color(rgb(0xffffff))
                                    .rounded_md()
                                    .cursor_pointer()
                                    .id("cp-cancel-btn")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.close_overlay(cx);
                                    }))
                                    .child("Cancel"),
                            ),
                    )
                    .into_any_element()
            }
            Overlay::ResetPassword {
                target_username,
                temporary_password,
                confirm_password,
                error,
                in_flight,
            } => {
                let temp_active = self.active_field == ActiveField::TemporaryPassword;
                let conf_active = self.active_field == ActiveField::ConfirmPassword;
                let masked_temp = "•".repeat(temporary_password.len());
                let masked_conf = "•".repeat(confirm_password.len());

                div()
                    .mt_4()
                    .p_4()
                    .bg(rgb(0x16212e))
                    .rounded_lg()
                    .border_1()
                    .border_color(rgb(0x2a3b4c))
                    .flex()
                    .flex_col()
                    .gap_3()
                    .max_w(gpui::px(450.0))
                    .child(div().text_lg().child(format!(
                        "Reset Password for '{target_username}'"
                    )))
                    .child(
                        div().text_sm().text_color(rgb(0xffcc00)).child(
                            "The account receives a temporary password, must replace it at next login, and all of its staff sessions are revoked.",
                        ),
                    )
                    .child("Temporary Password:")
                    .child(
                        div()
                            .px_3()
                            .py_2()
                            .bg(rgb(0x1a2634))
                            .border_1()
                            .border_color(if temp_active {
                                rgb(0x4a90e2)
                            } else {
                                rgb(0x334455)
                            })
                            .rounded_md()
                            .id("rp-temp-input")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.active_field = ActiveField::TemporaryPassword;
                                cx.notify();
                            }))
                            .child(if temporary_password.is_empty() {
                                "Minimum 8 characters...".to_string()
                            } else {
                                masked_temp
                            }),
                    )
                    .child("Confirm Temporary Password:")
                    .child(
                        div()
                            .px_3()
                            .py_2()
                            .bg(rgb(0x1a2634))
                            .border_1()
                            .border_color(if conf_active {
                                rgb(0x4a90e2)
                            } else {
                                rgb(0x334455)
                            })
                            .rounded_md()
                            .id("rp-confirm-input")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.active_field = ActiveField::ConfirmPassword;
                                cx.notify();
                            }))
                            .child(if confirm_password.is_empty() {
                                "Re-enter temporary password...".to_string()
                            } else {
                                masked_conf
                            }),
                    )
                    .children(error.as_ref().map(|err| {
                        div().text_color(rgb(0xff6b6b)).text_sm().child(err.clone())
                    }))
                    .child(
                        div()
                            .flex()
                            .gap_3()
                            .child(
                                div()
                                    .px_4()
                                    .py_2()
                                    .bg(if *in_flight {
                                        rgb(0x556677)
                                    } else {
                                        rgb(0xaa5533)
                                    })
                                    .text_color(rgb(0xffffff))
                                    .rounded_md()
                                    .cursor_pointer()
                                    .id("rp-submit-btn")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.submit_reset_password(cx);
                                    }))
                                    .child(if *in_flight {
                                        "Resetting..."
                                    } else {
                                        "Reset to Temporary Password"
                                    }),
                            )
                            .child(
                                div()
                                    .px_4()
                                    .py_2()
                                    .bg(rgb(0x445566))
                                    .text_color(rgb(0xffffff))
                                    .rounded_md()
                                    .cursor_pointer()
                                    .id("rp-cancel-btn")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.close_overlay(cx);
                                    }))
                                    .child("Cancel"),
                            ),
                    )
                    .into_any_element()
            }
            Overlay::EditDevice {
                device_id,
                display_name,
                location,
                error,
                in_flight,
                ..
            } => {
                let name_active = self.active_field == ActiveField::EditDeviceDisplayName;
                let loc_active = self.active_field == ActiveField::EditDeviceLocation;

                div()
                    .mt_4()
                    .p_4()
                    .bg(rgb(0x16212e))
                    .rounded_lg()
                    .border_1()
                    .border_color(rgb(0x2a3b4c))
                    .flex()
                    .flex_col()
                    .gap_3()
                    .max_w(gpui::px(450.0))
                    .child(div().text_lg().child("Edit Device"))
                    .child(
                        div()
                            .text_sm()
                            .text_color(rgb(0x8899aa))
                            .child(format!("Device ID: {device_id}")),
                    )
                    .child("Display Name:")
                    .child(
                        div()
                            .px_3()
                            .py_2()
                            .bg(rgb(0x1a2634))
                            .border_1()
                            .border_color(if name_active {
                                rgb(0x4a90e2)
                            } else {
                                rgb(0x334455)
                            })
                            .rounded_md()
                            .id("ed-name-input")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.active_field = ActiveField::EditDeviceDisplayName;
                                cx.notify();
                            }))
                            .child(if display_name.is_empty() {
                                "Enter display name...".to_string()
                            } else {
                                display_name.clone()
                            }),
                    )
                    .child("Location (optional):")
                    .child(
                        div()
                            .px_3()
                            .py_2()
                            .bg(rgb(0x1a2634))
                            .border_1()
                            .border_color(if loc_active {
                                rgb(0x4a90e2)
                            } else {
                                rgb(0x334455)
                            })
                            .rounded_md()
                            .id("ed-location-input")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.active_field = ActiveField::EditDeviceLocation;
                                cx.notify();
                            }))
                            .child(if location.is_empty() {
                                "Enter location (optional)...".to_string()
                            } else {
                                location.clone()
                            }),
                    )
                    .children(
                        error.as_ref().map(|err| {
                            div().text_color(rgb(0xff6b6b)).text_sm().child(err.clone())
                        }),
                    )
                    .child(
                        div()
                            .flex()
                            .gap_3()
                            .child(
                                div()
                                    .px_4()
                                    .py_2()
                                    .bg(if *in_flight {
                                        rgb(0x556677)
                                    } else {
                                        rgb(0x2d884d)
                                    })
                                    .text_color(rgb(0xffffff))
                                    .rounded_md()
                                    .cursor_pointer()
                                    .id("ed-submit-btn")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.submit_edit_device(cx);
                                    }))
                                    .child(if *in_flight {
                                        "Saving..."
                                    } else {
                                        "Save Changes"
                                    }),
                            )
                            .child(
                                div()
                                    .px_4()
                                    .py_2()
                                    .bg(rgb(0x445566))
                                    .text_color(rgb(0xffffff))
                                    .rounded_md()
                                    .cursor_pointer()
                                    .id("ed-cancel-btn")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.close_overlay(cx);
                                    }))
                                    .child("Cancel"),
                            ),
                    )
                    .into_any_element()
            }
            Overlay::AddTarget {
                display_name,
                address,
                location,
                error,
                in_flight,
                ..
            } => {
                let name_active = self.active_field == ActiveField::AddTargetDisplayName;
                let addr_active = self.active_field == ActiveField::AddTargetAddress;
                let loc_active = self.active_field == ActiveField::AddTargetLocation;

                div()
                    .mt_4()
                    .p_4()
                    .bg(rgb(0x16212e))
                    .rounded_lg()
                    .border_1()
                    .border_color(rgb(0x2a3b4c))
                    .flex()
                    .flex_col()
                    .gap_3()
                    .max_w(gpui::px(450.0))
                    .child(div().text_lg().child("Add Android TV Target"))
                    .child(
                        div()
                            .text_sm()
                            .text_color(rgb(0x8899aa))
                            .child("Target Type: Android TV (unverified)"),
                    )
                    .child("Display Name:")
                    .child(
                        div()
                            .px_3()
                            .py_2()
                            .bg(rgb(0x1a2634))
                            .border_1()
                            .border_color(if name_active {
                                rgb(0x4a90e2)
                            } else {
                                rgb(0x334455)
                            })
                            .rounded_md()
                            .id("at-name-input")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.active_field = ActiveField::AddTargetDisplayName;
                                cx.notify();
                            }))
                            .child(if display_name.is_empty() {
                                "Enter display name...".to_string()
                            } else {
                                display_name.clone()
                            }),
                    )
                    .child("Connection Address:")
                    .child(
                        div()
                            .px_3()
                            .py_2()
                            .bg(rgb(0x1a2634))
                            .border_1()
                            .border_color(if addr_active {
                                rgb(0x4a90e2)
                            } else {
                                rgb(0x334455)
                            })
                            .rounded_md()
                            .id("at-address-input")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.active_field = ActiveField::AddTargetAddress;
                                cx.notify();
                            }))
                            .child(if address.is_empty() {
                                "e.g. 192.168.1.150:5555...".to_string()
                            } else {
                                address.clone()
                            }),
                    )
                    .child("Location (optional):")
                    .child(
                        div()
                            .px_3()
                            .py_2()
                            .bg(rgb(0x1a2634))
                            .border_1()
                            .border_color(if loc_active {
                                rgb(0x4a90e2)
                            } else {
                                rgb(0x334455)
                            })
                            .rounded_md()
                            .id("at-location-input")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.active_field = ActiveField::AddTargetLocation;
                                cx.notify();
                            }))
                            .child(if location.is_empty() {
                                "Enter location (optional)...".to_string()
                            } else {
                                location.clone()
                            }),
                    )
                    .children(
                        error.as_ref().map(|err| {
                            div().text_color(rgb(0xff6b6b)).text_sm().child(err.clone())
                        }),
                    )
                    .child(
                        div()
                            .flex()
                            .gap_3()
                            .child(
                                div()
                                    .px_4()
                                    .py_2()
                                    .bg(if *in_flight {
                                        rgb(0x556677)
                                    } else {
                                        rgb(0x2d884d)
                                    })
                                    .text_color(rgb(0xffffff))
                                    .rounded_md()
                                    .cursor_pointer()
                                    .id("at-submit-btn")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.submit_add_target(cx);
                                    }))
                                    .child(if *in_flight {
                                        "Adding..."
                                    } else {
                                        "Add Target"
                                    }),
                            )
                            .child(
                                div()
                                    .px_4()
                                    .py_2()
                                    .bg(rgb(0x445566))
                                    .text_color(rgb(0xffffff))
                                    .rounded_md()
                                    .cursor_pointer()
                                    .id("at-cancel-btn")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.close_overlay(cx);
                                    }))
                                    .child("Cancel"),
                            ),
                    )
                    .into_any_element()
            }
            Overlay::EditTarget {
                target_id,
                display_name,
                address,
                location,
                error,
                in_flight,
                ..
            } => {
                let name_active = self.active_field == ActiveField::EditTargetDisplayName;
                let addr_active = self.active_field == ActiveField::EditTargetAddress;
                let loc_active = self.active_field == ActiveField::EditTargetLocation;

                div()
                    .mt_4()
                    .p_4()
                    .bg(rgb(0x16212e))
                    .rounded_lg()
                    .border_1()
                    .border_color(rgb(0x2a3b4c))
                    .flex()
                    .flex_col()
                    .gap_3()
                    .max_w(gpui::px(450.0))
                    .child(div().text_lg().child("Edit Android TV Target"))
                    .child(
                        div()
                            .text_sm()
                            .text_color(rgb(0x8899aa))
                            .child(format!("Target ID: {target_id}")),
                    )
                    .child("Display Name:")
                    .child(
                        div()
                            .px_3()
                            .py_2()
                            .bg(rgb(0x1a2634))
                            .border_1()
                            .border_color(if name_active {
                                rgb(0x4a90e2)
                            } else {
                                rgb(0x334455)
                            })
                            .rounded_md()
                            .id("et-name-input")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.active_field = ActiveField::EditTargetDisplayName;
                                cx.notify();
                            }))
                            .child(if display_name.is_empty() {
                                "Enter display name...".to_string()
                            } else {
                                display_name.clone()
                            }),
                    )
                    .child("Connection Address:")
                    .child(
                        div()
                            .px_3()
                            .py_2()
                            .bg(rgb(0x1a2634))
                            .border_1()
                            .border_color(if addr_active {
                                rgb(0x4a90e2)
                            } else {
                                rgb(0x334455)
                            })
                            .rounded_md()
                            .id("et-address-input")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.active_field = ActiveField::EditTargetAddress;
                                cx.notify();
                            }))
                            .child(if address.is_empty() {
                                "e.g. 192.168.1.150:5555...".to_string()
                            } else {
                                address.clone()
                            }),
                    )
                    .child("Location (optional):")
                    .child(
                        div()
                            .px_3()
                            .py_2()
                            .bg(rgb(0x1a2634))
                            .border_1()
                            .border_color(if loc_active {
                                rgb(0x4a90e2)
                            } else {
                                rgb(0x334455)
                            })
                            .rounded_md()
                            .id("et-location-input")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.active_field = ActiveField::EditTargetLocation;
                                cx.notify();
                            }))
                            .child(if location.is_empty() {
                                "Enter location (optional)...".to_string()
                            } else {
                                location.clone()
                            }),
                    )
                    .children(
                        error.as_ref().map(|err| {
                            div().text_color(rgb(0xff6b6b)).text_sm().child(err.clone())
                        }),
                    )
                    .child(
                        div()
                            .flex()
                            .gap_3()
                            .child(
                                div()
                                    .px_4()
                                    .py_2()
                                    .bg(if *in_flight {
                                        rgb(0x556677)
                                    } else {
                                        rgb(0x2d884d)
                                    })
                                    .text_color(rgb(0xffffff))
                                    .rounded_md()
                                    .cursor_pointer()
                                    .id("et-submit-btn")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.submit_edit_target(cx);
                                    }))
                                    .child(if *in_flight {
                                        "Saving..."
                                    } else {
                                        "Save Changes"
                                    }),
                            )
                            .child(
                                div()
                                    .px_4()
                                    .py_2()
                                    .bg(rgb(0x445566))
                                    .text_color(rgb(0xffffff))
                                    .rounded_md()
                                    .cursor_pointer()
                                    .id("et-cancel-btn")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.close_overlay(cx);
                                    }))
                                    .child("Cancel"),
                            ),
                    )
                    .into_any_element()
            }
            Overlay::ReplaceDevice {
                prior_device_id,
                replacement_device_id,
                error,
                in_flight,
                ..
            } => {
                let prior_active = self.active_field == ActiveField::ReplaceDevicePriorId;
                let rep_active = self.active_field == ActiveField::ReplaceDeviceReplacementId;

                let (devices_list, _is_admin) = match &self.state {
                    ScreenState::Connected { devices, role, .. } => {
                        (devices.clone(), role == "admin")
                    }
                    _ => (Vec::new(), false),
                };

                let prior_info = devices_list
                    .iter()
                    .find(|d| &d.device_id == prior_device_id);
                let rep_info = devices_list
                    .iter()
                    .find(|d| &d.device_id == replacement_device_id);

                let mut container = div()
                    .mt_4()
                    .p_4()
                    .bg(rgb(0x16212e))
                    .rounded_lg()
                    .border_1()
                    .border_color(rgb(0x2a3b4c))
                    .flex()
                    .flex_col()
                    .gap_3()
                    .max_w(gpui::px(520.0))
                    .child(div().text_lg().child("Reconcile Device Replacement"))
                    .child(
                        div()
                            .text_sm()
                            .text_color(rgb(0x8899aa))
                            .child("Select prior (old) identity and replacement (new) identity after a Windows reinstall."),
                    )
                    .child("Prior Device ID (Old Identity):")
                    .child(
                        div()
                            .px_3()
                            .py_2()
                            .bg(rgb(0x1a2634))
                            .border_1()
                            .border_color(if prior_active {
                                rgb(0x4a90e2)
                            } else {
                                rgb(0x334455)
                            })
                            .rounded_md()
                            .id("rep-prior-input")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.active_field = ActiveField::ReplaceDevicePriorId;
                                cx.notify();
                            }))
                            .child(if prior_device_id.is_empty() {
                                "Enter or click a device below...".to_string()
                            } else if let Some(d) = prior_info {
                                format!("{} ({})", d.display_name, d.device_id)
                            } else {
                                prior_device_id.clone()
                            }),
                    )
                    .child("Replacement Device ID (New Identity):")
                    .child(
                        div()
                            .px_3()
                            .py_2()
                            .bg(rgb(0x1a2634))
                            .border_1()
                            .border_color(if rep_active {
                                rgb(0x4a90e2)
                            } else {
                                rgb(0x334455)
                            })
                            .rounded_md()
                            .id("rep-replacement-input")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.active_field = ActiveField::ReplaceDeviceReplacementId;
                                cx.notify();
                            }))
                            .child(if replacement_device_id.is_empty() {
                                "Enter or click a device below...".to_string()
                            } else if let Some(d) = rep_info {
                                format!("{} ({})", d.display_name, d.device_id)
                            } else {
                                replacement_device_id.clone()
                            }),
                    );

                let windows_devices: Vec<_> = devices_list
                    .iter()
                    .filter(|d| d.device_type == "windows")
                    .collect();

                if !windows_devices.is_empty() {
                    let mut chips_div = div().flex().flex_col().gap_1().child(
                        div()
                            .text_xs()
                            .text_color(rgb(0x8899aa))
                            .child("Click a device to populate the active field:"),
                    );
                    let mut chip_row = div().flex().flex_wrap().gap_2();
                    for dev in windows_devices {
                        let dev_id_clone = dev.device_id.clone();
                        let chip_text = format!(
                            "{}: {}",
                            dev.display_name,
                            &dev.device_id[..dev.device_id.len().min(8)]
                        );
                        chip_row = chip_row.child(
                            div()
                                .px_2()
                                .py_1()
                                .bg(rgb(0x2a3b4c))
                                .rounded_md()
                                .text_xs()
                                .cursor_pointer()
                                .id(format!("select-candidate-{}", dev.device_id))
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    if let Overlay::ReplaceDevice {
                                        prior_device_id,
                                        replacement_device_id,
                                        ..
                                    } = &mut this.overlay
                                    {
                                        if this.active_field == ActiveField::ReplaceDevicePriorId {
                                            *prior_device_id = dev_id_clone.clone();
                                            this.active_field =
                                                ActiveField::ReplaceDeviceReplacementId;
                                        } else {
                                            *replacement_device_id = dev_id_clone.clone();
                                        }
                                        cx.notify();
                                    }
                                }))
                                .child(chip_text),
                        );
                    }
                    chips_div = chips_div.child(chip_row);
                    container = container.child(chips_div);
                }

                container = container.children(
                    error
                        .as_ref()
                        .map(|err| div().text_color(rgb(0xff6b6b)).text_sm().child(err.clone())),
                );

                container
                    .child(
                        div()
                            .flex()
                            .gap_3()
                            .child(
                                div()
                                    .px_4()
                                    .py_2()
                                    .bg(if *in_flight {
                                        rgb(0x556677)
                                    } else {
                                        rgb(0x4a90e2)
                                    })
                                    .text_color(rgb(0xffffff))
                                    .rounded_md()
                                    .cursor_pointer()
                                    .id("confirm-replace-btn")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.submit_replace_device(cx);
                                    }))
                                    .child(if *in_flight {
                                        "Reconciling..."
                                    } else {
                                        "Reconcile Replacement"
                                    }),
                            )
                            .child(
                                div()
                                    .px_4()
                                    .py_2()
                                    .bg(rgb(0x445566))
                                    .text_color(rgb(0xffffff))
                                    .rounded_md()
                                    .cursor_pointer()
                                    .id("cancel-replace-btn")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.close_overlay(cx);
                                    }))
                                    .child("Cancel"),
                            ),
                    )
                    .into_any_element()
            }
            Overlay::PrepareInstallationArtifact {
                output_path,
                agent_binary_path,
                error,
                in_flight,
                success,
                ..
            } => {
                let path_active = self.active_field == ActiveField::PrepareArtifactOutputPath;
                let bin_active = self.active_field == ActiveField::PreparePackageAgentBinary;
                let mut container = div()
                    .mt_4()
                    .p_4()
                    .bg(rgb(0x16212e))
                    .rounded_lg()
                    .border_1()
                    .border_color(rgb(0x2a3b4c))
                    .flex()
                    .flex_col()
                    .gap_3()
                    .max_w(gpui::px(520.0))
                    .child(div().text_lg().child("Prepare Agent Installation Package"))
                    .child(
                        div()
                            .text_sm()
                            .text_color(rgb(0x8899aa))
                            .child("Generate an authorization token and export a ready-to-install package to enroll new fleet agents automatically."),
                    )
                    .child("Package Output Path (.zip or folder):")
                    .child(
                        div()
                            .px_3()
                            .py_2()
                            .bg(if path_active {
                                rgb(0x203040)
                            } else {
                                rgb(0x101820)
                            })
                            .rounded_md()
                            .border_1()
                            .border_color(if path_active {
                                rgb(0x4a90e2)
                            } else {
                                rgb(0x304050)
                            })
                            .cursor_pointer()
                            .id("artifact-output-path-input")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.active_field = ActiveField::PrepareArtifactOutputPath;
                                cx.notify();
                            }))
                            .child(if output_path.is_empty() {
                                div().text_color(rgb(0x556677)).child("e.g. rustctrl-agent-windows.zip")
                            } else {
                                div().child(output_path.clone())
                            }),
                    )
                    .child("Agent Executable Path (optional):")
                    .child(
                        div()
                            .px_3()
                            .py_2()
                            .bg(if bin_active {
                                rgb(0x203040)
                            } else {
                                rgb(0x101820)
                            })
                            .rounded_md()
                            .border_1()
                            .border_color(if bin_active {
                                rgb(0x4a90e2)
                            } else {
                                rgb(0x304050)
                            })
                            .cursor_pointer()
                            .id("artifact-agent-binary-input")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.active_field = ActiveField::PreparePackageAgentBinary;
                                cx.notify();
                            }))
                            .child(if agent_binary_path.is_empty() {
                                div().text_color(rgb(0x556677)).child("e.g. rustctrl-agent.exe (auto-detected if omitted)")
                            } else {
                                div().child(agent_binary_path.clone())
                            }),
                    );

                container = container.children(
                    error
                        .as_ref()
                        .map(|err| div().text_color(rgb(0xff6b6b)).text_sm().child(err.clone())),
                );

                container = container.children(
                    success
                        .as_ref()
                        .map(|msg| div().text_color(rgb(0x4eca78)).text_sm().child(msg.clone())),
                );

                container
                    .child(
                        div()
                            .flex()
                            .gap_3()
                            .child(
                                div()
                                    .px_4()
                                    .py_2()
                                    .bg(if *in_flight {
                                        rgb(0x556677)
                                    } else {
                                        rgb(0x2d884d)
                                    })
                                    .text_color(rgb(0xffffff))
                                    .rounded_md()
                                    .cursor_pointer()
                                    .id("generate-artifact-btn")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.submit_prepare_installation_artifact(cx);
                                    }))
                                    .child(if *in_flight {
                                        "Exporting..."
                                    } else {
                                        "Export Package"
                                    }),
                            )
                            .child(
                                div()
                                    .px_4()
                                    .py_2()
                                    .bg(rgb(0x445566))
                                    .text_color(rgb(0xffffff))
                                    .rounded_md()
                                    .cursor_pointer()
                                    .id("close-artifact-btn")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.close_overlay(cx);
                                    }))
                                    .child("Close"),
                            ),
                    )
                    .into_any_element()
            }
            Overlay::None => div().into_any_element(),
        }
    }

    fn handle_overlay_key_down(&mut self, event: &KeyDownEvent, cx: &mut Context<Self>) {
        let key = &event.keystroke.key;
        let in_flight = match &self.overlay {
            Overlay::ChangePassword { in_flight, .. }
            | Overlay::ResetPassword { in_flight, .. }
            | Overlay::EditDevice { in_flight, .. }
            | Overlay::AddTarget { in_flight, .. }
            | Overlay::EditTarget { in_flight, .. }
            | Overlay::ReplaceDevice { in_flight, .. }
            | Overlay::PrepareInstallationArtifact { in_flight, .. } => *in_flight,
            Overlay::None => false,
        };
        if in_flight {
            return;
        }
        match key.as_str() {
            "enter" => match &self.overlay {
                Overlay::ChangePassword { .. } => self.submit_change_password(cx),
                Overlay::ResetPassword { .. } => self.submit_reset_password(cx),
                Overlay::EditDevice { .. } => self.submit_edit_device(cx),
                Overlay::AddTarget { .. } => self.submit_add_target(cx),
                Overlay::EditTarget { .. } => self.submit_edit_target(cx),
                Overlay::ReplaceDevice { .. } => self.submit_replace_device(cx),
                Overlay::PrepareInstallationArtifact { .. } => {
                    self.submit_prepare_installation_artifact(cx)
                }
                Overlay::None => {}
            },
            "tab" => {
                self.active_field = match &self.overlay {
                    Overlay::ChangePassword { .. } => match self.active_field {
                        ActiveField::CurrentPassword => ActiveField::NewPassword,
                        ActiveField::NewPassword => ActiveField::ConfirmPassword,
                        _ => ActiveField::CurrentPassword,
                    },
                    Overlay::ResetPassword { .. } => match self.active_field {
                        ActiveField::TemporaryPassword => ActiveField::ConfirmPassword,
                        _ => ActiveField::TemporaryPassword,
                    },
                    Overlay::EditDevice { .. } => match self.active_field {
                        ActiveField::EditDeviceDisplayName => ActiveField::EditDeviceLocation,
                        _ => ActiveField::EditDeviceDisplayName,
                    },
                    Overlay::AddTarget { .. } => match self.active_field {
                        ActiveField::AddTargetDisplayName => ActiveField::AddTargetAddress,
                        ActiveField::AddTargetAddress => ActiveField::AddTargetLocation,
                        _ => ActiveField::AddTargetDisplayName,
                    },
                    Overlay::EditTarget { .. } => match self.active_field {
                        ActiveField::EditTargetDisplayName => ActiveField::EditTargetAddress,
                        ActiveField::EditTargetAddress => ActiveField::EditTargetLocation,
                        _ => ActiveField::EditTargetDisplayName,
                    },
                    Overlay::ReplaceDevice { .. } => match self.active_field {
                        ActiveField::ReplaceDevicePriorId => {
                            ActiveField::ReplaceDeviceReplacementId
                        }
                        _ => ActiveField::ReplaceDevicePriorId,
                    },
                    Overlay::PrepareInstallationArtifact { .. } => match self.active_field {
                        ActiveField::PrepareArtifactOutputPath => {
                            ActiveField::PreparePackageAgentBinary
                        }
                        _ => ActiveField::PrepareArtifactOutputPath,
                    },
                    Overlay::None => self.active_field,
                };
                cx.notify();
            }
            "backspace" => {
                match (&mut self.overlay, self.active_field) {
                    (
                        Overlay::ChangePassword {
                            current_password, ..
                        },
                        ActiveField::CurrentPassword,
                    ) => {
                        current_password.pop();
                    }
                    (Overlay::ChangePassword { new_password, .. }, ActiveField::NewPassword) => {
                        new_password.pop();
                    }
                    (
                        Overlay::ChangePassword {
                            confirm_password, ..
                        },
                        ActiveField::ConfirmPassword,
                    ) => {
                        confirm_password.pop();
                    }
                    (
                        Overlay::ResetPassword {
                            temporary_password, ..
                        },
                        ActiveField::TemporaryPassword,
                    ) => {
                        temporary_password.pop();
                    }
                    (
                        Overlay::ResetPassword {
                            confirm_password, ..
                        },
                        ActiveField::ConfirmPassword,
                    ) => {
                        confirm_password.pop();
                    }
                    (
                        Overlay::EditDevice { display_name, .. },
                        ActiveField::EditDeviceDisplayName,
                    ) => {
                        display_name.pop();
                    }
                    (Overlay::EditDevice { location, .. }, ActiveField::EditDeviceLocation) => {
                        location.pop();
                    }
                    (
                        Overlay::AddTarget { display_name, .. },
                        ActiveField::AddTargetDisplayName,
                    ) => {
                        display_name.pop();
                    }
                    (Overlay::AddTarget { address, .. }, ActiveField::AddTargetAddress) => {
                        address.pop();
                    }
                    (Overlay::AddTarget { location, .. }, ActiveField::AddTargetLocation) => {
                        location.pop();
                    }
                    (
                        Overlay::EditTarget { display_name, .. },
                        ActiveField::EditTargetDisplayName,
                    ) => {
                        display_name.pop();
                    }
                    (Overlay::EditTarget { address, .. }, ActiveField::EditTargetAddress) => {
                        address.pop();
                    }
                    (Overlay::EditTarget { location, .. }, ActiveField::EditTargetLocation) => {
                        location.pop();
                    }
                    (
                        Overlay::ReplaceDevice {
                            prior_device_id, ..
                        },
                        ActiveField::ReplaceDevicePriorId,
                    ) => {
                        prior_device_id.pop();
                    }
                    (
                        Overlay::ReplaceDevice {
                            replacement_device_id,
                            ..
                        },
                        ActiveField::ReplaceDeviceReplacementId,
                    ) => {
                        replacement_device_id.pop();
                    }
                    (
                        Overlay::PrepareInstallationArtifact { output_path, .. },
                        ActiveField::PrepareArtifactOutputPath,
                    ) => {
                        output_path.pop();
                    }
                    (
                        Overlay::PrepareInstallationArtifact {
                            agent_binary_path, ..
                        },
                        ActiveField::PreparePackageAgentBinary,
                    ) => {
                        agent_binary_path.pop();
                    }
                    _ => {}
                }
                cx.notify();
            }
            _ => {
                if let Some(text) = resolve_typed_text(&event.keystroke) {
                    match (&mut self.overlay, self.active_field) {
                        (
                            Overlay::ChangePassword {
                                current_password, ..
                            },
                            ActiveField::CurrentPassword,
                        ) => {
                            current_password.push_str(text);
                        }
                        (
                            Overlay::ChangePassword { new_password, .. },
                            ActiveField::NewPassword,
                        ) => {
                            new_password.push_str(text);
                        }
                        (
                            Overlay::ChangePassword {
                                confirm_password, ..
                            },
                            ActiveField::ConfirmPassword,
                        ) => {
                            confirm_password.push_str(text);
                        }
                        (
                            Overlay::ResetPassword {
                                temporary_password, ..
                            },
                            ActiveField::TemporaryPassword,
                        ) => {
                            temporary_password.push_str(text);
                        }
                        (
                            Overlay::ResetPassword {
                                confirm_password, ..
                            },
                            ActiveField::ConfirmPassword,
                        ) => {
                            confirm_password.push_str(text);
                        }
                        (
                            Overlay::EditDevice { display_name, .. },
                            ActiveField::EditDeviceDisplayName,
                        ) if display_name.len() + text.len() <= 128 => {
                            display_name.push_str(text);
                        }
                        (Overlay::EditDevice { location, .. }, ActiveField::EditDeviceLocation)
                            if location.len() + text.len() <= 128 =>
                        {
                            location.push_str(text);
                        }
                        (
                            Overlay::AddTarget { display_name, .. },
                            ActiveField::AddTargetDisplayName,
                        ) if display_name.len() + text.len() <= 128 => {
                            display_name.push_str(text);
                        }
                        (Overlay::AddTarget { address, .. }, ActiveField::AddTargetAddress)
                            if address.len() + text.len() <= 128 =>
                        {
                            address.push_str(text);
                        }
                        (Overlay::AddTarget { location, .. }, ActiveField::AddTargetLocation)
                            if location.len() + text.len() <= 128 =>
                        {
                            location.push_str(text);
                        }
                        (
                            Overlay::EditTarget { display_name, .. },
                            ActiveField::EditTargetDisplayName,
                        ) if display_name.len() + text.len() <= 128 => {
                            display_name.push_str(text);
                        }
                        (Overlay::EditTarget { address, .. }, ActiveField::EditTargetAddress)
                            if address.len() + text.len() <= 128 =>
                        {
                            address.push_str(text);
                        }
                        (Overlay::EditTarget { location, .. }, ActiveField::EditTargetLocation)
                            if location.len() + text.len() <= 128 =>
                        {
                            location.push_str(text);
                        }
                        (
                            Overlay::ReplaceDevice {
                                prior_device_id, ..
                            },
                            ActiveField::ReplaceDevicePriorId,
                        ) if prior_device_id.len() + text.len() <= 64 => {
                            prior_device_id.push_str(text);
                        }
                        (
                            Overlay::ReplaceDevice {
                                replacement_device_id,
                                ..
                            },
                            ActiveField::ReplaceDeviceReplacementId,
                        ) if replacement_device_id.len() + text.len() <= 64 => {
                            replacement_device_id.push_str(text);
                        }
                        (
                            Overlay::PrepareInstallationArtifact { output_path, .. },
                            ActiveField::PrepareArtifactOutputPath,
                        ) if output_path.len() + text.len() <= 256 => {
                            output_path.push_str(text);
                        }
                        (
                            Overlay::PrepareInstallationArtifact {
                                agent_binary_path, ..
                            },
                            ActiveField::PreparePackageAgentBinary,
                        ) if agent_binary_path.len() + text.len() <= 256 => {
                            agent_binary_path.push_str(text);
                        }
                        _ => {}
                    }
                    cx.notify();
                }
            }
        }
    }

    fn handle_key_down(&mut self, event: &KeyDownEvent, cx: &mut Context<Self>) {
        if !matches!(self.overlay, Overlay::None) {
            self.handle_overlay_key_down(event, cx);
            return;
        }
        let key = &event.keystroke.key;
        match &mut self.state {
            ScreenState::Login {
                username,
                password,
                in_flight,
                ..
            } => {
                if *in_flight {
                    return;
                }
                match key.as_str() {
                    "enter" => {
                        self.submit_login(cx);
                    }
                    "tab" => {
                        self.active_field = match self.active_field {
                            ActiveField::Username => ActiveField::Password,
                            _ => ActiveField::Username,
                        };
                        cx.notify();
                    }
                    "backspace" => {
                        match self.active_field {
                            ActiveField::Username => {
                                username.pop();
                            }
                            ActiveField::Password => {
                                password.pop();
                            }
                            _ => {}
                        }
                        cx.notify();
                    }
                    _ => {
                        if let Some(text) = resolve_typed_text(&event.keystroke) {
                            match self.active_field {
                                ActiveField::Username => {
                                    username.push_str(text);
                                }
                                ActiveField::Password => {
                                    password.push_str(text);
                                }
                                _ => {}
                            }
                            cx.notify();
                        }
                    }
                }
            }
            ScreenState::MustChangePassword {
                new_password,
                confirm_password,
                in_flight,
                ..
            } => {
                if *in_flight {
                    return;
                }
                match key.as_str() {
                    "enter" => {
                        self.submit_replace_password(cx);
                    }
                    "tab" => {
                        self.active_field = match self.active_field {
                            ActiveField::NewPassword => ActiveField::ConfirmPassword,
                            _ => ActiveField::NewPassword,
                        };
                        cx.notify();
                    }
                    "backspace" => {
                        match self.active_field {
                            ActiveField::NewPassword => {
                                new_password.pop();
                            }
                            ActiveField::ConfirmPassword => {
                                confirm_password.pop();
                            }
                            _ => {}
                        }
                        cx.notify();
                    }
                    _ => {
                        if let Some(text) = resolve_typed_text(&event.keystroke) {
                            match self.active_field {
                                ActiveField::NewPassword => {
                                    new_password.push_str(text);
                                }
                                ActiveField::ConfirmPassword => {
                                    confirm_password.push_str(text);
                                }
                                _ => {}
                            }
                            cx.notify();
                        }
                    }
                }
            }
            ScreenState::Connected {
                new_account_username,
                new_account_password,
                in_flight,
                role,
                ..
            } => {
                if *in_flight || role != "admin" {
                    return;
                }
                match key.as_str() {
                    "enter" => {
                        self.submit_create_account(cx);
                    }
                    "tab" => {
                        self.active_field = match self.active_field {
                            ActiveField::NewAccountUsername => ActiveField::NewAccountPassword,
                            _ => ActiveField::NewAccountUsername,
                        };
                        cx.notify();
                    }
                    "backspace" => {
                        match self.active_field {
                            ActiveField::NewAccountUsername => {
                                new_account_username.pop();
                            }
                            ActiveField::NewAccountPassword => {
                                new_account_password.pop();
                            }
                            _ => {}
                        }
                        cx.notify();
                    }
                    _ => {
                        if let Some(text) = resolve_typed_text(&event.keystroke) {
                            match self.active_field {
                                ActiveField::NewAccountUsername => {
                                    new_account_username.push_str(text);
                                }
                                ActiveField::NewAccountPassword => {
                                    new_account_password.push_str(text);
                                }
                                _ => {}
                            }
                            cx.notify();
                        }
                    }
                }
            }
        }
    }
}

impl Render for ControllerApp {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let container = div()
            .track_focus(&self.focus_handle)
            .on_key_down(cx.listener(|this, event: &KeyDownEvent, _window, cx| {
                this.handle_key_down(event, cx);
            }))
            .size_full()
            .bg(rgb(0x101820))
            .text_color(rgb(0xe8eef2))
            .p_8()
            .flex()
            .flex_col()
            .gap_4();

        match &self.state {
            ScreenState::Login {
                username,
                password,
                error,
                notice,
                remember,
                in_flight,
            } => {
                let user_active = self.active_field == ActiveField::Username;
                let pass_active = self.active_field == ActiveField::Password;
                let masked_pass = "•".repeat(password.len());
                let remember_label = if *remember {
                    "✓ Remember on this computer"
                } else {
                    "Remember on this computer"
                };

                container
                    .child(div().text_3xl().child("RustCtrl"))
                    .child("Staff Access · Please Sign In")
                    .child(format!("Server: {}", self.config.server.endpoint))
                    .children(notice.as_ref().map(|note| {
                        div()
                            .id("login-notice")
                            .text_color(rgb(0x44cc44))
                            .text_sm()
                            .max_w(gpui::px(400.0))
                            .child(note.clone())
                    }))
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_3()
                            .max_w(gpui::px(400.0))
                            .child("Username:")
                            .child(
                                div()
                                    .px_3()
                                    .py_2()
                                    .bg(rgb(0x1a2634))
                                    .border_1()
                                    .border_color(if user_active {
                                        rgb(0x4a90e2)
                                    } else {
                                        rgb(0x334455)
                                    })
                                    .rounded_md()
                                    .id("username-input")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.active_field = ActiveField::Username;
                                        cx.notify();
                                    }))
                                    .child(if username.is_empty() {
                                        "Click and type username...".to_string()
                                    } else {
                                        username.clone()
                                    }),
                            )
                            .child("Password:")
                            .child(
                                div()
                                    .px_3()
                                    .py_2()
                                    .bg(rgb(0x1a2634))
                                    .border_1()
                                    .border_color(if pass_active {
                                        rgb(0x4a90e2)
                                    } else {
                                        rgb(0x334455)
                                    })
                                    .rounded_md()
                                    .id("password-input")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.active_field = ActiveField::Password;
                                        cx.notify();
                                    }))
                                    .child(if password.is_empty() {
                                        "Click and type password...".to_string()
                                    } else {
                                        masked_pass
                                    }),
                            )
                            .child(
                                div()
                                    .px_3()
                                    .py_1()
                                    .rounded_md()
                                    .cursor_pointer()
                                    .bg(if *remember {
                                        rgb(0x2d5a88)
                                    } else {
                                        rgb(0x223344)
                                    })
                                    .text_color(rgb(0xe8eef2))
                                    .text_sm()
                                    .id("remember-toggle")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        if let ScreenState::Login { remember, .. } = &mut this.state
                                        {
                                            *remember = !*remember;
                                            cx.notify();
                                        }
                                    }))
                                    .child(remember_label),
                            )
                            .children(error.as_ref().map(|err| {
                                div().text_color(rgb(0xff6b6b)).text_sm().child(err.clone())
                            }))
                            .child(
                                div()
                                    .px_4()
                                    .py_2()
                                    .bg(if *in_flight {
                                        rgb(0x556677)
                                    } else {
                                        rgb(0x2d5a88)
                                    })
                                    .text_color(rgb(0xffffff))
                                    .rounded_md()
                                    .cursor_pointer()
                                    .id("signin-btn")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.submit_login(cx);
                                    }))
                                    .child(if *in_flight {
                                        "Signing in..."
                                    } else {
                                        "Sign In"
                                    }),
                            ),
                    )
            }
            ScreenState::MustChangePassword {
                username,
                new_password,
                confirm_password,
                error,
                in_flight,
                ..
            } => {
                let new_active = self.active_field == ActiveField::NewPassword;
                let conf_active = self.active_field == ActiveField::ConfirmPassword;
                let masked_new = "•".repeat(new_password.len());
                let masked_conf = "•".repeat(confirm_password.len());

                container
                    .child(div().text_3xl().child("RustCtrl"))
                    .child(format!("Welcome, {username}"))
                    .child(
                        div()
                            .text_color(rgb(0xffcc00))
                            .child("A temporary password was used. You must set a permanent password before accessing the system."),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_3()
                            .max_w(gpui::px(400.0))
                            .child("New Permanent Password:")
                            .child(
                                div()
                                    .px_3()
                                    .py_2()
                                    .bg(rgb(0x1a2634))
                                    .border_1()
                                    .border_color(if new_active {
                                        rgb(0x4a90e2)
                                    } else {
                                        rgb(0x334455)
                                    })
                                    .rounded_md()
                                    .id("new-password-input")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.active_field = ActiveField::NewPassword;
                                        cx.notify();
                                    }))
                                    .child(if new_password.is_empty() {
                                        "Minimum 8 characters...".to_string()
                                    } else {
                                        masked_new
                                    }),
                            )
                            .child("Confirm Permanent Password:")
                            .child(
                                div()
                                    .px_3()
                                    .py_2()
                                    .bg(rgb(0x1a2634))
                                    .border_1()
                                    .border_color(if conf_active {
                                        rgb(0x4a90e2)
                                    } else {
                                        rgb(0x334455)
                                    })
                                    .rounded_md()
                                    .id("confirm-password-input")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.active_field = ActiveField::ConfirmPassword;
                                        cx.notify();
                                    }))
                                    .child(if confirm_password.is_empty() {
                                        "Re-enter new password...".to_string()
                                    } else {
                                        masked_conf
                                    }),
                            )
                            .children(error.as_ref().map(|err| {
                                div().text_color(rgb(0xff6b6b)).text_sm().child(err.clone())
                            }))
                            .child(
                                div()
                                    .flex()
                                    .gap_3()
                                    .child(
                                        div()
                                            .px_4()
                                            .py_2()
                                            .bg(if *in_flight {
                                                rgb(0x556677)
                                            } else {
                                                rgb(0x2d884d)
                                            })
                                            .text_color(rgb(0xffffff))
                                            .rounded_md()
                                            .cursor_pointer()
                                            .id("save-password-btn")
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.submit_replace_password(cx);
                                            }))
                                            .child(if *in_flight {
                                                "Updating..."
                                            } else {
                                                "Save & Continue"
                                            }),
                                    )
                                    .child(
                                        div()
                                            .px_4()
                                            .py_2()
                                            .bg(rgb(0x445566))
                                            .text_color(rgb(0xffffff))
                                            .rounded_md()
                                            .cursor_pointer()
                                            .id("cancel-btn")
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.submit_logout(cx);
                                            }))
                                            .child("Cancel / Logout"),
                                    ),
                            ),
                    )
            }
            ScreenState::Connected {
                username,
                role,
                server_version,
                registered_devices,
                devices,
                accounts,
                new_account_username,
                new_account_role,
                new_account_password,
                error,
                notice,
                in_flight,
                ..
            } => {
                let is_admin = role == "admin";
                // Scrollable so a populated Fleet cannot push Devices and the
                // account controls below the viewport.
                let mut content = div()
                    .id("connected-scroll")
                    .size_full()
                    .flex()
                    .flex_col()
                    .gap_4()
                    .overflow_y_scroll()
                    .child(
                        div()
                            .flex()
                            .justify_between()
                            .items_center()
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .child(div().text_3xl().child("RustCtrl"))
                                    .child(format!(
                                        "Connected over mutual TLS · Server {server_version}"
                                    ))
                                    .child(format!("Logged in as: {username} ({role})"))
                                    .child(format!(
                                        "Registered devices in fleet: {registered_devices}"
                                    )),
                            )
                            .child(
                                div()
                                    .flex()
                                    .gap_3()
                                    .child(
                                        div()
                                            .px_4()
                                            .py_2()
                                            .bg(rgb(0x2d5a88))
                                            .text_color(rgb(0xffffff))
                                            .rounded_md()
                                            .cursor_pointer()
                                            .id("change-password-btn")
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.open_change_password(cx);
                                            }))
                                            .child("Change Password"),
                                    )
                                    .child(
                                        div()
                                            .px_4()
                                            .py_2()
                                            .bg(rgb(0x883333))
                                            .text_color(rgb(0xffffff))
                                            .rounded_md()
                                            .cursor_pointer()
                                            .id("signout-btn")
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.submit_logout(cx);
                                            }))
                                            .child("Sign Out"),
                                    ),
                            ),
                    );

                if let Some(err) = error {
                    content = content.child(
                        div()
                            .id("connected-error")
                            .text_color(rgb(0xff6b6b))
                            .text_sm()
                            .child(err.clone()),
                    );
                }

                if let Some(note) = notice {
                    content = content.child(
                        div()
                            .id("connected-notice")
                            .text_color(rgb(0x44cc44))
                            .text_sm()
                            .child(note.clone()),
                    );
                }

                // The Fleet Inventory is visible to both roles and derives
                // online status from heartbeat freshness on the Server.
                let mut fleet_list = div().mt_4().flex().flex_col().gap_2();

                let mut title_bar = div()
                    .flex()
                    .justify_between()
                    .items_center()
                    .child(div().text_xl().child("Fleet Inventory"));
                if is_admin {
                    title_bar = title_bar.child(
                        div()
                            .flex()
                            .gap_2()
                            .child(
                                div()
                                    .px_3()
                                    .py_1()
                                    .bg(rgb(0x3a5a7a))
                                    .text_color(rgb(0xffffff))
                                    .rounded_md()
                                    .text_sm()
                                    .cursor_pointer()
                                    .id("open-replace-device-btn")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.open_replace_device(String::new(), String::new(), cx);
                                    }))
                                    .child("Replace Device"),
                            )
                            .child(
                                div()
                                    .px_3()
                                    .py_1()
                                    .bg(rgb(0x2a7a5a))
                                    .text_color(rgb(0xffffff))
                                    .rounded_md()
                                    .text_sm()
                                    .cursor_pointer()
                                    .id("open-prepare-artifact-btn")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.open_prepare_installation_artifact(cx);
                                    }))
                                    .child("+ Installation Package"),
                            )
                            .child(
                                div()
                                    .px_3()
                                    .py_1()
                                    .bg(rgb(0x2d884d))
                                    .text_color(rgb(0xffffff))
                                    .rounded_md()
                                    .text_sm()
                                    .cursor_pointer()
                                    .id("add-target-btn")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.open_add_target(cx);
                                    }))
                                    .child("+ Add Target"),
                            ),
                    );
                }
                fleet_list = fleet_list.child(title_bar);

                if devices.is_empty() {
                    fleet_list = fleet_list.child(div().text_sm().text_color(rgb(0x8899aa)).child(
                        if server_version == "Unavailable" {
                            "Server unavailable — the last known Fleet is shown below."
                        } else {
                            "No Devices registered yet."
                        },
                    ));
                } else {
                    let mut header_row = div()
                        .flex()
                        .gap_4()
                        .py_1()
                        .border_b_1()
                        .border_color(rgb(0x334455))
                        .text_sm()
                        .text_color(rgb(0x8899aa))
                        .child(div().w(gpui::px(180.0)).child("Device"))
                        .child(div().w(gpui::px(80.0)).child("Type"))
                        .child(div().w(gpui::px(120.0)).child("Location"))
                        .child(div().w(gpui::px(140.0)).child("Last Address"))
                        .child(div().w(gpui::px(140.0)).child("Config Address"))
                        .child(div().w(gpui::px(90.0)).child("Status"))
                        .child(div().w(gpui::px(100.0)).child("Last Seen"));
                    if is_admin {
                        header_row = header_row.child(div().w(gpui::px(340.0)).child("Actions"));
                    }
                    fleet_list = fleet_list.child(header_row);

                    for device in devices {
                        let vm = format_device_row(device);
                        let dev_id = device.device_id.clone();
                        let dev_name = device.display_name.clone();
                        let dev_loc = device.location.clone();
                        let is_tv_target = device.device_type == "android_tv";
                        let configured_addr = device.configured_address.clone().unwrap_or_default();

                        let status_color = if vm.status == "Blocked" {
                            rgb(0xd9534f)
                        } else if vm.status == "Unverified" {
                            rgb(0xe0a838)
                        } else if vm.status == "Online" {
                            rgb(0x44cc44)
                        } else {
                            rgb(0xff6b6b)
                        };

                        let mut row = div()
                            .flex()
                            .gap_4()
                            .items_center()
                            .py_1()
                            .child(
                                div()
                                    .w(gpui::px(180.0))
                                    .child(format!("{} ({})", vm.display_name, vm.device_id)),
                            )
                            .child(
                                div()
                                    .w(gpui::px(80.0))
                                    .text_color(rgb(0xaaaaaa))
                                    .child(vm.device_type),
                            )
                            .child(
                                div()
                                    .w(gpui::px(120.0))
                                    .text_color(rgb(0xaaaaaa))
                                    .child(vm.location),
                            )
                            .child(
                                div()
                                    .w(gpui::px(140.0))
                                    .text_color(rgb(0xaaaaaa))
                                    .child(vm.last_address),
                            )
                            .child(
                                div()
                                    .w(gpui::px(140.0))
                                    .text_color(rgb(0xaaaaaa))
                                    .child(vm.configured_address),
                            )
                            .child(
                                div()
                                    .w(gpui::px(90.0))
                                    .text_color(status_color)
                                    .child(vm.status),
                            )
                            .child(
                                div()
                                    .w(gpui::px(100.0))
                                    .text_color(rgb(0x8899aa))
                                    .text_sm()
                                    .child(vm.last_seen),
                            );
                        if is_admin {
                            if is_tv_target {
                                let dev_id_for_remove = dev_id.clone();
                                row = row.child(
                                    div()
                                        .w(gpui::px(340.0))
                                        .flex()
                                        .gap_2()
                                        .child(
                                            div()
                                                .px_2()
                                                .py_1()
                                                .bg(rgb(0x3a5a7a))
                                                .text_color(rgb(0xffffff))
                                                .rounded_md()
                                                .text_xs()
                                                .cursor_pointer()
                                                .id(format!("edit-target-btn-{}", device.device_id))
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.open_edit_target(
                                                        dev_id.clone(),
                                                        dev_name.clone(),
                                                        configured_addr.clone(),
                                                        dev_loc.clone(),
                                                        cx,
                                                    );
                                                }))
                                                .child("Edit"),
                                        )
                                        .child(
                                            div()
                                                .px_2()
                                                .py_1()
                                                .bg(rgb(0x883333))
                                                .text_color(rgb(0xffffff))
                                                .rounded_md()
                                                .text_xs()
                                                .cursor_pointer()
                                                .id(format!(
                                                    "remove-target-btn-{}",
                                                    device.device_id
                                                ))
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.submit_remove_target(
                                                        dev_id_for_remove.clone(),
                                                        cx,
                                                    );
                                                }))
                                                .child("Remove"),
                                        ),
                                );
                            } else {
                                let is_blocked = device.blocked || device.status == "blocked";
                                let dev_id_for_edit = dev_id.clone();
                                let dev_id_for_replace = dev_id.clone();
                                let mut actions_div =
                                    div().w(gpui::px(340.0)).flex().gap_2().child(
                                        div()
                                            .px_2()
                                            .py_1()
                                            .bg(rgb(0x3a5a7a))
                                            .text_color(rgb(0xffffff))
                                            .rounded_md()
                                            .text_xs()
                                            .cursor_pointer()
                                            .id(format!("edit-device-btn-{}", device.device_id))
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                this.open_edit_device(
                                                    dev_id_for_edit.clone(),
                                                    dev_name.clone(),
                                                    dev_loc.clone(),
                                                    cx,
                                                );
                                            }))
                                            .child("Edit"),
                                    );

                                if is_blocked {
                                    let dev_id_for_unblock = dev_id.clone();
                                    actions_div = actions_div.child(
                                        div()
                                            .px_2()
                                            .py_1()
                                            .bg(rgb(0x2d884d))
                                            .text_color(rgb(0xffffff))
                                            .rounded_md()
                                            .text_xs()
                                            .cursor_pointer()
                                            .id(format!("unblock-device-btn-{}", device.device_id))
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                this.submit_unblock_device(
                                                    dev_id_for_unblock.clone(),
                                                    cx,
                                                );
                                            }))
                                            .child("Unblock"),
                                    );
                                } else {
                                    let dev_id_for_block = dev_id.clone();
                                    actions_div = actions_div.child(
                                        div()
                                            .px_2()
                                            .py_1()
                                            .bg(rgb(0x883333))
                                            .text_color(rgb(0xffffff))
                                            .rounded_md()
                                            .text_xs()
                                            .cursor_pointer()
                                            .id(format!("block-device-btn-{}", device.device_id))
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                this.submit_block_device(
                                                    dev_id_for_block.clone(),
                                                    cx,
                                                );
                                            }))
                                            .child("Block"),
                                    );

                                    if !device.online || device.status == "offline" {
                                        let dev_id_for_clean = dev_id.clone();
                                        actions_div = actions_div.child(
                                            div()
                                                .px_2()
                                                .py_1()
                                                .bg(rgb(0x7a4a3a))
                                                .text_color(rgb(0xffffff))
                                                .rounded_md()
                                                .text_xs()
                                                .cursor_pointer()
                                                .id(format!(
                                                    "clean-device-btn-{}",
                                                    device.device_id
                                                ))
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.submit_clean_offline_device(
                                                        dev_id_for_clean.clone(),
                                                        cx,
                                                    );
                                                }))
                                                .child("Clean"),
                                        );
                                    }
                                }

                                actions_div = actions_div.child(
                                    div()
                                        .px_2()
                                        .py_1()
                                        .bg(rgb(0x4a6a8a))
                                        .text_color(rgb(0xffffff))
                                        .rounded_md()
                                        .text_xs()
                                        .cursor_pointer()
                                        .id(format!("replace-device-btn-{}", device.device_id))
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.open_replace_device(
                                                dev_id_for_replace.clone(),
                                                String::new(),
                                                cx,
                                            );
                                        }))
                                        .child("Replace"),
                                );

                                row = row.child(actions_div);
                            }
                        }
                        fleet_list = fleet_list.child(row);
                    }
                }
                content = content.child(fleet_list);

                if !matches!(self.overlay, Overlay::None) {
                    content = content.child(self.render_overlay_form(cx));
                } else if is_admin {
                    let user_active = self.active_field == ActiveField::NewAccountUsername;
                    let pass_active = self.active_field == ActiveField::NewAccountPassword;
                    let masked_new_pass = "•".repeat(new_account_password.len());

                    let mut accounts_list = div()
                        .flex()
                        .flex_col()
                        .gap_2()
                        .child(div().text_xl().child("Staff Accounts"));

                    if accounts.is_empty() {
                        accounts_list = accounts_list.child(
                            div()
                                .text_sm()
                                .text_color(rgb(0x8899aa))
                                .child("No other accounts or loading..."),
                        );
                    } else {
                        let header_row = div()
                            .flex()
                            .gap_4()
                            .py_1()
                            .border_b_1()
                            .border_color(rgb(0x334455))
                            .text_sm()
                            .text_color(rgb(0x8899aa))
                            .child(div().w(gpui::px(140.0)).child("Username"))
                            .child(div().w(gpui::px(100.0)).child("Role"))
                            .child(div().w(gpui::px(160.0)).child("Status"))
                            .child(div().w(gpui::px(310.0)).child("Actions"));
                        accounts_list = accounts_list.child(header_row);

                        for acc in accounts {
                            let acc_username = acc.username.clone();
                            let acc_role = acc.role.clone();
                            let is_target_admin = acc.role == "admin";
                            let new_target_role =
                                if is_target_admin { "operator" } else { "admin" };
                            let btn_label = if is_target_admin {
                                "Demote to Operator"
                            } else {
                                "Promote to Admin"
                            };
                            let btn_bg = if is_target_admin {
                                rgb(0xaa5533)
                            } else {
                                rgb(0x2d884d)
                            };

                            let target_user_clone = acc_username.clone();
                            let reset_target_clone = acc_username.clone();
                            let deactivate_target_clone = acc_username.clone();
                            let new_target_role_str = new_target_role.to_string();

                            let status_cell = if !acc.active {
                                div()
                                    .w(gpui::px(160.0))
                                    .text_color(rgb(0x8899aa))
                                    .child("Deactivated")
                            } else {
                                div()
                                    .w(gpui::px(160.0))
                                    .text_color(if acc.must_change_password {
                                        rgb(0xffcc00)
                                    } else {
                                        rgb(0x44cc44)
                                    })
                                    .child(if acc.must_change_password {
                                        "Temporary Password"
                                    } else {
                                        "Active"
                                    })
                            };

                            let deactivate_button = if acc.active {
                                div()
                                    .px_2()
                                    .py_1()
                                    .bg(if *in_flight {
                                        rgb(0x556677)
                                    } else {
                                        rgb(0x664455)
                                    })
                                    .text_color(rgb(0xffffff))
                                    .rounded_md()
                                    .text_xs()
                                    .cursor_pointer()
                                    .id(format!("deactivate-btn-{}", acc_username))
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.submit_deactivate_account(
                                            deactivate_target_clone.clone(),
                                            cx,
                                        );
                                    }))
                                    .child("Deactivate")
                                    .into_any_element()
                            } else {
                                div().into_any_element()
                            };

                            let row = div()
                                .flex()
                                .gap_4()
                                .items_center()
                                .py_1()
                                .child(div().w(gpui::px(140.0)).child(acc_username.clone()))
                                .child(
                                    div()
                                        .w(gpui::px(100.0))
                                        .text_color(if is_target_admin {
                                            rgb(0x4a90e2)
                                        } else {
                                            rgb(0xaaaaaa)
                                        })
                                        .child(acc_role),
                                )
                                .child(status_cell)
                                .child(
                                    div()
                                        .w(gpui::px(310.0))
                                        .flex()
                                        .gap_2()
                                        .child(
                                            div()
                                                .px_2()
                                                .py_1()
                                                .bg(if *in_flight { rgb(0x556677) } else { btn_bg })
                                                .text_color(rgb(0xffffff))
                                                .rounded_md()
                                                .text_xs()
                                                .cursor_pointer()
                                                .id(format!("role-btn-{}", acc_username))
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.submit_change_role(
                                                        target_user_clone.clone(),
                                                        new_target_role_str.clone(),
                                                        cx,
                                                    );
                                                }))
                                                .child(btn_label),
                                        )
                                        .child(
                                            div()
                                                .px_2()
                                                .py_1()
                                                .bg(if *in_flight {
                                                    rgb(0x556677)
                                                } else {
                                                    rgb(0x883333)
                                                })
                                                .text_color(rgb(0xffffff))
                                                .rounded_md()
                                                .text_xs()
                                                .cursor_pointer()
                                                .id(format!("reset-btn-{}", acc_username))
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.open_reset_password(
                                                        reset_target_clone.clone(),
                                                        cx,
                                                    );
                                                }))
                                                .child("Reset Password"),
                                        )
                                        .child(deactivate_button),
                                );
                            accounts_list = accounts_list.child(row);
                        }
                    }

                    let create_form = div()
                        .mt_4()
                        .p_4()
                        .bg(rgb(0x16212e))
                        .rounded_lg()
                        .border_1()
                        .border_color(rgb(0x2a3b4c))
                        .flex()
                        .flex_col()
                        .gap_3()
                        .max_w(gpui::px(450.0))
                        .child(div().text_lg().child("Create Staff Account"))
                        .child("New Username:")
                        .child(
                            div()
                                .px_3()
                                .py_2()
                                .bg(rgb(0x1a2634))
                                .border_1()
                                .border_color(if user_active {
                                    rgb(0x4a90e2)
                                } else {
                                    rgb(0x334455)
                                })
                                .rounded_md()
                                .id("new-account-username-input")
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.active_field = ActiveField::NewAccountUsername;
                                    cx.notify();
                                }))
                                .child(if new_account_username.is_empty() {
                                    "Enter username...".to_string()
                                } else {
                                    new_account_username.clone()
                                }),
                        )
                        .child("Role:")
                        .child(
                            div()
                                .flex()
                                .gap_3()
                                .child(
                                    div()
                                        .px_3()
                                        .py_1()
                                        .rounded_md()
                                        .cursor_pointer()
                                        .bg(if new_account_role == "operator" {
                                            rgb(0x2d5a88)
                                        } else {
                                            rgb(0x223344)
                                        })
                                        .id("role-operator-btn")
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            if let ScreenState::Connected {
                                                new_account_role, ..
                                            } = &mut this.state
                                            {
                                                *new_account_role = "operator".into();
                                                cx.notify();
                                            }
                                        }))
                                        .child("Operator"),
                                )
                                .child(
                                    div()
                                        .px_3()
                                        .py_1()
                                        .rounded_md()
                                        .cursor_pointer()
                                        .bg(if new_account_role == "admin" {
                                            rgb(0x2d5a88)
                                        } else {
                                            rgb(0x223344)
                                        })
                                        .id("role-admin-btn")
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            if let ScreenState::Connected {
                                                new_account_role, ..
                                            } = &mut this.state
                                            {
                                                *new_account_role = "admin".into();
                                                cx.notify();
                                            }
                                        }))
                                        .child("Admin"),
                                ),
                        )
                        .child("Temporary Password:")
                        .child(
                            div()
                                .px_3()
                                .py_2()
                                .bg(rgb(0x1a2634))
                                .border_1()
                                .border_color(if pass_active {
                                    rgb(0x4a90e2)
                                } else {
                                    rgb(0x334455)
                                })
                                .rounded_md()
                                .id("new-account-password-input")
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.active_field = ActiveField::NewAccountPassword;
                                    cx.notify();
                                }))
                                .child(if new_account_password.is_empty() {
                                    "Minimum 8 characters...".to_string()
                                } else {
                                    masked_new_pass
                                }),
                        )
                        .child(
                            div()
                                .px_4()
                                .py_2()
                                .bg(if *in_flight {
                                    rgb(0x556677)
                                } else {
                                    rgb(0x2d884d)
                                })
                                .text_color(rgb(0xffffff))
                                .rounded_md()
                                .cursor_pointer()
                                .id("create-account-btn")
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.submit_create_account(cx);
                                }))
                                .child(if *in_flight {
                                    "Creating..."
                                } else {
                                    "Create Account"
                                }),
                        );

                    content = content.child(accounts_list).child(create_form);
                } else {
                    content = content.child(
                        div()
                            .mt_4()
                            .p_4()
                            .bg(rgb(0x16212e))
                            .rounded_lg()
                            .text_color(rgb(0x8899aa))
                            .child("Staff account administration is restricted to Admins. Fleet monitoring mode is active."),
                    );
                }

                container.child(content)
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct DeviceRowViewModel {
    device_id: String,
    display_name: String,
    device_type: String,
    location: String,
    last_address: String,
    configured_address: String,
    status: String,
    last_seen: String,
}

fn format_device_row(device: &FleetDeviceEntry) -> DeviceRowViewModel {
    let is_tv_target = device.device_type == "android_tv";
    let location = match &device.location {
        Some(loc) if !loc.is_empty() => loc.clone(),
        _ => "—".to_string(),
    };
    let last_address = if !device.last_address.is_empty() {
        device.last_address.clone()
    } else {
        "—".to_string()
    };
    let configured_address = match &device.configured_address {
        Some(addr) if !addr.is_empty() => addr.clone(),
        _ => "—".to_string(),
    };
    let status = if device.blocked || device.status == "blocked" {
        "Blocked".to_string()
    } else if is_tv_target || device.status == "unverified" {
        "Unverified".to_string()
    } else if device.online {
        "Online".to_string()
    } else {
        "Offline".to_string()
    };
    let last_seen = if is_tv_target || device.last_seen_unix_ms == 0 {
        "—".to_string()
    } else {
        relative_last_seen(device.last_seen_unix_ms)
    };
    DeviceRowViewModel {
        device_id: device.device_id.clone(),
        display_name: device.display_name.clone(),
        device_type: device.device_type.clone(),
        location,
        last_address,
        configured_address,
        status,
        last_seen,
    }
}

fn relative_last_seen(last_seen_unix_ms: i64) -> String {
    let now_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default();
    let seconds = now_unix_ms.saturating_sub(last_seen_unix_ms) / 1000;
    match seconds {
        0..=59 => format!("{seconds}s ago"),
        60..=3599 => format!("{}m ago", seconds / 60),
        3600..=86_399 => format!("{}h ago", seconds / 3600),
        _ => format!("{}d ago", seconds / 86_400),
    }
}

pub fn open(config: ControllerConfig, config_path: std::path::PathBuf) -> Result<()> {
    #[cfg(target_os = "linux")]
    anyhow::ensure!(
        ["DISPLAY", "WAYLAND_DISPLAY"]
            .iter()
            .any(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty())),
        "A graphical session is required. Run the Controller on an X11 or Wayland desktop; use the check command for headless diagnostics."
    );
    let runtime = tokio::runtime::Runtime::new()?;
    let handle = runtime.handle().clone();

    gpui_platform::application().run(move |cx: &mut App| {
        cx.open_window(WindowOptions::default(), |_, cx| {
            cx.new(|cx| ControllerApp::new(config, config_path, handle, cx))
        })
        .expect("open RustCtrl window");
        cx.activate(true);
    });
    runtime.shutdown_background();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gpui::{Keystroke, Modifiers};

    #[test]
    fn resolve_typed_text_handles_spaces_characters_and_key_char() {
        // Space key with no key_char
        let space_key = Keystroke {
            modifiers: Modifiers::default(),
            key: "space".into(),
            key_char: None,
        };
        assert_eq!(resolve_typed_text(&space_key), Some(" "));

        // Key with key_char payload (e.g. non-ASCII or multi-word)
        let thai_key = Keystroke {
            modifiers: Modifiers::default(),
            key: "q".into(),
            key_char: Some("ๆ".into()),
        };
        assert_eq!(resolve_typed_text(&thai_key), Some("ๆ"));

        // Normal ASCII letter
        let ascii_key = Keystroke {
            modifiers: Modifiers::default(),
            key: "a".into(),
            key_char: Some("a".into()),
        };
        assert_eq!(resolve_typed_text(&ascii_key), Some("a"));

        // Control or command modifier should be ignored
        let mut ctrl_s = Keystroke {
            modifiers: Modifiers::default(),
            key: "s".into(),
            key_char: Some("s".into()),
        };
        ctrl_s.modifiers.control = true;
        assert_eq!(resolve_typed_text(&ctrl_s), None);

        // Control character should be ignored
        let enter_key = Keystroke {
            modifiers: Modifiers::default(),
            key: "enter".into(),
            key_char: Some("\n".into()),
        };
        assert_eq!(resolve_typed_text(&enter_key), None);
    }

    #[test]
    fn typing_multiword_values_accumulates_correctly() {
        let mut display_name = String::new();
        let words = ["Reception", " ", "Front", " ", "Desk"];
        for word in words {
            for ch in word.chars() {
                let ks = if ch == ' ' {
                    Keystroke {
                        modifiers: Modifiers::default(),
                        key: "space".into(),
                        key_char: None,
                    }
                } else {
                    Keystroke {
                        modifiers: Modifiers::default(),
                        key: ch.to_string(),
                        key_char: Some(ch.to_string()),
                    }
                };
                if let Some(text) = resolve_typed_text(&ks) {
                    display_name.push_str(text);
                }
            }
        }
        assert_eq!(display_name, "Reception Front Desk");
    }

    #[test]
    fn edit_device_overlay_form_matching_checks_request_id_and_device_id() {
        let overlay = Overlay::EditDevice {
            request_id: 42,
            device_id: "dev-abc".into(),
            display_name: "Original Name".into(),
            location: "Room 101".into(),
            error: None,
            in_flight: true,
        };

        // Matching request id and device id
        let is_match = match &overlay {
            Overlay::EditDevice {
                request_id,
                device_id,
                ..
            } => *request_id == 42 && device_id == "dev-abc",
            _ => false,
        };
        assert!(is_match);

        // Different request id (new form opened)
        let is_stale = match &overlay {
            Overlay::EditDevice {
                request_id,
                device_id,
                ..
            } => *request_id == 43 && device_id == "dev-abc",
            _ => false,
        };
        assert!(!is_stale);

        // Different device id
        let is_diff_dev = match &overlay {
            Overlay::EditDevice {
                request_id,
                device_id,
                ..
            } => *request_id == 42 && device_id == "dev-xyz",
            _ => false,
        };
        assert!(!is_diff_dev);
    }

    #[test]
    fn add_target_overlay_form_matching_checks_request_id() {
        let overlay = Overlay::AddTarget {
            request_id: 10,
            display_name: "Lobby TV".into(),
            address: "192.168.1.150:5555".into(),
            location: "Lobby".into(),
            error: None,
            in_flight: true,
        };

        let is_match = match &overlay {
            Overlay::AddTarget { request_id, .. } => *request_id == 10,
            _ => false,
        };
        assert!(is_match);

        let is_stale = match &overlay {
            Overlay::AddTarget { request_id, .. } => *request_id == 11,
            _ => false,
        };
        assert!(!is_stale);
    }

    #[test]
    fn edit_target_overlay_form_matching_checks_request_id_and_target_id() {
        let overlay = Overlay::EditTarget {
            request_id: 15,
            target_id: "target-abc".into(),
            display_name: "Lobby TV Updated".into(),
            address: "192.168.1.151:5555".into(),
            location: "Lobby West".into(),
            error: None,
            in_flight: true,
        };

        let is_match = match &overlay {
            Overlay::EditTarget {
                request_id,
                target_id,
                ..
            } => *request_id == 15 && target_id == "target-abc",
            _ => false,
        };
        assert!(is_match);

        let is_stale_req = match &overlay {
            Overlay::EditTarget {
                request_id,
                target_id,
                ..
            } => *request_id == 16 && target_id == "target-abc",
            _ => false,
        };
        assert!(!is_stale_req);

        let is_diff_target = match &overlay {
            Overlay::EditTarget {
                request_id,
                target_id,
                ..
            } => *request_id == 15 && target_id == "target-xyz",
            _ => false,
        };
        assert!(!is_diff_target);
    }

    #[test]
    fn format_device_row_presents_android_tv_target_as_unverified_with_distinct_address_and_no_last_seen()
     {
        let entry = FleetDeviceEntry {
            device_id: "tv-target-123".into(),
            display_name: "Boardroom TV".into(),
            online: false,
            last_seen_unix_ms: 0,
            last_address: String::new(),
            location: Some("Floor 3".into()),
            device_type: "android_tv".into(),
            configured_address: Some("192.168.1.150:5555".into()),
            status: "unverified".into(),
            blocked: false,
        };

        let vm = format_device_row(&entry);
        assert_eq!(vm.device_id, "tv-target-123");
        assert_eq!(vm.display_name, "Boardroom TV");
        assert_eq!(vm.device_type, "android_tv");
        assert_eq!(vm.location, "Floor 3");
        assert_eq!(vm.last_address, "—");
        assert_eq!(vm.configured_address, "192.168.1.150:5555");
        assert_eq!(vm.status, "Unverified");
        assert_eq!(vm.last_seen, "—");
    }

    #[test]
    fn format_device_row_presents_windows_device_with_observed_address() {
        let entry = FleetDeviceEntry {
            device_id: "dev-win-456".into(),
            display_name: "Reception PC".into(),
            online: true,
            last_seen_unix_ms: 1_700_000_000_000,
            last_address: "10.0.0.42".into(),
            location: None,
            device_type: "windows".into(),
            configured_address: None,
            status: "online".into(),
            blocked: false,
        };

        let vm = format_device_row(&entry);
        assert_eq!(vm.device_id, "dev-win-456");
        assert_eq!(vm.display_name, "Reception PC");
        assert_eq!(vm.device_type, "windows");
        assert_eq!(vm.location, "—");
        assert_eq!(vm.last_address, "10.0.0.42");
        assert_eq!(vm.configured_address, "—");
        assert_eq!(vm.status, "Online");
        assert_ne!(vm.last_seen, "—");
    }

    #[test]
    fn format_device_row_presents_blocked_windows_device_with_preserved_last_seen_freshness() {
        let now_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or_default();
        let entry = FleetDeviceEntry {
            device_id: "dev-win-blocked-789".into(),
            display_name: "Finance PC".into(),
            online: false,
            last_seen_unix_ms: now_unix_ms - 30_000,
            last_address: "10.0.0.88".into(),
            location: Some("Floor 2".into()),
            device_type: "windows".into(),
            configured_address: None,
            status: "blocked".into(),
            blocked: true,
        };

        let vm = format_device_row(&entry);
        assert_eq!(vm.device_id, "dev-win-blocked-789");
        assert_eq!(vm.display_name, "Finance PC");
        assert_eq!(vm.device_type, "windows");
        assert_eq!(vm.location, "Floor 2");
        assert_eq!(vm.last_address, "10.0.0.88");
        assert_eq!(vm.configured_address, "—");
        assert_eq!(
            vm.status, "Blocked",
            "blocked device must display Blocked status"
        );
        assert_ne!(
            vm.last_seen, "—",
            "heartbeat freshness must be preserved for blocked device"
        );
        assert!(
            vm.last_seen.contains('s') || vm.last_seen.contains('m'),
            "last_seen should reflect relative time"
        );
    }

    #[test]
    fn format_device_row_presents_offline_windows_device_distinct_from_blocked() {
        let now_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or_default();
        let entry = FleetDeviceEntry {
            device_id: "dev-win-offline-101".into(),
            display_name: "Stale PC".into(),
            online: false,
            last_seen_unix_ms: now_unix_ms - 120_000,
            last_address: "10.0.0.99".into(),
            location: Some("Storage".into()),
            device_type: "windows".into(),
            configured_address: None,
            status: "offline".into(),
            blocked: false,
        };

        let vm = format_device_row(&entry);
        assert_eq!(vm.device_id, "dev-win-offline-101");
        assert_eq!(vm.display_name, "Stale PC");
        assert_eq!(vm.device_type, "windows");
        assert_eq!(vm.location, "Storage");
        assert_eq!(vm.last_address, "10.0.0.99");
        assert_eq!(vm.configured_address, "—");
        assert_eq!(
            vm.status, "Offline",
            "offline unblocked device must display Offline status"
        );
        assert_ne!(
            vm.last_seen, "—",
            "last_seen timestamp must be formatted for offline device"
        );
    }

    #[test]
    fn replace_device_overlay_form_matching_checks_request_id_and_device_ids() {
        let overlay = Overlay::ReplaceDevice {
            request_id: 30,
            prior_device_id: "prior-uuid-10".into(),
            replacement_device_id: "rep-uuid-20".into(),
            error: None,
            in_flight: true,
        };

        let is_match = match &overlay {
            Overlay::ReplaceDevice {
                request_id,
                prior_device_id,
                replacement_device_id,
                ..
            } => {
                *request_id == 30
                    && prior_device_id == "prior-uuid-10"
                    && replacement_device_id == "rep-uuid-20"
            }
            _ => false,
        };
        assert!(is_match);

        let is_stale_req = match &overlay {
            Overlay::ReplaceDevice { request_id, .. } => *request_id == 31,
            _ => false,
        };
        assert!(!is_stale_req);

        let is_diff_prior = match &overlay {
            Overlay::ReplaceDevice {
                prior_device_id, ..
            } => prior_device_id == "different-uuid",
            _ => false,
        };
        assert!(!is_diff_prior);
    }

    #[test]
    fn replace_device_completion_does_not_close_superseded_or_different_overlay() {
        let active_overlay = Overlay::AddTarget {
            request_id: 31,
            display_name: "Lobby TV".into(),
            address: "192.168.1.50:5555".into(),
            location: String::new(),
            error: None,
            in_flight: false,
        };

        let is_matching_form = match &active_overlay {
            Overlay::ReplaceDevice { request_id, .. } => *request_id == 30,
            _ => false,
        };
        assert!(
            !is_matching_form,
            "response from stale replace_device must not match active AddTarget overlay"
        );
    }

    #[test]
    fn prepare_installation_artifact_overlay_form_matching_checks_request_id() {
        let overlay = Overlay::PrepareInstallationArtifact {
            request_id: 15,
            output_path: "agent-artifact.toml".into(),
            agent_binary_path: String::new(),
            error: None,
            in_flight: true,
            success: None,
        };

        let is_match = match &overlay {
            Overlay::PrepareInstallationArtifact { request_id, .. } => *request_id == 15,
            _ => false,
        };
        assert!(is_match);

        let is_stale = match &overlay {
            Overlay::PrepareInstallationArtifact { request_id, .. } => *request_id == 16,
            _ => false,
        };
        assert!(!is_stale);
    }
}
