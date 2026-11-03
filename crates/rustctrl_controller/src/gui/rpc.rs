use super::state::*;
use gpui::Context;
use rustctrl_core::DeviceId;
use rustctrl_protocol::auth::{
    BlockDeviceRequest, ChangeOwnPasswordRequest, ChangeStaffRoleRequest,
    CleanOfflineDeviceRequest, CreateStaffAccountRequest, CreateTargetRequest,
    DeactivateStaffAccountRequest, ListFleetDevicesRequest, ListInstallationAuthorizationsRequest,
    ListStaffAccountsRequest, LoginRequest, LogoutRequest, PrepareInstallationArtifactRequest,
    RemoveTargetRequest, ReplaceFleetDeviceRequest, ReplaceTemporaryPasswordRequest,
    ResetStaffPasswordRequest, RevokeInstallationAuthorizationRequest, StaffStatusRequest,
    UnblockDeviceRequest, UpdateFleetDeviceRequest, UpdateTargetRequest,
};

impl ControllerApp {
    pub(crate) fn submit_login(&mut self, cx: &mut Context<Self>) {
        let (username, password, remember) = match &self.state {
            ScreenState::Login {
                username: state_username,
                password: state_password,
                remember,
                in_flight,
                ..
            } => {
                let username = self
                    .login_username_input
                    .as_ref()
                    .map(|input| input.read(cx).text().to_string())
                    .unwrap_or_else(|| state_username.clone());
                let password = self
                    .login_password_input
                    .as_ref()
                    .map(|input| input.read(cx).text().to_string())
                    .unwrap_or_else(|| state_password.clone());

                let decision =
                    crate::login_state::submit_decision(&username, &password, *in_flight);
                if decision == crate::login_state::SubmitDecision::AlreadySubmitting {
                    return;
                }
                if let crate::login_state::SubmitDecision::Invalid(message) = decision {
                    self.state = ScreenState::Login {
                        username,
                        password,
                        error: Some(message.into()),
                        notice: None,
                        remember: *remember,
                        in_flight: false,
                    };
                    cx.notify();
                    return;
                }
                (username, password, *remember)
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
                            view.must_change_new_password_input = None;
                            view.must_change_confirm_password_input = None;
                            view.state = ScreenState::MustChangePassword {
                                session_token: reply.session_token,
                                username: reply.username,
                                role: reply.role,
                                new_password: String::new(),
                                confirm_password: String::new(),
                                error: warning,
                                in_flight: false,
                            };
                        } else {
                            view.login_password_input = None;
                            if !remember {
                                view.login_username_input = None;
                            }
                            let token = reply.session_token.clone();
                            view.state = ScreenState::Connected {
                                session_token: reply.session_token,
                                username: reply.username,
                                role: reply.role,
                                server_version: "Loading...".into(),
                                registered_devices: 0,
                                devices: Vec::new(),
                                accounts: Vec::new(),
                                authorizations: Vec::new(),
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

    pub(crate) fn submit_replace_password(&mut self, cx: &mut Context<Self>) {
        let (session_token, username, role, new_password) = match &self.state {
            ScreenState::MustChangePassword {
                session_token,
                username,
                role,
                new_password: state_new_password,
                confirm_password: state_confirm_password,
                in_flight: false,
                ..
            } => {
                let new_password = self
                    .must_change_new_password_input
                    .as_ref()
                    .map(|input| input.read(cx).text().to_string())
                    .unwrap_or_else(|| state_new_password.clone());
                let confirm_password = self
                    .must_change_confirm_password_input
                    .as_ref()
                    .map(|input| input.read(cx).text().to_string())
                    .unwrap_or_else(|| state_confirm_password.clone());

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
                    new_password,
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
                        view.must_change_new_password_input = None;
                        view.must_change_confirm_password_input = None;
                        view.login_password_input = None;
                        view.state = ScreenState::Connected {
                            session_token: session_token.clone(),
                            username: username.clone(),
                            role: role.clone(),
                            server_version: "Loading...".into(),
                            registered_devices: 0,
                            devices: Vec::new(),
                            accounts: Vec::new(),
                            authorizations: Vec::new(),
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

    pub(crate) fn submit_logout(&mut self, cx: &mut Context<Self>) {
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
        self.navigation.reset();
        // Any open password form belongs to the session being left behind.
        self.overlay = Overlay::None;
        self.modal_inputs = None;
        self.login_username_input = None;
        self.login_password_input = None;
        self.must_change_new_password_input = None;
        self.must_change_confirm_password_input = None;
        self.fleet_search_input = None;
        self.fleet_table = None;
        self.fleet_state.close_inspector();
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

    pub(crate) fn fetch_status(&mut self, session_token: String, cx: &mut Context<Self>) {
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
                    let accounts_res = if is_admin || reply.role == "admin" {
                        let mut list_req = tonic::Request::new(ListStaffAccountsRequest {});
                        list_req
                            .metadata_mut()
                            .insert("authorization", format!("Bearer {tok_for_req}").parse()?);
                        match client.list_staff_accounts(list_req).await {
                            Ok(r) => Ok(r.into_inner().accounts),
                            Err(e) => Err(e.to_string()),
                        }
                    } else {
                        Ok(Vec::new())
                    };
                    let authorizations_res = if is_admin || reply.role == "admin" {
                        let mut list_auth_req =
                            tonic::Request::new(ListInstallationAuthorizationsRequest {});
                        list_auth_req
                            .metadata_mut()
                            .insert("authorization", format!("Bearer {tok_for_req}").parse()?);
                        match client.list_installation_authorizations(list_auth_req).await {
                            Ok(r) => Ok(r.into_inner().authorizations),
                            Err(e) => Err(e.to_string()),
                        }
                    } else {
                        Ok(Vec::new())
                    };
                    Ok::<_, anyhow::Error>((reply, devices, accounts_res, authorizations_res))
                })
                .await;

            let _ = this.update(cx, |view, cx| {
                if let ScreenState::Connected {
                    session_token: tok,
                    username,
                    role,
                    registered_devices,
                    devices,
                    accounts,
                    authorizations,
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
                        Ok(Ok((reply, devices_reply, accs_res, auths_res))) => {
                            let mut err_msg = None;
                            let updated_accounts = if reply.role == "admin" {
                                match accs_res {
                                    Ok(accs) => accs,
                                    Err(e) => {
                                        err_msg =
                                            Some(format!("Failed to list staff accounts: {e}"));
                                        accounts.clone()
                                    }
                                }
                            } else {
                                Vec::new()
                            };
                            let updated_authorizations = if reply.role == "admin" {
                                match auths_res {
                                    Ok(auths) => auths,
                                    Err(e) => {
                                        let msg = format!(
                                            "Failed to list installation authorizations: {e}"
                                        );
                                        err_msg = Some(match err_msg {
                                            Some(prev) => format!("{prev}; {msg}"),
                                            None => msg,
                                        });
                                        authorizations.clone()
                                    }
                                }
                            } else {
                                Vec::new()
                            };
                            let keep_error = err_msg.or_else(|| error.clone());
                            let keep_notice = notice.clone();
                            view.state = ScreenState::Connected {
                                session_token: tok_for_update,
                                username: reply.username,
                                role: reply.role,
                                server_version: reply.server_version,
                                registered_devices: reply.registered_devices,
                                devices: devices_reply,
                                accounts: updated_accounts,
                                authorizations: updated_authorizations,
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
                                username: username.clone(),
                                role: role.clone(),
                                server_version: "Unavailable".into(),
                                registered_devices: *registered_devices,
                                devices: devices.clone(),
                                accounts: accounts.clone(),
                                authorizations: authorizations.clone(),
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
                                username: username.clone(),
                                role: role.clone(),
                                server_version: "Unavailable".into(),
                                registered_devices: *registered_devices,
                                devices: devices.clone(),
                                accounts: accounts.clone(),
                                authorizations: authorizations.clone(),
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

    pub(crate) fn submit_create_account(&mut self, cx: &mut Context<Self>) {
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
                let user = self
                    .new_account_username_input
                    .as_ref()
                    .map(|input| input.read(cx).text().to_string().trim().to_string())
                    .unwrap_or_else(|| new_account_username.trim().to_string());
                if user.is_empty() {
                    *error = Some("Username is required.".into());
                    cx.notify();
                    return;
                }
                let pass = self
                    .new_account_password_input
                    .as_ref()
                    .map(|input| input.read(cx).text().to_string())
                    .unwrap_or_else(|| new_account_password.clone());
                if pass.len() < 8 {
                    *error = Some("Temporary password must contain at least 8 characters.".into());
                    cx.notify();
                    return;
                }
                *in_flight = true;
                *error = None;
                (session_token.clone(), user, new_account_role.clone(), pass)
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
                            view.new_account_username_input = None;
                            view.new_account_password_input = None;
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

    pub(crate) fn submit_deactivate_account(
        &mut self,
        target_username: String,
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

    pub(crate) fn submit_change_role(
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

    pub(crate) fn open_change_password(&mut self, cx: &mut Context<Self>) {
        if let ScreenState::Connected { .. } = &self.state {
            self.overlay = Overlay::ChangePassword {
                current_password: String::new(),
                new_password: String::new(),
                confirm_password: String::new(),
                error: None,
                in_flight: false,
            };
            cx.notify();
        }
    }

    pub(crate) fn open_reset_password(&mut self, target_username: String, cx: &mut Context<Self>) {
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
            cx.notify();
        }
    }

    pub(crate) fn open_edit_device(
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
            cx.notify();
        }
    }

    pub(crate) fn open_add_target(&mut self, cx: &mut Context<Self>) {
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
            cx.notify();
        }
    }

    pub(crate) fn open_edit_target(
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
            cx.notify();
        }
    }

    pub(crate) fn open_replace_device(
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
            self.overlay = Overlay::ReplaceDevice {
                request_id,
                prior_device_id,
                replacement_device_id,
                error: None,
                in_flight: false,
            };
            cx.notify();
        }
    }

    pub(crate) fn open_prepare_installation_artifact(&mut self, cx: &mut Context<Self>) {
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
            cx.notify();
        }
    }

    pub(crate) fn close_overlay(&mut self, cx: &mut Context<Self>) {
        self.overlay = Overlay::None;
        self.modal_inputs = None;
        cx.notify();
    }

    pub(crate) fn submit_change_password(&mut self, cx: &mut Context<Self>) {
        if let Some(ModalInputs::ChangePassword {
            current_password: cur_in,
            new_password: new_in,
            confirm_password: conf_in,
        }) = &self.modal_inputs
            && let Overlay::ChangePassword {
                current_password,
                new_password,
                confirm_password,
                ..
            } = &mut self.overlay
        {
            *current_password = cur_in.read(cx).text().to_string();
            *new_password = new_in.read(cx).text().to_string();
            *confirm_password = conf_in.read(cx).text().to_string();
        }

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
                            view.modal_inputs = None;
                            view.emit_toast(
                                crate::toast::ToastKind::Success,
                                "Password Changed",
                                "Password changed successfully.",
                                cx,
                            );
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

    pub(crate) fn submit_reset_password(&mut self, cx: &mut Context<Self>) {
        if let Some(ModalInputs::ResetPassword {
            temporary_password: temp_in,
            confirm_password: conf_in,
        }) = &self.modal_inputs
            && let Overlay::ResetPassword {
                temporary_password,
                confirm_password,
                ..
            } = &mut self.overlay
        {
            *temporary_password = temp_in.read(cx).text().to_string();
            *confirm_password = conf_in.read(cx).text().to_string();
        }

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
                            view.modal_inputs = None;
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
                                if let ScreenState::Connected { notice, .. } = &mut view.state {
                                    *notice = Some(
                                        "Temporary password set; all target sessions revoked."
                                            .into(),
                                    );
                                }
                                view.emit_toast(
                                    crate::toast::ToastKind::Success,
                                    "Password Reset",
                                    "Temporary password set; all target sessions revoked.",
                                    cx,
                                );
                                let token = tok_check.clone();
                                view.fetch_status(token, cx);
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

    pub(crate) fn submit_edit_device(&mut self, cx: &mut Context<Self>) {
        if let Some(ModalInputs::EditDevice {
            display_name: dn_in,
            location: loc_in,
        }) = &self.modal_inputs
            && let Overlay::EditDevice {
                display_name,
                location,
                ..
            } = &mut self.overlay
        {
            *display_name = dn_in.read(cx).text().to_string();
            *location = loc_in.read(cx).text().to_string();
        }

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
                            view.emit_toast(
                                crate::toast::ToastKind::Success,
                                "Device Updated",
                                format!("Updated device '{device_id_label}'."),
                                cx,
                            );
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

    pub(crate) fn submit_add_target(&mut self, cx: &mut Context<Self>) {
        if let Some(ModalInputs::AddTarget {
            display_name: dn_in,
            address: addr_in,
            location: loc_in,
        }) = &self.modal_inputs
            && let Overlay::AddTarget {
                display_name,
                address,
                location,
                ..
            } = &mut self.overlay
        {
            *display_name = dn_in.read(cx).text().to_string();
            *address = addr_in.read(cx).text().to_string();
            *location = loc_in.read(cx).text().to_string();
        }

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
                            view.emit_toast(
                                crate::toast::ToastKind::Success,
                                "Target Added",
                                format!("Added Android TV target '{target_name_label}'."),
                                cx,
                            );
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

    pub(crate) fn submit_edit_target(&mut self, cx: &mut Context<Self>) {
        if let Some(ModalInputs::EditTarget {
            display_name: dn_in,
            address: addr_in,
            location: loc_in,
        }) = &self.modal_inputs
            && let Overlay::EditTarget {
                display_name,
                address,
                location,
                ..
            } = &mut self.overlay
        {
            *display_name = dn_in.read(cx).text().to_string();
            *address = addr_in.read(cx).text().to_string();
            *location = loc_in.read(cx).text().to_string();
        }

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
                            view.emit_toast(
                                crate::toast::ToastKind::Success,
                                "Target Updated",
                                format!("Updated target '{target_id_label}'."),
                                cx,
                            );
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

    pub(crate) fn submit_remove_target(&mut self, target_id: String, cx: &mut Context<Self>) {
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
                            view.emit_toast(
                                crate::toast::ToastKind::Info,
                                "Target Removed",
                                format!("Removed target '{target_label}'."),
                                cx,
                            );
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

    pub(crate) fn submit_block_device(&mut self, device_id: String, cx: &mut Context<Self>) {
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
                            view.emit_toast(
                                crate::toast::ToastKind::Warning,
                                "Device Blocked",
                                format!("Blocked device '{device_label}'."),
                                cx,
                            );
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

    pub(crate) fn submit_unblock_device(&mut self, device_id: String, cx: &mut Context<Self>) {
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
                            view.emit_toast(
                                crate::toast::ToastKind::Success,
                                "Device Unblocked",
                                format!("Unblocked device '{device_label}'."),
                                cx,
                            );
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

    pub(crate) fn submit_clean_offline_device(
        &mut self,
        device_id: String,
        cx: &mut Context<Self>,
    ) {
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
                            view.emit_toast(
                                crate::toast::ToastKind::Info,
                                "Device Cleaned",
                                format!("Cleaned offline device '{device_label}'."),
                                cx,
                            );
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

    pub(crate) fn submit_replace_device(&mut self, cx: &mut Context<Self>) {
        if let Some(ModalInputs::ReplaceDevice {
            prior_device_id: prior_in,
            replacement_device_id: repl_in,
        }) = &self.modal_inputs
            && let Overlay::ReplaceDevice {
                prior_device_id,
                replacement_device_id,
                ..
            } = &mut self.overlay
        {
            *prior_device_id = prior_in.read(cx).text().to_string();
            *replacement_device_id = repl_in.read(cx).text().to_string();
        }

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
                            view.emit_toast(
                                crate::toast::ToastKind::Success,
                                "Device Replaced",
                                format!(
                                    "Replaced device '{prior_label}' with '{replacement_label}'."
                                ),
                                cx,
                            );
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

    pub(crate) fn submit_revoke_authorization(
        &mut self,
        authorization_id: String,
        and_replace: bool,
        cx: &mut Context<Self>,
    ) {
        let session_token = match &mut self.state {
            ScreenState::Connected {
                session_token,
                role,
                in_flight,
                error,
                ..
            } if role == "admin" => {
                if *in_flight {
                    return;
                }
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
        let auth_label = authorization_id.clone();

        cx.spawn(async move |this, cx| {
            let res = handle
                .spawn(async move {
                    let mut client = rustctrl_network::connect_staff_auth(&client_cfg).await?;
                    let mut req = tonic::Request::new(RevokeInstallationAuthorizationRequest {
                        authorization_id,
                    });
                    req.metadata_mut()
                        .insert("authorization", format!("Bearer {tok}").parse()?);
                    client
                        .revoke_installation_authorization(req)
                        .await?
                        .into_inner();
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

                if let ScreenState::Connected { in_flight, .. } = &mut view.state {
                    *in_flight = false;
                }

                match res {
                    Ok(Ok(())) => {
                        if let ScreenState::Connected { notice, .. } = &mut view.state {
                            if and_replace {
                                *notice = Some(format!(
                                    "Revoked installation authorization '{auth_label}'. Prepare replacement package below."
                                ));
                            } else {
                                *notice = Some(format!(
                                    "Revoked installation authorization '{auth_label}'."
                                ));
                            }
                            let token = tok_check.clone();
                            view.fetch_status(token, cx);
                        }
                        if and_replace {
                            view.open_prepare_installation_artifact(cx);
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

    pub(crate) fn submit_prepare_installation_artifact(&mut self, cx: &mut Context<Self>) {
        if let Some(ModalInputs::PrepareArtifact {
            output_path: out_in,
            agent_binary_path: bin_in,
        }) = &self.modal_inputs
            && let Overlay::PrepareInstallationArtifact {
                output_path,
                agent_binary_path,
                ..
            } = &mut self.overlay
        {
            *output_path = out_in.read(cx).text().to_string();
            *agent_binary_path = bin_in.read(cx).text().to_string();
        }

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
                            view.emit_toast(
                                crate::toast::ToastKind::Success,
                                "Package Exported",
                                format!("{action} ({auth_id}) exported."),
                                cx,
                            );
                            view.fetch_status(tok_check.clone(), cx);
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
}
