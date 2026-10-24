use anyhow::Result;
use gpui::{
    App, Context, FocusHandle, IntoElement, KeyDownEvent, Render, Task, Window, WindowOptions, div,
    prelude::*, rgb,
};
use rustctrl_core::ControllerConfig;
use rustctrl_protocol::auth::{
    ChangeOwnPasswordRequest, ChangeStaffRoleRequest, CreateStaffAccountRequest,
    DeactivateStaffAccountRequest, ListStaffAccountsRequest, LoginRequest, LogoutRequest,
    ReplaceTemporaryPasswordRequest, ResetStaffPasswordRequest, StaffAccountEntry,
    StaffStatusRequest,
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
}

#[derive(Clone)]
enum ScreenState {
    Login {
        username: String,
        password: String,
        error: Option<String>,
        notice: Option<String>,
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
        accounts: Vec<StaffAccountEntry>,
        new_account_username: String,
        new_account_role: String,
        new_account_password: String,
        error: Option<String>,
        notice: Option<String>,
        in_flight: bool,
    },
}

struct ControllerApp {
    config: ControllerConfig,
    state: ScreenState,
    overlay: Overlay,
    active_field: ActiveField,
    focus_handle: FocusHandle,
    tokio_handle: tokio::runtime::Handle,
    _refresh: Task<()>,
}

impl ControllerApp {
    fn new(
        config: ControllerConfig,
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

        Self {
            config,
            state: ScreenState::Login {
                username: String::new(),
                password: String::new(),
                error: None,
                notice: None,
                in_flight: false,
            },
            overlay: Overlay::None,
            active_field: ActiveField::Username,
            focus_handle,
            tokio_handle,
            _refresh: refresh,
        }
    }

    fn submit_login(&mut self, cx: &mut Context<Self>) {
        let (username, password) = match &self.state {
            ScreenState::Login {
                username,
                password,
                in_flight: false,
                ..
            } => {
                if username.trim().is_empty() || password.is_empty() {
                    self.state = ScreenState::Login {
                        username: username.clone(),
                        password: password.clone(),
                        error: Some("Username and password are required.".into()),
                        notice: None,
                        in_flight: false,
                    };
                    cx.notify();
                    return;
                }
                (username.clone(), password.clone())
            }
            _ => return,
        };

        self.state = ScreenState::Login {
            username: username.clone(),
            password: password.clone(),
            error: None,
            notice: None,
            in_flight: true,
        };
        cx.notify();

        let client_cfg = self.config.server.clone();
        let handle = self.tokio_handle.clone();
        cx.spawn(async move |this, cx| {
            let res = handle
                .spawn(async move {
                    let mut client = rustctrl_network::connect_staff_auth(&client_cfg).await?;
                    let reply = client
                        .login(LoginRequest {
                            username: username.clone(),
                            password,
                        })
                        .await?
                        .into_inner();
                    Ok::<_, anyhow::Error>(reply)
                })
                .await;

            let _ = this.update(cx, |view, cx| {
                match res {
                    Ok(Ok(reply)) => {
                        if reply.must_change_password {
                            view.state = ScreenState::MustChangePassword {
                                session_token: reply.session_token,
                                username: reply.username,
                                role: reply.role,
                                new_password: String::new(),
                                confirm_password: String::new(),
                                error: None,
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
                                accounts: Vec::new(),
                                new_account_username: String::new(),
                                new_account_role: "operator".into(),
                                new_account_password: String::new(),
                                error: None,
                                notice: None,
                                in_flight: false,
                            };
                            view.fetch_status(token, cx);
                        }
                    }
                    Ok(Err(err)) => {
                        if let ScreenState::Login {
                            username, password, ..
                        } = &view.state
                        {
                            view.state = ScreenState::Login {
                                username: username.clone(),
                                password: password.clone(),
                                error: Some(err.to_string()),
                                notice: None,
                                in_flight: false,
                            };
                        }
                    }
                    Err(join_err) => {
                        if let ScreenState::Login {
                            username, password, ..
                        } = &view.state
                        {
                            view.state = ScreenState::Login {
                                username: username.clone(),
                                password: password.clone(),
                                error: Some(join_err.to_string()),
                                notice: None,
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
            in_flight: false,
        };
        // Any open password form belongs to the session being left behind.
        self.overlay = Overlay::None;
        self.active_field = ActiveField::Username;
        cx.notify();

        let client_cfg = self.config.server.clone();
        let handle = self.tokio_handle.clone();
        cx.spawn(async move |_this, _cx| {
            let _ = handle
                .spawn(async move {
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
                    Ok::<_, anyhow::Error>((reply, accounts))
                })
                .await;

            let _ = this.update(cx, |view, cx| {
                if let ScreenState::Connected {
                    session_token: tok,
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
                        Ok(Ok((reply, accs))) => {
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
                if res.is_ok() {
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
            Overlay::None => div().into_any_element(),
        }
    }

    fn handle_overlay_key_down(&mut self, event: &KeyDownEvent, cx: &mut Context<Self>) {
        let key = &event.keystroke.key;
        let change_active = matches!(
            (&self.overlay, self.active_field),
            (Overlay::ChangePassword { .. }, ActiveField::CurrentPassword)
                | (
                    Overlay::ResetPassword { .. },
                    ActiveField::TemporaryPassword
                )
        );
        let is_change = matches!(self.overlay, Overlay::ChangePassword { .. });
        let in_flight = match &self.overlay {
            Overlay::ChangePassword { in_flight, .. }
            | Overlay::ResetPassword { in_flight, .. } => *in_flight,
            Overlay::None => false,
        };
        if in_flight {
            return;
        }
        match key.as_str() {
            "enter" => {
                if is_change {
                    self.submit_change_password(cx);
                } else {
                    self.submit_reset_password(cx);
                }
            }
            "tab" => {
                self.active_field = match (is_change, change_active) {
                    (true, true) => ActiveField::NewPassword,
                    (true, _) if self.active_field == ActiveField::NewPassword => {
                        ActiveField::ConfirmPassword
                    }
                    (true, _) => ActiveField::CurrentPassword,
                    (false, true) => ActiveField::ConfirmPassword,
                    (false, _) => ActiveField::TemporaryPassword,
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
                    _ => {}
                }
                cx.notify();
            }
            k if k.chars().count() == 1 => {
                let c = k.chars().next().unwrap();
                if !c.is_control() {
                    match (&mut self.overlay, self.active_field) {
                        (
                            Overlay::ChangePassword {
                                current_password, ..
                            },
                            ActiveField::CurrentPassword,
                        ) => {
                            current_password.push(c);
                        }
                        (
                            Overlay::ChangePassword { new_password, .. },
                            ActiveField::NewPassword,
                        ) => {
                            new_password.push(c);
                        }
                        (
                            Overlay::ChangePassword {
                                confirm_password, ..
                            },
                            ActiveField::ConfirmPassword,
                        ) => {
                            confirm_password.push(c);
                        }
                        (
                            Overlay::ResetPassword {
                                temporary_password, ..
                            },
                            ActiveField::TemporaryPassword,
                        ) => {
                            temporary_password.push(c);
                        }
                        (
                            Overlay::ResetPassword {
                                confirm_password, ..
                            },
                            ActiveField::ConfirmPassword,
                        ) => {
                            confirm_password.push(c);
                        }
                        _ => {}
                    }
                    cx.notify();
                }
            }
            _ => {}
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
                    k if k.chars().count() == 1 => {
                        let c = k.chars().next().unwrap();
                        if !c.is_control() {
                            match self.active_field {
                                ActiveField::Username => {
                                    username.push(c);
                                }
                                ActiveField::Password => {
                                    password.push(c);
                                }
                                _ => {}
                            }
                            cx.notify();
                        }
                    }
                    _ => {}
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
                    k if k.chars().count() == 1 => {
                        let c = k.chars().next().unwrap();
                        if !c.is_control() {
                            match self.active_field {
                                ActiveField::NewPassword => {
                                    new_password.push(c);
                                }
                                ActiveField::ConfirmPassword => {
                                    confirm_password.push(c);
                                }
                                _ => {}
                            }
                            cx.notify();
                        }
                    }
                    _ => {}
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
                    k if k.chars().count() == 1 => {
                        let c = k.chars().next().unwrap();
                        if !c.is_control() {
                            match self.active_field {
                                ActiveField::NewAccountUsername => {
                                    new_account_username.push(c);
                                }
                                ActiveField::NewAccountPassword => {
                                    new_account_password.push(c);
                                }
                                _ => {}
                            }
                            cx.notify();
                        }
                    }
                    _ => {}
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
                in_flight,
            } => {
                let user_active = self.active_field == ActiveField::Username;
                let pass_active = self.active_field == ActiveField::Password;
                let masked_pass = "•".repeat(password.len());

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
                let mut content = container.child(
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

                content
            }
        }
    }
}

pub fn open(config: ControllerConfig) -> Result<()> {
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
            cx.new(|cx| ControllerApp::new(config, handle, cx))
        })
        .expect("open RustCtrl window");
        cx.activate(true);
    });
    runtime.shutdown_background();
    Ok(())
}
