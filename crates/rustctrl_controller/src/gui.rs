use anyhow::Result;
use gpui::{
    App, Context, FocusHandle, IntoElement, KeyDownEvent, Render, Task, Window, WindowOptions, div,
    prelude::*, rgb,
};
use rustctrl_core::ControllerConfig;
use rustctrl_protocol::auth::{
    ChangeStaffRoleRequest, CreateStaffAccountRequest, ListStaffAccountsRequest, LoginRequest,
    LogoutRequest, ReplaceTemporaryPasswordRequest, StaffAccountEntry, StaffStatusRequest,
};
use std::time::Duration;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ActiveField {
    Username,
    Password,
    NewPassword,
    ConfirmPassword,
    NewAccountUsername,
    NewAccountPassword,
}

#[derive(Clone)]
enum ScreenState {
    Login {
        username: String,
        password: String,
        error: Option<String>,
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
        in_flight: bool,
    },
}

struct ControllerApp {
    config: ControllerConfig,
    state: ScreenState,
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
                in_flight: false,
            },
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
            in_flight: false,
        };
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

    fn handle_key_down(&mut self, event: &KeyDownEvent, cx: &mut Context<Self>) {
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
                in_flight,
            } => {
                let user_active = self.active_field == ActiveField::Username;
                let pass_active = self.active_field == ActiveField::Password;
                let masked_pass = "•".repeat(password.len());

                container
                    .child(div().text_3xl().child("RustCtrl"))
                    .child("Staff Access · Please Sign In")
                    .child(format!("Server: {}", self.config.server.endpoint))
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

                if is_admin {
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
                            .child(div().w(gpui::px(160.0)).child("Action"));
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
                            let new_target_role_str = new_target_role.to_string();

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
                                .child(
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
                                        }),
                                )
                                .child(
                                    div().w(gpui::px(160.0)).child(
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
                                    ),
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
