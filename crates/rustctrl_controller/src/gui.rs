use anyhow::Result;
use gpui::{
    App, Context, FocusHandle, IntoElement, KeyDownEvent, Render, Task, Window, WindowOptions, div,
    prelude::*, rgb,
};
use rustctrl_core::ControllerConfig;
use rustctrl_protocol::auth::{
    LoginRequest, LogoutRequest, ReplaceTemporaryPasswordRequest, StaffStatusRequest,
};
use std::time::Duration;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ActiveField {
    Username,
    Password,
    NewPassword,
    ConfirmPassword,
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
        error: Option<String>,
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
                                error: None,
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
                            error: None,
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
        cx.spawn(async move |this, cx| {
            let res = handle
                .spawn(async move {
                    let mut client = rustctrl_network::connect_staff_auth(&client_cfg).await?;
                    let mut req = tonic::Request::new(StaffStatusRequest {});
                    req.metadata_mut()
                        .insert("authorization", format!("Bearer {tok_for_req}").parse()?);
                    let reply = client.get_staff_status(req).await?.into_inner();
                    Ok::<_, anyhow::Error>(reply)
                })
                .await;

            let _ = this.update(cx, |view, cx| {
                if let ScreenState::Connected {
                    session_token: tok,
                    username,
                    role,
                    ..
                } = &view.state
                    && *tok == tok_for_update
                {
                    match res {
                        Ok(Ok(reply)) => {
                            view.state = ScreenState::Connected {
                                session_token: tok_for_update,
                                username: username.clone(),
                                role: role.clone(),
                                server_version: reply.server_version,
                                registered_devices: reply.registered_devices,
                                error: None,
                            };
                        }
                        Ok(Err(err)) => {
                            view.state = ScreenState::Connected {
                                session_token: tok_for_update,
                                username: username.clone(),
                                role: role.clone(),
                                server_version: "Unavailable".into(),
                                registered_devices: 0,
                                error: Some(err.to_string()),
                            };
                        }
                        Err(e) => {
                            view.state = ScreenState::Connected {
                                session_token: tok_for_update,
                                username: username.clone(),
                                role: role.clone(),
                                server_version: "Unavailable".into(),
                                registered_devices: 0,
                                error: Some(e.to_string()),
                            };
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
            ScreenState::Connected { .. } => {}
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
                error,
                ..
            } => container
                .child(div().text_3xl().child("RustCtrl"))
                .child(format!(
                    "Connected over mutual TLS · Server {server_version}"
                ))
                .child(format!("Logged in as: {username} ({role})"))
                .child(format!("Registered devices in fleet: {registered_devices}"))
                .children(
                    error
                        .as_ref()
                        .map(|err| div().text_color(rgb(0xff6b6b)).text_sm().child(err.clone())),
                )
                .child(
                    div()
                        .mt_4()
                        .px_4()
                        .py_2()
                        .max_w(gpui::px(120.0))
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
