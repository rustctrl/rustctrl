use gpui::{Context, Entity, FocusHandle, Task};
use rustctrl_core::ControllerConfig;
use rustctrl_protocol::auth::{
    FleetDeviceEntry, InstallationAuthorizationEntry, StaffAccountEntry, StaffStatusRequest,
};
use std::time::Duration;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ActiveField {
    Username,
    Password,
    PasswordVisibility,
    RememberLogin,
    FleetSearch,
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

#[derive(Clone, Debug, PartialEq)]
pub enum Overlay {
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
pub enum ScreenState {
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
        authorizations: Vec<InstallationAuthorizationEntry>,
        new_account_username: String,
        new_account_role: String,
        new_account_password: String,
        error: Option<String>,
        notice: Option<String>,
        in_flight: bool,
    },
}

pub enum RestoreFailure {
    ExpiredOrRevoked,
    ServerUnavailable(String),
}

pub struct AbortOnDrop<T>(pub tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub struct ControllerApp {
    pub(crate) theme: crate::theme::Theme,
    pub(crate) config: ControllerConfig,
    pub(crate) config_path: std::path::PathBuf,
    pub(crate) state: ScreenState,
    pub(crate) overlay: Overlay,
    pub(crate) active_field: ActiveField,
    pub(crate) focus_handle: FocusHandle,
    pub(crate) visibility_focus: FocusHandle,
    pub(crate) remember_focus: FocusHandle,
    pub(crate) tokio_handle: tokio::runtime::Handle,
    pub(crate) next_edit_device_request_id: u64,
    pub(crate) next_target_request_id: u64,
    pub(crate) next_replace_device_request_id: u64,
    pub(crate) next_prepare_artifact_request_id: u64,
    pub(crate) server_status: crate::login_state::ServerStatus,
    pub(crate) show_password: bool,
    pub(crate) navigation: crate::navigation::Navigation,
    pub(crate) fleet_state: crate::fleet::FleetState,
    pub(crate) fleet_table: Option<
        Entity<gpui::component::table::TableState<crate::gui::views::fleet::FleetTableDelegate>>,
    >,
    pub(crate) remote_state: crate::remote::RemoteSessionState,
    pub(crate) toast_manager: crate::toast::ToastManager,
    pub(crate) _health: Task<()>,
    pub(crate) _refresh: Task<()>,
    pub(crate) _restore: Option<Task<()>>,
}

impl ControllerApp {
    pub fn new(
        theme: crate::theme::Theme,
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

        let health_config = config.server.clone();
        let health_handle = tokio_handle.clone();
        let health = cx.spawn(async move |this, cx| {
            loop {
                let config = health_config.clone();
                let mut task = AbortOnDrop(health_handle.spawn(async move {
                    let mut client = rustctrl_network::connect(&config).await?;
                    let reply = client
                        .get_health(rustctrl_protocol::bootstrap::HealthRequest {})
                        .await?
                        .into_inner();
                    Ok::<_, anyhow::Error>(reply.staff_bootstrap_required)
                }));
                let result = (&mut task.0).await;
                if this
                    .update(cx, |view, cx| {
                        view.server_status = match result {
                            Ok(Ok(bootstrap_required)) => {
                                crate::login_state::ServerStatus::Connected { bootstrap_required }
                            }
                            _ => crate::login_state::ServerStatus::Unreachable,
                        };
                        cx.notify();
                    })
                    .is_err()
                {
                    break;
                }
                cx.background_executor().timer(Duration::from_secs(5)).await;
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
                                authorizations: Vec::new(),
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
            theme,
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
            visibility_focus: cx.focus_handle(),
            remember_focus: cx.focus_handle(),
            tokio_handle,
            next_edit_device_request_id: 0,
            next_target_request_id: 0,
            next_replace_device_request_id: 0,
            next_prepare_artifact_request_id: 0,
            server_status: crate::login_state::ServerStatus::Connecting,
            show_password: false,
            navigation: crate::navigation::Navigation::default(),
            fleet_state: crate::fleet::FleetState::new(),
            fleet_table: None,
            remote_state: crate::remote::RemoteSessionState::default(),
            toast_manager: crate::toast::ToastManager::new(),
            _health: health,
            _refresh: refresh,
            _restore: Some(restore),
        }
    }

    pub(crate) fn emit_toast(
        &mut self,
        kind: crate::toast::ToastKind,
        title: impl Into<String>,
        message: impl Into<String>,
        cx: &mut Context<Self>,
    ) {
        let t = title.into();
        let m = message.into();
        match kind {
            crate::toast::ToastKind::Success => self.toast_manager.success(t, m),
            crate::toast::ToastKind::Error => self.toast_manager.error(t, m),
            crate::toast::ToastKind::Warning => self.toast_manager.warning(t, m),
            crate::toast::ToastKind::Info => self.toast_manager.info(t, m),
        };
        cx.notify();
        cx.spawn(async move |this, cx| {
            cx.background_executor()
                .timer(std::time::Duration::from_millis(3200))
                .await;
            let _ = this.update(cx, |this, cx| {
                this.toast_manager.tick_now();
                cx.notify();
            });
        })
        .detach();
    }

    pub(crate) fn launch_remote_for_item(
        &mut self,
        item: &crate::fleet::FleetDeviceItem,
        cx: &mut Context<Self>,
    ) {
        if item.is_remote_ready() {
            self.start_remote_session(item.device_id.clone(), item.display_name.clone(), cx);
        } else {
            self.emit_toast(
                crate::toast::ToastKind::Warning,
                "Remote Session Unavailable",
                format!(
                    "Device '{}' is not ready for remote desktop control.",
                    item.display_name
                ),
                cx,
            );
        }
    }

    pub(crate) fn start_remote_session(
        &mut self,
        device_id: String,
        device_name: String,
        cx: &mut Context<Self>,
    ) {
        self.remote_state.start_session(&device_id, &device_name);
        if let ScreenState::Connected { role, .. } = &self.state {
            self.navigation
                .select(crate::navigation::Route::Remote, role);
        }
        self.navigation.collapsed = true;
        self.emit_toast(
            crate::toast::ToastKind::Success,
            "Remote Session Started",
            format!("Interactive session active for '{device_name}'."),
            cx,
        );
        cx.notify();
    }

    pub(crate) fn disconnect_remote_session(&mut self, cx: &mut Context<Self>) {
        if let Some(session) = self.remote_state.active_session() {
            let name = session.device_name.clone();
            self.remote_state.disconnect();
            self.emit_toast(
                crate::toast::ToastKind::Info,
                "Remote Session Disconnected",
                format!("Session ended for '{name}' and device lock released."),
                cx,
            );
            cx.notify();
        }
    }

    pub(crate) fn select_remote_monitor(
        &mut self,
        monitor: crate::remote::MonitorTarget,
        cx: &mut Context<Self>,
    ) {
        self.remote_state.set_monitor(monitor);
        self.emit_toast(
            crate::toast::ToastKind::Info,
            "Display Target Changed",
            format!("Viewing {}", monitor.label()),
            cx,
        );
        cx.notify();
    }

    pub(crate) fn trigger_sas(&mut self, cx: &mut Context<Self>) {
        self.emit_toast(
            crate::toast::ToastKind::Info,
            "Secure Attention Sequence (SAS)",
            "Ctrl+Alt+Del triggered on remote target.",
            cx,
        );
        cx.notify();
    }

    pub(crate) fn toggle_remote_input_mode(&mut self, cx: &mut Context<Self>) {
        self.remote_state.toggle_input_mode();
        if let Some(session) = self.remote_state.active_session() {
            let mode = session.input_mode;
            self.emit_toast(
                crate::toast::ToastKind::Info,
                "Input Mode Toggled",
                format!("Switched to {}", mode.label()),
                cx,
            );
        }
        cx.notify();
    }

    pub(crate) fn toggle_remote_fullscreen(&mut self, cx: &mut Context<Self>) {
        self.remote_state.toggle_fullscreen();
        if let Some(session) = self.remote_state.active_session() {
            let label = if session.fullscreen {
                "Entered fullscreen mode (F11 to exit)"
            } else {
                "Returned to windowed mode"
            };
            self.emit_toast(crate::toast::ToastKind::Info, "Display Mode", label, cx);
        }
        cx.notify();
    }

    pub(crate) fn ungrab_remote_keyboard(&mut self, cx: &mut Context<Self>) {
        self.remote_state.ungrab_keyboard();
        self.emit_toast(
            crate::toast::ToastKind::Warning,
            "Keyboard Released",
            "Keystrokes returned to local Controller. Click canvas to re-grab.",
            cx,
        );
        cx.notify();
    }
}
