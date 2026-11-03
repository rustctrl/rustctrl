use super::overlays;
use super::state::*;
use gpui::base::StyledExt as _;
use gpui::{
    Context, InteractiveElement as _, IntoElement, KeyDownEvent, ParentElement as _, Render,
    Styled as _, Window, div, prelude::*, rgb,
};

impl ControllerApp {
    pub(in crate::gui) fn ensure_modal_inputs(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.modal_inputs.is_some() {
            return;
        }

        use gpui::component::input::{InputEvent, InputState};

        match &self.overlay {
            Overlay::ChangePassword {
                current_password,
                new_password,
                confirm_password,
                ..
            } => {
                let cur = cx.new(|cx| {
                    InputState::new(window, cx)
                        .masked(true)
                        .placeholder("Enter current password...")
                        .default_value(current_password.clone())
                });
                let new = cx.new(|cx| {
                    InputState::new(window, cx)
                        .masked(true)
                        .placeholder("Minimum 8 characters...")
                        .default_value(new_password.clone())
                });
                let conf = cx.new(|cx| {
                    InputState::new(window, cx)
                        .masked(true)
                        .placeholder("Re-enter new password...")
                        .default_value(confirm_password.clone())
                });

                cx.subscribe(
                    &cur,
                    |this: &mut ControllerApp, _, event: &InputEvent, cx| {
                        if matches!(event, InputEvent::PressEnter { .. }) {
                            this.submit_change_password(cx);
                        }
                    },
                )
                .detach();
                cx.subscribe(
                    &new,
                    |this: &mut ControllerApp, _, event: &InputEvent, cx| {
                        if matches!(event, InputEvent::PressEnter { .. }) {
                            this.submit_change_password(cx);
                        }
                    },
                )
                .detach();
                cx.subscribe(
                    &conf,
                    |this: &mut ControllerApp, _, event: &InputEvent, cx| {
                        if matches!(event, InputEvent::PressEnter { .. }) {
                            this.submit_change_password(cx);
                        }
                    },
                )
                .detach();

                self.modal_inputs = Some(ModalInputs::ChangePassword {
                    current_password: cur,
                    new_password: new,
                    confirm_password: conf,
                });
            }
            Overlay::ResetPassword {
                temporary_password,
                confirm_password,
                ..
            } => {
                let temp = cx.new(|cx| {
                    InputState::new(window, cx)
                        .masked(true)
                        .placeholder("Minimum 8 characters...")
                        .default_value(temporary_password.clone())
                });
                let conf = cx.new(|cx| {
                    InputState::new(window, cx)
                        .masked(true)
                        .placeholder("Re-enter temporary password...")
                        .default_value(confirm_password.clone())
                });

                cx.subscribe(
                    &temp,
                    |this: &mut ControllerApp, _, event: &InputEvent, cx| {
                        if matches!(event, InputEvent::PressEnter { .. }) {
                            this.submit_reset_password(cx);
                        }
                    },
                )
                .detach();
                cx.subscribe(
                    &conf,
                    |this: &mut ControllerApp, _, event: &InputEvent, cx| {
                        if matches!(event, InputEvent::PressEnter { .. }) {
                            this.submit_reset_password(cx);
                        }
                    },
                )
                .detach();

                self.modal_inputs = Some(ModalInputs::ResetPassword {
                    temporary_password: temp,
                    confirm_password: conf,
                });
            }
            Overlay::EditDevice {
                display_name,
                location,
                ..
            } => {
                let name = cx.new(|cx| {
                    InputState::new(window, cx)
                        .placeholder("Friendly name...")
                        .default_value(display_name.clone())
                });
                let loc = cx.new(|cx| {
                    InputState::new(window, cx)
                        .placeholder("e.g. Building B Floor 3")
                        .default_value(location.clone())
                });

                cx.subscribe(
                    &name,
                    |this: &mut ControllerApp, _, event: &InputEvent, cx| {
                        if matches!(event, InputEvent::PressEnter { .. }) {
                            this.submit_edit_device(cx);
                        }
                    },
                )
                .detach();
                cx.subscribe(
                    &loc,
                    |this: &mut ControllerApp, _, event: &InputEvent, cx| {
                        if matches!(event, InputEvent::PressEnter { .. }) {
                            this.submit_edit_device(cx);
                        }
                    },
                )
                .detach();

                self.modal_inputs = Some(ModalInputs::EditDevice {
                    display_name: name,
                    location: loc,
                });
            }
            Overlay::AddTarget {
                display_name,
                address,
                location,
                ..
            } => {
                let name = cx.new(|cx| {
                    InputState::new(window, cx)
                        .placeholder("e.g. Conference Room TV")
                        .default_value(display_name.clone())
                });
                let addr = cx.new(|cx| {
                    InputState::new(window, cx)
                        .placeholder("192.168.1.50:5555")
                        .default_value(address.clone())
                });
                let loc = cx.new(|cx| {
                    InputState::new(window, cx)
                        .placeholder("Building A, 2nd Floor")
                        .default_value(location.clone())
                });

                cx.subscribe(
                    &name,
                    |this: &mut ControllerApp, _, event: &InputEvent, cx| {
                        if matches!(event, InputEvent::PressEnter { .. }) {
                            this.submit_add_target(cx);
                        }
                    },
                )
                .detach();
                cx.subscribe(
                    &addr,
                    |this: &mut ControllerApp, _, event: &InputEvent, cx| {
                        if matches!(event, InputEvent::PressEnter { .. }) {
                            this.submit_add_target(cx);
                        }
                    },
                )
                .detach();
                cx.subscribe(
                    &loc,
                    |this: &mut ControllerApp, _, event: &InputEvent, cx| {
                        if matches!(event, InputEvent::PressEnter { .. }) {
                            this.submit_add_target(cx);
                        }
                    },
                )
                .detach();

                self.modal_inputs = Some(ModalInputs::AddTarget {
                    display_name: name,
                    address: addr,
                    location: loc,
                });
            }
            Overlay::EditTarget {
                display_name,
                address,
                location,
                ..
            } => {
                let name = cx.new(|cx| {
                    InputState::new(window, cx)
                        .placeholder("e.g. Conference Room TV")
                        .default_value(display_name.clone())
                });
                let addr = cx.new(|cx| {
                    InputState::new(window, cx)
                        .placeholder("192.168.1.50:5555")
                        .default_value(address.clone())
                });
                let loc = cx.new(|cx| {
                    InputState::new(window, cx)
                        .placeholder("Building A, 2nd Floor")
                        .default_value(location.clone())
                });

                cx.subscribe(
                    &name,
                    |this: &mut ControllerApp, _, event: &InputEvent, cx| {
                        if matches!(event, InputEvent::PressEnter { .. }) {
                            this.submit_edit_target(cx);
                        }
                    },
                )
                .detach();
                cx.subscribe(
                    &addr,
                    |this: &mut ControllerApp, _, event: &InputEvent, cx| {
                        if matches!(event, InputEvent::PressEnter { .. }) {
                            this.submit_edit_target(cx);
                        }
                    },
                )
                .detach();
                cx.subscribe(
                    &loc,
                    |this: &mut ControllerApp, _, event: &InputEvent, cx| {
                        if matches!(event, InputEvent::PressEnter { .. }) {
                            this.submit_edit_target(cx);
                        }
                    },
                )
                .detach();

                self.modal_inputs = Some(ModalInputs::EditTarget {
                    display_name: name,
                    address: addr,
                    location: loc,
                });
            }
            Overlay::ReplaceDevice {
                prior_device_id,
                replacement_device_id,
                ..
            } => {
                let prior = cx.new(|cx| {
                    InputState::new(window, cx)
                        .placeholder("ID of decommissioned device...")
                        .default_value(prior_device_id.clone())
                });
                let repl = cx.new(|cx| {
                    InputState::new(window, cx)
                        .placeholder("ID of new target device...")
                        .default_value(replacement_device_id.clone())
                });

                cx.subscribe(
                    &prior,
                    |this: &mut ControllerApp, _, event: &InputEvent, cx| {
                        if matches!(event, InputEvent::PressEnter { .. }) {
                            this.submit_replace_device(cx);
                        }
                    },
                )
                .detach();
                cx.subscribe(
                    &repl,
                    |this: &mut ControllerApp, _, event: &InputEvent, cx| {
                        if matches!(event, InputEvent::PressEnter { .. }) {
                            this.submit_replace_device(cx);
                        }
                    },
                )
                .detach();

                self.modal_inputs = Some(ModalInputs::ReplaceDevice {
                    prior_device_id: prior,
                    replacement_device_id: repl,
                });
            }
            Overlay::PrepareInstallationArtifact {
                output_path,
                agent_binary_path,
                ..
            } => {
                let out = cx.new(|cx| {
                    InputState::new(window, cx)
                        .placeholder("/path/to/rustctrl-agent-bundle.zip")
                        .default_value(output_path.clone())
                });
                let bin = cx.new(|cx| {
                    InputState::new(window, cx)
                        .placeholder("Optional path to custom agent executable...")
                        .default_value(agent_binary_path.clone())
                });

                cx.subscribe(
                    &out,
                    |this: &mut ControllerApp, _, event: &InputEvent, cx| {
                        if matches!(event, InputEvent::PressEnter { .. }) {
                            this.submit_prepare_installation_artifact(cx);
                        }
                    },
                )
                .detach();
                cx.subscribe(
                    &bin,
                    |this: &mut ControllerApp, _, event: &InputEvent, cx| {
                        if matches!(event, InputEvent::PressEnter { .. }) {
                            this.submit_prepare_installation_artifact(cx);
                        }
                    },
                )
                .detach();

                self.modal_inputs = Some(ModalInputs::PrepareArtifact {
                    output_path: out,
                    agent_binary_path: bin,
                });
            }
            Overlay::None => {}
        }
    }

    pub(in crate::gui) fn sync_modal_dialog(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        use gpui::component::WindowExt as _;
        let has_active_dialog = window.has_active_dialog(cx);

        if !matches!(self.overlay, Overlay::None) {
            self.ensure_modal_inputs(window, cx);
            if !has_active_dialog {
                let app = cx.entity().clone();
                window.open_dialog(cx, move |dialog, _window, cx| {
                    let (overlay, modal_inputs, theme) = {
                        let app_ref = app.read(cx);
                        (
                            app_ref.overlay.clone(),
                            app_ref.modal_inputs.clone(),
                            app_ref.theme,
                        )
                    };

                    let Some(inputs) = modal_inputs else {
                        return dialog;
                    };

                    match overlay {
                        Overlay::ChangePassword {
                            error, in_flight, ..
                        } => overlays::change_password::render_change_password_dialog(
                            &inputs,
                            error.as_ref(),
                            in_flight,
                            &theme,
                            app.clone(),
                            cx,
                        ),
                        Overlay::ResetPassword {
                            target_username,
                            error,
                            in_flight,
                            ..
                        } => overlays::reset_password::render_reset_password_dialog(
                            &target_username,
                            &inputs,
                            error.as_ref(),
                            in_flight,
                            &theme,
                            app.clone(),
                            cx,
                        ),
                        Overlay::EditDevice {
                            device_id,
                            error,
                            in_flight,
                            ..
                        } => overlays::target_management::render_edit_device_dialog(
                            &device_id,
                            &inputs,
                            error.as_ref(),
                            in_flight,
                            &theme,
                            app.clone(),
                            cx,
                        ),
                        Overlay::AddTarget {
                            error, in_flight, ..
                        } => overlays::target_management::render_add_target_dialog(
                            &inputs,
                            error.as_ref(),
                            in_flight,
                            &theme,
                            app.clone(),
                            cx,
                        ),
                        Overlay::EditTarget {
                            target_id,
                            error,
                            in_flight,
                            ..
                        } => overlays::target_management::render_edit_target_dialog(
                            &target_id,
                            &inputs,
                            error.as_ref(),
                            in_flight,
                            &theme,
                            app.clone(),
                            cx,
                        ),
                        Overlay::ReplaceDevice {
                            error, in_flight, ..
                        } => overlays::replace_device::render_replace_device_dialog(
                            &inputs,
                            error.as_ref(),
                            in_flight,
                            &theme,
                            app.clone(),
                            cx,
                        ),
                        Overlay::PrepareInstallationArtifact {
                            error,
                            success,
                            in_flight,
                            ..
                        } => overlays::prepare_artifact::render_prepare_artifact_dialog(
                            &inputs,
                            error.as_ref(),
                            success.as_ref(),
                            in_flight,
                            &theme,
                            app.clone(),
                            cx,
                        ),
                        Overlay::None => dialog,
                    }
                });
            }
        } else if has_active_dialog {
            window.close_dialog(cx);
            self.modal_inputs = None;
        }
    }

    fn handle_key_down(
        &mut self,
        event: &KeyDownEvent,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let key = &event.keystroke.key;
        match &mut self.state {
            ScreenState::Login { in_flight, .. } => {
                if *in_flight {
                    return;
                }
                if key == "enter" {
                    self.submit_login(cx);
                }
            }
            ScreenState::MustChangePassword { in_flight, .. } => {
                if *in_flight {
                    return;
                }
                if key == "enter" {
                    self.submit_replace_password(cx);
                }
            }
            ScreenState::Connected {
                in_flight, role, ..
            } => {
                if *in_flight {
                    return;
                }
                if self.navigation.active(role) == crate::navigation::Route::Remote
                    && self.remote_state.is_active()
                {
                    if key == "f11" {
                        self.toggle_remote_fullscreen(cx);
                        return;
                    }
                    if event.keystroke.modifiers.control
                        && event.keystroke.modifiers.shift
                        && key == "escape"
                    {
                        self.ungrab_remote_keyboard(cx);
                    }
                }
            }
        }
    }
}

impl Render for ControllerApp {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let container = div()
            .track_focus(&self.focus_handle)
            .on_key_down(cx.listener(|this, event: &KeyDownEvent, _window, cx| {
                this.handle_key_down(event, _window, cx);
            }))
            .size_full()
            .bg(rgb(self.theme.bg_app))
            .text_color(rgb(self.theme.text_primary))
            .flex()
            .flex_col()
            .gap_4();

        if matches!(
            self.state,
            ScreenState::Login { .. } | ScreenState::MustChangePassword { .. }
        ) {
            self.ensure_auth_inputs(window, cx);
        }

        if matches!(self.state, ScreenState::Connected { .. }) {
            self.ensure_fleet_table(window, cx);
            self.ensure_fleet_search_input(window, cx);
            self.ensure_new_account_inputs(window, cx);
        } else {
            use gpui::component::WindowExt as _;
            if window.has_active_sheet(cx) {
                window.close_sheet(cx);
                self.fleet_state.close_inspector();
            }
        }

        self.sync_modal_dialog(window, cx);

        let main_view: gpui::AnyElement = match &self.state {
            ScreenState::Login { .. } => self.render_login(container.p_8(), cx).into_any_element(),
            ScreenState::MustChangePassword { .. } => self
                .render_must_change_password(container.p_8(), cx)
                .into_any_element(),
            ScreenState::Connected {
                username,
                role,
                server_version,
                registered_devices,
                error,
                notice,
                ..
            } => {
                use crate::navigation::{Navigation, Route};
                use gpui::assets::IconName;
                use gpui::component::Sizable as _;
                use gpui::component::button::{Button, ButtonVariants as _};
                use gpui::component::separator::Separator;
                use gpui::component::sidebar::{
                    Sidebar, SidebarMenu, SidebarMenuItem, SidebarToggleButton,
                };
                use gpui::component::tag::Tag;
                use gpui::px;

                let is_admin = role == "admin";
                let active = self.navigation.active(role);
                let collapsed = self.navigation.collapsed;
                let mut menu = SidebarMenu::new();
                for route in Navigation::routes(role) {
                    let icon = match route {
                        Route::Fleet => IconName::LayoutDashboard,
                        Route::Remote => IconName::Monitor,
                        Route::Accounts => IconName::Users,
                        Route::Deployment => IconName::Package,
                        Route::Audit => IconName::FileClock,
                    };
                    menu = menu.child(
                        SidebarMenuItem::new(route.label())
                            .icon(icon)
                            .active(active == route)
                            .on_click(cx.listener(move |this, _, _, cx| {
                                if let ScreenState::Connected { role, .. } = &this.state {
                                    this.navigation.select(route, role);
                                    cx.notify();
                                }
                            })),
                    );
                }

                let toggle_button =
                    SidebarToggleButton::new()
                        .collapsed(collapsed)
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.navigation.collapsed = !this.navigation.collapsed;
                            cx.notify();
                        }));

                let sidebar_header = if collapsed {
                    div()
                        .w_full()
                        .h(px(48.0))
                        .flex()
                        .items_center()
                        .justify_center()
                        .child(toggle_button)
                } else {
                    div()
                        .w_full()
                        .h(px(48.0))
                        .px_3()
                        .flex()
                        .items_center()
                        .justify_between()
                        .child(
                            div()
                                .text_lg()
                                .font_bold()
                                .text_color(rgb(self.theme.accent_primary))
                                .child("RustCtrl"),
                        )
                        .child(toggle_button)
                };

                let sidebar = Sidebar::new("navigation")
                    .w(gpui::px(220.))
                    .collapsed(collapsed)
                    .header(sidebar_header)
                    .child(menu);

                let (status, status_color) = match self.server_status {
                    crate::login_state::ServerStatus::Connecting => {
                        ("Connecting", self.theme.status_reconnecting)
                    }
                    crate::login_state::ServerStatus::Connected { .. } => {
                        ("Connected over mutual TLS", self.theme.status_online)
                    }
                    crate::login_state::ServerStatus::Unreachable => {
                        ("Server unreachable", self.theme.status_blocked)
                    }
                };

                let topbar = div()
                    .h(px(48.0))
                    .px_4()
                    .bg(rgb(self.theme.bg_app))
                    .border_b_1()
                    .border_color(rgb(self.theme.border_subtle))
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_3()
                            .child(
                                div()
                                    .text_sm()
                                    .font_semibold()
                                    .text_color(rgb(self.theme.text_primary))
                                    .child(active.label()),
                            )
                            .child(Separator::vertical().h(px(16.0)))
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child(div().size_2().rounded_full().bg(rgb(status_color)))
                                    .child(
                                        div()
                                            .text_xs()
                                            .text_color(rgb(self.theme.text_muted))
                                            .child(status),
                                    ),
                            )
                            .child(Separator::vertical().h(px(16.0)))
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(rgb(self.theme.text_muted))
                                    .child(format!("Server {server_version}")),
                            )
                            .child(Separator::vertical().h(px(16.0)))
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(rgb(self.theme.text_muted))
                                    .child(format!("{registered_devices} registered")),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(
                                div()
                                    .text_sm()
                                    .font_medium()
                                    .text_color(rgb(self.theme.text_primary))
                                    .child(username.clone()),
                            )
                            .child(if is_admin {
                                Tag::primary().child("Admin")
                            } else {
                                Tag::secondary().child("Operator")
                            })
                            .child(Separator::vertical().h(px(16.0)))
                            .child(
                                Button::new("change-password-btn")
                                    .ghost()
                                    .small()
                                    .icon(IconName::Key)
                                    .tooltip("Change Password")
                                    .on_click(
                                        cx.listener(|this, _, _, cx| this.open_change_password(cx)),
                                    ),
                            )
                            .child(
                                Button::new("signout-btn")
                                    .ghost()
                                    .small()
                                    .icon(IconName::LogOut)
                                    .tooltip("Sign Out")
                                    .on_click(cx.listener(|this, _, _, cx| this.submit_logout(cx))),
                            ),
                    );

                let mut content = div()
                    .id("connected-scroll")
                    .flex_1()
                    .min_h_0()
                    .w_full()
                    .p_4()
                    .flex()
                    .flex_col()
                    .gap_4()
                    .overflow_y_scroll();
                if let Some(err) = error {
                    content = content.child(
                        div()
                            .id("connected-error")
                            .text_color(rgb(self.theme.status_blocked))
                            .text_sm()
                            .child(err.clone()),
                    );
                }

                if let Some(note) = notice {
                    content = content.child(
                        div()
                            .id("connected-notice")
                            .text_color(rgb(self.theme.status_online))
                            .text_sm()
                            .child(note.clone()),
                    );
                }

                if active == Route::Fleet {
                    self.sync_fleet_inspector_sheet(window, cx);
                    content = content.child(self.render_fleet(cx));
                } else {
                    use gpui::component::WindowExt as _;
                    if window.has_active_sheet(cx) {
                        window.close_sheet(cx);
                        self.fleet_state.close_inspector();
                    }
                }
                if active == Route::Remote {
                    content = content.child(self.render_remote(cx));
                }
                if active == Route::Accounts {
                    content = content.child(self.render_accounts(cx));
                }
                if active == Route::Deployment {
                    content = content.child(self.render_deployment(cx));
                }
                if active == Route::Audit {
                    content = content.child(self.render_audit(cx));
                }
                if active == Route::Remote
                    && self
                        .remote_state
                        .active_session()
                        .is_some_and(|s| s.fullscreen)
                {
                    container
                        .gap_0()
                        .child(self.render_remote(cx))
                        .into_any_element()
                } else {
                    container
                        .flex_row()
                        .gap_0()
                        .child(sidebar)
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .flex_1()
                                .min_w_0()
                                .h_full()
                                .child(topbar)
                                .child(content),
                        )
                        .into_any_element()
                }
            }
        };

        div().relative().size_full().child(main_view)
    }
}
