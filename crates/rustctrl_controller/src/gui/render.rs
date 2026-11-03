use super::helpers::resolve_typed_text;
use super::overlays;
use super::state::*;
use gpui::{
    Context, InteractiveElement as _, IntoElement, KeyDownEvent, ParentElement as _, Render,
    Styled as _, Window, div, prelude::*, rgb,
};

impl ControllerApp {
    fn render_overlay_form(&self, cx: &mut Context<Self>) -> impl IntoElement {
        match &self.overlay {
            Overlay::ChangePassword {
                current_password,
                new_password,
                confirm_password,
                error,
                in_flight,
            } => overlays::change_password::render_change_password_dialog(
                current_password,
                new_password,
                confirm_password,
                error.as_ref(),
                *in_flight,
                self.active_field,
                &self.theme,
                cx,
            ),
            Overlay::ResetPassword {
                target_username,
                temporary_password,
                confirm_password,
                error,
                in_flight,
            } => overlays::reset_password::render_reset_password_dialog(
                target_username,
                temporary_password,
                confirm_password,
                error.as_ref(),
                *in_flight,
                self.active_field,
                &self.theme,
                cx,
            ),
            Overlay::EditDevice {
                device_id,
                display_name,
                location,
                error,
                in_flight,
                ..
            } => overlays::target_management::render_edit_device_dialog(
                device_id,
                display_name,
                location,
                error.as_ref(),
                *in_flight,
                self.active_field,
                &self.theme,
                cx,
            ),
            Overlay::AddTarget {
                display_name,
                address,
                location,
                error,
                in_flight,
                ..
            } => overlays::target_management::render_add_target_dialog(
                display_name,
                address,
                location,
                error.as_ref(),
                *in_flight,
                self.active_field,
                &self.theme,
                cx,
            ),
            Overlay::EditTarget {
                target_id,
                display_name,
                address,
                location,
                error,
                in_flight,
                ..
            } => overlays::target_management::render_edit_target_dialog(
                target_id,
                display_name,
                address,
                location,
                error.as_ref(),
                *in_flight,
                self.active_field,
                &self.theme,
                cx,
            ),
            Overlay::ReplaceDevice {
                prior_device_id,
                replacement_device_id,
                error,
                in_flight,
                ..
            } => overlays::replace_device::render_replace_device_dialog(
                prior_device_id,
                replacement_device_id,
                error.as_ref(),
                *in_flight,
                self.active_field,
                &self.theme,
                cx,
            ),
            Overlay::PrepareInstallationArtifact {
                output_path,
                agent_binary_path,
                error,
                in_flight,
                success,
                ..
            } => overlays::prepare_artifact::render_prepare_artifact_dialog(
                output_path,
                agent_binary_path,
                error.as_ref(),
                success.as_ref(),
                *in_flight,
                self.active_field,
                &self.theme,
                cx,
            ),
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
            "escape" => {
                self.close_overlay(cx);
            }
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

    fn handle_key_down(
        &mut self,
        event: &KeyDownEvent,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if !matches!(self.overlay, Overlay::None) {
            self.handle_overlay_key_down(event, cx);
            return;
        }
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
                new_account_username,
                new_account_password,
                in_flight,
                role,
                ..
            } => {
                if *in_flight {
                    return;
                }
                if self.active_field == ActiveField::FleetSearch {
                    match key.as_str() {
                        "escape" => {
                            self.fleet_state.search_query.clear();
                            cx.notify();
                        }
                        "backspace" => {
                            self.fleet_state.search_query.pop();
                            cx.notify();
                        }
                        _ => {
                            if let Some(text) = resolve_typed_text(&event.keystroke) {
                                self.fleet_state.search_query.push_str(text);
                                cx.notify();
                            }
                        }
                    }
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
                        return;
                    }
                }
                if role != "admin"
                    || self.navigation.active(role) != crate::navigation::Route::Accounts
                    || !matches!(
                        self.active_field,
                        ActiveField::NewAccountUsername | ActiveField::NewAccountPassword
                    )
                {
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
        }

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
                use gpui::component::button::Button;
                use gpui::component::sidebar::{
                    Sidebar, SidebarMenu, SidebarMenuItem, SidebarToggleButton,
                };

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
                                    if matches!(this.overlay, Overlay::None) {
                                        this.active_field = ActiveField::Username;
                                    }
                                    cx.notify();
                                }
                            })),
                    );
                }
                let sidebar =
                    Sidebar::new("navigation")
                        .w(gpui::px(220.))
                        .collapsed(collapsed)
                        .header(SidebarToggleButton::new().collapsed(collapsed).on_click(
                            cx.listener(|this, _, _, cx| {
                                this.navigation.collapsed = !this.navigation.collapsed;
                                cx.notify();
                            }),
                        ))
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
                let header = div()
                    .w_full()
                    .px_4()
                    .py_3()
                    .flex()
                    .items_center()
                    .justify_between()
                    .border_b_1()
                    .border_color(rgb(self.theme.border_subtle))
                    .bg(rgb(self.theme.bg_surface))
                    .child(
                        div()
                            .flex()
                            .gap_3()
                            .items_center()
                            .child(div().text_color(rgb(status_color)).child(status))
                            .child(div().text_color(rgb(self.theme.text_muted)).child(format!(
                                "Server {server_version} · {registered_devices} devices"
                            ))),
                    )
                    .child(
                        div()
                            .flex()
                            .gap_3()
                            .items_center()
                            .child(username.clone())
                            .child(
                                div()
                                    .px_2()
                                    .rounded_md()
                                    .bg(rgb(self.theme.bg_surface_hover))
                                    .child(if is_admin { "Admin" } else { "Operator" }),
                            )
                            .child(
                                Button::new("change-password-btn")
                                    .label("Change Password")
                                    .on_click(
                                        cx.listener(|this, _, _, cx| this.open_change_password(cx)),
                                    ),
                            )
                            .child(
                                Button::new("signout-btn")
                                    .label("Sign Out")
                                    .on_click(cx.listener(|this, _, _, cx| this.submit_logout(cx))),
                            ),
                    );
                let mut content = div()
                    .id("connected-scroll")
                    .size_full()
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
                    content = content.child(self.render_fleet(cx));
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
                        .child(header)
                        .child(
                            div()
                                .flex()
                                .flex_1()
                                .min_h_0()
                                .child(sidebar)
                                .child(content),
                        )
                        .into_any_element()
                }
            }
        };

        let mut root = div().relative().size_full().child(main_view);

        if !matches!(self.overlay, Overlay::None) {
            root = root.child(self.render_overlay_form(cx));
        }

        root
    }
}
