use super::super::*;
use gpui::component::button::Button;

impl ControllerApp {
    pub(in crate::gui) fn render_login(
        &self,
        container: gpui::Div,
        cx: &mut Context<Self>,
    ) -> gpui::Div {
        let ScreenState::Login {
            username,
            password,
            error,
            notice,
            remember,
            in_flight,
        } = &self.state
        else {
            unreachable!()
        };
        let theme = self.theme;
        let (status, color) = match self.server_status {
            crate::login_state::ServerStatus::Connecting => {
                ("Connecting", theme.status_reconnecting)
            }
            crate::login_state::ServerStatus::Connected { .. } => {
                ("Connected over mutual TLS", theme.status_online)
            }
            crate::login_state::ServerStatus::Unreachable => {
                ("Server unreachable", theme.status_blocked)
            }
        };
        let input = |active: bool| {
            div()
                .px_3()
                .py_2()
                .bg(rgb(theme.bg_app))
                .border_1()
                .border_color(rgb(if active {
                    theme.border_focus
                } else {
                    theme.border_subtle
                }))
                .rounded_md()
        };
        container.items_center().justify_center().child(
            div().w_full().max_w(gpui::px(440.)).p_6().rounded_lg().border_1().border_color(rgb(theme.border_subtle)).bg(rgb(theme.bg_surface)).flex().flex_col().gap_3()
                .child(div().text_3xl().child("RustCtrl"))
                .child(div().text_color(rgb(theme.text_muted)).child("Sign in to your Staff Account"))
                .child(div().text_color(rgb(color)).child(status))
                .child(div().text_sm().text_color(rgb(theme.text_muted)).child(format!("Server: {}", self.config.server.endpoint)))
                .when(self.server_status.show_bootstrap_notice(), |card| card.child(div().p_3().rounded_md().bg(rgb(theme.bg_surface_hover)).text_color(rgb(theme.status_reconnecting)).child("No Staff Accounts exist yet. On the Server shell, run rustctrl-server bootstrap-admin to create the first Admin.")))
                .children(notice.as_ref().map(|note| div().text_sm().text_color(rgb(theme.status_online)).child(note.clone())))
                .child("Username")
                .child(input(self.active_field == ActiveField::Username).id("username-input").on_click(cx.listener(|this, _, window, cx| { this.active_field = ActiveField::Username; window.focus(&this.focus_handle, cx); cx.notify(); })).child(if username.is_empty() { "Enter username".to_string() } else { username.clone() }))
                .child("Password")
                .child(input(self.active_field == ActiveField::Password).id("password-input").on_click(cx.listener(|this, _, window, cx| { this.active_field = ActiveField::Password; window.focus(&this.focus_handle, cx); cx.notify(); })).child(if password.is_empty() { "Enter password".to_string() } else if self.show_password { password.clone() } else { "•".repeat(password.chars().count()) }))
                .child(div().border_1().border_color(rgb(if self.active_field == ActiveField::PasswordVisibility { theme.border_focus } else { theme.bg_surface })).child(Button::new("password-visibility").track_focus(&self.visibility_focus).label(if self.show_password { "Hide password" } else { "Show password" }).on_click(cx.listener(|this, _, _, cx| { this.active_field = ActiveField::PasswordVisibility; this.show_password = !this.show_password; cx.notify(); }))))
                .child(div().border_1().border_color(rgb(if self.active_field == ActiveField::RememberLogin { theme.border_focus } else { theme.bg_surface })).child(Button::new("remember-toggle").track_focus(&self.remember_focus).label(if *remember { "✓ Remember this computer" } else { "Remember this computer" }).on_click(cx.listener(|this, _, _, cx| { this.active_field = ActiveField::RememberLogin; if let ScreenState::Login { remember, .. } = &mut this.state { *remember = !*remember; cx.notify(); } }))))
                .children(error.as_ref().map(|err| div().text_color(rgb(theme.status_blocked)).text_sm().child(err.clone())))
                .child(Button::new("signin-btn").label(if *in_flight { "Signing in..." } else { "Sign in" }).loading(*in_flight).on_click(cx.listener(|this, _, window, cx| { window.focus(&this.focus_handle, cx); this.submit_login(cx); })))
        )
    }
}
