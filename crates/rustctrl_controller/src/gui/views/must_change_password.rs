use super::super::*;

impl ControllerApp {
    pub(in crate::gui) fn render_must_change_password(
        &self,
        container: gpui::Div,
        cx: &mut Context<Self>,
    ) -> gpui::Div {
        let ScreenState::MustChangePassword {
            username,
            new_password,
            confirm_password,
            error,
            in_flight,
            ..
        } = &self.state
        else {
            unreachable!()
        };
        let new_active = self.active_field == ActiveField::NewPassword;
        let conf_active = self.active_field == ActiveField::ConfirmPassword;
        let masked_new = "•".repeat(new_password.chars().count());
        let masked_conf = "•".repeat(confirm_password.chars().count());

        container.items_center().justify_center()
                    .child(div().text_3xl().child("RustCtrl"))
                    .child(format!("Welcome, {username}"))
                    .child(
                        div()
                            .text_color(rgb(self.theme.status_reconnecting))
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
                                    .bg(rgb(self.theme.bg_app))
                                    .border_1()
                                    .border_color(if new_active {
                                        rgb(self.theme.border_focus)
                                    } else {
                                        rgb(self.theme.border_subtle)
                                    })
                                    .rounded_md()
                                    .id("new-password-input")
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        window.focus(&this.focus_handle, cx);
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
                                    .bg(rgb(self.theme.bg_app))
                                    .border_1()
                                    .border_color(if conf_active {
                                        rgb(self.theme.border_focus)
                                    } else {
                                        rgb(self.theme.border_subtle)
                                    })
                                    .rounded_md()
                                    .id("confirm-password-input")
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        window.focus(&this.focus_handle, cx);
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
                                div().text_color(rgb(self.theme.status_blocked)).text_sm().child(err.clone())
                            }))
                            .child(
                                div()
                                    .flex()
                                    .gap_3()
                                    .child(
                                        gpui::component::button::Button::new("save-password-btn")
                                            .label(if *in_flight { "Updating..." } else { "Save & Continue" })
                                            .loading(*in_flight)
                                            .on_click(cx.listener(|this, _, _, cx| this.submit_replace_password(cx))),
                                    )
                                    .child(
                                        gpui::component::button::Button::new("cancel-btn")
                                            .label("Cancel / Logout")
                                            .on_click(cx.listener(|this, _, window, cx| { window.focus(&this.focus_handle, cx); this.submit_logout(cx); })),
                                    ),
                            ),
                    )
    }
}
