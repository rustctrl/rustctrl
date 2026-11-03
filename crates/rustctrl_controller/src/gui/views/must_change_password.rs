use super::super::*;
use gpui::base::StyledExt as _;
use gpui::component::alert::Alert;
use gpui::component::button::{Button, ButtonVariants as _};
use gpui::component::input::Input;
use gpui::{Context, ParentElement as _, Styled as _, div, prelude::FluentBuilder as _, rgb};

impl ControllerApp {
    pub(in crate::gui) fn render_must_change_password(
        &self,
        container: gpui::Div,
        cx: &mut Context<Self>,
    ) -> gpui::Div {
        let ScreenState::MustChangePassword {
            username,
            error,
            in_flight,
            ..
        } = &self.state
        else {
            unreachable!()
        };
        let theme = self.theme;

        container.items_center().justify_center().child(
            div()
                .w_full()
                .max_w(gpui::px(440.))
                .p_6()
                .rounded_lg()
                .border_1()
                .border_color(rgb(theme.border_subtle))
                .bg(rgb(theme.bg_surface))
                .flex()
                .flex_col()
                .gap_3()
                .child(div().text_3xl().font_bold().child("RustCtrl"))
                .child(
                    div()
                        .text_color(rgb(theme.text_muted))
                        .child(format!("Welcome, {username}")),
                )
                .child(
                    Alert::warning(
                        "must-change-password-notice",
                        "A temporary password was used. You must set a permanent password before accessing the system.",
                    )
                    .title("Password Update Required"),
                )
                .child(
                    div()
                        .text_sm()
                        .font_semibold()
                        .child("New Permanent Password:"),
                )
                .when_some(
                    self.must_change_new_password_input.as_ref(),
                    |form, input_state| {
                        form.child(Input::new(input_state).mask_toggle())
                    },
                )
                .child(
                    div()
                        .text_sm()
                        .font_semibold()
                        .child("Confirm Permanent Password:"),
                )
                .when_some(
                    self.must_change_confirm_password_input.as_ref(),
                    |form, input_state| {
                        form.child(Input::new(input_state).mask_toggle())
                    },
                )
                .when_some(error.as_ref(), |form, err| {
                    form.child(Alert::error("change-password-error", err.clone()))
                })
                .child(
                    div()
                        .flex()
                        .gap_3()
                        .child(
                            Button::new("save-password-btn")
                                .primary()
                                .label(if *in_flight {
                                    "Updating..."
                                } else {
                                    "Save & Continue"
                                })
                                .loading(*in_flight)
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.submit_replace_password(cx)
                                })),
                        )
                        .child(
                            Button::new("cancel-btn")
                                .label("Cancel / Logout")
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.submit_logout(cx);
                                })),
                        ),
                ),
        )
    }
}
