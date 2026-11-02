#![allow(clippy::too_many_arguments)]

use super::{
    render_cancel_button, render_dialog_card, render_dialog_input, render_error_box,
    render_submit_button,
};
use crate::gui::{ActiveField, ControllerApp};
use crate::theme::Theme;
use gpui::{AnyElement, Context, ParentElement as _, Styled as _, div, rgb};

pub(crate) fn render_reset_password_dialog(
    target_username: &str,
    temporary_password: &str,
    confirm_password: &str,
    error: Option<&String>,
    in_flight: bool,
    active_field: ActiveField,
    theme: &Theme,
    cx: &mut Context<ControllerApp>,
) -> AnyElement {
    let title = format!("Reset Password for '{target_username}'");
    let notice = div()
        .p_2()
        .bg(gpui::rgba(0xe0af6822))
        .border_1()
        .border_color(rgb(theme.status_reconnecting))
        .rounded_md()
        .text_xs()
        .text_color(rgb(theme.status_reconnecting))
        .child("The account receives a temporary password, must replace it at next login, and all of its staff sessions are revoked.");

    let content = div()
        .flex()
        .flex_col()
        .gap_3()
        .child(notice)
        .child(render_dialog_input(
            "rp-temp-input",
            "Temporary Password",
            temporary_password,
            "Minimum 8 characters...",
            true,
            active_field == ActiveField::TemporaryPassword,
            ActiveField::TemporaryPassword,
            theme,
            cx,
        ))
        .child(render_dialog_input(
            "rp-confirm-input",
            "Confirm Temporary Password",
            confirm_password,
            "Re-enter temporary password...",
            true,
            active_field == ActiveField::ConfirmPassword,
            ActiveField::ConfirmPassword,
            theme,
            cx,
        ))
        .children(render_error_box(error, theme));

    let footer = div()
        .flex()
        .items_center()
        .gap_2()
        .child(render_cancel_button("rp-cancel-btn", in_flight, cx))
        .child(render_submit_button(
            "rp-submit-btn",
            "Reset Password",
            "Resetting...",
            in_flight,
            |this, cx| this.submit_reset_password(cx),
            cx,
        ));

    render_dialog_card(
        &title,
        Some("Administrative credential reset with mandatory replacement upon next sign-in."),
        content,
        footer,
        in_flight,
        theme,
        cx,
    )
}
