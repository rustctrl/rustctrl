#![allow(clippy::too_many_arguments)]

use super::{
    render_cancel_button, render_dialog_card, render_dialog_input, render_error_box,
    render_submit_button,
};
use crate::gui::{ActiveField, ControllerApp};
use crate::theme::Theme;
use gpui::{AnyElement, Context, ParentElement as _, Styled as _, div};

pub(crate) fn render_change_password_dialog(
    current_password: &str,
    new_password: &str,
    confirm_password: &str,
    error: Option<&String>,
    in_flight: bool,
    active_field: ActiveField,
    theme: &Theme,
    cx: &mut Context<ControllerApp>,
) -> AnyElement {
    let content = div()
        .flex()
        .flex_col()
        .gap_3()
        .child(render_dialog_input(
            "cp-current-input",
            "Current Password",
            current_password,
            "Enter current password...",
            true,
            active_field == ActiveField::CurrentPassword,
            ActiveField::CurrentPassword,
            theme,
            cx,
        ))
        .child(render_dialog_input(
            "cp-new-input",
            "New Password",
            new_password,
            "Minimum 8 characters...",
            true,
            active_field == ActiveField::NewPassword,
            ActiveField::NewPassword,
            theme,
            cx,
        ))
        .child(render_dialog_input(
            "cp-confirm-input",
            "Confirm New Password",
            confirm_password,
            "Re-enter new password...",
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
        .child(render_cancel_button("cp-cancel-btn", in_flight, cx))
        .child(render_submit_button(
            "cp-submit-btn",
            "Update Password",
            "Updating...",
            in_flight,
            |this, cx| this.submit_change_password(cx),
            cx,
        ));

    render_dialog_card(
        "Change Password",
        Some("Update your personal staff account credentials."),
        content,
        footer,
        in_flight,
        theme,
        cx,
    )
}
