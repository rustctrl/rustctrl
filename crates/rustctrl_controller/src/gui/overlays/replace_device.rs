use super::{
    render_cancel_button, render_dialog_card, render_dialog_input, render_error_box,
    render_submit_button,
};
use crate::gui::{ActiveField, ControllerApp};
use crate::theme::Theme;
use gpui::{AnyElement, Context, ParentElement as _, Styled as _, div, rgb};

pub(crate) fn render_replace_device_dialog(
    prior_device_id: &str,
    replacement_device_id: &str,
    error: Option<&String>,
    in_flight: bool,
    active_field: ActiveField,
    theme: &Theme,
    cx: &mut Context<ControllerApp>,
) -> AnyElement {
    let warning = div()
        .p_2()
        .bg(gpui::rgba(0xe0af6822))
        .border_1()
        .border_color(rgb(theme.status_reconnecting))
        .rounded_md()
        .text_xs()
        .text_color(rgb(theme.status_reconnecting))
        .child("Replacing a device identity rebinds credentials and invalidates the previous endpoint certificate.");

    let content = div()
        .flex()
        .flex_col()
        .gap_3()
        .child(warning)
        .child(render_dialog_input(
            "rd-prior-input",
            "Prior Device ID",
            prior_device_id,
            "ID of decommissioned device...",
            false,
            active_field == ActiveField::ReplaceDevicePriorId,
            ActiveField::ReplaceDevicePriorId,
            theme,
            cx,
        ))
        .child(render_dialog_input(
            "rd-replacement-input",
            "Replacement Device ID",
            replacement_device_id,
            "ID of new target device...",
            false,
            active_field == ActiveField::ReplaceDeviceReplacementId,
            ActiveField::ReplaceDeviceReplacementId,
            theme,
            cx,
        ))
        .children(render_error_box(error, theme));

    let footer = div()
        .flex()
        .items_center()
        .gap_2()
        .child(render_cancel_button("rd-cancel-btn", in_flight, cx))
        .child(render_submit_button(
            "rd-submit-btn",
            "Replace Identity",
            "Replacing...",
            in_flight,
            |this, cx| this.submit_replace_device(cx),
            cx,
        ));

    render_dialog_card(
        "Replace Device Identity",
        Some("Migrate device configuration and access credentials to a replacement endpoint."),
        content,
        footer,
        in_flight,
        theme,
        cx,
    )
}
