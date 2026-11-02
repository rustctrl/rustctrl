#![allow(clippy::too_many_arguments)]

use super::{
    render_cancel_button, render_dialog_card, render_dialog_input, render_error_box,
    render_submit_button,
};
use crate::gui::{ActiveField, ControllerApp};
use crate::theme::Theme;
use gpui::{AnyElement, Context, ParentElement as _, Styled as _, div};

pub(crate) fn render_add_target_dialog(
    display_name: &str,
    address: &str,
    location: &str,
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
            "at-name-input",
            "Display Name",
            display_name,
            "e.g. Conference Room TV",
            false,
            active_field == ActiveField::AddTargetDisplayName,
            ActiveField::AddTargetDisplayName,
            theme,
            cx,
        ))
        .child(render_dialog_input(
            "at-address-input",
            "Network Address (IP:Port)",
            address,
            "192.168.1.50:5555",
            false,
            active_field == ActiveField::AddTargetAddress,
            ActiveField::AddTargetAddress,
            theme,
            cx,
        ))
        .child(render_dialog_input(
            "at-location-input",
            "Physical Location (Optional)",
            location,
            "Building A, 2nd Floor",
            false,
            active_field == ActiveField::AddTargetLocation,
            ActiveField::AddTargetLocation,
            theme,
            cx,
        ))
        .children(render_error_box(error, theme));

    let footer = div()
        .flex()
        .items_center()
        .gap_2()
        .child(render_cancel_button("at-cancel-btn", in_flight, cx))
        .child(render_submit_button(
            "at-submit-btn",
            "Add Target",
            "Adding...",
            in_flight,
            |this, cx| this.submit_add_target(cx),
            cx,
        ));

    render_dialog_card(
        "Add Android TV Target",
        Some("Configure a network endpoint target for remote control and media display."),
        content,
        footer,
        in_flight,
        theme,
        cx,
    )
}

pub(crate) fn render_edit_target_dialog(
    target_id: &str,
    display_name: &str,
    address: &str,
    location: &str,
    error: Option<&String>,
    in_flight: bool,
    active_field: ActiveField,
    theme: &Theme,
    cx: &mut Context<ControllerApp>,
) -> AnyElement {
    let title = format!("Edit Android TV Target '{target_id}'");
    let content = div()
        .flex()
        .flex_col()
        .gap_3()
        .child(render_dialog_input(
            "et-name-input",
            "Display Name",
            display_name,
            "e.g. Conference Room TV",
            false,
            active_field == ActiveField::EditTargetDisplayName,
            ActiveField::EditTargetDisplayName,
            theme,
            cx,
        ))
        .child(render_dialog_input(
            "et-address-input",
            "Network Address (IP:Port)",
            address,
            "192.168.1.50:5555",
            false,
            active_field == ActiveField::EditTargetAddress,
            ActiveField::EditTargetAddress,
            theme,
            cx,
        ))
        .child(render_dialog_input(
            "et-location-input",
            "Physical Location (Optional)",
            location,
            "Building A, 2nd Floor",
            false,
            active_field == ActiveField::EditTargetLocation,
            ActiveField::EditTargetLocation,
            theme,
            cx,
        ))
        .children(render_error_box(error, theme));

    let footer = div()
        .flex()
        .items_center()
        .gap_2()
        .child(render_cancel_button("et-cancel-btn", in_flight, cx))
        .child(render_submit_button(
            "et-submit-btn",
            "Save Target",
            "Saving...",
            in_flight,
            |this, cx| this.submit_edit_target(cx),
            cx,
        ));

    render_dialog_card(
        &title,
        Some("Update endpoint address or location information."),
        content,
        footer,
        in_flight,
        theme,
        cx,
    )
}

pub(crate) fn render_edit_device_dialog(
    device_id: &str,
    display_name: &str,
    location: &str,
    error: Option<&String>,
    in_flight: bool,
    active_field: ActiveField,
    theme: &Theme,
    cx: &mut Context<ControllerApp>,
) -> AnyElement {
    let title = format!("Edit Device '{device_id}'");
    let content = div()
        .flex()
        .flex_col()
        .gap_3()
        .child(render_dialog_input(
            "ed-name-input",
            "Display Name",
            display_name,
            "Friendly name...",
            false,
            active_field == ActiveField::EditDeviceDisplayName,
            ActiveField::EditDeviceDisplayName,
            theme,
            cx,
        ))
        .child(render_dialog_input(
            "ed-location-input",
            "Physical Location",
            location,
            "e.g. Building B Floor 3",
            false,
            active_field == ActiveField::EditDeviceLocation,
            ActiveField::EditDeviceLocation,
            theme,
            cx,
        ))
        .children(render_error_box(error, theme));

    let footer = div()
        .flex()
        .items_center()
        .gap_2()
        .child(render_cancel_button("ed-cancel-btn", in_flight, cx))
        .child(render_submit_button(
            "ed-submit-btn",
            "Save Device",
            "Saving...",
            in_flight,
            |this, cx| this.submit_edit_device(cx),
            cx,
        ));

    render_dialog_card(
        &title,
        Some("Modify friendly hostname or location metadata."),
        content,
        footer,
        in_flight,
        theme,
        cx,
    )
}
