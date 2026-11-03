use super::{render_dialog_error, render_dialog_field};
use crate::gui::ControllerApp;
use crate::gui::state::ModalInputs;
use crate::theme::Theme;
use gpui::component::Disableable as _;
use gpui::component::button::{Button, ButtonVariants as _};
use gpui::component::dialog::{
    Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
};
use gpui::component::input::Input;
use gpui::{App, Entity, ParentElement as _, Styled as _, px};

pub(crate) fn render_add_target_dialog(
    inputs: &ModalInputs,
    error: Option<&String>,
    in_flight: bool,
    theme: &Theme,
    app: Entity<ControllerApp>,
    cx: &mut App,
) -> Dialog {
    let ModalInputs::AddTarget {
        display_name,
        address,
        location,
    } = inputs
    else {
        return Dialog::new(cx);
    };

    let app_close = app.clone();
    let app_cancel = app.clone();
    let app_submit = app.clone();

    Dialog::new(cx)
        .w(px(480.0))
        .centered()
        .close_button(!in_flight)
        .keyboard(!in_flight)
        .overlay_closable(!in_flight)
        .on_close(move |_, _, cx| {
            app_close.update(cx, |this, cx| {
                this.close_overlay(cx);
            });
        })
        .child(
            DialogHeader::new()
                .child(DialogTitle::new().child("Add Android TV Target"))
                .child(DialogDescription::new().child(
                    "Configure a network endpoint target for remote control and media display.",
                )),
        )
        .child(
            DialogContent::new()
                .gap_3()
                .child(render_dialog_field(
                    "Display Name",
                    Input::new(display_name),
                    theme,
                ))
                .child(render_dialog_field(
                    "Network Address (IP:Port)",
                    Input::new(address),
                    theme,
                ))
                .child(render_dialog_field(
                    "Physical Location (Optional)",
                    Input::new(location),
                    theme,
                ))
                .children(render_dialog_error("at-error-alert", error)),
        )
        .footer(
            DialogFooter::new()
                .child(
                    Button::new("at-cancel-btn")
                        .outline()
                        .disabled(in_flight)
                        .label("Cancel")
                        .on_click(move |_, window, cx| {
                            if !in_flight {
                                use gpui::component::WindowExt as _;
                                window.close_dialog(cx);
                                app_cancel.update(cx, |this, cx| this.close_overlay(cx));
                            }
                        }),
                )
                .child(
                    Button::new("at-submit-btn")
                        .primary()
                        .loading(in_flight)
                        .disabled(in_flight)
                        .label(if in_flight { "Adding..." } else { "Add Target" })
                        .on_click(move |_, _, cx| {
                            if !in_flight {
                                app_submit.update(cx, |this, cx| this.submit_add_target(cx));
                            }
                        }),
                ),
        )
}

pub(crate) fn render_edit_target_dialog(
    target_id: &str,
    inputs: &ModalInputs,
    error: Option<&String>,
    in_flight: bool,
    theme: &Theme,
    app: Entity<ControllerApp>,
    cx: &mut App,
) -> Dialog {
    let ModalInputs::EditTarget {
        display_name,
        address,
        location,
    } = inputs
    else {
        return Dialog::new(cx);
    };

    let app_close = app.clone();
    let app_cancel = app.clone();
    let app_submit = app.clone();
    let title = format!("Edit Android TV Target '{target_id}'");

    Dialog::new(cx)
        .w(px(480.0))
        .centered()
        .close_button(!in_flight)
        .keyboard(!in_flight)
        .overlay_closable(!in_flight)
        .on_close(move |_, _, cx| {
            app_close.update(cx, |this, cx| {
                this.close_overlay(cx);
            });
        })
        .child(
            DialogHeader::new()
                .child(DialogTitle::new().child(title))
                .child(
                    DialogDescription::new()
                        .child("Update endpoint address or location information."),
                ),
        )
        .child(
            DialogContent::new()
                .gap_3()
                .child(render_dialog_field(
                    "Display Name",
                    Input::new(display_name),
                    theme,
                ))
                .child(render_dialog_field(
                    "Network Address (IP:Port)",
                    Input::new(address),
                    theme,
                ))
                .child(render_dialog_field(
                    "Physical Location (Optional)",
                    Input::new(location),
                    theme,
                ))
                .children(render_dialog_error("et-error-alert", error)),
        )
        .footer(
            DialogFooter::new()
                .child(
                    Button::new("et-cancel-btn")
                        .outline()
                        .disabled(in_flight)
                        .label("Cancel")
                        .on_click(move |_, window, cx| {
                            if !in_flight {
                                use gpui::component::WindowExt as _;
                                window.close_dialog(cx);
                                app_cancel.update(cx, |this, cx| this.close_overlay(cx));
                            }
                        }),
                )
                .child(
                    Button::new("et-submit-btn")
                        .primary()
                        .loading(in_flight)
                        .disabled(in_flight)
                        .label(if in_flight {
                            "Saving..."
                        } else {
                            "Save Target"
                        })
                        .on_click(move |_, _, cx| {
                            if !in_flight {
                                app_submit.update(cx, |this, cx| this.submit_edit_target(cx));
                            }
                        }),
                ),
        )
}

pub(crate) fn render_edit_device_dialog(
    device_id: &str,
    inputs: &ModalInputs,
    error: Option<&String>,
    in_flight: bool,
    theme: &Theme,
    app: Entity<ControllerApp>,
    cx: &mut App,
) -> Dialog {
    let ModalInputs::EditDevice {
        display_name,
        location,
    } = inputs
    else {
        return Dialog::new(cx);
    };

    let app_close = app.clone();
    let app_cancel = app.clone();
    let app_submit = app.clone();
    let title = format!("Edit Device '{device_id}'");

    Dialog::new(cx)
        .w(px(480.0))
        .centered()
        .close_button(!in_flight)
        .keyboard(!in_flight)
        .overlay_closable(!in_flight)
        .on_close(move |_, _, cx| {
            app_close.update(cx, |this, cx| {
                this.close_overlay(cx);
            });
        })
        .child(
            DialogHeader::new()
                .child(DialogTitle::new().child(title))
                .child(
                    DialogDescription::new()
                        .child("Modify friendly hostname or location metadata."),
                ),
        )
        .child(
            DialogContent::new()
                .gap_3()
                .child(render_dialog_field(
                    "Display Name",
                    Input::new(display_name),
                    theme,
                ))
                .child(render_dialog_field(
                    "Physical Location",
                    Input::new(location),
                    theme,
                ))
                .children(render_dialog_error("ed-error-alert", error)),
        )
        .footer(
            DialogFooter::new()
                .child(
                    Button::new("ed-cancel-btn")
                        .outline()
                        .disabled(in_flight)
                        .label("Cancel")
                        .on_click(move |_, window, cx| {
                            if !in_flight {
                                use gpui::component::WindowExt as _;
                                window.close_dialog(cx);
                                app_cancel.update(cx, |this, cx| this.close_overlay(cx));
                            }
                        }),
                )
                .child(
                    Button::new("ed-submit-btn")
                        .primary()
                        .loading(in_flight)
                        .disabled(in_flight)
                        .label(if in_flight {
                            "Saving..."
                        } else {
                            "Save Device"
                        })
                        .on_click(move |_, _, cx| {
                            if !in_flight {
                                app_submit.update(cx, |this, cx| this.submit_edit_device(cx));
                            }
                        }),
                ),
        )
}
