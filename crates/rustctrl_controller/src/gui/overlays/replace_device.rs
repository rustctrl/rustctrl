use super::{render_dialog_error, render_dialog_field};
use crate::gui::ControllerApp;
use crate::gui::state::ModalInputs;
use crate::theme::Theme;
use gpui::component::Disableable as _;
use gpui::component::alert::Alert;
use gpui::component::button::{Button, ButtonVariants as _};
use gpui::component::dialog::{
    Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
};
use gpui::component::input::Input;
use gpui::{App, Entity, ParentElement as _, Styled as _, px};

pub(crate) fn render_replace_device_dialog(
    inputs: &ModalInputs,
    error: Option<&String>,
    in_flight: bool,
    theme: &Theme,
    app: Entity<ControllerApp>,
    cx: &mut App,
) -> Dialog {
    let ModalInputs::ReplaceDevice {
        prior_device_id,
        replacement_device_id,
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
                .child(DialogTitle::new().child("Replace Device Identity"))
                .child(DialogDescription::new().child(
                    "Migrate device configuration and access credentials to a replacement endpoint.",
                )),
        )
        .child(
            DialogContent::new()
                .gap_3()
                .child(Alert::warning(
                    "rd-warning-alert",
                    "Replacing a device identity rebinds credentials and invalidates the previous endpoint certificate.",
                ))
                .child(render_dialog_field(
                    "Prior Device ID",
                    Input::new(prior_device_id),
                    theme,
                ))
                .child(render_dialog_field(
                    "Replacement Device ID",
                    Input::new(replacement_device_id),
                    theme,
                ))
                .children(render_dialog_error("rd-error-alert", error)),
        )
        .footer(
            DialogFooter::new()
                .child(
                    Button::new("rd-cancel-btn")
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
                    Button::new("rd-submit-btn")
                        .primary()
                        .loading(in_flight)
                        .disabled(in_flight)
                        .label(if in_flight {
                            "Replacing..."
                        } else {
                            "Replace Identity"
                        })
                        .on_click(move |_, _, cx| {
                            if !in_flight {
                                app_submit.update(cx, |this, cx| this.submit_replace_device(cx));
                            }
                        }),
                ),
        )
}
