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

pub(crate) fn render_reset_password_dialog(
    target_username: &str,
    inputs: &ModalInputs,
    error: Option<&String>,
    in_flight: bool,
    theme: &Theme,
    app: Entity<ControllerApp>,
    cx: &mut App,
) -> Dialog {
    let ModalInputs::ResetPassword {
        temporary_password,
        confirm_password,
    } = inputs
    else {
        return Dialog::new(cx);
    };

    let app_close = app.clone();
    let app_cancel = app.clone();
    let app_submit = app.clone();
    let title = format!("Reset Password for '{target_username}'");

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
                .child(DialogDescription::new().child(
                    "Administrative credential reset with mandatory replacement upon next sign-in.",
                )),
        )
        .child(
            DialogContent::new()
                .gap_3()
                .child(Alert::warning(
                    "rp-warning-alert",
                    "The account receives a temporary password, must replace it at next login, and all of its staff sessions are revoked.",
                ))
                .child(render_dialog_field(
                    "Temporary Password",
                    Input::new(temporary_password),
                    theme,
                ))
                .child(render_dialog_field(
                    "Confirm Temporary Password",
                    Input::new(confirm_password),
                    theme,
                ))
                .children(render_dialog_error("rp-error-alert", error)),
        )
        .footer(
            DialogFooter::new()
                .child(
                    Button::new("rp-cancel-btn")
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
                    Button::new("rp-submit-btn")
                        .primary()
                        .loading(in_flight)
                        .disabled(in_flight)
                        .label(if in_flight {
                            "Resetting..."
                        } else {
                            "Reset Password"
                        })
                        .on_click(move |_, _, cx| {
                            if !in_flight {
                                app_submit.update(cx, |this, cx| this.submit_reset_password(cx));
                            }
                        }),
                ),
        )
}
