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

pub(crate) fn render_prepare_artifact_dialog(
    inputs: &ModalInputs,
    error: Option<&String>,
    success: Option<&String>,
    in_flight: bool,
    theme: &Theme,
    app: Entity<ControllerApp>,
    cx: &mut App,
) -> Dialog {
    let ModalInputs::PrepareArtifact {
        output_path,
        agent_binary_path,
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
                .child(DialogTitle::new().child("Prepare Installation Package"))
                .child(DialogDescription::new().child(
                    "Generate an installation bundle with server CA certificates and configuration.",
                )),
        )
        .child(
            DialogContent::new()
                .gap_3()
                .child(render_dialog_field(
                    "Output Package Path (.zip)",
                    Input::new(output_path),
                    theme,
                ))
                .child(render_dialog_field(
                    "Agent Binary Path (Optional)",
                    Input::new(agent_binary_path),
                    theme,
                ))
                .children(render_dialog_error("pa-error-alert", error))
                .children(success.map(|msg| {
                    Alert::success("pa-success-alert", msg.clone())
                })),
        )
        .footer(
            DialogFooter::new()
                .child(
                    Button::new("pa-cancel-btn")
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
                    Button::new("pa-submit-btn")
                        .primary()
                        .loading(in_flight)
                        .disabled(in_flight)
                        .label(if in_flight {
                            "Creating..."
                        } else {
                            "Create Package"
                        })
                        .on_click(move |_, _, cx| {
                            if !in_flight {
                                app_submit.update(cx, |this, cx| {
                                    this.submit_prepare_installation_artifact(cx);
                                });
                            }
                        }),
                ),
        )
}
