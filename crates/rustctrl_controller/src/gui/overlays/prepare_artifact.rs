#![allow(clippy::too_many_arguments)]

use super::{
    render_cancel_button, render_dialog_card, render_dialog_input, render_error_box,
    render_submit_button,
};
use crate::gui::{ActiveField, ControllerApp};
use crate::theme::Theme;
use gpui::{AnyElement, Context, ParentElement as _, Styled as _, div, rgb};

pub(crate) fn render_prepare_artifact_dialog(
    output_path: &str,
    agent_binary_path: &str,
    error: Option<&String>,
    success: Option<&String>,
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
            "pa-output-input",
            "Output Package Path (.zip)",
            output_path,
            "/path/to/rustctrl-agent-bundle.zip",
            false,
            active_field == ActiveField::PrepareArtifactOutputPath,
            ActiveField::PrepareArtifactOutputPath,
            theme,
            cx,
        ))
        .child(render_dialog_input(
            "pa-binary-input",
            "Agent Binary Path (Optional)",
            agent_binary_path,
            "Optional path to custom agent executable...",
            false,
            active_field == ActiveField::PreparePackageAgentBinary,
            ActiveField::PreparePackageAgentBinary,
            theme,
            cx,
        ))
        .children(render_error_box(error, theme))
        .children(success.map(|msg| {
            div()
                .p_2()
                .bg(gpui::rgba(0x4caf5022))
                .border_1()
                .border_color(rgb(theme.status_online))
                .rounded_md()
                .text_xs()
                .text_color(rgb(theme.status_online))
                .child(msg.clone())
        }));

    let footer = div()
        .flex()
        .items_center()
        .gap_2()
        .child(render_cancel_button("pa-cancel-btn", in_flight, cx))
        .child(render_submit_button(
            "pa-submit-btn",
            "Create Package",
            "Creating...",
            in_flight,
            |this, cx| this.submit_prepare_installation_artifact(cx),
            cx,
        ));

    render_dialog_card(
        "Prepare Installation Package",
        Some("Generate an installation bundle with server CA certificates and configuration."),
        content,
        footer,
        in_flight,
        theme,
        cx,
    )
}
