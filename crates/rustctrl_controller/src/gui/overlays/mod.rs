pub(crate) mod change_password;
pub(crate) mod prepare_artifact;
pub(crate) mod replace_device;
pub(crate) mod reset_password;
pub(crate) mod target_management;

use crate::theme::Theme;
use gpui::component::alert::Alert;
use gpui::{IntoElement, ParentElement as _, Styled as _, div, rgb};

/// Renders a labeled form field container for dialog inputs.
pub(crate) fn render_dialog_field(
    label: &str,
    input: impl IntoElement,
    theme: &Theme,
) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .gap_1p5()
        .child(
            div()
                .text_xs()
                .font_weight(gpui::FontWeight::MEDIUM)
                .text_color(rgb(theme.text_muted))
                .child(label.to_string()),
        )
        .child(input)
}

/// Renders an inline Alert component if an error is present.
pub(crate) fn render_dialog_error(
    id: &'static str,
    error: Option<&String>,
) -> Option<impl IntoElement> {
    error.map(|err| Alert::error(id, err.clone()))
}
