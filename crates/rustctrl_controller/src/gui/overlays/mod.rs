#![allow(clippy::too_many_arguments)]

pub(crate) mod change_password;
pub(crate) mod prepare_artifact;
pub(crate) mod replace_device;
pub(crate) mod reset_password;
pub(crate) mod target_management;

use crate::gui::{ActiveField, ControllerApp};
use crate::theme::Theme;
use gpui::assets::IconName;
use gpui::base::Disableable as _;
use gpui::component::Icon;
use gpui::component::button::{Button, ButtonVariants as _};
use gpui::{
    AnyElement, Context, InteractiveElement as _, IntoElement, ParentElement as _,
    StatefulInteractiveElement as _, Styled as _, div, px, rgb, rgba,
};

/// Renders the modal backdrop and centered dialog card.
pub(crate) fn render_dialog_card(
    title: &str,
    description: Option<&str>,
    content: impl IntoElement,
    footer: impl IntoElement,
    in_flight: bool,
    theme: &Theme,
    cx: &mut Context<ControllerApp>,
) -> AnyElement {
    div()
        .absolute()
        .inset_0()
        .bg(rgba(0x0a0e14cc))
        .flex()
        .items_center()
        .justify_center()
        .id("modal-backdrop")
        .on_click(cx.listener(move |this, _, _, cx| {
            if !in_flight {
                this.close_overlay(cx);
            }
        }))
        .child(
            div()
                .w(px(480.0))
                .max_w(px(520.0))
                .bg(rgb(theme.bg_surface))
                .border_1()
                .border_color(rgb(theme.border_subtle))
                .rounded_xl()
                .p_6()
                .flex()
                .flex_col()
                .gap_4()
                .id("modal-dialog-card")
                .on_click(|_, _, _| {}) // stop propagation
                .child(
                    // Header
                    div()
                        .flex()
                        .items_start()
                        .justify_between()
                        .gap_3()
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .gap_1()
                                .child(
                                    div()
                                        .text_lg()
                                        .font_weight(gpui::FontWeight::SEMIBOLD)
                                        .text_color(rgb(theme.text_primary))
                                        .child(title.to_string()),
                                )
                                .children(description.map(|desc| {
                                    div()
                                        .text_xs()
                                        .text_color(rgb(theme.text_muted))
                                        .child(desc.to_string())
                                })),
                        )
                        .child(
                            div()
                                .id("dialog-close-x")
                                .cursor_pointer()
                                .p_1()
                                .rounded_md()
                                .text_color(rgb(theme.text_muted))
                                .hover(|s| s.text_color(rgb(theme.text_primary)))
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    if !in_flight {
                                        this.close_overlay(cx);
                                    }
                                }))
                                .child(Icon::new(IconName::X)),
                        ),
                )
                // Body
                .child(div().flex().flex_col().gap_3().child(content))
                // Footer
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .pt_2()
                        .border_t_1()
                        .border_color(rgb(theme.border_subtle))
                        .child(
                            div()
                                .text_xs()
                                .text_color(rgb(theme.text_muted))
                                .child("Press Enter to submit, Esc to cancel"),
                        )
                        .child(footer),
                ),
        )
        .into_any_element()
}

pub(crate) fn render_dialog_input(
    id: &'static str,
    label: &str,
    value: &str,
    placeholder: &str,
    is_masked: bool,
    is_active: bool,
    field: ActiveField,
    theme: &Theme,
    cx: &mut Context<ControllerApp>,
) -> impl IntoElement {
    let display_text = if value.is_empty() {
        placeholder.to_string()
    } else if is_masked {
        "•".repeat(value.len())
    } else {
        value.to_string()
    };

    let text_color = if value.is_empty() {
        rgb(theme.text_muted)
    } else {
        rgb(theme.text_primary)
    };

    div()
        .flex()
        .flex_col()
        .gap_1()
        .child(
            div()
                .text_xs()
                .font_weight(gpui::FontWeight::MEDIUM)
                .text_color(rgb(theme.text_primary))
                .child(label.to_string()),
        )
        .child(
            div()
                .px_3()
                .py_2()
                .bg(rgb(theme.bg_app))
                .border_1()
                .border_color(if is_active {
                    rgb(theme.accent_primary)
                } else {
                    rgb(theme.border_subtle)
                })
                .rounded_md()
                .cursor_text()
                .id(id)
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.active_field = field;
                    cx.notify();
                }))
                .child(div().text_sm().text_color(text_color).child(display_text)),
        )
}

pub(crate) fn render_submit_button(
    id: &'static str,
    label: &str,
    in_flight_label: &str,
    in_flight: bool,
    on_submit: impl Fn(&mut ControllerApp, &mut Context<ControllerApp>) + 'static + Copy,
    cx: &mut Context<ControllerApp>,
) -> impl IntoElement {
    if in_flight {
        Button::new(id)
            .primary()
            .disabled(true)
            .icon(Icon::new(IconName::Loader))
            .label(in_flight_label.to_string())
    } else {
        Button::new(id)
            .primary()
            .label(label.to_string())
            .on_click(cx.listener(move |this, _, _, cx| {
                on_submit(this, cx);
            }))
    }
}

pub(crate) fn render_cancel_button(
    id: &'static str,
    in_flight: bool,
    cx: &mut Context<ControllerApp>,
) -> impl IntoElement {
    Button::new(id)
        .outline()
        .disabled(in_flight)
        .label("Cancel")
        .on_click(cx.listener(move |this, _, _, cx| {
            if !in_flight {
                this.close_overlay(cx);
            }
        }))
}

pub(crate) fn render_error_box(error: Option<&String>, theme: &Theme) -> Option<impl IntoElement> {
    error.map(|err| {
        div()
            .p_2()
            .bg(rgba(0xef535022))
            .border_1()
            .border_color(rgb(theme.status_blocked))
            .rounded_md()
            .text_xs()
            .text_color(rgb(theme.status_blocked))
            .child(err.clone())
    })
}
