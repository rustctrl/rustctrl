use super::super::*;
use crate::remote::{InputMode, MonitorTarget, RemoteSession};
use crate::theme::Theme;
use gpui::assets::IconName;
use gpui::base::StyledExt as _;
use gpui::component::Icon;
use gpui::component::button::{Button, ButtonVariants as _};
use gpui::component::empty::{
    Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyMediaVariant, EmptyTitle,
};
use gpui::{
    AnyElement, Context, InteractiveElement as _, IntoElement, ParentElement as _,
    StatefulInteractiveElement as _, Styled as _, div, prelude::FluentBuilder as _, px, rgb,
};

impl ControllerApp {
    pub(in crate::gui) fn render_remote(&self, cx: &mut Context<Self>) -> impl IntoElement {
        if let Some(session) = self.remote_state.active_session() {
            self.render_active_remote_canvas(session, &self.theme, cx)
                .into_any_element()
        } else {
            self.render_remote_empty_state(&self.theme, cx)
                .into_any_element()
        }
    }

    fn render_remote_empty_state(&self, theme: &Theme, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .size_full()
            .flex()
            .flex_col()
            .items_center()
            .justify_center()
            .p_8()
            .bg(rgb(theme.bg_app))
            .child(
                div()
                    .max_w(px(520.0))
                    .w_full()
                    .p_6()
                    .bg(rgb(theme.bg_surface))
                    .border_1()
                    .border_color(rgb(theme.border_subtle))
                    .rounded_xl()
                    .flex()
                    .flex_col()
                    .items_center()
                    .gap_4()
                    .child(
                        Empty::new()
                            .header(
                                EmptyHeader::new()
                                    .media(
                                        EmptyMedia::new()
                                            .with_variant(EmptyMediaVariant::Icon)
                                            .child(
                                                Icon::new(IconName::Monitor)
                                                    .size_6()
                                                    .text_color(rgb(theme.accent_primary)),
                                            ),
                                    )
                                    .title(
                                        EmptyTitle::new().child(
                                            div()
                                                .text_base()
                                                .font_semibold()
                                                .text_color(rgb(theme.text_primary))
                                                .child("No Active Remote Session"),
                                        ),
                                    )
                                    .description(
                                        EmptyDescription::new().child(
                                            div()
                                                .text_sm()
                                                .text_color(rgb(theme.text_muted))
                                                .child(
                                                    "Select an online Windows endpoint from the Fleet Inventory and start a Remote Session to begin interactive desktop management.",
                                                ),
                                        ),
                                    ),
                            )
                            .content(
                                EmptyContent::new().child(
                                    Button::new("remote-empty-goto-fleet-btn")
                                        .primary()
                                        .label("Go to Fleet Inventory")
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            if let ScreenState::Connected { role, .. } = &this.state {
                                                this.navigation
                                                    .select(crate::navigation::Route::Fleet, role);
                                                cx.notify();
                                            }
                                        })),
                                ),
                            ),
                    ),
            )
    }

    fn render_active_remote_canvas(
        &self,
        session: &RemoteSession,
        theme: &Theme,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let is_toolbar_visible = self.remote_state.toolbar_visible;

        div()
            .relative()
            .size_full()
            .bg(rgb(theme.bg_app))
            .overflow_hidden()
            .flex()
            .flex_col()
            // 1. Main Virtual Display Frame (underneath toolbar)
            .child(
                div()
                    .size_full()
                    .flex()
                    .flex_col()
                    .p_4()
                    .gap_3()
                    .child(self.render_display_viewport(session, theme, cx)),
            )
            // 2. Top Proximity Sensor Area for auto-hiding floating toolbar
            .child(
                div()
                    .id("remote-proximity-sensor")
                    .absolute()
                    .top_0()
                    .left_0()
                    .w_full()
                    .h(px(64.0))
                    .on_hover(cx.listener(|this, hovered, _, cx| {
                        if *hovered && !this.remote_state.toolbar_visible {
                            this.remote_state.set_toolbar_visible(true);
                            cx.notify();
                        }
                    })),
            )
            // 3. Floating Overlay Toolbar (anchored top center)
            .when(is_toolbar_visible, |canvas| {
                canvas.child(
                    div()
                        .absolute()
                        .top_4()
                        .left_0()
                        .w_full()
                        .flex()
                        .justify_center()
                        .child(self.render_floating_toolbar(session, theme, cx)),
                )
            })
            // 4. Re-show Toolbar button when hidden
            .when(!is_toolbar_visible, |canvas| {
                canvas.child(
                    div()
                        .absolute()
                        .top_2()
                        .left_0()
                        .w_full()
                        .flex()
                        .justify_center()
                        .child(
                            Button::new("remote-show-toolbar-pill")
                                .secondary()
                                .label("Show Controls")
                                .icon(IconName::Monitor)
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.remote_state.set_toolbar_visible(true);
                                    cx.notify();
                                })),
                        ),
                )
            })
    }

    fn render_floating_toolbar(
        &self,
        session: &RemoteSession,
        theme: &Theme,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        div()
            .id("remote-floating-toolbar")
            .bg(rgb(theme.bg_surface))
            .border_1()
            .border_color(rgb(theme.border_subtle))
            .rounded_xl()
            .shadow_lg()
            .px_3()
            .py_2()
            .flex()
            .items_center()
            .gap_2()
            // 1. Target Endpoint info
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .px_2()
                    .child(Icon::new(IconName::Monitor).text_color(rgb(theme.status_online)))
                    .child(
                        div()
                            .text_sm()
                            .font_semibold()
                            .text_color(rgb(theme.text_primary))
                            .child(session.device_name.clone()),
                    ),
            )
            .child(self.render_toolbar_separator(theme))
            // 2. Multi-Monitor Selector
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_1()
                    .children(MonitorTarget::ALL.iter().map(|&mon| {
                        let is_selected = session.monitor == mon;
                        let btn = Button::new(format!("mon-target-btn-{}", mon.label()))
                            .label(mon.label())
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.select_remote_monitor(mon, cx);
                            }));
                        if is_selected {
                            btn.primary()
                        } else {
                            btn.ghost()
                        }
                    })),
            )
            .child(self.render_toolbar_separator(theme))
            // 3. SAS (Ctrl+Alt+Del) Button
            .child(
                Button::new("remote-sas-btn")
                    .secondary()
                    .label("Ctrl+Alt+Del")
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.trigger_sas(cx);
                    })),
            )
            .child(self.render_toolbar_separator(theme))
            // 4. Input Mode Toggle (Interactive Control vs View-Only Mode)
            .child(
                Button::new("remote-input-mode-btn")
                    .secondary()
                    .icon(match session.input_mode {
                        InputMode::Interactive => IconName::MousePointer,
                        InputMode::ViewOnly => IconName::Eye,
                    })
                    .label(session.input_mode.label())
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.toggle_remote_input_mode(cx);
                    })),
            )
            .child(self.render_toolbar_separator(theme))
            // 5. Latency, FPS, and stream quality status badge
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .px_2p5()
                    .py_1()
                    .rounded_md()
                    .bg(rgb(theme.bg_surface))
                    .border_1()
                    .border_color(rgb(theme.border_subtle))
                    .child(div().size_2().rounded_full().bg(rgb(theme.status_online)))
                    .child(
                        div()
                            .text_xs()
                            .text_color(rgb(theme.text_muted))
                            .child(format!(
                                "{}ms • {} FPS • {}",
                                session.metrics.latency_ms,
                                session.metrics.fps,
                                session.metrics.quality_label
                            )),
                    ),
            )
            .child(self.render_toolbar_separator(theme))
            // 6. Fullscreen Toggle Button (with F11 shortcut)
            .child(
                Button::new("remote-fullscreen-btn")
                    .ghost()
                    .icon(if session.fullscreen {
                        IconName::Minimize
                    } else {
                        IconName::Maximize
                    })
                    .label(if session.fullscreen {
                        "Windowed (F11)"
                    } else {
                        "Fullscreen (F11)"
                    })
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.toggle_remote_fullscreen(cx);
                    })),
            )
            .child(self.render_toolbar_separator(theme))
            // 7. Keyboard Ungrab indicator & button (Ctrl+Shift+Esc)
            .child(
                Button::new("remote-ungrab-btn")
                    .ghost()
                    .icon(IconName::Keyboard)
                    .label(if session.keyboard_grabbed {
                        "Grabbed (Ctrl+Shift+Esc)"
                    } else {
                        "Ungrabbed"
                    })
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.ungrab_remote_keyboard(cx);
                    })),
            )
            .child(self.render_toolbar_separator(theme))
            // 8. Prominent Red Disconnect Button
            .child(
                Button::new("remote-disconnect-btn")
                    .danger()
                    .icon(IconName::LogOut)
                    .label("Disconnect")
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.disconnect_remote_session(cx);
                    })),
            )
            // 9. Hide Toolbar Button
            .child(
                Button::new("remote-hide-toolbar-btn")
                    .ghost()
                    .icon(IconName::X)
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.remote_state.set_toolbar_visible(false);
                        cx.notify();
                    })),
            )
    }

    fn render_toolbar_separator(&self, theme: &Theme) -> AnyElement {
        div()
            .w(px(1.0))
            .h(px(20.0))
            .bg(rgb(theme.border_subtle))
            .into_any_element()
    }

    fn render_display_viewport(
        &self,
        session: &RemoteSession,
        theme: &Theme,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        div()
            .flex_1()
            .size_full()
            .bg(rgb(theme.bg_surface))
            .border_1()
            .border_color(rgb(theme.border_subtle))
            .rounded_xl()
            .flex()
            .flex_col()
            .overflow_hidden()
            // Viewport Header Bar
            .child(
                div()
                    .h(px(40.0))
                    .bg(rgb(theme.bg_app))
                    .border_b_1()
                    .border_color(rgb(theme.border_subtle))
                    .px_4()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_3()
                            .child(
                                div()
                                    .text_sm()
                                    .font_semibold()
                                    .text_color(rgb(theme.text_primary))
                                    .child(format!(
                                        "{} — {}",
                                        session.device_name,
                                        session.monitor.label()
                                    )),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .px_2()
                                    .py_0p5()
                                    .rounded_md()
                                    .bg(rgb(theme.bg_surface))
                                    .text_color(rgb(theme.text_muted))
                                    .child(session.metrics.resolution.clone()),
                            ),
                    )
                    .child(
                        div().flex().items_center().gap_2().child(
                            div()
                                .text_xs()
                                .font_medium()
                                .text_color(rgb(if session.input_mode == InputMode::Interactive {
                                    theme.status_online
                                } else {
                                    theme.status_reconnecting
                                }))
                                .child(session.input_mode.label()),
                        ),
                    ),
            )
            // Interactive Stream Canvas Area
            .child(
                div()
                    .id("remote-stream-canvas")
                    .flex_1()
                    .size_full()
                    .bg(rgb(theme.bg_app))
                    .flex()
                    .flex_col()
                    .items_center()
                    .justify_center()
                    .gap_4()
                    .on_hover(cx.listener(|this, hovered, _, cx| {
                        if *hovered && this.remote_state.toolbar_visible {
                            this.remote_state.set_toolbar_visible(false);
                            cx.notify();
                        }
                    }))
                    .on_click(cx.listener(|this, _, _, cx| {
                        // Re-grab keyboard when canvas is clicked
                        if let Some(sess) = this.remote_state.active_session()
                            && !sess.keyboard_grabbed
                        {
                            this.remote_state.toggle_keyboard_grab();
                            this.emit_toast(
                                crate::toast::ToastKind::Info,
                                "Keyboard Captured",
                                "Keystrokes are now sent to the remote endpoint.",
                                cx,
                            );
                            cx.notify();
                        }
                    }))
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .items_center()
                            .gap_2()
                            .child(
                                Icon::new(IconName::Monitor).text_color(rgb(theme.accent_primary)),
                            )
                            .child(
                                div()
                                    .text_base()
                                    .font_semibold()
                                    .text_color(rgb(theme.text_primary))
                                    .child(format!("Remote Desktop — {}", session.device_name)),
                            )
                            .child(div().text_xs().text_color(rgb(theme.text_muted)).child(
                                format!(
                                    "Streaming {} at {} FPS ({}ms latency)",
                                    session.metrics.resolution,
                                    session.metrics.fps,
                                    session.metrics.latency_ms
                                ),
                            )),
                    ),
            )
            // Viewport Footer / Status Help Bar
            .child(
                div()
                    .h(px(32.0))
                    .bg(rgb(theme.bg_app))
                    .border_t_1()
                    .border_color(rgb(theme.border_subtle))
                    .px_4()
                    .flex()
                    .items_center()
                    .justify_between()
                    .text_xs()
                    .text_color(rgb(theme.text_muted))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_4()
                            .child(div().child("Ctrl+Shift+Esc: Ungrab Keyboard"))
                            .child(div().child("F11: Toggle Fullscreen"))
                            .child(div().child("Hover top edge: Show Controls")),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(div().size_1p5().rounded_full().bg(rgb(
                                if session.keyboard_grabbed {
                                    theme.status_online
                                } else {
                                    theme.status_reconnecting
                                },
                            )))
                            .child(div().child(if session.keyboard_grabbed {
                                "Keyboard Captured"
                            } else {
                                "Keyboard Released (Click canvas to re-grab)"
                            })),
                    ),
            )
            .into_any_element()
    }
}
