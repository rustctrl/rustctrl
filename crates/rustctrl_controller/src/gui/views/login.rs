use super::super::*;
use gpui::base::StyledExt as _;
use gpui::component::alert::Alert;
use gpui::component::button::{Button, ButtonVariants as _};
use gpui::component::checkbox::Checkbox;
use gpui::component::input::Input;
use gpui::component::tag::Tag;
use gpui::{
    Context, ParentElement as _, Styled as _, Window, div, prelude::FluentBuilder as _, rgb,
};

impl ControllerApp {
    pub(in crate::gui) fn ensure_auth_inputs(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.login_username_input.is_none() {
            let (default_user, default_pass) = match &self.state {
                ScreenState::Login {
                    username, password, ..
                } => (username.clone(), password.clone()),
                _ => (String::new(), String::new()),
            };

            let username = cx.new(|cx| {
                let mut state = gpui::component::input::InputState::new(window, cx)
                    .placeholder("Enter username");
                if !default_user.is_empty() {
                    state = state.default_value(default_user);
                }
                state
            });

            let password = cx.new(|cx| {
                let mut state = gpui::component::input::InputState::new(window, cx)
                    .masked(true)
                    .placeholder("Enter password");
                if !default_pass.is_empty() {
                    state = state.default_value(default_pass);
                }
                state
            });

            cx.subscribe(
                &username,
                |this: &mut ControllerApp,
                 _input,
                 event: &gpui::component::input::InputEvent,
                 cx| {
                    if matches!(event, gpui::component::input::InputEvent::PressEnter { .. }) {
                        this.submit_login(cx);
                    }
                },
            )
            .detach();

            cx.subscribe(
                &password,
                |this: &mut ControllerApp,
                 _input,
                 event: &gpui::component::input::InputEvent,
                 cx| {
                    if matches!(event, gpui::component::input::InputEvent::PressEnter { .. }) {
                        this.submit_login(cx);
                    }
                },
            )
            .detach();

            self.login_username_input = Some(username);
            self.login_password_input = Some(password);
        }

        if self.must_change_new_password_input.is_none() {
            let new_pwd = cx.new(|cx| {
                gpui::component::input::InputState::new(window, cx)
                    .masked(true)
                    .placeholder("Minimum 8 characters...")
            });

            let confirm_pwd = cx.new(|cx| {
                gpui::component::input::InputState::new(window, cx)
                    .masked(true)
                    .placeholder("Re-enter new password...")
            });

            cx.subscribe(
                &new_pwd,
                |this: &mut ControllerApp,
                 _input,
                 event: &gpui::component::input::InputEvent,
                 cx| {
                    if matches!(event, gpui::component::input::InputEvent::PressEnter { .. }) {
                        this.submit_replace_password(cx);
                    }
                },
            )
            .detach();

            cx.subscribe(
                &confirm_pwd,
                |this: &mut ControllerApp,
                 _input,
                 event: &gpui::component::input::InputEvent,
                 cx| {
                    if matches!(event, gpui::component::input::InputEvent::PressEnter { .. }) {
                        this.submit_replace_password(cx);
                    }
                },
            )
            .detach();

            self.must_change_new_password_input = Some(new_pwd);
            self.must_change_confirm_password_input = Some(confirm_pwd);
        }
    }

    pub(in crate::gui) fn render_login(
        &self,
        container: gpui::Div,
        cx: &mut Context<Self>,
    ) -> gpui::Div {
        let ScreenState::Login {
            error,
            notice,
            remember,
            in_flight,
            ..
        } = &self.state
        else {
            unreachable!()
        };
        let theme = self.theme;

        let status_tag = match self.server_status {
            crate::login_state::ServerStatus::Connecting => Tag::warning().child("Connecting"),
            crate::login_state::ServerStatus::Connected { .. } => {
                Tag::success().child("Connected over mutual TLS")
            }
            crate::login_state::ServerStatus::Unreachable => {
                Tag::danger().child("Server unreachable")
            }
        };

        container.items_center().justify_center().child(
            div()
                .w_full()
                .max_w(gpui::px(440.))
                .p_6()
                .rounded_lg()
                .border_1()
                .border_color(rgb(theme.border_subtle))
                .bg(rgb(theme.bg_surface))
                .flex()
                .flex_col()
                .gap_3()
                .child(div().text_3xl().font_bold().child("RustCtrl"))
                .child(
                    div()
                        .text_color(rgb(theme.text_muted))
                        .child("Sign in to your Staff Account"),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .child(status_tag),
                )
                .child(
                    div()
                        .text_sm()
                        .text_color(rgb(theme.text_muted))
                        .child(format!("Server: {}", self.config.server.endpoint)),
                )
                .when(self.server_status.show_bootstrap_notice(), |card| {
                    card.child(
                        Alert::warning(
                            "bootstrap-notice",
                            "No Staff Accounts exist yet. On the Server shell, run rustctrl-server bootstrap-admin to create the first Admin.",
                        )
                        .title("First-time setup"),
                    )
                })
                .when_some(notice.as_ref(), |card, note| {
                    card.child(Alert::info("login-notice", note.clone()))
                })
                .child(div().text_sm().font_semibold().child("Username"))
                .when_some(self.login_username_input.as_ref(), |card, input_state| {
                    card.child(Input::new(input_state).cleanable(true))
                })
                .child(div().text_sm().font_semibold().child("Password"))
                .when_some(self.login_password_input.as_ref(), |card, input_state| {
                    card.child(Input::new(input_state).mask_toggle())
                })
                .child(
                    Checkbox::new("remember-computer")
                        .checked(*remember)
                        .label("Remember this computer")
                        .on_click(cx.listener(|this, checked, _, cx| {
                            if let ScreenState::Login { remember, .. } = &mut this.state {
                                *remember = *checked;
                                cx.notify();
                            }
                        })),
                )
                .when_some(error.as_ref(), |card, err| {
                    card.child(Alert::error("login-error", err.clone()))
                })
                .child(
                    Button::new("signin-btn")
                        .primary()
                        .label(if *in_flight { "Signing in..." } else { "Sign in" })
                        .loading(*in_flight)
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.submit_login(cx);
                        })),
                ),
        )
    }
}
