use super::super::*;
use gpui::assets::IconName;
use gpui::base::StyledExt as _;
use gpui::component::button::{Button, ButtonVariants as _};
use gpui::component::empty::{
    Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyMediaVariant, EmptyTitle,
};
use gpui::component::input::Input;
use gpui::component::table::{Table, TableBody, TableCell, TableHead, TableHeader, TableRow};
use gpui::component::tag::Tag;
use gpui::component::{Disableable as _, Icon};
use gpui::{Context, IntoElement, ParentElement as _, Styled as _, Window, div, px, rgb};

impl ControllerApp {
    pub(in crate::gui) fn ensure_new_account_inputs(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.new_account_username_input.is_none() {
            let user_input = cx.new(|cx| {
                gpui::component::input::InputState::new(window, cx).placeholder("Enter username...")
            });
            cx.subscribe(
                &user_input,
                |this: &mut ControllerApp,
                 _input,
                 event: &gpui::component::input::InputEvent,
                 cx| {
                    if matches!(event, gpui::component::input::InputEvent::PressEnter { .. }) {
                        this.submit_create_account(cx);
                    }
                },
            )
            .detach();
            self.new_account_username_input = Some(user_input);
        }

        if self.new_account_password_input.is_none() {
            let pass_input = cx.new(|cx| {
                gpui::component::input::InputState::new(window, cx)
                    .masked(true)
                    .placeholder("Enter temporary password (min 12 chars)...")
            });
            cx.subscribe(
                &pass_input,
                |this: &mut ControllerApp,
                 _input,
                 event: &gpui::component::input::InputEvent,
                 cx| {
                    if matches!(event, gpui::component::input::InputEvent::PressEnter { .. }) {
                        this.submit_create_account(cx);
                    }
                },
            )
            .detach();
            self.new_account_password_input = Some(pass_input);
        }
    }

    pub(in crate::gui) fn render_accounts(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let (accounts, new_account_role, in_flight) = if let ScreenState::Connected {
            accounts,
            new_account_role,
            in_flight,
            ..
        } = &self.state
        {
            (accounts.clone(), new_account_role.clone(), *in_flight)
        } else {
            return div().into_any_element();
        };

        let theme = self.theme;
        let username_input = self.new_account_username_input.as_ref();
        let password_input = self.new_account_password_input.as_ref();

        let mut accounts_list = div().flex().flex_col().gap_3().child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .child(Icon::new(IconName::Users).text_color(rgb(theme.accent_primary)))
                        .child(
                            div()
                                .text_xl()
                                .font_bold()
                                .text_color(rgb(theme.text_primary))
                                .child("Staff Accounts"),
                        ),
                )
                .child(
                    div()
                        .text_sm()
                        .text_color(rgb(theme.text_muted))
                        .child(format!("{} accounts registered", accounts.len())),
                ),
        );

        if accounts.is_empty() {
            accounts_list = accounts_list.child(
                Empty::new().header(
                    EmptyHeader::new()
                        .media(
                            EmptyMedia::new()
                                .with_variant(EmptyMediaVariant::Icon)
                                .child(Icon::new(IconName::Users)),
                        )
                        .title(EmptyTitle::new().child("No Staff Accounts"))
                        .description(
                            EmptyDescription::new().child("No staff accounts loaded or loading..."),
                        ),
                ),
            );
        } else {
            let table = Table::new()
                .rounded_lg()
                .border_1()
                .border_color(rgb(theme.border_subtle))
                .overflow_hidden()
                .child(
                    TableHeader::new().child(
                        TableRow::new()
                            .child(TableHead::new().w(px(180.0)).child("USERNAME"))
                            .child(TableHead::new().w(px(120.0)).child("ROLE"))
                            .child(TableHead::new().w(px(160.0)).child("STATUS"))
                            .child(TableHead::new().flex_1().child("ACTIONS")),
                    ),
                )
                .child(TableBody::new().children(accounts.iter().map(|acc| {
                    let acc_username = acc.username.clone();
                    let is_target_admin = acc.role == "admin";
                    let btn_label = if is_target_admin {
                        "Demote to Operator"
                    } else {
                        "Promote to Admin"
                    };
                    let new_target_role_str = if is_target_admin {
                        "operator".to_string()
                    } else {
                        "admin".to_string()
                    };
                    let target_user_clone = acc.username.clone();
                    let reset_target_clone = acc.username.clone();
                    let deactivate_target_clone = acc.username.clone();

                    let status_badge = if !acc.active {
                        Tag::danger().child("Deactivated")
                    } else if acc.must_change_password {
                        Tag::warning().child("Must Change Pass")
                    } else {
                        Tag::success().child("Active")
                    };

                    let role_badge = if is_target_admin {
                        Tag::primary().child("Admin")
                    } else {
                        Tag::secondary().child("Operator")
                    };

                    let mut actions_cell = div()
                        .flex()
                        .gap_2()
                        .items_center()
                        .child(
                            Button::new(format!("role-btn-{}", acc_username))
                                .secondary()
                                .label(btn_label)
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.submit_change_role(
                                        target_user_clone.clone(),
                                        new_target_role_str.clone(),
                                        cx,
                                    );
                                })),
                        )
                        .child(
                            Button::new(format!("reset-btn-{}", acc_username))
                                .ghost()
                                .label("Reset Password")
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.open_reset_password(reset_target_clone.clone(), cx);
                                })),
                        );

                    if acc.active {
                        actions_cell = actions_cell.child(
                            Button::new(format!("deactivate-btn-{}", acc_username))
                                .danger()
                                .label("Deactivate")
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.submit_deactivate_account(
                                        deactivate_target_clone.clone(),
                                        cx,
                                    );
                                })),
                        );
                    }

                    TableRow::new()
                        .child(
                            TableCell::new()
                                .w(px(180.0))
                                .font_semibold()
                                .text_color(rgb(theme.text_primary))
                                .child(acc_username),
                        )
                        .child(TableCell::new().w(px(120.0)).child(role_badge))
                        .child(TableCell::new().w(px(160.0)).child(status_badge))
                        .child(TableCell::new().flex_1().child(actions_cell))
                })));

            accounts_list = accounts_list.child(table);
        }

        // Create Staff Account Form Card
        let create_form = div()
            .mt_4()
            .p_6()
            .bg(rgb(theme.bg_surface))
            .rounded_lg()
            .border_1()
            .border_color(rgb(theme.border_subtle))
            .flex()
            .flex_col()
            .gap_4()
            .max_w(px(480.0))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(Icon::new(IconName::UserPlus).text_color(rgb(theme.accent_primary)))
                    .child(
                        div()
                            .text_lg()
                            .font_bold()
                            .text_color(rgb(theme.text_primary))
                            .child("Create Staff Account"),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1p5()
                    .child(
                        div()
                            .text_xs()
                            .font_semibold()
                            .text_color(rgb(theme.text_muted))
                            .child("NEW USERNAME"),
                    )
                    .children(username_input.map(Input::new)),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1p5()
                    .child(
                        div()
                            .text_xs()
                            .font_semibold()
                            .text_color(rgb(theme.text_muted))
                            .child("ROLE ASSIGNMENT"),
                    )
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .child({
                                let mut b = Button::new("role-operator-btn")
                                    .label("Operator")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        if let ScreenState::Connected {
                                            new_account_role, ..
                                        } = &mut this.state
                                        {
                                            *new_account_role = "operator".into();
                                            cx.notify();
                                        }
                                    }));
                                if new_account_role == "operator" {
                                    b = b.primary();
                                } else {
                                    b = b.ghost();
                                }
                                b
                            })
                            .child({
                                let mut b = Button::new("role-admin-btn").label("Admin").on_click(
                                    cx.listener(|this, _, _, cx| {
                                        if let ScreenState::Connected {
                                            new_account_role, ..
                                        } = &mut this.state
                                        {
                                            *new_account_role = "admin".into();
                                            cx.notify();
                                        }
                                    }),
                                );
                                if new_account_role == "admin" {
                                    b = b.primary();
                                } else {
                                    b = b.ghost();
                                }
                                b
                            }),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1p5()
                    .child(
                        div()
                            .text_xs()
                            .font_semibold()
                            .text_color(rgb(theme.text_muted))
                            .child("TEMPORARY PASSWORD"),
                    )
                    .children(password_input.map(Input::new)),
            )
            .child(
                div().pt_2().child(
                    Button::new("submit-create-account-btn")
                        .primary()
                        .loading(in_flight)
                        .disabled(in_flight)
                        .label(if in_flight {
                            "Creating..."
                        } else {
                            "Create Staff Account"
                        })
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.submit_create_account(cx);
                        })),
                ),
            );

        div()
            .size_full()
            .flex()
            .flex_col()
            .gap_4()
            .child(accounts_list)
            .child(create_form)
            .into_any_element()
    }
}
