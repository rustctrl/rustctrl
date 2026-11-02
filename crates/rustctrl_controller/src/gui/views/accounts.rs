use super::super::*;
use gpui::assets::IconName;
use gpui::base::StyledExt as _;
use gpui::component::Icon;
use gpui::component::button::{Button, ButtonVariants as _};
use gpui::{
    Context, InteractiveElement as _, IntoElement, ParentElement as _, Styled as _, div, px, rgb,
};

impl ControllerApp {
    pub(in crate::gui) fn render_accounts(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let (accounts, new_account_username, new_account_role, new_account_password, _in_flight) =
            if let ScreenState::Connected {
                accounts,
                new_account_username,
                new_account_role,
                new_account_password,
                in_flight,
                ..
            } = &self.state
            {
                (
                    accounts.clone(),
                    new_account_username.clone(),
                    new_account_role.clone(),
                    new_account_password.clone(),
                    *in_flight,
                )
            } else {
                return div().into_any_element();
            };

        let theme = self.theme;
        let user_active = self.active_field == ActiveField::NewAccountUsername;
        let pass_active = self.active_field == ActiveField::NewAccountPassword;
        let masked_new_pass = "•".repeat(new_account_password.len());

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
                div()
                    .p_6()
                    .rounded_lg()
                    .border_1()
                    .border_color(rgb(theme.border_subtle))
                    .bg(rgb(theme.bg_surface))
                    .text_sm()
                    .text_color(rgb(theme.text_muted))
                    .child("No staff accounts loaded or loading..."),
            );
        } else {
            let header_row = div()
                .flex()
                .gap_4()
                .px_4()
                .py_2()
                .border_b_1()
                .border_color(rgb(theme.border_subtle))
                .bg(rgb(theme.bg_surface))
                .rounded_t_lg()
                .text_xs()
                .font_semibold()
                .text_color(rgb(theme.text_muted))
                .child(div().w(px(180.0)).child("USERNAME"))
                .child(div().w(px(120.0)).child("ROLE"))
                .child(div().w(px(160.0)).child("STATUS"))
                .child(div().flex_1().child("ACTIONS"));

            let mut table_container = div()
                .rounded_lg()
                .border_1()
                .border_color(rgb(theme.border_subtle))
                .bg(rgb(theme.bg_surface))
                .child(header_row);

            for (ix, acc) in accounts.iter().enumerate() {
                let acc_username = acc.username.clone();
                let is_target_admin = acc.role == "admin";
                let new_target_role = if is_target_admin { "operator" } else { "admin" };
                let btn_label = if is_target_admin {
                    "Demote to Operator"
                } else {
                    "Promote to Admin"
                };

                let target_user_clone = acc_username.clone();
                let reset_target_clone = acc_username.clone();
                let deactivate_target_clone = acc_username.clone();
                let new_target_role_str = new_target_role.to_string();

                let status_badge = if !acc.active {
                    div()
                        .w(px(160.0))
                        .flex()
                        .items_center()
                        .gap_1p5()
                        .child(div().size_2().rounded_full().bg(rgb(theme.status_blocked)))
                        .child(
                            div()
                                .text_sm()
                                .text_color(rgb(theme.status_blocked))
                                .child("Deactivated"),
                        )
                } else if acc.must_change_password {
                    div()
                        .w(px(160.0))
                        .flex()
                        .items_center()
                        .gap_1p5()
                        .child(
                            div()
                                .size_2()
                                .rounded_full()
                                .bg(rgb(theme.status_reconnecting)),
                        )
                        .child(
                            div()
                                .text_sm()
                                .text_color(rgb(theme.status_reconnecting))
                                .child("Temporary Password"),
                        )
                } else {
                    div()
                        .w(px(160.0))
                        .flex()
                        .items_center()
                        .gap_1p5()
                        .child(div().size_2().rounded_full().bg(rgb(theme.status_online)))
                        .child(
                            div()
                                .text_sm()
                                .text_color(rgb(theme.status_online))
                                .child("Active"),
                        )
                };

                let role_badge = if is_target_admin {
                    div().w(px(120.0)).child(
                        div()
                            .px_2()
                            .py_0p5()
                            .rounded_md()
                            .bg(rgb(theme.accent_primary))
                            .text_color(rgb(theme.bg_app))
                            .text_xs()
                            .font_semibold()
                            .child("Admin"),
                    )
                } else {
                    div().w(px(120.0)).child(
                        div()
                            .px_2()
                            .py_0p5()
                            .rounded_md()
                            .bg(rgb(theme.bg_surface_hover))
                            .text_color(rgb(theme.text_muted))
                            .text_xs()
                            .child("Operator"),
                    )
                };

                let is_last = ix == accounts.len() - 1;
                let mut row = div()
                    .flex()
                    .gap_4()
                    .items_center()
                    .px_4()
                    .py_2p5()
                    .hover(|s| s.bg(rgb(theme.bg_surface_hover)));

                if !is_last {
                    row = row.border_b_1().border_color(rgb(theme.border_subtle));
                }

                let mut actions_cell = div()
                    .flex_1()
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
                                this.submit_deactivate_account(deactivate_target_clone.clone(), cx);
                            })),
                    );
                }

                row = row
                    .child(
                        div()
                            .w(px(180.0))
                            .font_semibold()
                            .text_color(rgb(theme.text_primary))
                            .child(acc_username.clone()),
                    )
                    .child(role_badge)
                    .child(status_badge)
                    .child(actions_cell);

                table_container = table_container.child(row);
            }

            accounts_list = accounts_list.child(table_container);
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
                    .child(
                        div()
                            .px_3()
                            .py_2()
                            .bg(rgb(theme.bg_app))
                            .border_1()
                            .border_color(rgb(if user_active {
                                theme.border_focus
                            } else {
                                theme.border_subtle
                            }))
                            .rounded_md()
                            .id("new-account-username-input")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.active_field = ActiveField::NewAccountUsername;
                                cx.notify();
                            }))
                            .child(if new_account_username.is_empty() {
                                div()
                                    .text_color(rgb(theme.text_muted))
                                    .child("Enter username...")
                            } else {
                                div()
                                    .text_color(rgb(theme.text_primary))
                                    .child(new_account_username.clone())
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
                    .child(
                        div()
                            .px_3()
                            .py_2()
                            .bg(rgb(theme.bg_app))
                            .border_1()
                            .border_color(rgb(if pass_active {
                                theme.border_focus
                            } else {
                                theme.border_subtle
                            }))
                            .rounded_md()
                            .id("new-account-password-input")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.active_field = ActiveField::NewAccountPassword;
                                cx.notify();
                            }))
                            .child(if new_account_password.is_empty() {
                                div()
                                    .text_color(rgb(theme.text_muted))
                                    .child("Enter temporary password (min 12 chars)...")
                            } else {
                                div()
                                    .text_color(rgb(theme.text_primary))
                                    .child(masked_new_pass)
                            }),
                    ),
            )
            .child(
                div().pt_2().child(
                    Button::new("submit-create-account-btn")
                        .primary()
                        .label("Create Staff Account")
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
