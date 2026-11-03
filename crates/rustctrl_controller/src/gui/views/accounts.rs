use super::super::*;
use gpui::assets::IconName;
use gpui::base::StyledExt as _;
use gpui::component::button::{Button, ButtonVariants as _};
use gpui::component::empty::{
    Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyMediaVariant, EmptyTitle,
};
use gpui::component::table::{Table, TableBody, TableCell, TableHead, TableHeader, TableRow};
use gpui::component::tag::Tag;
use gpui::component::{Icon, Sizable as _};
use gpui::{Context, IntoElement, ParentElement as _, Styled as _, div, px, rgb};

fn action_icon_button(
    id: impl Into<gpui::ElementId>,
    icon: IconName,
    tooltip: &'static str,
) -> Button {
    Button::new(id).ghost().small().icon(icon).tooltip(tooltip)
}

impl ControllerApp {
    pub(in crate::gui) fn render_accounts(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let (accounts, is_admin) =
            if let ScreenState::Connected { accounts, role, .. } = &self.state {
                (accounts.clone(), role == "admin")
            } else {
                return div().into_any_element();
            };

        let theme = self.theme;
        let app = cx.entity().clone();
        let total_accounts = accounts.len();

        let app_refresh = app.clone();
        let app_create = app.clone();

        let count_text = if total_accounts == 1 {
            "1 account".to_string()
        } else {
            format!("{total_accounts} accounts")
        };

        let mut title_bar = div().flex().justify_between().items_center().child(
            div()
                .flex()
                .items_center()
                .gap_3()
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .child(Icon::new(IconName::Users).text_color(rgb(theme.accent_primary)))
                        .child(
                            div()
                                .text_xl()
                                .font_semibold()
                                .text_color(rgb(theme.text_primary))
                                .child("Staff Accounts"),
                        ),
                )
                .child(
                    div()
                        .px_2()
                        .py_0p5()
                        .rounded_md()
                        .bg(rgb(theme.bg_surface_hover))
                        .text_color(rgb(theme.text_muted))
                        .text_xs()
                        .font_medium()
                        .child(count_text),
                ),
        );

        let mut toolbar_actions = div().flex().items_center().gap_2().child(
            Button::new("refresh-accounts-btn")
                .ghost()
                .icon(IconName::RotateCw)
                .tooltip("Refresh Accounts")
                .on_click(move |_, _, cx| {
                    cx.stop_propagation();
                    app_refresh.update(cx, |this, cx| {
                        if let ScreenState::Connected { session_token, .. } = &this.state {
                            let tok = session_token.clone();
                            this.fetch_status(tok, cx);
                        }
                    });
                }),
        );

        if is_admin {
            toolbar_actions = toolbar_actions.child(
                Button::new("create-staff-account-btn")
                    .primary()
                    .icon(IconName::UserPlus)
                    .label("Create Staff Account")
                    .on_click(move |_, _, cx| {
                        cx.stop_propagation();
                        app_create.update(cx, |this, cx| {
                            this.open_create_account(cx);
                        });
                    }),
            );
        }

        title_bar = title_bar.child(toolbar_actions);

        let content = if accounts.is_empty() {
            Empty::new()
                .header(
                    EmptyHeader::new()
                        .media(
                            EmptyMedia::new()
                                .with_variant(EmptyMediaVariant::Icon)
                                .child(Icon::new(IconName::Users)),
                        )
                        .title(EmptyTitle::new().child("No Staff Accounts"))
                        .description(
                            EmptyDescription::new().child("No staff accounts loaded or available."),
                        ),
                )
                .into_any_element()
        } else {
            let table = Table::new()
                .rounded_lg()
                .border_1()
                .border_color(rgb(theme.border_subtle))
                .overflow_hidden()
                .child(
                    TableHeader::new().child(
                        TableRow::new()
                            .child(TableHead::new().w(px(220.0)).child("USERNAME"))
                            .child(TableHead::new().w(px(140.0)).child("ROLE"))
                            .child(TableHead::new().w(px(160.0)).child("STATUS"))
                            .child(TableHead::new().flex_1().child("ACTIONS")),
                    ),
                )
                .child(TableBody::new().children(accounts.iter().map(|acc| {
                    let acc_username = acc.username.clone();
                    let is_target_admin = acc.role == "admin";

                    let status_badge = if !acc.active {
                        Tag::danger().child("Deactivated")
                    } else if acc.must_change_password {
                        Tag::warning().child("Must Change Pass")
                    } else {
                        Tag::success().child("Active")
                    };

                    let role_badge = if is_target_admin {
                        Tag::primary().child("Administrator")
                    } else {
                        Tag::secondary().child("Operator")
                    };

                    let actions_cell = if is_admin {
                        let role_target = acc.username.clone();
                        let new_role_str = if is_target_admin {
                            "operator".to_string()
                        } else {
                            "admin".to_string()
                        };
                        let reset_target = acc.username.clone();
                        let deact_target = acc.username.clone();

                        let app_role = app.clone();
                        let app_reset = app.clone();
                        let app_deact = app.clone();

                        let (role_icon, role_tooltip) = if is_target_admin {
                            (IconName::ShieldMinus, "Demote to Operator")
                        } else {
                            (IconName::ShieldCheck, "Promote to Administrator")
                        };

                        let mut act = div()
                            .flex()
                            .gap_1p5()
                            .items_center()
                            .child(
                                action_icon_button(
                                    format!("role-btn-{}", acc_username),
                                    role_icon,
                                    role_tooltip,
                                )
                                .on_click(move |_, _, cx| {
                                    cx.stop_propagation();
                                    app_role.update(cx, |this, cx| {
                                        this.submit_change_role(
                                            role_target.clone(),
                                            new_role_str.clone(),
                                            cx,
                                        );
                                    });
                                }),
                            )
                            .child(
                                action_icon_button(
                                    format!("reset-btn-{}", acc_username),
                                    IconName::KeyRound,
                                    "Reset Temporary Password",
                                )
                                .on_click(move |_, _, cx| {
                                    cx.stop_propagation();
                                    app_reset.update(cx, |this, cx| {
                                        this.open_reset_password(reset_target.clone(), cx);
                                    });
                                }),
                            );

                        if acc.active {
                            act = act.child(
                                action_icon_button(
                                    format!("deactivate-btn-{}", acc_username),
                                    IconName::Ban,
                                    "Deactivate Account",
                                )
                                .danger()
                                .on_click(move |_, _, cx| {
                                    cx.stop_propagation();
                                    app_deact.update(cx, |this, cx| {
                                        this.submit_deactivate_account(deact_target.clone(), cx);
                                    });
                                }),
                            );
                        }

                        act.into_any_element()
                    } else {
                        div()
                            .text_color(rgb(theme.text_muted))
                            .text_xs()
                            .child("—")
                            .into_any_element()
                    };

                    TableRow::new()
                        .child(
                            TableCell::new().w(px(220.0)).child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child(
                                        Icon::new(IconName::User).text_color(rgb(theme.text_muted)),
                                    )
                                    .child(
                                        div()
                                            .font_semibold()
                                            .text_color(rgb(theme.text_primary))
                                            .child(acc_username),
                                    ),
                            ),
                        )
                        .child(TableCell::new().w(px(140.0)).child(role_badge))
                        .child(TableCell::new().w(px(160.0)).child(status_badge))
                        .child(TableCell::new().flex_1().child(actions_cell))
                })));

            table.into_any_element()
        };

        div()
            .size_full()
            .flex()
            .flex_col()
            .gap_4()
            .child(title_bar)
            .child(content)
            .into_any_element()
    }
}
