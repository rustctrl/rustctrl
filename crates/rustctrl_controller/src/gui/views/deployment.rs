use super::super::*;
use gpui::assets::IconName;
use gpui::base::StyledExt as _;
use gpui::component::Icon;
use gpui::component::button::{Button, ButtonVariants as _};
use gpui::component::empty::{
    Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyMediaVariant, EmptyTitle,
};
use gpui::component::table::{Table, TableBody, TableCell, TableHead, TableHeader, TableRow};
use gpui::component::tag::Tag;
use gpui::{Context, IntoElement, ParentElement as _, Styled as _, div, px, rgb};

impl ControllerApp {
    pub(in crate::gui) fn render_deployment(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let (authorizations, error, _in_flight) = if let ScreenState::Connected {
            authorizations,
            error,
            in_flight,
            ..
        } = &self.state
        {
            (authorizations.clone(), error.clone(), *in_flight)
        } else {
            return div().into_any_element();
        };

        let theme = self.theme;

        let mut auth_list = div().flex().flex_col().gap_3().child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .child(Icon::new(IconName::Key).text_color(rgb(theme.accent_primary)))
                        .child(
                            div()
                                .text_xl()
                                .font_bold()
                                .text_color(rgb(theme.text_primary))
                                .child("Installation Authorizations"),
                        ),
                )
                .child(
                    div()
                        .text_sm()
                        .text_color(rgb(theme.text_muted))
                        .child(format!("{} authorizations issued", authorizations.len())),
                ),
        );

        if authorizations.is_empty() {
            let (title, description) = if error.is_some() {
                (
                    "Error Loading Authorizations",
                    "Unable to load installation authorizations from server.",
                )
            } else {
                (
                    "No Installation Authorizations",
                    "No installation authorizations issued yet. Generate a package above to enroll agents.",
                )
            };
            auth_list = auth_list.child(
                Empty::new().header(
                    EmptyHeader::new()
                        .media(
                            EmptyMedia::new()
                                .with_variant(EmptyMediaVariant::Icon)
                                .child(Icon::new(IconName::Key)),
                        )
                        .title(EmptyTitle::new().child(title))
                        .description(EmptyDescription::new().child(description)),
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
                            .child(TableHead::new().w(px(280.0)).child("AUTHORIZATION ID"))
                            .child(TableHead::new().w(px(140.0)).child("CREATED BY"))
                            .child(TableHead::new().w(px(160.0)).child("STATUS"))
                            .child(TableHead::new().flex_1().child("ACTIONS")),
                    ),
                )
                .child(TableBody::new().children(authorizations.iter().map(|auth| {
                    let auth_id = auth.authorization_id.clone();
                    let is_revoked = auth.revoked_at_unix_ms.is_some();

                    let status_badge = if let Some(revoked_at) = auth.revoked_at_unix_ms {
                        Tag::danger().child(format!("Revoked ({revoked_at})"))
                    } else {
                        Tag::success().child("Active")
                    };

                    let actions_cell = if !is_revoked {
                        let auth_id_revoke = auth_id.clone();
                        let auth_id_replace = auth_id.clone();
                        div()
                            .flex()
                            .gap_2()
                            .items_center()
                            .child(
                                Button::new(format!("revoke-btn-{}", auth_id))
                                    .danger()
                                    .label("Revoke")
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.submit_revoke_authorization(
                                            auth_id_revoke.clone(),
                                            false,
                                            cx,
                                        );
                                    })),
                            )
                            .child(
                                Button::new(format!("revoke-replace-btn-{}", auth_id))
                                    .secondary()
                                    .label("Revoke & Replace")
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.submit_revoke_authorization(
                                            auth_id_replace.clone(),
                                            true,
                                            cx,
                                        );
                                    })),
                            )
                    } else {
                        div()
                            .text_xs()
                            .text_color(rgb(theme.text_muted))
                            .child("No actions available")
                    };

                    TableRow::new()
                        .child(
                            TableCell::new()
                                .w(px(280.0))
                                .font_semibold()
                                .text_color(rgb(theme.text_primary))
                                .child(auth.authorization_id.clone()),
                        )
                        .child(
                            TableCell::new()
                                .w(px(140.0))
                                .text_color(rgb(theme.text_muted))
                                .child(auth.created_by.clone()),
                        )
                        .child(TableCell::new().w(px(160.0)).child(status_badge))
                        .child(TableCell::new().flex_1().child(actions_cell))
                })));

            auth_list = auth_list.child(table);
        }

        div()
            .size_full()
            .flex()
            .flex_col()
            .gap_6()
            // Deployment overview banner card
            .child(
                div()
                    .p_6()
                    .bg(rgb(theme.bg_surface))
                    .rounded_lg()
                    .border_1()
                    .border_color(rgb(theme.border_subtle))
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child(
                                        Icon::new(IconName::Package)
                                            .text_color(rgb(theme.accent_primary)),
                                    )
                                    .child(
                                        div()
                                            .text_xl()
                                            .font_bold()
                                            .text_color(rgb(theme.text_primary))
                                            .child("Agent Deployment"),
                                    ),
                            )
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(rgb(theme.text_muted))
                                    .child(
                                        "Generate cryptographically signed installation bundles (.zip or .toml) and manage active Installation Authorizations.",
                                    ),
                            ),
                    )
                    .child(
                        Button::new("deployment-package-btn")
                            .primary()
                            .icon(IconName::Package)
                            .label("Create Agent Package")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.open_prepare_installation_artifact(cx);
                            })),
                    ),
            )
            .child(auth_list)
            .into_any_element()
    }
}
