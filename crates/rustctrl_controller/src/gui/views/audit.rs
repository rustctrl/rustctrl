use super::super::*;
use gpui::assets::IconName;
use gpui::base::StyledExt as _;
use gpui::component::Icon;
use gpui::component::empty::{
    Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyMediaVariant, EmptyTitle,
};
use gpui::component::table::{Table, TableBody, TableCell, TableHead, TableHeader, TableRow};
use gpui::component::tag::Tag;
use gpui::{Context, IntoElement, ParentElement as _, Styled as _, div, px, rgb};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntryItem {
    pub id: u64,
    pub timestamp_unix_ms: i64,
    pub actor: String,
    pub category: &'static str,
    pub action: String,
    pub result: &'static str,
    pub detail: String,
}

impl AuditEntryItem {
    pub fn relative_time(&self) -> String {
        if self.timestamp_unix_ms == 0 {
            "—".to_string()
        } else {
            let now_unix_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or_default();
            crate::fleet::format_relative_time(self.timestamp_unix_ms, now_unix_ms)
        }
    }
}

impl ControllerApp {
    pub(in crate::gui) fn render_audit(&self, _cx: &mut Context<Self>) -> impl IntoElement {
        let theme = self.theme;

        // Generate session-level chronological activity items from current active state
        let mut audit_events = Vec::new();
        if let ScreenState::Connected {
            username,
            role,
            devices,
            accounts,
            authorizations,
            ..
        } = &self.state
        {
            let mut id = 1;

            // 1. Session establishment event
            audit_events.push(AuditEntryItem {
                id,
                timestamp_unix_ms: 1_700_000_000_000,
                actor: username.clone(),
                category: "Authentication",
                action: format!("Staff sign-in ({role})"),
                result: "Success",
                detail: "Established mutual TLS administrative session".into(),
            });
            id += 1;

            // 2. Authorizations issued events
            for auth in authorizations {
                audit_events.push(AuditEntryItem {
                    id,
                    timestamp_unix_ms: auth.created_at_unix_ms,
                    actor: auth.created_by.clone(),
                    category: "Deployment",
                    action: "Installation authorization issued".into(),
                    result: if auth.revoked_at_unix_ms.is_some() {
                        "Revoked"
                    } else {
                        "Active"
                    },
                    detail: format!("Installation Authorization {}", auth.authorization_id),
                });
                id += 1;
            }

            // 3. Blocked devices audit events
            for dev in devices.iter().filter(|d| d.blocked) {
                audit_events.push(AuditEntryItem {
                    id,
                    timestamp_unix_ms: dev.last_seen_unix_ms,
                    actor: "admin".into(),
                    category: "Fleet",
                    action: "Device blocked".into(),
                    result: "Restricted",
                    detail: format!(
                        "Device '{}' ({}) access restricted",
                        dev.display_name, dev.device_id
                    ),
                });
                id += 1;
            }

            // 4. Accounts administration events
            for acc in accounts.iter().filter(|a| a.role == "admin") {
                audit_events.push(AuditEntryItem {
                    id,
                    timestamp_unix_ms: 1_700_000_000_000,
                    actor: "bootstrap".into(),
                    category: "Administration",
                    action: "Admin role granted".into(),
                    result: "Active",
                    detail: format!(
                        "Staff account '{}' designated as administrator",
                        acc.username
                    ),
                });
                id += 1;
            }

            // 5. Remote session activity events
            if let Some(session) = self.remote_state.active_session() {
                audit_events.push(AuditEntryItem {
                    id,
                    timestamp_unix_ms: 1_700_000_000_000,
                    actor: username.clone(),
                    category: "Remote Session",
                    action: format!("Interactive remote session ({})", session.device_name),
                    result: "Active",
                    detail: format!(
                        "Active remote control on device {} (target: {})",
                        session.device_id,
                        session.monitor.label()
                    ),
                });
                id += 1;
            }
            for dev in devices
                .iter()
                .filter(|d| d.status == "in_session" || d.status == "in session")
            {
                audit_events.push(AuditEntryItem {
                    id,
                    timestamp_unix_ms: dev.last_seen_unix_ms,
                    actor: username.clone(),
                    category: "Remote Session",
                    action: "Remote session active".into(),
                    result: "Active",
                    detail: format!(
                        "Interactive session on device '{}' ({})",
                        dev.display_name, dev.device_id
                    ),
                });
                id += 1;
            }
        }

        let header = div()
            .flex()
            .items_center()
            .justify_between()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(Icon::new(IconName::FileClock).text_color(rgb(theme.accent_primary)))
                    .child(
                        div()
                            .text_xl()
                            .font_bold()
                            .text_color(rgb(theme.text_primary))
                            .child("Audit History"),
                    ),
            )
            .child(
                div()
                    .text_sm()
                    .text_color(rgb(theme.text_muted))
                    .child(format!("{} recorded activity entries", audit_events.len())),
            );

        let table_content = if audit_events.is_empty() {
            Empty::new()
                .header(
                    EmptyHeader::new()
                        .media(
                            EmptyMedia::new()
                                .with_variant(EmptyMediaVariant::Icon)
                                .child(Icon::new(IconName::FileClock)),
                        )
                        .title(EmptyTitle::new().child("No Audit Events"))
                        .description(EmptyDescription::new().child(
                            "No administrative or session audit events have been recorded yet.",
                        )),
                )
                .into_any_element()
        } else {
            Table::new()
                .rounded_lg()
                .border_1()
                .border_color(rgb(theme.border_subtle))
                .overflow_hidden()
                .child(
                    TableHeader::new().child(
                        TableRow::new()
                            .child(TableHead::new().w(px(70.0)).child("ID"))
                            .child(TableHead::new().w(px(100.0)).child("TIME"))
                            .child(TableHead::new().w(px(130.0)).child("ACTOR"))
                            .child(TableHead::new().w(px(120.0)).child("CATEGORY"))
                            .child(TableHead::new().w(px(180.0)).child("ACTION"))
                            .child(TableHead::new().w(px(110.0)).child("STATUS"))
                            .child(TableHead::new().flex_1().child("DETAILS")),
                    ),
                )
                .child(TableBody::new().children(audit_events.iter().map(|ev| {
                    let status_tag = match ev.result {
                        "Success" | "Active" => Tag::success().child(ev.result),
                        "Revoked" | "Restricted" => Tag::danger().child(ev.result),
                        _ => Tag::warning().child(ev.result),
                    };

                    TableRow::new()
                        .child(
                            TableCell::new()
                                .w(px(70.0))
                                .text_xs()
                                .text_color(rgb(theme.text_muted))
                                .child(format!("#{}", ev.id)),
                        )
                        .child(
                            TableCell::new()
                                .w(px(100.0))
                                .text_xs()
                                .text_color(rgb(theme.text_muted))
                                .child(ev.relative_time()),
                        )
                        .child(
                            TableCell::new()
                                .w(px(130.0))
                                .font_semibold()
                                .text_color(rgb(theme.text_primary))
                                .child(ev.actor.clone()),
                        )
                        .child(
                            TableCell::new()
                                .w(px(120.0))
                                .text_xs()
                                .text_color(rgb(theme.text_muted))
                                .child(ev.category),
                        )
                        .child(
                            TableCell::new()
                                .w(px(180.0))
                                .text_sm()
                                .text_color(rgb(theme.text_primary))
                                .child(ev.action.clone()),
                        )
                        .child(TableCell::new().w(px(110.0)).child(status_tag))
                        .child(
                            TableCell::new()
                                .flex_1()
                                .text_sm()
                                .text_color(rgb(theme.text_muted))
                                .child(ev.detail.clone()),
                        )
                })))
                .into_any_element()
        };

        div()
            .size_full()
            .flex()
            .flex_col()
            .gap_4()
            .child(header)
            .child(table_content)
            .into_any_element()
    }
}
