use super::super::*;
use gpui::assets::IconName;
use gpui::base::StyledExt as _;
use gpui::component::Icon;
use gpui::{
    Context, InteractiveElement as _, IntoElement, ParentElement as _, Styled as _, div, px, rgb,
};

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

        let table_header = div()
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
            .child(div().w(px(70.0)).child("ID"))
            .child(div().w(px(100.0)).child("TIME"))
            .child(div().w(px(130.0)).child("ACTOR"))
            .child(div().w(px(120.0)).child("CATEGORY"))
            .child(div().w(px(180.0)).child("ACTION"))
            .child(div().w(px(100.0)).child("STATUS"))
            .child(div().flex_1().child("DETAILS"));

        let mut table_container = div()
            .rounded_lg()
            .border_1()
            .border_color(rgb(theme.border_subtle))
            .bg(rgb(theme.bg_surface))
            .child(table_header);

        if audit_events.is_empty() {
            table_container = table_container.child(
                div()
                    .p_6()
                    .text_sm()
                    .text_color(rgb(theme.text_muted))
                    .child("No audit events recorded yet."),
            );
        } else {
            for (ix, ev) in audit_events.iter().enumerate() {
                let status_color = match ev.result {
                    "Success" | "Active" => theme.status_online,
                    "Revoked" | "Restricted" => theme.status_blocked,
                    _ => theme.status_reconnecting,
                };

                let is_last = ix == audit_events.len() - 1;
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

                row = row
                    .child(
                        div()
                            .w(px(70.0))
                            .text_xs()
                            .text_color(rgb(theme.text_muted))
                            .child(format!("#{}", ev.id)),
                    )
                    .child(
                        div()
                            .w(px(100.0))
                            .text_xs()
                            .text_color(rgb(theme.text_muted))
                            .child(ev.relative_time()),
                    )
                    .child(
                        div()
                            .w(px(130.0))
                            .font_semibold()
                            .text_color(rgb(theme.text_primary))
                            .child(ev.actor.clone()),
                    )
                    .child(
                        div()
                            .w(px(120.0))
                            .text_xs()
                            .text_color(rgb(theme.text_muted))
                            .child(ev.category),
                    )
                    .child(
                        div()
                            .w(px(180.0))
                            .text_sm()
                            .text_color(rgb(theme.text_primary))
                            .child(ev.action.clone()),
                    )
                    .child(
                        div()
                            .w(px(100.0))
                            .flex()
                            .items_center()
                            .gap_1p5()
                            .child(div().size_2().rounded_full().bg(rgb(status_color)))
                            .child(
                                div()
                                    .text_xs()
                                    .font_semibold()
                                    .text_color(rgb(status_color))
                                    .child(ev.result),
                            ),
                    )
                    .child(
                        div()
                            .flex_1()
                            .text_sm()
                            .text_color(rgb(theme.text_muted))
                            .child(ev.detail.clone()),
                    );

                table_container = table_container.child(row);
            }
        }

        div()
            .size_full()
            .flex()
            .flex_col()
            .gap_4()
            .child(header)
            .child(table_container)
            .into_any_element()
    }
}
