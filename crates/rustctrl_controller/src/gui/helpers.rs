use gpui::Keystroke;
#[cfg(test)]
use rustctrl_protocol::auth::FleetDeviceEntry;

pub fn configure_tokyo_night_theme(
    theme: crate::theme::Theme,
    kit: &mut gpui::component::theme::Theme,
) {
    use gpui::rgb;

    // Window surface and typography
    kit.background = rgb(theme.bg_app).into();
    kit.foreground = rgb(theme.text_primary).into();
    kit.border = rgb(theme.border_subtle).into();

    // Semantic roles
    kit.primary = rgb(0x7aa2f7).into();
    kit.primary_hover = rgb(0x89b4fa).into();
    kit.primary_active = rgb(0x7dcfff).into();
    kit.primary_foreground = rgb(theme.bg_app).into();

    kit.accent = rgb(theme.accent_primary).into();
    kit.accent_foreground = rgb(theme.bg_app).into();

    kit.danger = rgb(theme.status_blocked).into();
    kit.danger_hover = rgb(0xff9eaf).into();
    kit.danger_active = rgb(theme.status_blocked).into();
    kit.danger_foreground = rgb(theme.bg_app).into();

    kit.warning = rgb(theme.status_reconnecting).into();
    kit.warning_hover = rgb(0xffc777).into();
    kit.warning_active = rgb(theme.status_reconnecting).into();
    kit.warning_foreground = rgb(theme.bg_app).into();

    kit.success = rgb(theme.status_online).into();
    kit.success_hover = rgb(0xb9f27c).into();
    kit.success_active = rgb(theme.status_online).into();
    kit.success_foreground = rgb(theme.bg_app).into();

    kit.info = rgb(0x7aa2f7).into();
    kit.info_hover = rgb(0x89b4fa).into();
    kit.info_active = rgb(0x7aa2f7).into();
    kit.info_foreground = rgb(theme.bg_app).into();

    // Controls & surfaces
    kit.input = rgb(theme.border_subtle).into();
    kit.muted = rgb(theme.bg_surface).into();
    kit.muted_foreground = rgb(theme.text_muted).into();
    kit.popover = rgb(theme.bg_surface).into();
    kit.popover_foreground = rgb(theme.text_primary).into();

    // Navigation and data tables
    kit.sidebar = rgb(0x16161e).into();
    kit.sidebar_border = rgb(theme.border_subtle).into();
    kit.sidebar_foreground = rgb(theme.text_primary).into();
    kit.sidebar_accent = rgb(theme.bg_surface_hover).into();
    kit.sidebar_accent_foreground = rgb(theme.accent_primary).into();

    kit.table = rgb(theme.bg_app).into();
    kit.table_head = rgb(theme.bg_surface).into();
    kit.table_hover = rgb(theme.bg_surface_hover).into();
    kit.table_row_border = rgb(theme.border_subtle).into();

    // Buttons
    kit.button = rgb(theme.bg_surface_hover).into();
    kit.button_hover = rgb(theme.border_subtle).into();
    kit.button_active = rgb(theme.border_focus).into();
    kit.button_foreground = rgb(theme.text_primary).into();
}

pub fn resolve_typed_text(keystroke: &Keystroke) -> Option<&str> {
    if keystroke.modifiers.control || keystroke.modifiers.platform {
        return None;
    }
    if let Some(kc) = keystroke.key_char.as_deref()
        && !kc.is_empty()
        && !kc.chars().any(|c| c.is_control())
    {
        return Some(kc);
    }
    if keystroke.key == "space" {
        return Some(" ");
    }
    if keystroke.key.chars().count() == 1 {
        let c = keystroke.key.chars().next().unwrap();
        if !c.is_control() {
            return Some(&keystroke.key);
        }
    }
    None
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub struct DeviceRowViewModel {
    pub device_id: String,
    pub display_name: String,
    pub device_type: String,
    pub location: String,
    pub last_address: String,
    pub configured_address: String,
    pub status: String,
    pub last_seen: String,
}

#[cfg(test)]
pub fn format_device_row(device: &FleetDeviceEntry) -> DeviceRowViewModel {
    let is_tv_target = device.device_type == "android_tv";
    let location = match &device.location {
        Some(loc) if !loc.is_empty() => loc.clone(),
        _ => "—".to_string(),
    };
    let last_address = if !device.last_address.is_empty() {
        device.last_address.clone()
    } else {
        "—".to_string()
    };
    let configured_address = match &device.configured_address {
        Some(addr) if !addr.is_empty() => addr.clone(),
        _ => "—".to_string(),
    };
    let status = if device.blocked || device.status == "blocked" {
        "Blocked".to_string()
    } else if is_tv_target || device.status == "unverified" {
        "Unverified".to_string()
    } else if device.online {
        "Online".to_string()
    } else {
        "Offline".to_string()
    };
    let last_seen = if is_tv_target || device.last_seen_unix_ms == 0 {
        "—".to_string()
    } else {
        relative_last_seen(device.last_seen_unix_ms)
    };
    DeviceRowViewModel {
        device_id: device.device_id.clone(),
        display_name: device.display_name.clone(),
        device_type: device.device_type.clone(),
        location,
        last_address,
        configured_address,
        status,
        last_seen,
    }
}

#[cfg(test)]
pub fn relative_last_seen(last_seen_unix_ms: i64) -> String {
    let now_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default();
    let seconds = now_unix_ms.saturating_sub(last_seen_unix_ms) / 1000;
    match seconds {
        0..=59 => format!("{seconds}s ago"),
        60..=3599 => format!("{}m ago", seconds / 60),
        3600..=86_399 => format!("{}h ago", seconds / 3600),
        _ => format!("{}d ago", seconds / 86_400),
    }
}
