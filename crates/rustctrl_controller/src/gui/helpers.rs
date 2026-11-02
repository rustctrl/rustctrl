use gpui::Keystroke;
#[cfg(test)]
use rustctrl_protocol::auth::FleetDeviceEntry;

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
