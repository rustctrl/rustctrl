use rustctrl_protocol::auth::FleetDeviceEntry;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FleetFilterChip {
    #[default]
    All,
    Windows,
    AndroidTv,
    Online,
    Offline,
    Blocked,
}

impl FleetFilterChip {
    pub const ALL: [Self; 6] = [
        Self::All,
        Self::Windows,
        Self::AndroidTv,
        Self::Online,
        Self::Offline,
        Self::Blocked,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::Windows => "Windows",
            Self::AndroidTv => "Android TV",
            Self::Online => "Online",
            Self::Offline => "Offline",
            Self::Blocked => "Blocked",
        }
    }

    pub fn matches(self, item: &FleetDeviceItem) -> bool {
        match self {
            Self::All => true,
            Self::Windows => item.is_windows(),
            Self::AndroidTv => item.is_android_tv(),
            Self::Online => item.status == DeviceStatusKind::Online,
            Self::Offline => item.status == DeviceStatusKind::Offline,
            Self::Blocked => item.status == DeviceStatusKind::Blocked,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FleetSortColumn {
    Status,
    Name,
    Platform,
    Address,
    #[allow(dead_code)]
    Location,
    LastSeen,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortDirection {
    #[default]
    Ascending,
    Descending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceStatusKind {
    Online,
    Offline,
    Blocked,
    InSession,
    Unverified,
}

impl DeviceStatusKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Online => "Online",
            Self::Offline => "Offline",
            Self::Blocked => "Blocked",
            Self::InSession => "In Session",
            Self::Unverified => "Unverified",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetDeviceItem {
    pub device_id: String,
    pub display_name: String,
    pub device_type: String,
    pub last_address: String,
    pub configured_address: Option<String>,
    pub location: Option<String>,
    pub status: DeviceStatusKind,
    pub online: bool,
    pub blocked: bool,
    pub last_seen_unix_ms: i64,
}

impl FleetDeviceItem {
    pub fn from_entry(entry: &FleetDeviceEntry) -> Self {
        let is_tv_target = entry.device_type == "android_tv";
        let status = if entry.blocked || entry.status.eq_ignore_ascii_case("blocked") {
            DeviceStatusKind::Blocked
        } else if entry.status.eq_ignore_ascii_case("in_session")
            || entry.status.eq_ignore_ascii_case("in session")
        {
            DeviceStatusKind::InSession
        } else if is_tv_target || entry.status.eq_ignore_ascii_case("unverified") {
            DeviceStatusKind::Unverified
        } else if entry.online {
            DeviceStatusKind::Online
        } else {
            DeviceStatusKind::Offline
        };

        Self {
            device_id: entry.device_id.clone(),
            display_name: entry.display_name.clone(),
            device_type: entry.device_type.clone(),
            last_address: entry.last_address.clone(),
            configured_address: entry.configured_address.clone(),
            location: entry.location.clone(),
            status,
            online: entry.online,
            blocked: entry.blocked,
            last_seen_unix_ms: entry.last_seen_unix_ms,
        }
    }

    pub fn display_label(&self) -> &str {
        if !self.display_name.is_empty() {
            &self.display_name
        } else {
            &self.device_id
        }
    }

    pub fn primary_address(&self) -> &str {
        if !self.last_address.is_empty() {
            &self.last_address
        } else if let Some(addr) = &self.configured_address
            && !addr.is_empty()
        {
            addr
        } else {
            "—"
        }
    }

    pub fn location_label(&self) -> &str {
        if let Some(loc) = &self.location
            && !loc.is_empty()
        {
            loc
        } else {
            "—"
        }
    }

    pub fn is_android_tv(&self) -> bool {
        self.device_type == "android_tv"
    }

    pub fn is_windows(&self) -> bool {
        self.device_type != "android_tv"
    }

    pub fn relative_last_seen(&self) -> String {
        if self.is_android_tv() || self.last_seen_unix_ms == 0 {
            "—".to_string()
        } else {
            let now_unix_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or_default();
            format_relative_time(self.last_seen_unix_ms, now_unix_ms)
        }
    }
}

pub fn format_relative_time(last_seen_unix_ms: i64, now_unix_ms: i64) -> String {
    if last_seen_unix_ms == 0 {
        return "—".to_string();
    }
    let seconds = now_unix_ms.saturating_sub(last_seen_unix_ms) / 1000;
    match seconds {
        0..=59 => format!("{seconds}s ago"),
        60..=3599 => format!("{}m ago", seconds / 60),
        3600..=86_399 => format!("{}h ago", seconds / 3600),
        _ => format!("{}d ago", seconds / 86_400),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FleetEmptyState {
    None,
    EmptyFleet,
    NoMatchingResults,
}

#[derive(Debug, Clone, Default)]
pub struct FleetState {
    pub search_query: String,
    pub filter: FleetFilterChip,
    pub sort_column: Option<FleetSortColumn>,
    pub sort_direction: SortDirection,
}

impl FleetState {
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(dead_code)]
    pub fn set_search(&mut self, query: impl Into<String>) {
        self.search_query = query.into();
    }

    pub fn set_filter(&mut self, filter: FleetFilterChip) {
        self.filter = filter;
    }

    pub fn set_sort(&mut self, column: FleetSortColumn, direction: SortDirection) {
        self.sort_column = Some(column);
        self.sort_direction = direction;
    }

    #[allow(dead_code)]
    pub fn toggle_sort(&mut self, column: FleetSortColumn) {
        if self.sort_column == Some(column) {
            match self.sort_direction {
                SortDirection::Ascending => self.sort_direction = SortDirection::Descending,
                SortDirection::Descending => {
                    self.sort_column = None;
                    self.sort_direction = SortDirection::Ascending;
                }
            }
        } else {
            self.sort_column = Some(column);
            self.sort_direction = SortDirection::Ascending;
        }
    }

    pub fn reset_filters(&mut self) {
        self.search_query.clear();
        self.filter = FleetFilterChip::All;
    }

    pub fn filter_and_sort(&self, devices: &[FleetDeviceEntry]) -> Vec<FleetDeviceItem> {
        let query = self.search_query.trim().to_lowercase();
        let mut items: Vec<FleetDeviceItem> = devices
            .iter()
            .map(FleetDeviceItem::from_entry)
            .filter(|item| {
                if !self.filter.matches(item) {
                    return false;
                }
                if query.is_empty() {
                    return true;
                }
                item.display_name.to_lowercase().contains(&query)
                    || item.device_id.to_lowercase().contains(&query)
                    || item.last_address.to_lowercase().contains(&query)
                    || item
                        .configured_address
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&query)
                    || item
                        .location
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&query)
            })
            .collect();

        if let Some(col) = self.sort_column {
            items.sort_by(|a, b| {
                let cmp = match col {
                    FleetSortColumn::Status => a.status.label().cmp(b.status.label()),
                    FleetSortColumn::Name => a
                        .display_label()
                        .to_lowercase()
                        .cmp(&b.display_label().to_lowercase()),
                    FleetSortColumn::Platform => a.device_type.cmp(&b.device_type),
                    FleetSortColumn::Address => a.primary_address().cmp(b.primary_address()),
                    FleetSortColumn::Location => a.location_label().cmp(b.location_label()),
                    FleetSortColumn::LastSeen => a.last_seen_unix_ms.cmp(&b.last_seen_unix_ms),
                };
                match self.sort_direction {
                    SortDirection::Ascending => cmp,
                    SortDirection::Descending => cmp.reverse(),
                }
            });
        }

        items
    }

    pub fn empty_state(&self, total_devices: usize, filtered_count: usize) -> FleetEmptyState {
        if total_devices == 0 {
            FleetEmptyState::EmptyFleet
        } else if filtered_count == 0 {
            FleetEmptyState::NoMatchingResults
        } else {
            FleetEmptyState::None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_devices() -> Vec<FleetDeviceEntry> {
        vec![
            FleetDeviceEntry {
                device_id: "win-pc-01".into(),
                display_name: "Reception Desktop".into(),
                device_type: "windows".into(),
                last_address: "192.168.1.101:50051".into(),
                online: true,
                last_seen_unix_ms: 100_000,
                location: Some("Building A Front Desk".into()),
                configured_address: None,
                status: "online".into(),
                blocked: false,
            },
            FleetDeviceEntry {
                device_id: "win-pc-02".into(),
                display_name: "Finance Host".into(),
                device_type: "windows".into(),
                last_address: "192.168.1.102:50051".into(),
                online: false,
                last_seen_unix_ms: 80_000,
                location: Some("Floor 2 Room 204".into()),
                configured_address: None,
                status: "offline".into(),
                blocked: false,
            },
            FleetDeviceEntry {
                device_id: "tv-target-01".into(),
                display_name: "Lobby Android TV".into(),
                device_type: "android_tv".into(),
                last_address: "".into(),
                online: false,
                last_seen_unix_ms: 0,
                location: Some("Main Lobby".into()),
                configured_address: Some("192.168.1.200:5555".into()),
                status: "unverified".into(),
                blocked: false,
            },
            FleetDeviceEntry {
                device_id: "win-pc-bad".into(),
                display_name: "Compromised Terminal".into(),
                device_type: "windows".into(),
                last_address: "192.168.1.199:50051".into(),
                online: true,
                last_seen_unix_ms: 95_000,
                location: Some("Warehouse Kiosk".into()),
                configured_address: None,
                status: "blocked".into(),
                blocked: true,
            },
            FleetDeviceEntry {
                device_id: "win-pc-busy".into(),
                display_name: "Support Station".into(),
                device_type: "windows".into(),
                last_address: "192.168.1.150:50051".into(),
                online: true,
                last_seen_unix_ms: 99_000,
                location: Some("Support Center".into()),
                configured_address: None,
                status: "in_session".into(),
                blocked: false,
            },
        ]
    }

    #[test]
    fn item_mapping_and_status_derivation() {
        let devices = sample_devices();
        let items: Vec<FleetDeviceItem> = devices.iter().map(FleetDeviceItem::from_entry).collect();

        assert_eq!(items[0].status, DeviceStatusKind::Online);
        assert_eq!(items[0].display_label(), "Reception Desktop");
        assert_eq!(items[0].primary_address(), "192.168.1.101:50051");
        assert!(items[0].is_windows());

        assert_eq!(items[1].status, DeviceStatusKind::Offline);
        assert_eq!(items[2].status, DeviceStatusKind::Unverified);
        assert!(items[2].is_android_tv());
        assert_eq!(items[2].primary_address(), "192.168.1.200:5555");

        assert_eq!(items[3].status, DeviceStatusKind::Blocked);
        assert_eq!(items[4].status, DeviceStatusKind::InSession);
    }

    #[test]
    fn filter_chips_narrowing() {
        let devices = sample_devices();
        let mut state = FleetState::new();

        // All
        state.set_filter(FleetFilterChip::All);
        assert_eq!(state.filter_and_sort(&devices).len(), 5);

        // Windows
        state.set_filter(FleetFilterChip::Windows);
        let win = state.filter_and_sort(&devices);
        assert_eq!(win.len(), 4);
        assert!(win.iter().all(|d| d.is_windows()));

        // Android TV
        state.set_filter(FleetFilterChip::AndroidTv);
        let tv = state.filter_and_sort(&devices);
        assert_eq!(tv.len(), 1);
        assert_eq!(tv[0].device_id, "tv-target-01");

        // Online
        state.set_filter(FleetFilterChip::Online);
        let online = state.filter_and_sort(&devices);
        assert_eq!(online.len(), 1);
        assert_eq!(online[0].device_id, "win-pc-01");

        // Offline
        state.set_filter(FleetFilterChip::Offline);
        let offline = state.filter_and_sort(&devices);
        assert_eq!(offline.len(), 1);
        assert_eq!(offline[0].device_id, "win-pc-02");

        // Blocked
        state.set_filter(FleetFilterChip::Blocked);
        let blocked = state.filter_and_sort(&devices);
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].device_id, "win-pc-bad");
    }

    #[test]
    fn search_filtering_by_fields() {
        let devices = sample_devices();
        let mut state = FleetState::new();

        // Search by display name
        state.set_search("Finance");
        let res = state.filter_and_sort(&devices);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].device_id, "win-pc-02");

        // Search by device_id (hostname fallback)
        state.set_search("tv-target");
        let res = state.filter_and_sort(&devices);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].display_name, "Lobby Android TV");

        // Search by IP address
        state.set_search("192.168.1.199");
        let res = state.filter_and_sort(&devices);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].device_id, "win-pc-bad");

        // Search by location
        state.set_search("Main Lobby");
        let res = state.filter_and_sort(&devices);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].device_id, "tv-target-01");

        // Case-insensitivity & whitespace trimming
        state.set_search("   wArEhOuSe  ");
        let res = state.filter_and_sort(&devices);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].device_id, "win-pc-bad");
    }

    #[test]
    fn combined_search_and_filter() {
        let devices = sample_devices();
        let mut state = FleetState::new();

        state.set_filter(FleetFilterChip::Windows);
        state.set_search("Lobby");
        // Lobby is an Android TV, so filtering with Windows yields 0
        let res = state.filter_and_sort(&devices);
        assert_eq!(res.len(), 0);

        state.set_filter(FleetFilterChip::AndroidTv);
        let res = state.filter_and_sort(&devices);
        assert_eq!(res.len(), 1);
    }

    #[test]
    fn sorting_columns_and_toggle() {
        let devices = sample_devices();
        let mut state = FleetState::new();

        // Sort by Name Ascending
        state.set_sort(FleetSortColumn::Name, SortDirection::Ascending);
        let res = state.filter_and_sort(&devices);
        assert_eq!(res[0].display_label(), "Compromised Terminal");
        assert_eq!(res.last().unwrap().display_label(), "Support Station");

        // Sort by Name Descending
        state.set_sort(FleetSortColumn::Name, SortDirection::Descending);
        let res = state.filter_and_sort(&devices);
        assert_eq!(res[0].display_label(), "Support Station");
        assert_eq!(res.last().unwrap().display_label(), "Compromised Terminal");

        // Toggle sort cycle: Ascending -> Descending -> None
        state.sort_column = None;
        state.toggle_sort(FleetSortColumn::Status);
        assert_eq!(state.sort_column, Some(FleetSortColumn::Status));
        assert_eq!(state.sort_direction, SortDirection::Ascending);

        state.toggle_sort(FleetSortColumn::Status);
        assert_eq!(state.sort_column, Some(FleetSortColumn::Status));
        assert_eq!(state.sort_direction, SortDirection::Descending);

        state.toggle_sort(FleetSortColumn::Status);
        assert_eq!(state.sort_column, None);
    }

    #[test]
    fn empty_state_triggers_and_reset() {
        let mut state = FleetState::new();

        // Fresh deployment with 0 devices
        assert_eq!(state.empty_state(0, 0), FleetEmptyState::EmptyFleet);

        // Filter yields 0 matches
        assert_eq!(state.empty_state(5, 0), FleetEmptyState::NoMatchingResults);

        // Normal populated view
        assert_eq!(state.empty_state(5, 2), FleetEmptyState::None);

        // Reset filter
        state.set_search("random nonexistent string");
        state.set_filter(FleetFilterChip::Blocked);
        state.reset_filters();
        assert_eq!(state.search_query, "");
        assert_eq!(state.filter, FleetFilterChip::All);
    }

    #[test]
    fn relative_heartbeat_formatting() {
        let now = 1_000_000_000;
        assert_eq!(format_relative_time(now - 3_000, now), "3s ago");
        assert_eq!(format_relative_time(now - 120_000, now), "2m ago");
        assert_eq!(format_relative_time(now - 7_200_000, now), "2h ago");
        assert_eq!(format_relative_time(now - 172_800_000, now), "2d ago");
        assert_eq!(format_relative_time(0, now), "—");
    }
}
