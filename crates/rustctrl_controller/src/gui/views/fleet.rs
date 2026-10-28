use super::super::*;
use gpui::WeakEntity;
use gpui::assets::IconName;
use gpui::base::StyledExt;
use gpui::component::Sizable;
use gpui::component::button::{Button, ButtonVariants};
use gpui::component::empty::{
    Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyMediaVariant, EmptyTitle,
};
use gpui::component::menu::DropdownMenu;
use gpui::component::table::{Column, ColumnSort, DataTable, TableDelegate, TableState};

impl ControllerApp {
    pub(in crate::gui) fn render_fleet(
        &self,
        is_admin: bool,
        devices: &[FleetDeviceEntry],
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> gpui::Div {
        let theme = self.theme;
        let computed = self.fleet_model.computed_devices(devices);
        let empty_state = self.fleet_model.evaluate_empty_state(devices, &computed);

        let mut fleet_container = div().flex().flex_col().gap_4().size_full();

        // 1. Title bar
        let mut title_bar = div().flex().justify_between().items_center().child(
            div()
                .flex()
                .items_baseline()
                .gap_3()
                .child(
                    div()
                        .text_xl()
                        .font_bold()
                        .text_color(rgb(theme.text_primary))
                        .child("Fleet Inventory"),
                )
                .child(
                    div()
                        .text_xs()
                        .text_color(rgb(theme.text_muted))
                        .child(format!("{} of {} devices", computed.len(), devices.len())),
                ),
        );

        if is_admin {
            title_bar = title_bar.child(
                div()
                    .flex()
                    .gap_2()
                    .child(
                        Button::new("open-replace-device-btn")
                            .small()
                            .label("Replace Device")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.open_replace_device(String::new(), String::new(), cx);
                            })),
                    )
                    .child(
                        Button::new("open-prepare-artifact-btn")
                            .small()
                            .label("+ Installation Package")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.open_prepare_installation_artifact(cx);
                            })),
                    )
                    .child(
                        Button::new("add-target-btn")
                            .small()
                            .label("+ Add Target")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.open_add_target(cx);
                            })),
                    ),
            );
        }
        fleet_container = fleet_container.child(title_bar);

        // 2. Toolbar: Search box & Filter chips
        let is_search_active = self.active_field == ActiveField::FleetSearch;
        let search_query = &self.fleet_model.filter.search_query;
        let search_box = div()
            .id("fleet-search-box")
            .w_full()
            .max_w(gpui::px(380.0))
            .flex()
            .items_center()
            .gap_2()
            .px_3()
            .py_1p5()
            .rounded_md()
            .border_1()
            .border_color(rgb(if is_search_active {
                theme.border_focus
            } else {
                theme.border_subtle
            }))
            .bg(rgb(theme.bg_surface))
            .cursor_text()
            .on_click(cx.listener(|this, _, window, cx| {
                this.active_field = ActiveField::FleetSearch;
                window.focus(&this.focus_handle, cx);
                cx.notify();
            }))
            .child(
                div()
                    .text_color(rgb(if is_search_active {
                        theme.accent_primary
                    } else {
                        theme.text_muted
                    }))
                    .child(IconName::Search),
            )
            .child(
                div()
                    .flex_1()
                    .text_sm()
                    .text_color(rgb(if search_query.is_empty() {
                        theme.text_muted
                    } else {
                        theme.text_primary
                    }))
                    .child(if search_query.is_empty() {
                        "Search by name, IP, or location...".to_string()
                    } else {
                        search_query.clone()
                    }),
            )
            .when(!search_query.is_empty(), |this| {
                this.child(
                    div()
                        .id("clear-search-btn")
                        .cursor_pointer()
                        .text_color(rgb(theme.text_muted))
                        .hover(|s| s.text_color(rgb(theme.text_primary)))
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.fleet_model.filter.search_query.clear();
                            cx.notify();
                        }))
                        .child(IconName::X),
                )
            });

        let mut chips_row = div().flex().items_center().gap_2().flex_wrap();
        for chip in FleetFilterChip::ALL_CHIPS {
            let is_active = chip == self.fleet_model.filter.active_chip;
            let chip_label = chip.label();
            chips_row = chips_row.child(
                div()
                    .id(format!("filter-chip-{}", chip_label))
                    .cursor_pointer()
                    .px_3()
                    .py_1()
                    .rounded_full()
                    .text_xs()
                    .font_medium()
                    .border_1()
                    .border_color(rgb(if is_active {
                        theme.accent_primary
                    } else {
                        theme.border_subtle
                    }))
                    .bg(rgb(if is_active {
                        theme.bg_surface_hover
                    } else {
                        theme.bg_surface
                    }))
                    .text_color(rgb(if is_active {
                        theme.accent_primary
                    } else {
                        theme.text_muted
                    }))
                    .hover(|s| s.bg(rgb(theme.bg_surface_hover)))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.fleet_model.filter.active_chip = chip;
                        cx.notify();
                    }))
                    .child(chip_label),
            );
        }

        let toolbar = div()
            .flex()
            .justify_between()
            .items_center()
            .gap_4()
            .child(search_box)
            .child(chips_row);

        fleet_container = fleet_container.child(toolbar);

        // 3. Body: Empty State or DataTable
        match empty_state {
            Some(FleetEmptyState::EmptyFleet) => {
                let empty_card = Empty::new()
                    .header(
                        EmptyHeader::new()
                            .media(
                                EmptyMedia::new()
                                    .with_variant(EmptyMediaVariant::Icon)
                                    .child(IconName::Inbox),
                            )
                            .title(EmptyTitle::new().child("No Fleet Devices Registered"))
                            .description(
                                EmptyDescription::new().child(
                                    "Deploy the RustCtrl agent to Windows devices or add Android TV targets to begin fleet monitoring.",
                                ),
                            ),
                    )
                    .when(is_admin, |this| {
                        this.content(
                            EmptyContent::new().child(
                                Button::new("empty-create-package-btn")
                                    .label("Create Agent Package")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.open_prepare_installation_artifact(cx);
                                    })),
                            ),
                        )
                    });
                fleet_container.child(empty_card)
            }
            Some(FleetEmptyState::EmptySearch {
                active_chip,
                search_query,
            }) => {
                let desc = if search_query.is_empty() {
                    format!("No devices found under filter '{}'.", active_chip.label())
                } else {
                    format!(
                        "No devices match '{search_query}' under filter '{}'.",
                        active_chip.label()
                    )
                };
                let empty_card = Empty::new()
                    .header(
                        EmptyHeader::new()
                            .media(
                                EmptyMedia::new()
                                    .with_variant(EmptyMediaVariant::Icon)
                                    .child(IconName::Search),
                            )
                            .title(EmptyTitle::new().child("No Matching Devices Found"))
                            .description(EmptyDescription::new().child(desc)),
                    )
                    .content(
                        EmptyContent::new().child(
                            Button::new("reset-filter-btn")
                                .label("Reset Filter")
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.fleet_model.filter.reset();
                                    cx.notify();
                                })),
                        ),
                    );
                fleet_container.child(empty_card)
            }
            None => {
                let rows: Vec<FleetRowViewModel> = computed
                    .iter()
                    .map(|d| format_fleet_row(d, &theme))
                    .collect();

                let table_state = {
                    let mut table_ref = self.fleet_table.borrow_mut();
                    if let Some(existing) = &*table_ref {
                        existing.update(cx, |state, cx| {
                            state.delegate_mut().rows = rows;
                            state.delegate_mut().is_admin = is_admin;
                            state.delegate_mut().theme = theme;
                            if let Some((col_ix, sort)) = state.delegate().active_sort {
                                state.delegate_mut().apply_sort(col_ix, sort);
                            }
                            state.refresh(cx);
                        });
                        existing.clone()
                    } else {
                        let mut delegate = FleetTableDelegate::new(rows, is_admin, theme);
                        delegate.app = Some(cx.entity().downgrade());
                        let state = cx.new(|cx| TableState::new(delegate, window, cx));
                        *table_ref = Some(state.clone());
                        state
                    }
                };

                fleet_container.child(
                    div()
                        .size_full()
                        .flex_1()
                        .child(DataTable::new(&table_state).bordered(true)),
                )
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetRowViewModel {
    pub device_id: String,
    pub name: String,
    pub status: &'static str,
    pub status_color: u32,
    pub is_tv: bool,
    pub device_type: String,
    pub icon_name: IconName,
    pub address_and_location: String,
    pub last_seen: String,
    pub last_seen_unix_ms: i64,
    pub location: Option<String>,
    pub configured_address: Option<String>,
}

pub fn format_fleet_row(
    device: &FleetDeviceEntry,
    theme: &crate::theme::Theme,
) -> FleetRowViewModel {
    let status = device.derived_status();
    let status_color = match status {
        "Online" => theme.status_online,
        "Blocked" => theme.status_blocked,
        "In Session" => theme.accent_primary,
        "Unverified" => theme.status_reconnecting,
        _ => theme.status_offline,
    };
    let is_tv = device.device_type.eq_ignore_ascii_case("android_tv");
    let icon_name = if is_tv {
        IconName::Tv
    } else {
        IconName::Monitor
    };
    let name = device.effective_name().to_string();
    let effective_addr = device.effective_address();
    let address_and_location = match &device.location {
        Some(loc) if !loc.trim().is_empty() => {
            if effective_addr != "—" {
                format!("{effective_addr} · {loc}")
            } else {
                loc.clone()
            }
        }
        _ => effective_addr.to_string(),
    };
    let last_seen = if is_tv || device.last_seen_unix_ms == 0 {
        "—".to_string()
    } else {
        relative_last_seen(device.last_seen_unix_ms)
    };

    FleetRowViewModel {
        device_id: device.device_id.clone(),
        name,
        status,
        status_color,
        is_tv,
        device_type: device.device_type.clone(),
        icon_name,
        address_and_location,
        last_seen,
        last_seen_unix_ms: device.last_seen_unix_ms,
        location: device.location.clone(),
        configured_address: device.configured_address.clone(),
    }
}

pub struct FleetTableDelegate {
    pub rows: Vec<FleetRowViewModel>,
    pub is_admin: bool,
    pub theme: crate::theme::Theme,
    pub active_sort: Option<(usize, ColumnSort)>,
    pub app: Option<WeakEntity<ControllerApp>>,
}

impl FleetTableDelegate {
    pub fn new(rows: Vec<FleetRowViewModel>, is_admin: bool, theme: crate::theme::Theme) -> Self {
        Self {
            rows,
            is_admin,
            theme,
            active_sort: None,
            app: None,
        }
    }

    #[cfg(test)]
    pub fn columns_count_headless(&self) -> usize {
        6
    }

    #[cfg(test)]
    pub fn rows_count_headless(&self) -> usize {
        self.rows.len()
    }

    pub fn column_definitions(&self) -> Vec<Column> {
        vec![
            Column::new("status", "Status")
                .width(gpui::px(110.0))
                .sortable(),
            Column::new("device_name", "Device Name")
                .width(gpui::px(220.0))
                .sortable(),
            Column::new("platform", "Platform")
                .width(gpui::px(120.0))
                .sortable(),
            Column::new("address_location", "Network & Location")
                .width(gpui::px(220.0))
                .sortable(),
            Column::new("last_seen", "Last Seen")
                .width(gpui::px(120.0))
                .sortable(),
            Column::new("actions", "Actions")
                .width(gpui::px(160.0))
                .selectable(false),
        ]
    }

    pub fn apply_sort(&mut self, col_ix: usize, sort: ColumnSort) {
        if matches!(sort, ColumnSort::Default) {
            return;
        }
        let ascending = matches!(sort, ColumnSort::Ascending);
        self.rows.sort_by(|a, b| {
            let cmp = match col_ix {
                0 => a.status.cmp(b.status),
                1 => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                2 => a
                    .device_type
                    .to_lowercase()
                    .cmp(&b.device_type.to_lowercase()),
                3 => a.address_and_location.cmp(&b.address_and_location),
                4 => a.last_seen_unix_ms.cmp(&b.last_seen_unix_ms),
                _ => std::cmp::Ordering::Equal,
            };
            if ascending { cmp } else { cmp.reverse() }
        });
    }
}

fn build_row_action_menu(
    row: &FleetRowViewModel,
    is_admin: bool,
    app: Option<WeakEntity<ControllerApp>>,
    menu: gpui::component::menu::PopupMenu,
) -> gpui::component::menu::PopupMenu {
    let dev_id = row.device_id.clone();
    let dev_name = row.name.clone();
    let location = row.location.clone();
    let configured_address = row.configured_address.clone().unwrap_or_default();
    let is_tv = row.is_tv;
    let is_blocked = row.status == "Blocked";
    let is_offline = row.status == "Offline";

    let mut menu = menu.item(
        gpui::component::menu::PopupMenuItem::new("Remote Session").on_click({
            let app = app.clone();
            move |_, _, cx| {
                if let Some(app) = app.as_ref().and_then(|a| a.upgrade()) {
                    app.update(cx, |this, cx| {
                        if let ScreenState::Connected { role, .. } = &this.state {
                            this.navigation
                                .select(crate::navigation::Route::Remote, role);
                            cx.notify();
                        }
                    });
                }
            }
        }),
    );

    if is_admin {
        menu = menu.separator();
        if is_tv {
            let dev_id_edit = dev_id.clone();
            let dev_name_edit = dev_name.clone();
            let dev_id_remove = dev_id.clone();
            let conf_addr_edit = configured_address.clone();
            let loc_edit = location.clone();
            menu = menu
                .item(
                    gpui::component::menu::PopupMenuItem::new("Edit Target").on_click({
                        let app = app.clone();
                        move |_, _, cx| {
                            if let Some(app) = app.as_ref().and_then(|a| a.upgrade()) {
                                app.update(cx, |this, cx| {
                                    this.open_edit_target(
                                        dev_id_edit.clone(),
                                        dev_name_edit.clone(),
                                        conf_addr_edit.clone(),
                                        loc_edit.clone(),
                                        cx,
                                    );
                                });
                            }
                        }
                    }),
                )
                .item(
                    gpui::component::menu::PopupMenuItem::new("Remove Target").on_click({
                        let app = app.clone();
                        move |_, _, cx| {
                            if let Some(app) = app.as_ref().and_then(|a| a.upgrade()) {
                                app.update(cx, |this, cx| {
                                    this.submit_remove_target(dev_id_remove.clone(), cx);
                                });
                            }
                        }
                    }),
                );
        } else {
            let dev_id_edit = dev_id.clone();
            let dev_name_edit = dev_name.clone();
            let loc_edit = location.clone();
            menu = menu.item(
                gpui::component::menu::PopupMenuItem::new("Edit Device").on_click({
                    let app = app.clone();
                    move |_, _, cx| {
                        if let Some(app) = app.as_ref().and_then(|a| a.upgrade()) {
                            app.update(cx, |this, cx| {
                                this.open_edit_device(
                                    dev_id_edit.clone(),
                                    dev_name_edit.clone(),
                                    loc_edit.clone(),
                                    cx,
                                );
                            });
                        }
                    }
                }),
            );
            if is_blocked {
                let dev_id_unblock = dev_id.clone();
                menu = menu.item(
                    gpui::component::menu::PopupMenuItem::new("Unblock Device").on_click({
                        let app = app.clone();
                        move |_, _, cx| {
                            if let Some(app) = app.as_ref().and_then(|a| a.upgrade()) {
                                app.update(cx, |this, cx| {
                                    this.submit_unblock_device(dev_id_unblock.clone(), cx);
                                });
                            }
                        }
                    }),
                );
            } else {
                let dev_id_block = dev_id.clone();
                menu = menu.item(
                    gpui::component::menu::PopupMenuItem::new("Block Device").on_click({
                        let app = app.clone();
                        move |_, _, cx| {
                            if let Some(app) = app.as_ref().and_then(|a| a.upgrade()) {
                                app.update(cx, |this, cx| {
                                    this.submit_block_device(dev_id_block.clone(), cx);
                                });
                            }
                        }
                    }),
                );
                if is_offline {
                    let dev_id_clean = dev_id.clone();
                    menu = menu.item(
                        gpui::component::menu::PopupMenuItem::new("Clean Offline").on_click({
                            let app = app.clone();
                            move |_, _, cx| {
                                if let Some(app) = app.as_ref().and_then(|a| a.upgrade()) {
                                    app.update(cx, |this, cx| {
                                        this.submit_clean_offline_device(dev_id_clean.clone(), cx);
                                    });
                                }
                            }
                        }),
                    );
                }
            }
            let dev_id_replace = dev_id.clone();
            menu = menu.item(
                gpui::component::menu::PopupMenuItem::new("Replace Device").on_click({
                    let app = app.clone();
                    move |_, _, cx| {
                        if let Some(app) = app.as_ref().and_then(|a| a.upgrade()) {
                            app.update(cx, |this, cx| {
                                this.open_replace_device(dev_id_replace.clone(), String::new(), cx);
                            });
                        }
                    }
                }),
            );
        }
    }

    menu
}

impl TableDelegate for FleetTableDelegate {
    fn columns_count(&self, _cx: &App) -> usize {
        6
    }

    fn rows_count(&self, _cx: &App) -> usize {
        self.rows.len()
    }

    fn column(&self, col_ix: usize, _cx: &App) -> Column {
        self.column_definitions()
            .into_iter()
            .nth(col_ix)
            .unwrap_or_else(|| Column::new("", ""))
    }

    fn perform_sort(
        &mut self,
        col_ix: usize,
        sort: ColumnSort,
        _window: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) {
        let col = match col_ix {
            0 => FleetSortColumn::Status,
            1 => FleetSortColumn::DeviceName,
            2 => FleetSortColumn::Platform,
            3 => FleetSortColumn::AddressLocation,
            4 => FleetSortColumn::LastSeen,
            _ => return,
        };
        let direction = match sort {
            ColumnSort::Descending => SortDirection::Descending,
            _ => SortDirection::Ascending,
        };
        self.active_sort = Some((col_ix, sort));
        self.apply_sort(col_ix, sort);
        if let Some(app) = self.app.as_ref().and_then(|a| a.upgrade()) {
            app.update(cx, |this, cx| {
                this.fleet_model.sort = Some(FleetSortState {
                    column: col,
                    direction,
                });
                cx.notify();
            });
        }
        cx.notify();
    }

    fn context_menu(
        &mut self,
        row_ix: usize,
        menu: gpui::component::menu::PopupMenu,
        _window: &mut Window,
        _cx: &mut Context<TableState<Self>>,
    ) -> gpui::component::menu::PopupMenu {
        let Some(row) = self.rows.get(row_ix) else {
            return menu;
        };
        build_row_action_menu(row, self.is_admin, self.app.clone(), menu)
    }

    fn render_td(
        &mut self,
        row_ix: usize,
        col_ix: usize,
        _window: &mut Window,
        _cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        let Some(row) = self.rows.get(row_ix) else {
            return div().into_any_element();
        };
        let theme = self.theme;

        match col_ix {
            0 => {
                // Status Badge formatted with Tokyo Night tokens
                div()
                    .flex()
                    .items_center()
                    .child(
                        div()
                            .px_2()
                            .py_0p5()
                            .rounded_full()
                            .text_xs()
                            .font_medium()
                            .bg(rgb(row.status_color).opacity(0.15))
                            .text_color(rgb(row.status_color))
                            .border_1()
                            .border_color(rgb(row.status_color).opacity(0.3))
                            .child(row.status),
                    )
                    .into_any_element()
            }
            1 => {
                // Device Name (with hostname fallback)
                let show_secondary = row.name != row.device_id && !row.device_id.is_empty();
                div()
                    .flex()
                    .flex_col()
                    .justify_center()
                    .child(
                        div()
                            .text_sm()
                            .font_medium()
                            .text_color(rgb(theme.text_primary))
                            .child(row.name.clone()),
                    )
                    .when(show_secondary, |this| {
                        this.child(
                            div()
                                .text_xs()
                                .text_color(rgb(theme.text_muted))
                                .child(row.device_id.clone()),
                        )
                    })
                    .into_any_element()
            }
            2 => {
                // OS Platform Icon (Lucide Monitor vs Tv)
                div()
                    .flex()
                    .items_center()
                    .gap_1p5()
                    .text_color(rgb(theme.text_muted))
                    .child(row.icon_name)
                    .child(
                        div()
                            .text_xs()
                            .child(if row.is_tv { "Android TV" } else { "Windows" }),
                    )
                    .into_any_element()
            }
            3 => {
                // Network Address & Location
                div()
                    .flex()
                    .items_center()
                    .text_sm()
                    .text_color(rgb(theme.text_primary))
                    .child(row.address_and_location.clone())
                    .into_any_element()
            }
            4 => {
                // Relative Last Heartbeat ("3s ago", "2h ago")
                div()
                    .flex()
                    .items_center()
                    .text_xs()
                    .text_color(rgb(theme.text_muted))
                    .child(row.last_seen.clone())
                    .into_any_element()
            }
            5 => {
                // Quick Actions (`Remote` button and dropdown `...`)
                let app = self.app.clone();
                let is_admin = self.is_admin;
                let row_clone = row.clone();

                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(
                        Button::new(format!("remote-btn-{}", row.device_id))
                            .xsmall()
                            .label("Remote")
                            .on_click({
                                let app = app.clone();
                                move |_event, _window, cx| {
                                    if let Some(app) = app.as_ref().and_then(|a| a.upgrade()) {
                                        app.update(cx, |this, cx| {
                                            if let ScreenState::Connected { role, .. } = &this.state
                                            {
                                                this.navigation
                                                    .select(crate::navigation::Route::Remote, role);
                                                cx.notify();
                                            }
                                        });
                                    }
                                }
                            }),
                    )
                    .child(
                        Button::new(format!("more-btn-{}", row.device_id))
                            .xsmall()
                            .ghost()
                            .icon(IconName::Ellipsis)
                            .dropdown_menu(move |menu, _window, _cx| {
                                build_row_action_menu(&row_clone, is_admin, app.clone(), menu)
                            }),
                    )
                    .into_any_element()
            }
            _ => div().into_any_element(),
        }
    }

    fn cell_text(&self, row_ix: usize, col_ix: usize, _cx: &App) -> String {
        let Some(row) = self.rows.get(row_ix) else {
            return String::new();
        };
        match col_ix {
            0 => row.status.to_string(),
            1 => row.name.clone(),
            2 => if row.is_tv { "Android TV" } else { "Windows" }.to_string(),
            3 => row.address_and_location.clone(),
            4 => row.last_seen.clone(),
            5 => "Actions".to_string(),
            _ => String::new(),
        }
    }
}

pub trait FleetDeviceExt {
    fn effective_name(&self) -> &str;
    fn effective_address(&self) -> &str;
    fn derived_status(&self) -> &'static str;
}

impl FleetDeviceExt for FleetDeviceEntry {
    fn effective_name(&self) -> &str {
        let name = self.display_name.trim();
        if !name.is_empty() {
            name
        } else {
            &self.device_id
        }
    }

    fn effective_address(&self) -> &str {
        if !self.last_address.is_empty() {
            &self.last_address
        } else if let Some(addr) = &self.configured_address {
            if !addr.is_empty() { addr } else { "—" }
        } else {
            "—"
        }
    }

    fn derived_status(&self) -> &'static str {
        if self.blocked || self.status.eq_ignore_ascii_case("blocked") {
            "Blocked"
        } else if self.status.eq_ignore_ascii_case("in_session")
            || self.status.eq_ignore_ascii_case("in session")
        {
            "In Session"
        } else if self.device_type.eq_ignore_ascii_case("android_tv")
            || self.status.eq_ignore_ascii_case("unverified")
        {
            "Unverified"
        } else if self.online || self.status.eq_ignore_ascii_case("online") {
            "Online"
        } else {
            "Offline"
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FleetSortColumn {
    Status,
    DeviceName,
    Platform,
    AddressLocation,
    LastSeen,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortDirection {
    #[default]
    Ascending,
    Descending,
}

impl SortDirection {
    #[allow(dead_code)]
    pub fn toggle(self) -> Self {
        match self {
            Self::Ascending => Self::Descending,
            Self::Descending => Self::Ascending,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FleetSortState {
    pub column: FleetSortColumn,
    pub direction: SortDirection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FleetEmptyState {
    /// Fleet contains 0 registered devices in total.
    /// Guides Admins with quick "Create Agent Package" action.
    EmptyFleet,
    /// Fleet has registered devices, but current search/filter combination yields 0 results.
    /// Shows a "Reset Filter" action.
    EmptySearch {
        active_chip: FleetFilterChip,
        search_query: String,
    },
}

#[derive(Debug, Clone, Default)]
pub struct FleetInventoryModel {
    pub filter: FleetFilterState,
    pub sort: Option<FleetSortState>,
}

impl FleetInventoryModel {
    pub fn evaluate_empty_state(
        &self,
        total_devices: &[FleetDeviceEntry],
        filtered_devices: &[&FleetDeviceEntry],
    ) -> Option<FleetEmptyState> {
        if total_devices.is_empty() {
            Some(FleetEmptyState::EmptyFleet)
        } else if filtered_devices.is_empty() {
            Some(FleetEmptyState::EmptySearch {
                active_chip: self.filter.active_chip,
                search_query: self.filter.search_query.clone(),
            })
        } else {
            None
        }
    }
    #[allow(dead_code)]
    pub fn toggle_sort(&mut self, column: FleetSortColumn) {
        if let Some(current) = self.sort {
            if current.column == column {
                self.sort = Some(FleetSortState {
                    column,
                    direction: current.direction.toggle(),
                });
            } else {
                self.sort = Some(FleetSortState {
                    column,
                    direction: SortDirection::Ascending,
                });
            }
        } else {
            self.sort = Some(FleetSortState {
                column,
                direction: SortDirection::Ascending,
            });
        }
    }

    pub fn computed_devices<'a>(
        &self,
        devices: &'a [FleetDeviceEntry],
    ) -> Vec<&'a FleetDeviceEntry> {
        let mut list = self.filter.filter_devices(devices);
        if let Some(sort) = self.sort {
            list.sort_by(|a, b| {
                let cmp = match sort.column {
                    FleetSortColumn::Status => a.derived_status().cmp(b.derived_status()),
                    FleetSortColumn::DeviceName => a
                        .effective_name()
                        .to_lowercase()
                        .cmp(&b.effective_name().to_lowercase()),
                    FleetSortColumn::Platform => a
                        .device_type
                        .to_lowercase()
                        .cmp(&b.device_type.to_lowercase()),
                    FleetSortColumn::AddressLocation => {
                        let a_addr = a.effective_address();
                        let b_addr = b.effective_address();
                        a_addr.cmp(b_addr)
                    }
                    FleetSortColumn::LastSeen => a.last_seen_unix_ms.cmp(&b.last_seen_unix_ms),
                };
                match sort.direction {
                    SortDirection::Ascending => cmp,
                    SortDirection::Descending => cmp.reverse(),
                }
            });
        }
        list
    }
}

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
    pub const ALL_CHIPS: [Self; 6] = [
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

    pub fn matches(self, device: &FleetDeviceEntry) -> bool {
        let is_tv = device.device_type.eq_ignore_ascii_case("android_tv");
        let derived = device.derived_status();

        match self {
            Self::All => true,
            Self::Windows => !is_tv,
            Self::AndroidTv => is_tv,
            Self::Online => derived == "Online" || derived == "In Session",
            Self::Offline => derived == "Offline",
            Self::Blocked => derived == "Blocked",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct FleetFilterState {
    pub search_query: String,
    pub active_chip: FleetFilterChip,
}

impl FleetFilterState {
    pub fn reset(&mut self) {
        self.search_query.clear();
        self.active_chip = FleetFilterChip::All;
    }

    pub fn filter_devices<'a>(&self, devices: &'a [FleetDeviceEntry]) -> Vec<&'a FleetDeviceEntry> {
        let query = self.search_query.trim().to_lowercase();
        devices
            .iter()
            .filter(|device| {
                if !self.active_chip.matches(device) {
                    return false;
                }
                if query.is_empty() {
                    return true;
                }
                Self::device_matches_query(device, &query)
            })
            .collect()
    }

    fn device_matches_query(device: &FleetDeviceEntry, query: &str) -> bool {
        if device.display_name.to_lowercase().contains(query) {
            return true;
        }
        if device.device_id.to_lowercase().contains(query) {
            return true;
        }
        if device.last_address.to_lowercase().contains(query) {
            return true;
        }
        if let Some(configured) = &device.configured_address
            && configured.to_lowercase().contains(query)
        {
            return true;
        }
        if let Some(location) = &device.location
            && location.to_lowercase().contains(query)
        {
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_fleet() -> Vec<FleetDeviceEntry> {
        vec![
            FleetDeviceEntry {
                device_id: "win-pc-01".into(),
                display_name: "Reception PC".into(),
                device_type: "windows".into(),
                last_address: "192.168.1.101".into(),
                online: true,
                last_seen_unix_ms: 1_700_000_000_000,
                location: Some("Front Desk".into()),
                configured_address: None,
                status: "online".into(),
                blocked: false,
            },
            FleetDeviceEntry {
                device_id: "win-pc-02".into(),
                display_name: "Finance PC".into(),
                device_type: "windows".into(),
                last_address: "192.168.1.102".into(),
                online: false,
                last_seen_unix_ms: 1_699_000_000_000,
                location: Some("Finance Office".into()),
                configured_address: None,
                status: "offline".into(),
                blocked: false,
            },
            FleetDeviceEntry {
                device_id: "win-pc-03".into(),
                display_name: "".into(), // empty name to test hostname/id fallback
                device_type: "windows".into(),
                last_address: "192.168.1.103".into(),
                online: false,
                last_seen_unix_ms: 1_699_000_000_000,
                location: Some("Server Room".into()),
                configured_address: None,
                status: "blocked".into(),
                blocked: true,
            },
            FleetDeviceEntry {
                device_id: "tv-target-01".into(),
                display_name: "Lobby TV".into(),
                device_type: "android_tv".into(),
                last_address: "".into(),
                online: false,
                last_seen_unix_ms: 0,
                location: Some("Ground Lobby".into()),
                configured_address: Some("192.168.1.201:5555".into()),
                status: "unverified".into(),
                blocked: false,
            },
        ]
    }

    #[test]
    fn filter_chips_correctly_categorize_fleet_devices() {
        let fleet = sample_fleet();
        let state = FleetFilterState::default();

        let all = state.filter_devices(&fleet);
        assert_eq!(all.len(), 4, "All filter should return all devices");

        let win_state = FleetFilterState {
            active_chip: FleetFilterChip::Windows,
            ..Default::default()
        };
        let windows = win_state.filter_devices(&fleet);
        assert_eq!(windows.len(), 3, "Windows should match 3 Windows devices");
        assert!(windows.iter().all(|d| d.device_type == "windows"));

        let tv_state = FleetFilterState {
            active_chip: FleetFilterChip::AndroidTv,
            ..Default::default()
        };
        let tvs = tv_state.filter_devices(&fleet);
        assert_eq!(tvs.len(), 1, "AndroidTv should match 1 TV target");
        assert_eq!(tvs[0].device_id, "tv-target-01");

        let online_state = FleetFilterState {
            active_chip: FleetFilterChip::Online,
            ..Default::default()
        };
        let online = online_state.filter_devices(&fleet);
        assert_eq!(
            online.len(),
            1,
            "Online should match 1 online unblocked device"
        );
        assert_eq!(online[0].device_id, "win-pc-01");

        let offline_state = FleetFilterState {
            active_chip: FleetFilterChip::Offline,
            ..Default::default()
        };
        let offline = offline_state.filter_devices(&fleet);
        assert_eq!(
            offline.len(),
            1,
            "Offline should match 1 offline unblocked Windows device"
        );
        assert_eq!(offline[0].device_id, "win-pc-02");

        let blocked_state = FleetFilterState {
            active_chip: FleetFilterChip::Blocked,
            ..Default::default()
        };
        let blocked = blocked_state.filter_devices(&fleet);
        assert_eq!(blocked.len(), 1, "Blocked should match 1 blocked device");
        assert_eq!(blocked[0].device_id, "win-pc-03");
    }

    #[test]
    fn search_query_matches_display_name_hostname_ip_and_location() {
        let fleet = sample_fleet();

        // Search by display name
        let name_query = FleetFilterState {
            search_query: "reception".into(),
            ..Default::default()
        };
        let res = name_query.filter_devices(&fleet);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].device_id, "win-pc-01");

        // Search by hostname / device_id fallback
        let id_query = FleetFilterState {
            search_query: "win-pc-03".into(),
            ..Default::default()
        };
        let res = id_query.filter_devices(&fleet);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].device_id, "win-pc-03");

        // Search by IP in last_address
        let ip_query = FleetFilterState {
            search_query: "192.168.1.102".into(),
            ..Default::default()
        };
        let res = ip_query.filter_devices(&fleet);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].device_id, "win-pc-02");

        // Search by IP in configured_address
        let config_ip_query = FleetFilterState {
            search_query: "192.168.1.201".into(),
            ..Default::default()
        };
        let res = config_ip_query.filter_devices(&fleet);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].device_id, "tv-target-01");

        // Search by location
        let loc_query = FleetFilterState {
            search_query: "Server Room".into(),
            ..Default::default()
        };
        let res = loc_query.filter_devices(&fleet);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].device_id, "win-pc-03");

        // Search with no matches
        let no_match = FleetFilterState {
            search_query: "NonExistent".into(),
            ..Default::default()
        };
        assert!(no_match.filter_devices(&fleet).is_empty());
    }

    #[test]
    fn search_query_and_filter_chip_combine_with_conjunction() {
        let fleet = sample_fleet();

        let state = FleetFilterState {
            active_chip: FleetFilterChip::Windows,
            search_query: "Lobby".into(),
        };
        // Lobby is an Android TV, but filter chip is Windows -> should yield 0 results
        let res = state.filter_devices(&fleet);
        assert!(
            res.is_empty(),
            "Windows filter + Lobby TV search query must yield 0 results"
        );

        let mut state = state;
        state.active_chip = FleetFilterChip::AndroidTv;
        let res = state.filter_devices(&fleet);
        assert_eq!(
            res.len(),
            1,
            "AndroidTv filter + Lobby search query must match"
        );
    }

    #[test]
    fn column_sorting_orders_by_name_last_seen_and_status() {
        let fleet = sample_fleet();
        let mut model = FleetInventoryModel {
            sort: Some(FleetSortState {
                column: FleetSortColumn::DeviceName,
                direction: SortDirection::Ascending,
            }),
            ..Default::default()
        };
        let sorted = model.computed_devices(&fleet);
        let names: Vec<&str> = sorted.iter().map(|d| d.effective_name()).collect();
        assert_eq!(
            names,
            vec!["Finance PC", "Lobby TV", "Reception PC", "win-pc-03"]
        );

        // 2. Sort by DeviceName Descending
        model.sort = Some(FleetSortState {
            column: FleetSortColumn::DeviceName,
            direction: SortDirection::Descending,
        });
        let sorted_desc = model.computed_devices(&fleet);
        let names_desc: Vec<&str> = sorted_desc.iter().map(|d| d.effective_name()).collect();
        assert_eq!(
            names_desc,
            vec!["win-pc-03", "Reception PC", "Lobby TV", "Finance PC"]
        );

        // 3. Sort by LastSeen Ascending
        model.sort = Some(FleetSortState {
            column: FleetSortColumn::LastSeen,
            direction: SortDirection::Ascending,
        });
        let by_last_seen = model.computed_devices(&fleet);
        assert_eq!(
            by_last_seen[0].device_id, "tv-target-01",
            "0 last_seen_unix_ms should be first"
        );
        assert_eq!(
            by_last_seen[3].device_id, "win-pc-01",
            "largest last_seen_unix_ms should be last"
        );

        // 4. Sort by LastSeen Descending
        model.sort = Some(FleetSortState {
            column: FleetSortColumn::LastSeen,
            direction: SortDirection::Descending,
        });
        let by_last_seen_desc = model.computed_devices(&fleet);
        assert_eq!(by_last_seen_desc[0].device_id, "win-pc-01");
        assert_eq!(by_last_seen_desc[3].device_id, "tv-target-01");

        // 5. Sort by Platform
        model.sort = Some(FleetSortState {
            column: FleetSortColumn::Platform,
            direction: SortDirection::Ascending,
        });
        let by_platform = model.computed_devices(&fleet);
        assert_eq!(by_platform[0].device_type, "android_tv");
        assert_eq!(by_platform[1].device_type, "windows");

        // 6. Test toggle_sort
        model.toggle_sort(FleetSortColumn::Status);
        assert_eq!(
            model.sort,
            Some(FleetSortState {
                column: FleetSortColumn::Status,
                direction: SortDirection::Ascending,
            })
        );
        model.toggle_sort(FleetSortColumn::Status);
        assert_eq!(
            model.sort,
            Some(FleetSortState {
                column: FleetSortColumn::Status,
                direction: SortDirection::Descending,
            })
        );
        model.toggle_sort(FleetSortColumn::Status);
        assert_eq!(
            model.sort,
            Some(FleetSortState {
                column: FleetSortColumn::Status,
                direction: SortDirection::Ascending,
            })
        );
    }

    #[test]
    fn empty_state_triggers_and_reset() {
        let fleet = sample_fleet();
        let mut model = FleetInventoryModel::default();

        // When entire fleet is empty (fresh deployment)
        let empty_fleet: Vec<FleetDeviceEntry> = Vec::new();
        let computed = model.computed_devices(&empty_fleet);
        assert_eq!(
            model.evaluate_empty_state(&empty_fleet, &computed),
            Some(FleetEmptyState::EmptyFleet),
            "0 total devices triggers EmptyFleet"
        );

        // When fleet has devices, but search yields 0 matches
        model.filter.search_query = "UnknownDevice".into();
        let computed = model.computed_devices(&fleet);
        assert!(computed.is_empty());
        assert_eq!(
            model.evaluate_empty_state(&fleet, &computed),
            Some(FleetEmptyState::EmptySearch {
                active_chip: FleetFilterChip::All,
                search_query: "UnknownDevice".into(),
            }),
            "0 matches on non-empty fleet triggers EmptySearch"
        );

        // Resetting filter restores the items and clears empty state
        model.filter.reset();
        let computed_restored = model.computed_devices(&fleet);
        assert_eq!(computed_restored.len(), 4);
        assert_eq!(
            model.evaluate_empty_state(&fleet, &computed_restored),
            None,
            "Populated results produce None empty state"
        );
    }

    #[test]
    fn format_fleet_row_applies_tokyo_night_tokens_and_fallbacks() {
        let theme = crate::theme::Theme::tokyo_night();
        let fleet = sample_fleet();

        // 1. Online Windows device
        let row_online = format_fleet_row(&fleet[0], &theme);
        assert_eq!(row_online.device_id, "win-pc-01");
        assert_eq!(row_online.name, "Reception PC");
        assert_eq!(row_online.status, "Online");
        assert_eq!(row_online.status_color, theme.status_online);
        assert_eq!(row_online.icon_name, gpui::assets::IconName::Monitor);
        assert!(!row_online.is_tv);
        assert_eq!(
            row_online.address_and_location,
            "192.168.1.101 · Front Desk"
        );
        assert_ne!(row_online.last_seen, "—");

        // 2. Blocked device with empty display name (fallback to hostname/device_id)
        let row_blocked = format_fleet_row(&fleet[2], &theme);
        assert_eq!(row_blocked.device_id, "win-pc-03");
        assert_eq!(
            row_blocked.name, "win-pc-03",
            "empty display name falls back to device_id"
        );
        assert_eq!(row_blocked.status, "Blocked");
        assert_eq!(row_blocked.status_color, theme.status_blocked);
        assert_eq!(row_blocked.icon_name, gpui::assets::IconName::Monitor);

        // 3. Android TV target
        let row_tv = format_fleet_row(&fleet[3], &theme);
        assert_eq!(row_tv.device_id, "tv-target-01");
        assert_eq!(row_tv.name, "Lobby TV");
        assert_eq!(row_tv.status, "Unverified");
        assert_eq!(row_tv.status_color, theme.status_reconnecting);
        assert_eq!(row_tv.icon_name, gpui::assets::IconName::Tv);
        assert!(row_tv.is_tv);
        assert_eq!(
            row_tv.address_and_location,
            "192.168.1.201:5555 · Ground Lobby"
        );
        assert_eq!(row_tv.last_seen, "—", "TV target has no last seen");
    }

    #[test]
    fn fleet_table_delegate_reports_six_standard_columns() {
        let theme = crate::theme::Theme::tokyo_night();
        let fleet = sample_fleet();
        let rows: Vec<FleetRowViewModel> =
            fleet.iter().map(|d| format_fleet_row(d, &theme)).collect();
        let delegate = FleetTableDelegate::new(rows, true, theme);

        assert_eq!(delegate.columns_count_headless(), 6);
        assert_eq!(delegate.rows_count_headless(), 4);

        let cols = delegate.column_definitions();
        assert_eq!(cols.len(), 6);
        assert_eq!(cols[0].key.as_ref(), "status");
        assert_eq!(cols[1].key.as_ref(), "device_name");
        assert_eq!(cols[2].key.as_ref(), "platform");
        assert_eq!(cols[3].key.as_ref(), "address_location");
        assert_eq!(cols[4].key.as_ref(), "last_seen");
        assert_eq!(cols[5].key.as_ref(), "actions");
        assert!(
            !cols[5].selectable,
            "Actions column must not participate in selection"
        );
    }
}
