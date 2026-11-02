use super::super::*;
use crate::fleet::{
    DeviceStatusKind, FleetDeviceItem, FleetEmptyState, FleetFilterChip, FleetSortColumn,
    SortDirection,
};
use crate::theme::Theme;
use gpui::assets::IconName;
use gpui::base::StyledExt as _;
use gpui::component::Icon;
use gpui::component::button::{Button, ButtonVariants as _};
use gpui::component::empty::{
    Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyMediaVariant, EmptyTitle,
};
use gpui::component::table::{
    Column, ColumnSort, DataTable, TableDelegate, TableEvent, TableState,
};
use gpui::{
    App, Context, Entity, InteractiveElement as _, IntoElement, ParentElement as _, Stateful,
    Styled as _, Window, div, prelude::FluentBuilder as _, px, rgb,
};

pub(crate) struct FleetTableDelegate {
    pub(crate) items: Vec<FleetDeviceItem>,
    pub(crate) theme: Theme,
    pub(crate) is_admin: bool,
    pub(crate) empty_state: FleetEmptyState,
    pub(crate) app: Entity<ControllerApp>,
}

impl TableDelegate for FleetTableDelegate {
    fn columns_count(&self, _cx: &App) -> usize {
        6
    }

    fn rows_count(&self, _cx: &App) -> usize {
        self.items.len()
    }

    fn column(&self, col_ix: usize, _cx: &App) -> Column {
        match col_ix {
            0 => Column::new("status", "Status")
                .width(px(130.))
                .min_width(px(100.))
                .sortable(),
            1 => Column::new("name", "Device Name")
                .width(px(240.))
                .min_width(px(160.))
                .sortable(),
            2 => Column::new("platform", "Platform")
                .width(px(130.))
                .min_width(px(100.))
                .sortable(),
            3 => Column::new("network_location", "Network & Location")
                .width(px(250.))
                .min_width(px(180.))
                .sortable(),
            4 => Column::new("last_seen", "Last Heartbeat")
                .width(px(140.))
                .min_width(px(110.))
                .sortable(),
            5 => Column::new("actions", "Actions")
                .width(px(220.))
                .min_width(px(160.))
                .resizable(false)
                .movable(false),
            _ => unreachable!(),
        }
    }

    fn perform_sort(
        &mut self,
        col_ix: usize,
        sort: ColumnSort,
        _window: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) {
        let col = match col_ix {
            0 => Some(FleetSortColumn::Status),
            1 => Some(FleetSortColumn::Name),
            2 => Some(FleetSortColumn::Platform),
            3 => Some(FleetSortColumn::Address),
            4 => Some(FleetSortColumn::LastSeen),
            _ => None,
        };
        let dir = match sort {
            ColumnSort::Ascending => Some(SortDirection::Ascending),
            ColumnSort::Descending => Some(SortDirection::Descending),
            ColumnSort::Default => None,
        };

        let app = self.app.clone();
        app.update(cx, |this, cx| {
            if let (Some(col), Some(dir)) = (col, dir) {
                this.fleet_state.set_sort(col, dir);
            } else {
                this.fleet_state.sort_column = None;
            }
            cx.notify();
        });
    }

    fn render_tr(
        &mut self,
        row_ix: usize,
        _window: &mut Window,
        _cx: &mut Context<TableState<Self>>,
    ) -> Stateful<gpui::Div> {
        let theme = self.theme;
        div()
            .id(("row", row_ix))
            .border_b_1()
            .border_color(rgb(theme.border_subtle))
            .hover(move |style| style.bg(rgb(theme.bg_surface_hover)))
    }

    fn render_th(
        &mut self,
        col_ix: usize,
        _window: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        let theme = self.theme;
        div()
            .size_full()
            .flex()
            .items_center()
            .text_xs()
            .font_semibold()
            .text_color(rgb(theme.text_muted))
            .child(self.column(col_ix, cx).name.clone())
    }

    fn render_empty(
        &mut self,
        _window: &mut Window,
        _cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        let app = self.app.clone();
        let theme = self.theme;
        match self.empty_state {
            FleetEmptyState::EmptyFleet => Empty::new()
                .header(
                    EmptyHeader::new()
                        .media(
                            EmptyMedia::new()
                                .with_variant(EmptyMediaVariant::Icon)
                                .child(
                                    Icon::new(IconName::PackagePlus)
                                        .size_6()
                                        .text_color(rgb(theme.accent_primary)),
                                ),
                        )
                        .title(
                            EmptyTitle::new().child(
                                div()
                                    .text_base()
                                    .font_semibold()
                                    .text_color(rgb(theme.text_primary))
                                    .child("No Fleet Devices Registered"),
                            ),
                        )
                        .description(
                            EmptyDescription::new().child(
                                div()
                                    .text_sm()
                                    .text_color(rgb(theme.text_muted))
                                    .child("Create an installation package to enroll Windows PCs or add an Android TV target to start monitoring."),
                            ),
                        ),
                )
                .content(EmptyContent::new().when(self.is_admin, |content| {
                    content.child(
                        Button::new("empty-create-package-btn")
                            .label("Create Agent Package")
                            .on_click(move |_, _, cx| {
                                app.update(cx, |this, cx| {
                                    this.open_prepare_installation_artifact(cx);
                                });
                            }),
                    )
                }))
                .into_any_element(),
            FleetEmptyState::NoMatchingResults => Empty::new()
                .header(
                    EmptyHeader::new()
                        .media(
                            EmptyMedia::new()
                                .with_variant(EmptyMediaVariant::Icon)
                                .child(
                                    Icon::new(IconName::SearchX)
                                        .size_6()
                                        .text_color(rgb(theme.status_blocked)),
                                ),
                        )
                        .title(
                            EmptyTitle::new().child(
                                div()
                                    .text_base()
                                    .font_semibold()
                                    .text_color(rgb(theme.text_primary))
                                    .child("No Matching Devices Found"),
                            ),
                        )
                        .description(
                            EmptyDescription::new().child(
                                div()
                                    .text_sm()
                                    .text_color(rgb(theme.text_muted))
                                    .child("No devices match your current search query or active filter chip."),
                            ),
                        ),
                )
                .content(
                    EmptyContent::new().child(
                        Button::new("empty-reset-filter-btn")
                            .label("Reset Filter")
                            .on_click(move |_, _, cx| {
                                app.update(cx, |this, cx| {
                                    this.fleet_state.reset_filters();
                                    cx.notify();
                                });
                            }),
                    ),
                )
                .into_any_element(),
            FleetEmptyState::None => div().into_any_element(),
        }
    }

    fn render_td(
        &mut self,
        row_ix: usize,
        col_ix: usize,
        _window: &mut Window,
        _cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        let Some(item) = self.items.get(row_ix) else {
            return div().into_any_element();
        };
        let theme = self.theme;

        match col_ix {
            0 => {
                let (status_text, status_color, status_bg) = match item.status {
                    DeviceStatusKind::Online => ("Online", theme.status_online, theme.bg_surface),
                    DeviceStatusKind::Offline => {
                        ("Offline", theme.status_offline, theme.bg_surface)
                    }
                    DeviceStatusKind::Blocked => {
                        ("Blocked", theme.status_blocked, theme.bg_surface)
                    }
                    DeviceStatusKind::InSession => {
                        ("In Session", theme.accent_primary, theme.bg_surface)
                    }
                    DeviceStatusKind::Unverified => {
                        ("Unverified", theme.status_reconnecting, theme.bg_surface)
                    }
                };

                div()
                    .flex()
                    .items_center()
                    .h_full()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_1p5()
                            .px_2()
                            .py_0p5()
                            .rounded_full()
                            .border_1()
                            .border_color(rgb(status_color))
                            .bg(rgb(status_bg))
                            .child(div().size_2().rounded_full().bg(rgb(status_color)))
                            .child(
                                div()
                                    .text_xs()
                                    .font_medium()
                                    .text_color(rgb(status_color))
                                    .child(status_text),
                            ),
                    )
                    .into_any_element()
            }
            1 => div()
                .flex()
                .flex_col()
                .justify_center()
                .h_full()
                .child(
                    div()
                        .text_sm()
                        .font_medium()
                        .text_color(rgb(theme.text_primary))
                        .child(item.display_label().to_string()),
                )
                .when(!item.display_name.is_empty(), |d| {
                    d.child(
                        div()
                            .text_xs()
                            .text_color(rgb(theme.text_muted))
                            .child(item.device_id.clone()),
                    )
                })
                .into_any_element(),
            2 => {
                let (icon_name, platform_label) = if item.is_android_tv() {
                    (IconName::Tv, "Android TV")
                } else {
                    (IconName::Monitor, "Windows")
                };

                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .h_full()
                    .child(
                        Icon::new(icon_name)
                            .size_4()
                            .text_color(rgb(theme.accent_primary)),
                    )
                    .child(
                        div()
                            .text_sm()
                            .text_color(rgb(theme.text_primary))
                            .child(platform_label),
                    )
                    .into_any_element()
            }
            3 => div()
                .flex()
                .flex_col()
                .justify_center()
                .h_full()
                .child(
                    div()
                        .text_sm()
                        .text_color(rgb(theme.text_primary))
                        .child(item.primary_address().to_string()),
                )
                .child(
                    div()
                        .text_xs()
                        .text_color(rgb(theme.text_muted))
                        .child(item.location_label().to_string()),
                )
                .into_any_element(),
            4 => div()
                .flex()
                .items_center()
                .h_full()
                .child(
                    div()
                        .text_sm()
                        .text_color(rgb(theme.text_muted))
                        .child(item.relative_last_seen()),
                )
                .into_any_element(),
            5 => {
                let app = self.app.clone();
                let dev_id = item.device_id.clone();
                let dev_name = item.display_name.clone();
                let dev_loc = item.location.clone();
                let configured_addr = item.configured_address.clone().unwrap_or_default();
                let is_tv_target = item.is_android_tv();
                let is_blocked = item.blocked || item.status == DeviceStatusKind::Blocked;
                let is_offline = !item.online || item.status == DeviceStatusKind::Offline;

                let app_remote = app.clone();
                let remote_item = item.clone();
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .h_full()
                    .child(
                        Button::new(format!("remote-btn-{}", item.device_id))
                            .label("Remote")
                            .on_click(move |_, _, cx| {
                                let item = remote_item.clone();
                                app_remote.update(cx, |this, cx| {
                                    this.launch_remote_for_item(&item, cx);
                                });
                            }),
                    )
                    .when(self.is_admin, |actions| {
                        if is_tv_target {
                            let app_edit = app.clone();
                            let app_remove = app.clone();
                            let id_edit = dev_id.clone();
                            let id_remove = dev_id.clone();
                            let name_edit = dev_name.clone();
                            let loc_edit = dev_loc.clone();
                            let addr_edit = configured_addr.clone();

                            actions
                                .child(
                                    Button::new(format!("edit-target-btn-{}", id_edit))
                                        .label("Edit")
                                        .on_click(move |_, _, cx| {
                                            app_edit.update(cx, |this, cx| {
                                                this.open_edit_target(
                                                    id_edit.clone(),
                                                    name_edit.clone(),
                                                    addr_edit.clone(),
                                                    loc_edit.clone(),
                                                    cx,
                                                );
                                            });
                                        }),
                                )
                                .child(
                                    Button::new(format!("remove-target-btn-{}", id_remove))
                                        .label("Remove")
                                        .on_click(move |_, _, cx| {
                                            app_remove.update(cx, |this, cx| {
                                                this.submit_remove_target(id_remove.clone(), cx);
                                            });
                                        }),
                                )
                        } else {
                            let app_edit = app.clone();
                            let id_edit = dev_id.clone();
                            let name_edit = dev_name.clone();
                            let loc_edit = dev_loc.clone();

                            let mut act = actions.child(
                                Button::new(format!("edit-device-btn-{}", id_edit))
                                    .label("Edit")
                                    .on_click(move |_, _, cx| {
                                        app_edit.update(cx, |this, cx| {
                                            this.open_edit_device(
                                                id_edit.clone(),
                                                name_edit.clone(),
                                                loc_edit.clone(),
                                                cx,
                                            );
                                        });
                                    }),
                            );

                            if is_blocked {
                                let app_unblock = app.clone();
                                let id_unblock = dev_id.clone();
                                act = act.child(
                                    Button::new(format!("unblock-device-btn-{}", id_unblock))
                                        .label("Unblock")
                                        .on_click(move |_, _, cx| {
                                            app_unblock.update(cx, |this, cx| {
                                                this.submit_unblock_device(id_unblock.clone(), cx);
                                            });
                                        }),
                                );
                            } else {
                                let app_block = app.clone();
                                let id_block = dev_id.clone();
                                act = act.child(
                                    Button::new(format!("block-device-btn-{}", id_block))
                                        .label("Block")
                                        .on_click(move |_, _, cx| {
                                            app_block.update(cx, |this, cx| {
                                                this.submit_block_device(id_block.clone(), cx);
                                            });
                                        }),
                                );
                                if is_offline {
                                    let app_clean = app.clone();
                                    let id_clean = dev_id.clone();
                                    act = act.child(
                                        Button::new(format!("clean-device-btn-{}", id_clean))
                                            .label("Clean")
                                            .on_click(move |_, _, cx| {
                                                app_clean.update(cx, |this, cx| {
                                                    this.submit_clean_offline_device(
                                                        id_clean.clone(),
                                                        cx,
                                                    );
                                                });
                                            }),
                                    );
                                }
                            }

                            let app_replace = app.clone();
                            let id_replace = dev_id.clone();
                            act = act.child(
                                Button::new(format!("replace-device-btn-{}", id_replace))
                                    .label("Replace")
                                    .on_click(move |_, _, cx| {
                                        app_replace.update(cx, |this, cx| {
                                            this.open_replace_device(
                                                id_replace.clone(),
                                                String::new(),
                                                cx,
                                            );
                                        });
                                    }),
                            );

                            act
                        }
                    })
                    .into_any_element()
            }
            _ => div().into_any_element(),
        }
    }
}

impl ControllerApp {
    pub(in crate::gui) fn ensure_fleet_table(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.fleet_table.is_none() {
            let delegate = FleetTableDelegate {
                items: Vec::new(),
                theme: self.theme,
                is_admin: false,
                empty_state: FleetEmptyState::None,
                app: cx.entity().clone(),
            };
            let table = cx.new(|cx| TableState::new(delegate, window, cx));
            cx.subscribe(
                &table,
                |this: &mut ControllerApp, _table, event: &TableEvent, cx| match event {
                    TableEvent::SelectRow(row_ix) => {
                        if let ScreenState::Connected { devices, .. } = &this.state {
                            let filtered = this.fleet_state.filter_and_sort(devices);
                            if let Some(item) = filtered.get(*row_ix) {
                                this.fleet_state.select_device(Some(item.device_id.clone()));
                                cx.notify();
                            }
                        }
                    }
                    TableEvent::DoubleClickedRow(row_ix) => {
                        if let ScreenState::Connected { devices, .. } = &this.state {
                            let filtered = this.fleet_state.filter_and_sort(devices);
                            if let Some(item) = filtered.get(*row_ix) {
                                this.launch_remote_for_item(item, cx);
                            }
                        }
                    }
                    _ => {}
                },
            )
            .detach();
            self.fleet_table = Some(table);
        }
    }

    pub(in crate::gui) fn render_fleet(&self, cx: &mut Context<Self>) -> gpui::Div {
        let (devices, is_admin) = match &self.state {
            ScreenState::Connected { devices, role, .. } => (devices.as_slice(), role == "admin"),
            _ => (&[][..], false),
        };

        let total_devices = devices.len();
        let filtered_items = self.fleet_state.filter_and_sort(devices);
        let empty_state = self
            .fleet_state
            .empty_state(total_devices, filtered_items.len());
        let theme = self.theme;

        if let Some(table) = &self.fleet_table {
            table.update(cx, |table, cx| {
                let delegate = table.delegate_mut();
                delegate.items = filtered_items.clone();
                delegate.theme = theme;
                delegate.is_admin = is_admin;
                delegate.empty_state = empty_state;
                table.refresh(cx);
            });
        }

        let is_search_active = self.active_field == ActiveField::FleetSearch;
        let search_query = &self.fleet_state.search_query;
        let active_chip = self.fleet_state.filter;

        let mut fleet_view = div().flex().flex_col().gap_4().flex_1();

        // 1. Title bar
        let count_text = if filtered_items.len() == total_devices {
            format!("{total_devices} endpoints")
        } else {
            format!("{} of {total_devices} endpoints", filtered_items.len())
        };

        let mut title_bar = div().flex().justify_between().items_center().child(
            div()
                .flex()
                .items_center()
                .gap_3()
                .child(
                    div()
                        .text_xl()
                        .font_semibold()
                        .text_color(rgb(theme.text_primary))
                        .child("Fleet Inventory"),
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

        if is_admin {
            title_bar = title_bar.child(
                div()
                    .flex()
                    .gap_2()
                    .child(
                        Button::new("open-replace-device-btn")
                            .label("Replace Device")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.open_replace_device(String::new(), String::new(), cx);
                            })),
                    )
                    .child(
                        Button::new("open-prepare-artifact-btn")
                            .label("+ Installation Package")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.open_prepare_installation_artifact(cx);
                            })),
                    )
                    .child(
                        Button::new("add-target-btn")
                            .label("+ Add Target")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.open_add_target(cx);
                            })),
                    ),
            );
        }
        fleet_view = fleet_view.child(title_bar);

        // 2. Search & Filter Bar
        let search_box = div()
            .flex()
            .items_center()
            .gap_2()
            .px_3()
            .py_1p5()
            .w(px(360.))
            .bg(rgb(theme.bg_surface))
            .border_1()
            .border_color(rgb(if is_search_active {
                theme.border_focus
            } else {
                theme.border_subtle
            }))
            .rounded_md()
            .cursor_text()
            .id("fleet-search-input")
            .on_click(cx.listener(|this, _, window, cx| {
                this.active_field = ActiveField::FleetSearch;
                window.focus(&this.focus_handle, cx);
                cx.notify();
            }))
            .child(
                Icon::new(IconName::Search)
                    .size_4()
                    .text_color(rgb(theme.text_muted)),
            )
            .child(
                div()
                    .flex_1()
                    .text_sm()
                    .text_color(if search_query.is_empty() {
                        rgb(theme.text_muted)
                    } else {
                        rgb(theme.text_primary)
                    })
                    .child(if search_query.is_empty() {
                        "Search by name, ID, IP, location...".to_string()
                    } else {
                        search_query.clone()
                    }),
            )
            .when(!search_query.is_empty(), |box_el| {
                box_el.child(
                    div()
                        .cursor_pointer()
                        .id("clear-search-btn")
                        .p_1()
                        .rounded_md()
                        .hover(|s| s.bg(rgb(theme.bg_surface_hover)))
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.fleet_state.search_query.clear();
                            cx.notify();
                        }))
                        .child(
                            Icon::new(IconName::SearchX)
                                .size_4()
                                .text_color(rgb(theme.text_muted)),
                        ),
                )
            });

        let mut filter_row = div().flex().items_center().gap_2().flex_wrap();
        for chip in FleetFilterChip::ALL {
            let is_selected = active_chip == chip;
            let label = chip.label();
            filter_row = filter_row.child(
                div()
                    .id(format!(
                        "filter-chip-{}",
                        label.to_lowercase().replace(' ', "-")
                    ))
                    .px_3()
                    .py_1()
                    .rounded_full()
                    .text_xs()
                    .font_medium()
                    .cursor_pointer()
                    .border_1()
                    .border_color(rgb(if is_selected {
                        theme.accent_primary
                    } else {
                        theme.border_subtle
                    }))
                    .bg(rgb(if is_selected {
                        theme.bg_surface_hover
                    } else {
                        theme.bg_surface
                    }))
                    .text_color(rgb(if is_selected {
                        theme.accent_primary
                    } else {
                        theme.text_muted
                    }))
                    .hover(|s| {
                        s.bg(rgb(theme.bg_surface_hover))
                            .text_color(rgb(theme.text_primary))
                    })
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.fleet_state.set_filter(chip);
                        cx.notify();
                    }))
                    .child(label),
            );
        }

        if !self.fleet_state.search_query.is_empty()
            || self.fleet_state.filter != FleetFilterChip::All
        {
            filter_row = filter_row.child(
                Button::new("reset-filter-btn")
                    .label("Reset Filter")
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.fleet_state.reset_filters();
                        cx.notify();
                    })),
            );
        }

        let controls_bar = div()
            .flex()
            .flex_wrap()
            .gap_4()
            .items_center()
            .justify_between()
            .child(search_box)
            .child(filter_row);

        fleet_view = fleet_view.child(controls_bar);

        // 3. DataTable & Inspector Sheet
        if let Some(table) = &self.fleet_table {
            let mut main_area = div().flex().flex_1().gap_4().w_full().min_h(px(400.));

            let table_container = div()
                .flex_1()
                .w_full()
                .rounded_lg()
                .border_1()
                .border_color(rgb(theme.border_subtle))
                .bg(rgb(theme.bg_surface))
                .overflow_hidden()
                .child(DataTable::new(table).bordered(false));

            main_area = main_area.child(table_container);

            if let Some(selected) = self.fleet_state.selected_device(devices) {
                let telemetry = selected.telemetry();
                let inspector = self.render_inspector_sheet(&selected, &telemetry, &theme, cx);
                main_area = main_area.child(inspector);
            }

            fleet_view = fleet_view.child(main_area);
        }

        fleet_view
    }

    fn render_inspector_sheet(
        &self,
        item: &FleetDeviceItem,
        telemetry: &crate::fleet::DeviceTelemetry,
        theme: &Theme,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let (status_text, status_color) = match item.status {
            DeviceStatusKind::Online => ("Online", theme.status_online),
            DeviceStatusKind::Offline => ("Offline", theme.status_offline),
            DeviceStatusKind::Blocked => ("Blocked", theme.status_blocked),
            DeviceStatusKind::InSession => ("In Session", theme.accent_primary),
            DeviceStatusKind::Unverified => ("Unverified", theme.status_reconnecting),
        };

        let uptime_str = format_uptime(telemetry.uptime_seconds);
        let remote_ready = telemetry.remote_ready;

        div()
            .w(px(340.0))
            .bg(rgb(theme.bg_surface))
            .border_1()
            .border_color(rgb(theme.border_subtle))
            .rounded_lg()
            .p_4()
            .flex()
            .flex_col()
            .gap_4()
            .id("inspector-sheet")
            .child(
                div()
                    .flex()
                    .items_start()
                    .justify_between()
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(
                                div()
                                    .text_base()
                                    .font_semibold()
                                    .text_color(rgb(theme.text_primary))
                                    .child(item.display_label().to_string()),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(rgb(theme.text_muted))
                                    .child(item.device_id.clone()),
                            ),
                    )
                    .child(
                        div()
                            .id("close-inspector-btn")
                            .cursor_pointer()
                            .p_1()
                            .rounded_md()
                            .text_color(rgb(theme.text_muted))
                            .hover(|s| s.text_color(rgb(theme.text_primary)))
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.fleet_state.close_inspector();
                                cx.notify();
                            }))
                            .child(Icon::new(IconName::X)),
                    ),
            )
            .child(
                div()
                    .p_3()
                    .bg(rgb(theme.bg_app))
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(theme.border_subtle))
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(rgb(theme.text_muted))
                                    .child("Status"),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_1p5()
                                    .child(div().size_2().rounded_full().bg(rgb(status_color)))
                                    .child(
                                        div()
                                            .text_xs()
                                            .font_medium()
                                            .text_color(rgb(status_color))
                                            .child(status_text),
                                    ),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(rgb(theme.text_muted))
                                    .child("Platform"),
                            )
                            .child(div().text_xs().text_color(rgb(theme.text_primary)).child(
                                if item.is_android_tv() {
                                    "Android TV"
                                } else {
                                    "Windows PC"
                                },
                            )),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(rgb(theme.text_muted))
                                    .child("Address"),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(rgb(theme.text_primary))
                                    .child(item.primary_address().to_string()),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(rgb(theme.text_muted))
                                    .child("Location"),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(rgb(theme.text_primary))
                                    .child(item.location_label().to_string()),
                            ),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(
                        div()
                            .text_xs()
                            .font_semibold()
                            .text_color(rgb(theme.text_muted))
                            .child("LIVE TELEMETRY"),
                    )
                    .child(render_telemetry_bar(
                        "CPU Utilization",
                        telemetry.cpu_usage_percent,
                        theme,
                    ))
                    .child(render_telemetry_bar(
                        "Memory Usage",
                        telemetry.memory_usage_percent,
                        theme,
                    ))
                    .child(render_telemetry_bar(
                        "Disk Usage",
                        telemetry.disk_usage_percent,
                        theme,
                    )),
            )
            .child(
                div()
                    .flex()
                    .gap_2()
                    .child(
                        div()
                            .flex_1()
                            .p_2()
                            .bg(rgb(theme.bg_app))
                            .rounded_md()
                            .border_1()
                            .border_color(rgb(theme.border_subtle))
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(rgb(theme.text_muted))
                                    .child("Uptime"),
                            )
                            .child(
                                div()
                                    .text_sm()
                                    .font_semibold()
                                    .text_color(rgb(theme.text_primary))
                                    .child(uptime_str),
                            ),
                    )
                    .child(
                        div()
                            .flex_1()
                            .p_2()
                            .bg(rgb(theme.bg_app))
                            .rounded_md()
                            .border_1()
                            .border_color(rgb(theme.border_subtle))
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(rgb(theme.text_muted))
                                    .child("Processes"),
                            )
                            .child(
                                div()
                                    .text_sm()
                                    .font_semibold()
                                    .text_color(rgb(theme.text_primary))
                                    .child(telemetry.process_count.to_string()),
                            ),
                    ),
            )
            .child(
                div()
                    .pt_2()
                    .border_t_1()
                    .border_color(rgb(theme.border_subtle))
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(rgb(theme.text_muted))
                                    .child("Remote Readiness"),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .font_medium()
                                    .text_color(rgb(if remote_ready {
                                        theme.status_online
                                    } else {
                                        theme.status_blocked
                                    }))
                                    .child(if remote_ready {
                                        "Ready"
                                    } else if telemetry.is_android_tv {
                                        "TV (Restricted)"
                                    } else {
                                        "Unavailable"
                                    }),
                            ),
                    )
                    .child({
                        let inspector_item = item.clone();
                        Button::new("inspector-start-remote-btn")
                            .primary()
                            .label("Start Remote Session")
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.launch_remote_for_item(&inspector_item, cx);
                            }))
                    }),
            )
    }
}

fn format_uptime(uptime_seconds: u64) -> String {
    let days = uptime_seconds / 86400;
    let hours = (uptime_seconds % 86400) / 3600;
    let mins = (uptime_seconds % 3600) / 60;
    if days > 0 {
        format!("{days}d {hours}h {mins}m")
    } else if hours > 0 {
        format!("{hours}h {mins}m")
    } else {
        format!("{mins}m")
    }
}

fn render_telemetry_bar(label: &str, percent: f32, theme: &Theme) -> impl IntoElement {
    let bar_color = if percent > 85.0 {
        theme.status_blocked
    } else if percent > 70.0 {
        theme.status_reconnecting
    } else {
        theme.status_online
    };

    div()
        .flex()
        .flex_col()
        .gap_1()
        .child(
            div()
                .flex()
                .justify_between()
                .items_center()
                .text_xs()
                .child(
                    div()
                        .text_color(rgb(theme.text_muted))
                        .child(label.to_string()),
                )
                .child(
                    div()
                        .font_medium()
                        .text_color(rgb(theme.text_primary))
                        .child(format!("{percent:.1}%")),
                ),
        )
        .child(
            div()
                .w_full()
                .h(px(6.0))
                .bg(rgb(theme.bg_surface_hover))
                .rounded_full()
                .overflow_hidden()
                .child(
                    div()
                        .h_full()
                        .w(gpui::relative(percent.clamp(0.0, 100.0) / 100.0))
                        .bg(rgb(bar_color))
                        .rounded_full(),
                ),
        )
}
