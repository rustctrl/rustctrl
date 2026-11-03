pub mod helpers;
pub mod overlays;
pub mod render;
pub mod rpc;
pub mod state;
pub mod views;

#[cfg(test)]
mod tests;

pub use gpui::prelude::*;
#[cfg(test)]
pub use helpers::*;
pub use state::*;

use anyhow::Result;
use gpui::{App, WindowOptions};
use rustctrl_core::ControllerConfig;

pub fn open(config: ControllerConfig, config_path: std::path::PathBuf) -> Result<()> {
    #[cfg(target_os = "linux")]
    anyhow::ensure!(
        ["DISPLAY", "WAYLAND_DISPLAY"]
            .iter()
            .any(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty())),
        "A graphical session is required. Run the Controller on an X11 or Wayland desktop; use the check command for headless diagnostics."
    );
    let preferences_path = crate::theme::preferences_path()?;
    let preferences = crate::theme::Preferences::load(&preferences_path)?;
    if !preferences_path.exists() {
        if let Some(parent) = preferences_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        preferences.save(&preferences_path)?;
    }
    let theme = preferences.theme();
    let runtime = tokio::runtime::Runtime::new()?;
    let handle = runtime.handle().clone();

    gpui::application()
        .with_assets(gpui::assets::AllAssets)
        .run(move |cx: &mut App| {
            gpui::init(cx);
            gpui::component::theme::Theme::change(
                gpui::component::theme::ThemeMode::Dark,
                None,
                cx,
            );
            gpui::component::theme::Theme::update(cx, |kit| {
                helpers::configure_tokyo_night_theme(theme, kit);
            });
            gpui::open_window(WindowOptions::default(), cx, |window, cx| {
                let window_handle = window.window_handle();
                let view = cx.new(|cx| {
                    ControllerApp::new(theme, config, config_path, handle, Some(window_handle), cx)
                });
                let focus = view.read(cx).focus_handle.clone();
                window.focus(&focus, cx);
                view
            })
            .expect("open RustCtrl window");
            cx.activate(true);
        });
    runtime.shutdown_background();
    Ok(())
}
