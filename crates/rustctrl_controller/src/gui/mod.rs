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
use gpui::{App, WindowOptions, rgb};
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
                kit.colors.button = rgb(theme.bg_surface_hover).into();
                kit.colors.button_hover = rgb(theme.border_subtle).into();
                kit.colors.button_active = rgb(theme.border_focus).into();
                kit.colors.button_foreground = rgb(theme.text_primary).into();
            });
            cx.open_window(WindowOptions::default(), |window, cx| {
                let view = cx.new(|cx| ControllerApp::new(theme, config, config_path, handle, cx));
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
