use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub fn preferences_path() -> Result<std::path::PathBuf> {
    #[cfg(target_os = "windows")]
    let base = std::env::var_os("APPDATA").map(std::path::PathBuf::from);
    #[cfg(not(target_os = "windows"))]
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|value| std::path::Path::new(value).is_absolute())
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".config"))
        });
    Ok(base
        .context("cannot locate user configuration directory")?
        .join("rustctrl")
        .join("preferences.toml"))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Preferences {
    pub theme: String,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            theme: "tokyo-night".into(),
        }
    }
}

impl Preferences {
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(body) => toml::from_str(&body).context("parse preferences"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let body = toml::to_string_pretty(self).context("serialize preferences")?;
        std::fs::write(path, body).with_context(|| format!("write {}", path.display()))
    }

    pub fn theme(&self) -> Theme {
        match self.theme.as_str() {
            "tokyo-storm" => Theme::tokyo_storm(),
            _ => Theme::tokyo_night(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    pub bg_app: u32,
    pub bg_surface: u32,
    pub bg_surface_hover: u32,
    pub border_subtle: u32,
    pub border_focus: u32,
    pub text_primary: u32,
    pub text_muted: u32,
    pub accent_primary: u32,
    pub status_online: u32,
    pub status_offline: u32,
    pub status_blocked: u32,
    pub status_reconnecting: u32,
}

impl Theme {
    pub const fn tokyo_storm() -> Self {
        let mut theme = Self::tokyo_night();
        theme.bg_app = 0x24283b;
        theme.bg_surface = 0x292e42;
        theme.bg_surface_hover = 0x414868;
        theme
    }

    pub const fn tokyo_night() -> Self {
        Self {
            bg_app: 0x1a1b26,
            bg_surface: 0x24283b,
            bg_surface_hover: 0x292e42,
            border_subtle: 0x3b4261,
            border_focus: 0x7dcfff,
            text_primary: 0xc0caf5,
            text_muted: 0x9aa5ce,
            accent_primary: 0x7dcfff,
            status_online: 0x9ece6a,
            status_offline: 0x565f89,
            status_blocked: 0xf7768e,
            status_reconnecting: 0xe0af68,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preferences_file_survives_reload() {
        let directory =
            std::env::temp_dir().join(format!("rustctrl-preferences-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("preferences.toml");
        let preferences = Preferences {
            theme: "future-theme".into(),
        };
        preferences.save(&path).unwrap();
        assert_eq!(Preferences::load(&path).unwrap(), preferences);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn preferences_roundtrip_and_unknown_theme_fallback() {
        let preferences: Preferences = toml::from_str("theme = 'unknown'\n").unwrap();
        assert_eq!(preferences.theme(), Theme::tokyo_night());
        let encoded = toml::to_string_pretty(&preferences).unwrap();
        assert_eq!(encoded, "theme = \"unknown\"\n");
        assert_eq!(
            toml::from_str::<Preferences>(&encoded).unwrap(),
            preferences
        );
        assert_eq!(
            Preferences {
                theme: "tokyo-storm".into()
            }
            .theme()
            .bg_app,
            0x24283b
        );
        let theme = Theme::tokyo_night();
        assert_eq!(
            [
                theme.bg_app,
                theme.bg_surface,
                theme.bg_surface_hover,
                theme.border_subtle,
                theme.border_focus,
                theme.text_primary,
                theme.text_muted,
                theme.accent_primary,
                theme.status_online,
                theme.status_offline,
                theme.status_blocked,
                theme.status_reconnecting
            ],
            [
                0x1a1b26, 0x24283b, 0x292e42, 0x3b4261, 0x7dcfff, 0xc0caf5, 0x9aa5ce, 0x7dcfff,
                0x9ece6a, 0x565f89, 0xf7768e, 0xe0af68
            ]
        );
        assert_eq!(Theme::tokyo_night().bg_app, 0x1a1b26);
        assert_eq!(Theme::tokyo_night().status_online, 0x9ece6a);
    }
}
