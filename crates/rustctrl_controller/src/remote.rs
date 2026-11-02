//! Remote Session viewer state and control models.
//!
//! Provides the headless state machine for interactive remote desktop sessions,
//! multi-monitor switching, input mode toggling, stream quality metrics,
//! and keyboard grab management.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InputMode {
    #[default]
    Interactive,
    ViewOnly,
}

impl InputMode {
    pub fn toggle(self) -> Self {
        match self {
            Self::Interactive => Self::ViewOnly,
            Self::ViewOnly => Self::Interactive,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Interactive => "Interactive Control",
            Self::ViewOnly => "View-Only Mode",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MonitorTarget {
    #[default]
    Display1,
    Display2,
    All,
}

impl MonitorTarget {
    pub const ALL: [Self; 3] = [Self::Display1, Self::Display2, Self::All];

    pub fn label(self) -> &'static str {
        match self {
            Self::Display1 => "Display 1",
            Self::Display2 => "Display 2",
            Self::All => "All Displays",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamMetrics {
    pub latency_ms: u32,
    pub fps: u32,
    pub resolution: String,
    pub quality_label: String,
}

impl Default for StreamMetrics {
    fn default() -> Self {
        Self {
            latency_ms: 12,
            fps: 60,
            resolution: "1920x1080".to_string(),
            quality_label: "Optimal".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSession {
    pub device_id: String,
    pub device_name: String,
    pub monitor: MonitorTarget,
    pub input_mode: InputMode,
    pub fullscreen: bool,
    pub keyboard_grabbed: bool,
    pub metrics: StreamMetrics,
}

#[derive(Debug, Clone, Default)]
pub struct RemoteSessionState {
    active_session: Option<RemoteSession>,
    pub toolbar_visible: bool,
}

impl RemoteSessionState {
    pub fn is_active(&self) -> bool {
        self.active_session.is_some()
    }

    pub fn active_session(&self) -> Option<&RemoteSession> {
        self.active_session.as_ref()
    }

    pub fn start_session(&mut self, device_id: impl Into<String>, device_name: impl Into<String>) {
        self.active_session = Some(RemoteSession {
            device_id: device_id.into(),
            device_name: device_name.into(),
            monitor: MonitorTarget::default(),
            input_mode: InputMode::default(),
            fullscreen: false,
            keyboard_grabbed: true,
            metrics: StreamMetrics::default(),
        });
        self.toolbar_visible = true;
    }

    pub fn disconnect(&mut self) {
        self.active_session = None;
        self.toolbar_visible = false;
    }

    pub fn toggle_input_mode(&mut self) {
        if let Some(session) = &mut self.active_session {
            session.input_mode = session.input_mode.toggle();
        }
    }

    pub fn set_monitor(&mut self, monitor: MonitorTarget) {
        if let Some(session) = &mut self.active_session {
            session.monitor = monitor;
        }
    }

    pub fn toggle_fullscreen(&mut self) {
        if let Some(session) = &mut self.active_session {
            session.fullscreen = !session.fullscreen;
        }
    }

    pub fn ungrab_keyboard(&mut self) {
        if let Some(session) = &mut self.active_session {
            session.keyboard_grabbed = false;
        }
    }

    pub fn toggle_keyboard_grab(&mut self) {
        if let Some(session) = &mut self.active_session {
            session.keyboard_grabbed = !session.keyboard_grabbed;
        }
    }

    pub fn set_toolbar_visible(&mut self, visible: bool) {
        self.toolbar_visible = visible;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_start_session_initializes_defaults() {
        let mut state = RemoteSessionState::default();
        assert!(!state.is_active());
        assert!(state.active_session().is_none());

        state.start_session("win-dev-01", "Workstation Alpha");
        assert!(state.is_active());

        let session = state.active_session().expect("session should be active");
        assert_eq!(session.device_id, "win-dev-01");
        assert_eq!(session.device_name, "Workstation Alpha");
        assert_eq!(session.monitor, MonitorTarget::Display1);
        assert_eq!(session.input_mode, InputMode::Interactive);
        assert!(!session.fullscreen);
        assert!(session.keyboard_grabbed);
        assert_eq!(session.metrics.fps, 60);
    }

    #[test]
    fn test_toggle_input_mode() {
        let mut state = RemoteSessionState::default();
        state.start_session("win-dev-01", "Workstation Alpha");

        state.toggle_input_mode();
        assert_eq!(
            state.active_session().unwrap().input_mode,
            InputMode::ViewOnly
        );

        state.toggle_input_mode();
        assert_eq!(
            state.active_session().unwrap().input_mode,
            InputMode::Interactive
        );
    }

    #[test]
    fn test_monitor_switching() {
        let mut state = RemoteSessionState::default();
        state.start_session("win-dev-01", "Workstation Alpha");

        state.set_monitor(MonitorTarget::Display2);
        assert_eq!(
            state.active_session().unwrap().monitor,
            MonitorTarget::Display2
        );

        state.set_monitor(MonitorTarget::All);
        assert_eq!(state.active_session().unwrap().monitor, MonitorTarget::All);
    }

    #[test]
    fn test_fullscreen_and_ungrab_keyboard() {
        let mut state = RemoteSessionState::default();
        state.start_session("win-dev-01", "Workstation Alpha");

        assert!(!state.active_session().unwrap().fullscreen);
        state.toggle_fullscreen();
        assert!(state.active_session().unwrap().fullscreen);
        state.toggle_fullscreen();
        assert!(!state.active_session().unwrap().fullscreen);

        assert!(state.active_session().unwrap().keyboard_grabbed);
        state.ungrab_keyboard();
        assert!(!state.active_session().unwrap().keyboard_grabbed);
    }

    #[test]
    fn test_disconnect_clears_session() {
        let mut state = RemoteSessionState::default();
        state.start_session("win-dev-01", "Workstation Alpha");
        assert!(state.is_active());

        state.disconnect();
        assert!(!state.is_active());
        assert!(state.active_session().is_none());
    }

    #[test]
    fn test_proximity_toolbar_visibility() {
        let mut state = RemoteSessionState::default();
        assert!(!state.toolbar_visible);
        state.set_toolbar_visible(true);
        assert!(state.toolbar_visible);
        state.set_toolbar_visible(false);
        assert!(!state.toolbar_visible);
    }

    #[test]
    fn test_tab_switching_preserves_remote_session_state() {
        let mut nav = crate::navigation::Navigation::default();
        let mut remote_state = RemoteSessionState::default();

        // Start session
        remote_state.start_session("win-dev-01", "Workstation Alpha");
        nav.select(crate::navigation::Route::Remote, "operator");
        nav.collapsed = true;

        assert_eq!(nav.active("operator"), crate::navigation::Route::Remote);
        assert!(nav.collapsed);
        assert!(remote_state.is_active());

        // Switch tab to Fleet Inventory
        nav.select(crate::navigation::Route::Fleet, "operator");
        assert_eq!(nav.active("operator"), crate::navigation::Route::Fleet);
        // Remote session must be preserved across tab switches
        assert!(remote_state.is_active());
        assert_eq!(
            remote_state.active_session().unwrap().device_id,
            "win-dev-01"
        );

        // Switch back to Remote
        nav.select(crate::navigation::Route::Remote, "operator");
        assert_eq!(nav.active("operator"), crate::navigation::Route::Remote);
        assert!(remote_state.is_active());
        assert_eq!(
            remote_state.active_session().unwrap().device_name,
            "Workstation Alpha"
        );
    }
}
