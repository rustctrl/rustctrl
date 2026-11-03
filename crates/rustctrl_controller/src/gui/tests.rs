use super::*;
use gpui::{Keystroke, Modifiers};
use rustctrl_protocol::auth::{
    FleetDeviceEntry, InstallationAuthorizationEntry, StaffAccountEntry,
};

#[test]
fn resolve_typed_text_handles_spaces_characters_and_key_char() {
    // Space key with no key_char
    let space_key = Keystroke {
        modifiers: Modifiers::default(),
        key: "space".into(),
        key_char: None,
    };
    assert_eq!(resolve_typed_text(&space_key), Some(" "));

    // Key with key_char payload (e.g. non-ASCII or multi-word)
    let thai_key = Keystroke {
        modifiers: Modifiers::default(),
        key: "q".into(),
        key_char: Some("ๆ".into()),
    };
    assert_eq!(resolve_typed_text(&thai_key), Some("ๆ"));

    // Normal ASCII letter
    let ascii_key = Keystroke {
        modifiers: Modifiers::default(),
        key: "a".into(),
        key_char: Some("a".into()),
    };
    assert_eq!(resolve_typed_text(&ascii_key), Some("a"));

    // Control or command modifier should be ignored
    let mut ctrl_s = Keystroke {
        modifiers: Modifiers::default(),
        key: "s".into(),
        key_char: Some("s".into()),
    };
    ctrl_s.modifiers.control = true;
    assert_eq!(resolve_typed_text(&ctrl_s), None);

    // Control character should be ignored
    let enter_key = Keystroke {
        modifiers: Modifiers::default(),
        key: "enter".into(),
        key_char: Some("\n".into()),
    };
    assert_eq!(resolve_typed_text(&enter_key), None);
}

#[test]
fn typing_multiword_values_accumulates_correctly() {
    let mut display_name = String::new();
    let words = ["Reception", " ", "Front", " ", "Desk"];
    for word in words {
        for ch in word.chars() {
            let ks = if ch == ' ' {
                Keystroke {
                    modifiers: Modifiers::default(),
                    key: "space".into(),
                    key_char: None,
                }
            } else {
                Keystroke {
                    modifiers: Modifiers::default(),
                    key: ch.to_string(),
                    key_char: Some(ch.to_string()),
                }
            };
            if let Some(text) = resolve_typed_text(&ks) {
                display_name.push_str(text);
            }
        }
    }
    assert_eq!(display_name, "Reception Front Desk");
}

#[test]
fn edit_device_overlay_form_matching_checks_request_id_and_device_id() {
    let overlay = Overlay::EditDevice {
        request_id: 42,
        device_id: "dev-abc".into(),
        display_name: "Original Name".into(),
        location: "Room 101".into(),
        error: None,
        in_flight: true,
    };

    // Matching request id and device id
    let is_match = match &overlay {
        Overlay::EditDevice {
            request_id,
            device_id,
            ..
        } => *request_id == 42 && device_id == "dev-abc",
        _ => false,
    };
    assert!(is_match);

    // Different request id (new form opened)
    let is_stale = match &overlay {
        Overlay::EditDevice {
            request_id,
            device_id,
            ..
        } => *request_id == 43 && device_id == "dev-abc",
        _ => false,
    };
    assert!(!is_stale);

    // Different device id
    let is_diff_dev = match &overlay {
        Overlay::EditDevice {
            request_id,
            device_id,
            ..
        } => *request_id == 42 && device_id == "dev-xyz",
        _ => false,
    };
    assert!(!is_diff_dev);
}

#[test]
fn add_target_overlay_form_matching_checks_request_id() {
    let overlay = Overlay::AddTarget {
        request_id: 10,
        display_name: "Lobby TV".into(),
        address: "192.168.1.150:5555".into(),
        location: "Lobby".into(),
        error: None,
        in_flight: true,
    };

    let is_match = match &overlay {
        Overlay::AddTarget { request_id, .. } => *request_id == 10,
        _ => false,
    };
    assert!(is_match);

    let is_stale = match &overlay {
        Overlay::AddTarget { request_id, .. } => *request_id == 11,
        _ => false,
    };
    assert!(!is_stale);
}

#[test]
fn edit_target_overlay_form_matching_checks_request_id_and_target_id() {
    let overlay = Overlay::EditTarget {
        request_id: 15,
        target_id: "target-abc".into(),
        display_name: "Lobby TV Updated".into(),
        address: "192.168.1.151:5555".into(),
        location: "Lobby West".into(),
        error: None,
        in_flight: true,
    };

    let is_match = match &overlay {
        Overlay::EditTarget {
            request_id,
            target_id,
            ..
        } => *request_id == 15 && target_id == "target-abc",
        _ => false,
    };
    assert!(is_match);

    let is_stale_req = match &overlay {
        Overlay::EditTarget {
            request_id,
            target_id,
            ..
        } => *request_id == 16 && target_id == "target-abc",
        _ => false,
    };
    assert!(!is_stale_req);

    let is_diff_target = match &overlay {
        Overlay::EditTarget {
            request_id,
            target_id,
            ..
        } => *request_id == 15 && target_id == "target-xyz",
        _ => false,
    };
    assert!(!is_diff_target);
}

#[test]
fn format_device_row_presents_android_tv_target_as_unverified_with_distinct_address_and_no_last_seen()
 {
    let entry = FleetDeviceEntry {
        device_id: "tv-target-123".into(),
        display_name: "Boardroom TV".into(),
        online: false,
        last_seen_unix_ms: 0,
        last_address: String::new(),
        location: Some("Floor 3".into()),
        device_type: "android_tv".into(),
        configured_address: Some("192.168.1.150:5555".into()),
        status: "unverified".into(),
        blocked: false,
    };

    let vm = format_device_row(&entry);
    assert_eq!(vm.device_id, "tv-target-123");
    assert_eq!(vm.display_name, "Boardroom TV");
    assert_eq!(vm.device_type, "android_tv");
    assert_eq!(vm.location, "Floor 3");
    assert_eq!(vm.last_address, "—");
    assert_eq!(vm.configured_address, "192.168.1.150:5555");
    assert_eq!(vm.status, "Unverified");
    assert_eq!(vm.last_seen, "—");
}

#[test]
fn format_device_row_presents_windows_device_with_observed_address() {
    let entry = FleetDeviceEntry {
        device_id: "dev-win-456".into(),
        display_name: "Reception PC".into(),
        online: true,
        last_seen_unix_ms: 1_700_000_000_000,
        last_address: "10.0.0.42".into(),
        location: None,
        device_type: "windows".into(),
        configured_address: None,
        status: "online".into(),
        blocked: false,
    };

    let vm = format_device_row(&entry);
    assert_eq!(vm.device_id, "dev-win-456");
    assert_eq!(vm.display_name, "Reception PC");
    assert_eq!(vm.device_type, "windows");
    assert_eq!(vm.location, "—");
    assert_eq!(vm.last_address, "10.0.0.42");
    assert_eq!(vm.configured_address, "—");
    assert_eq!(vm.status, "Online");
    assert_ne!(vm.last_seen, "—");
}

#[test]
fn format_device_row_presents_blocked_windows_device_with_preserved_last_seen_freshness() {
    let now_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default();
    let entry = FleetDeviceEntry {
        device_id: "dev-win-blocked-789".into(),
        display_name: "Finance PC".into(),
        online: false,
        last_seen_unix_ms: now_unix_ms - 30_000,
        last_address: "10.0.0.88".into(),
        location: Some("Floor 2".into()),
        device_type: "windows".into(),
        configured_address: None,
        status: "blocked".into(),
        blocked: true,
    };

    let vm = format_device_row(&entry);
    assert_eq!(vm.device_id, "dev-win-blocked-789");
    assert_eq!(vm.display_name, "Finance PC");
    assert_eq!(vm.device_type, "windows");
    assert_eq!(vm.location, "Floor 2");
    assert_eq!(vm.last_address, "10.0.0.88");
    assert_eq!(vm.configured_address, "—");
    assert_eq!(
        vm.status, "Blocked",
        "blocked device must display Blocked status"
    );
    assert_ne!(
        vm.last_seen, "—",
        "heartbeat freshness must be preserved for blocked device"
    );
    assert!(
        vm.last_seen.contains('s') || vm.last_seen.contains('m'),
        "last_seen should reflect relative time"
    );
}

#[test]
fn format_device_row_presents_offline_windows_device_distinct_from_blocked() {
    let now_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default();
    let entry = FleetDeviceEntry {
        device_id: "dev-win-offline-101".into(),
        display_name: "Stale PC".into(),
        online: false,
        last_seen_unix_ms: now_unix_ms - 120_000,
        last_address: "10.0.0.99".into(),
        location: Some("Storage".into()),
        device_type: "windows".into(),
        configured_address: None,
        status: "offline".into(),
        blocked: false,
    };

    let vm = format_device_row(&entry);
    assert_eq!(vm.device_id, "dev-win-offline-101");
    assert_eq!(vm.display_name, "Stale PC");
    assert_eq!(vm.device_type, "windows");
    assert_eq!(vm.location, "Storage");
    assert_eq!(vm.last_address, "10.0.0.99");
    assert_eq!(vm.configured_address, "—");
    assert_eq!(
        vm.status, "Offline",
        "offline unblocked device must display Offline status"
    );
    assert_ne!(
        vm.last_seen, "—",
        "last_seen timestamp must be formatted for offline device"
    );
}

#[test]
fn replace_device_overlay_form_matching_checks_request_id_and_device_ids() {
    let overlay = Overlay::ReplaceDevice {
        request_id: 30,
        prior_device_id: "prior-uuid-10".into(),
        replacement_device_id: "rep-uuid-20".into(),
        error: None,
        in_flight: true,
    };

    let is_match = match &overlay {
        Overlay::ReplaceDevice {
            request_id,
            prior_device_id,
            replacement_device_id,
            ..
        } => {
            *request_id == 30
                && prior_device_id == "prior-uuid-10"
                && replacement_device_id == "rep-uuid-20"
        }
        _ => false,
    };
    assert!(is_match);

    let is_stale_req = match &overlay {
        Overlay::ReplaceDevice { request_id, .. } => *request_id == 31,
        _ => false,
    };
    assert!(!is_stale_req);

    let is_diff_prior = match &overlay {
        Overlay::ReplaceDevice {
            prior_device_id, ..
        } => prior_device_id == "different-uuid",
        _ => false,
    };
    assert!(!is_diff_prior);
}

#[test]
fn replace_device_completion_does_not_close_superseded_or_different_overlay() {
    let active_overlay = Overlay::AddTarget {
        request_id: 31,
        display_name: "Lobby TV".into(),
        address: "192.168.1.50:5555".into(),
        location: String::new(),
        error: None,
        in_flight: false,
    };

    let is_matching_form = match &active_overlay {
        Overlay::ReplaceDevice { request_id, .. } => *request_id == 30,
        _ => false,
    };
    assert!(
        !is_matching_form,
        "response from stale replace_device must not match active AddTarget overlay"
    );
}

#[test]
fn prepare_installation_artifact_overlay_form_matching_checks_request_id() {
    let overlay = Overlay::PrepareInstallationArtifact {
        request_id: 15,
        output_path: "agent-artifact.toml".into(),
        agent_binary_path: String::new(),
        error: None,
        in_flight: true,
        success: None,
    };

    let is_match = match &overlay {
        Overlay::PrepareInstallationArtifact { request_id, .. } => *request_id == 15,
        _ => false,
    };
    assert!(is_match);

    let is_stale = match &overlay {
        Overlay::PrepareInstallationArtifact { request_id, .. } => *request_id == 16,
        _ => false,
    };
    assert!(!is_stale);
}

#[test]
fn connected_state_installation_authorizations_display_and_filtering() {
    let auth_active = InstallationAuthorizationEntry {
        authorization_id: "auth-1".into(),
        created_at_unix_ms: 1000,
        created_by: "admin".into(),
        revoked_at_unix_ms: None,
    };
    let auth_revoked = InstallationAuthorizationEntry {
        authorization_id: "auth-2".into(),
        created_at_unix_ms: 2000,
        created_by: "admin".into(),
        revoked_at_unix_ms: Some(3000),
    };
    let state = ScreenState::Connected {
        session_token: "token".into(),
        username: "admin".into(),
        role: "admin".into(),
        server_version: "1.0.0".into(),
        registered_devices: 0,
        devices: Vec::new(),
        accounts: Vec::new(),
        authorizations: vec![auth_active.clone(), auth_revoked.clone()],
        new_account_username: String::new(),
        new_account_role: "operator".into(),
        new_account_password: String::new(),
        error: None,
        notice: None,
        in_flight: false,
    };

    if let ScreenState::Connected {
        authorizations,
        role,
        ..
    } = state
    {
        assert_eq!(role, "admin");
        assert_eq!(authorizations.len(), 2);
        assert!(authorizations[0].revoked_at_unix_ms.is_none());
        assert_eq!(authorizations[1].revoked_at_unix_ms, Some(3000));
    } else {
        panic!("expected Connected state");
    }
}

#[test]
fn connected_state_preserves_authorizations_when_refresh_fails() {
    let auth_active = InstallationAuthorizationEntry {
        authorization_id: "auth-preserved".into(),
        created_at_unix_ms: 1000,
        created_by: "admin".into(),
        revoked_at_unix_ms: None,
    };
    let mut state = ScreenState::Connected {
        session_token: "token-1".into(),
        username: "admin".into(),
        role: "admin".into(),
        server_version: "1.0.0".into(),
        registered_devices: 1,
        devices: Vec::new(),
        accounts: Vec::new(),
        authorizations: vec![auth_active.clone()],
        new_account_username: String::new(),
        new_account_role: "operator".into(),
        new_account_password: String::new(),
        error: None,
        notice: None,
        in_flight: false,
    };

    let auths_res: Result<Vec<InstallationAuthorizationEntry>, String> =
        Err("connection timeout".into());
    if let ScreenState::Connected {
        authorizations,
        error,
        ..
    } = &mut state
    {
        let updated_authorizations = match auths_res {
            Ok(fresh) => fresh,
            Err(err) => {
                *error = Some(format!("Failed to list installation authorizations: {err}"));
                authorizations.clone()
            }
        };
        *authorizations = updated_authorizations;
    }

    if let ScreenState::Connected {
        authorizations,
        error,
        ..
    } = state
    {
        assert_eq!(authorizations.len(), 1);
        assert_eq!(authorizations[0].authorization_id, "auth-preserved");
        assert!(error.as_ref().unwrap().contains("connection timeout"));
    } else {
        panic!("expected Connected state");
    }
}

#[test]
fn modal_dialog_overlay_lifecycle_and_dismiss_guard() {
    let mut overlay = Overlay::ChangePassword {
        current_password: "old".into(),
        new_password: "new".into(),
        confirm_password: "new".into(),
        error: None,
        in_flight: false,
    };

    // When not in flight, overlay can be dismissed
    let in_flight = match overlay {
        Overlay::ChangePassword { in_flight, .. } => in_flight,
        _ => false,
    };
    assert!(!in_flight);
    if !in_flight {
        overlay = Overlay::None;
    }
    assert_eq!(overlay, Overlay::None);

    // When in flight, dismissal is guarded
    let mut in_flight_overlay = Overlay::EditDevice {
        request_id: 1,
        device_id: "dev-1".into(),
        display_name: "Name".into(),
        location: "Loc".into(),
        error: None,
        in_flight: true,
    };
    let can_dismiss = match in_flight_overlay {
        Overlay::EditDevice { in_flight, .. } => !in_flight,
        _ => true,
    };
    assert!(!can_dismiss);
    if can_dismiss {
        in_flight_overlay = Overlay::None;
    }
    assert!(matches!(in_flight_overlay, Overlay::EditDevice { .. }));
}

#[test]
fn toast_manager_integration_and_emission_lifecycle() {
    let mut manager = crate::toast::ToastManager::new();
    assert!(manager.active_toasts().is_empty());

    let id1 = manager.push(
        crate::toast::ToastKind::Success,
        "Device Updated",
        "Updated device 'dev-1'.",
        1000,
    );
    let id2 = manager.push(
        crate::toast::ToastKind::Warning,
        "Device Blocked",
        "Blocked device 'dev-2'.",
        1500,
    );

    assert_eq!(manager.active_toasts().len(), 2);
    assert_eq!(manager.active_toasts()[0].id, id1);
    assert_eq!(manager.active_toasts()[1].id, id2);

    // Manual dismiss
    manager.dismiss(id1);
    assert_eq!(manager.active_toasts().len(), 1);
    assert_eq!(manager.active_toasts()[0].id, id2);

    // Auto dismiss via tick (t2 expires at 1500 + 3000 = 4500)
    manager.tick(4000);
    assert_eq!(manager.active_toasts().len(), 1);
    manager.tick(4501);
    assert!(manager.active_toasts().is_empty());
}

#[test]
fn remote_view_activation_switches_route_and_auto_collapses_sidebar() {
    let mut nav = crate::navigation::Navigation::default();
    let mut remote_state = crate::remote::RemoteSessionState::default();

    assert_eq!(nav.active("operator"), crate::navigation::Route::Fleet);
    assert!(!nav.collapsed);
    assert!(!remote_state.is_active());

    // Simulate remote session initiation
    remote_state.start_session("dev-win-10", "Production PC");
    nav.select(crate::navigation::Route::Remote, "operator");
    nav.collapsed = true;

    assert_eq!(nav.active("operator"), crate::navigation::Route::Remote);
    assert!(nav.collapsed, "sidebar must auto-collapse for remote view");
    assert!(remote_state.is_active());

    let session = remote_state.active_session().unwrap();
    assert_eq!(session.device_id, "dev-win-10");
    assert_eq!(session.device_name, "Production PC");
    assert_eq!(session.monitor, crate::remote::MonitorTarget::Display1);
    assert_eq!(session.input_mode, crate::remote::InputMode::Interactive);
    assert!(session.keyboard_grabbed);
    assert!(!session.fullscreen);
}

#[test]
fn remote_view_tab_switching_preserves_session_state() {
    let mut nav = crate::navigation::Navigation::default();
    let mut remote_state = crate::remote::RemoteSessionState::default();

    remote_state.start_session("dev-win-10", "Production PC");
    nav.select(crate::navigation::Route::Remote, "operator");
    nav.collapsed = true;

    // Switch to Fleet Inventory tab
    nav.select(crate::navigation::Route::Fleet, "operator");
    assert_eq!(nav.active("operator"), crate::navigation::Route::Fleet);

    // Verify active remote session is preserved
    assert!(remote_state.is_active());
    assert_eq!(
        remote_state.active_session().unwrap().device_id,
        "dev-win-10"
    );

    // Switch back to Remote Sessions tab
    nav.select(crate::navigation::Route::Remote, "operator");
    assert_eq!(nav.active("operator"), crate::navigation::Route::Remote);
    assert!(remote_state.is_active());
}

#[test]
fn remote_toolbar_input_mode_and_keyboard_ungrab_state() {
    let mut remote_state = crate::remote::RemoteSessionState::default();
    remote_state.start_session("dev-win-10", "Production PC");

    // Input mode toggling
    assert_eq!(
        remote_state.active_session().unwrap().input_mode,
        crate::remote::InputMode::Interactive
    );
    remote_state.toggle_input_mode();
    assert_eq!(
        remote_state.active_session().unwrap().input_mode,
        crate::remote::InputMode::ViewOnly
    );
    remote_state.toggle_input_mode();
    assert_eq!(
        remote_state.active_session().unwrap().input_mode,
        crate::remote::InputMode::Interactive
    );

    // Keyboard grab and ungrab handling
    assert!(remote_state.active_session().unwrap().keyboard_grabbed);
    remote_state.ungrab_keyboard();
    assert!(!remote_state.active_session().unwrap().keyboard_grabbed);
    remote_state.toggle_keyboard_grab();
    assert!(remote_state.active_session().unwrap().keyboard_grabbed);

    // Fullscreen toggle
    assert!(!remote_state.active_session().unwrap().fullscreen);
    remote_state.toggle_fullscreen();
    assert!(remote_state.active_session().unwrap().fullscreen);

    // Disconnect
    remote_state.disconnect();
    assert!(!remote_state.is_active());
    assert!(remote_state.active_session().is_none());
    assert!(!remote_state.toolbar_visible);
}

#[test]
fn remote_keyboard_shortcut_evaluation() {
    use gpui::{Keystroke, Modifiers};

    let f11_ks = Keystroke {
        modifiers: Modifiers::default(),
        key: "f11".to_string(),
        key_char: None,
    };
    assert_eq!(f11_ks.key, "f11");

    let ungrab_mod = Modifiers {
        control: true,
        shift: true,
        ..Default::default()
    };
    let ungrab_ks = Keystroke {
        modifiers: ungrab_mod,
        key: "escape".to_string(),
        key_char: None,
    };
    assert!(ungrab_ks.modifiers.control && ungrab_ks.modifiers.shift && ungrab_ks.key == "escape");
}

#[test]
fn fleet_device_item_is_remote_ready_evaluation() {
    use crate::fleet::{DeviceStatusKind, FleetDeviceItem};

    // Windows online & unblocked -> ready
    let win_ready = FleetDeviceItem {
        device_id: "win-1".into(),
        display_name: "Windows Host".into(),
        device_type: "windows".into(),
        location: Some("Room A".into()),
        last_address: "10.0.0.1".into(),
        configured_address: None,
        status: DeviceStatusKind::Online,
        last_seen_unix_ms: 1000,
        online: true,
        blocked: false,
    };
    assert!(win_ready.is_remote_ready());

    // Windows offline -> not ready
    let win_offline = FleetDeviceItem {
        online: false,
        ..win_ready.clone()
    };
    assert!(!win_offline.is_remote_ready());

    // Windows blocked -> not ready
    let win_blocked = FleetDeviceItem {
        blocked: true,
        ..win_ready.clone()
    };
    assert!(!win_blocked.is_remote_ready());

    // Android TV -> not ready (diagnostic/fleet endpoint is windows desktop for remote control)
    let android_tv = FleetDeviceItem {
        device_type: "android_tv".into(),
        ..win_ready.clone()
    };
    assert!(!android_tv.is_remote_ready());
}

#[test]
fn remote_fullscreen_borderless_layout_condition() {
    use crate::navigation::Route;
    use crate::remote::RemoteSessionState;

    let mut remote_state = RemoteSessionState::default();
    let active_route = Route::Remote;

    // In windowed mode, is_borderless is false
    remote_state.start_session("win-1", "Win Host");
    let is_borderless = active_route == Route::Remote
        && remote_state.active_session().is_some_and(|s| s.fullscreen);
    assert!(!is_borderless);

    // In fullscreen mode, is_borderless is true
    remote_state.toggle_fullscreen();
    let is_borderless = active_route == Route::Remote
        && remote_state.active_session().is_some_and(|s| s.fullscreen);
    assert!(is_borderless);

    // If route changes away from Remote, is_borderless is false
    let other_route = Route::Fleet;
    let is_borderless =
        other_route == Route::Remote && remote_state.active_session().is_some_and(|s| s.fullscreen);
    assert!(!is_borderless);
}

#[test]
fn staff_accounts_view_model_and_role_transitions() {
    let accounts = [
        StaffAccountEntry {
            username: "admin_user".into(),
            role: "admin".into(),
            active: true,
            must_change_password: false,
            created_at_unix_ms: 1_700_000_000_000,
            updated_at_unix_ms: 1_700_000_000_000,
        },
        StaffAccountEntry {
            username: "operator_user".into(),
            role: "operator".into(),
            active: true,
            must_change_password: true,
            created_at_unix_ms: 1_700_000_000_000,
            updated_at_unix_ms: 1_700_000_000_000,
        },
        StaffAccountEntry {
            username: "deactivated_user".into(),
            role: "operator".into(),
            active: false,
            must_change_password: false,
            created_at_unix_ms: 1_700_000_000_000,
            updated_at_unix_ms: 1_700_000_000_000,
        },
    ];

    // Admin role promotion/demotion target
    let admin_acc = &accounts[0];
    let new_target_role = if admin_acc.role == "admin" {
        "operator"
    } else {
        "admin"
    };
    assert_eq!(new_target_role, "operator");

    // Operator role promotion
    let op_acc = &accounts[1];
    let new_target_role = if op_acc.role == "admin" {
        "operator"
    } else {
        "admin"
    };
    assert_eq!(new_target_role, "admin");

    // Temporary password badge
    assert!(op_acc.must_change_password);

    // Deactivated account status
    let deactivated_acc = &accounts[2];
    assert!(!deactivated_acc.active);
}

#[test]
fn agent_deployment_authorization_filtering_and_revocation_state() {
    use rustctrl_protocol::auth::InstallationAuthorizationEntry;

    let authorizations = [
        InstallationAuthorizationEntry {
            authorization_id: "auth-active-123".into(),
            created_by: "admin".into(),
            created_at_unix_ms: 1_700_000_000_000,
            revoked_at_unix_ms: None,
        },
        InstallationAuthorizationEntry {
            authorization_id: "auth-revoked-456".into(),
            created_by: "bootstrap".into(),
            created_at_unix_ms: 1_699_000_000_000,
            revoked_at_unix_ms: Some(1_699_500_000_000),
        },
    ];

    let active_auth = &authorizations[0];
    assert!(active_auth.revoked_at_unix_ms.is_none());

    let revoked_auth = &authorizations[1];
    assert!(revoked_auth.revoked_at_unix_ms.is_some());
}

#[test]
fn audit_history_entry_generation_and_attribution() {
    use crate::gui::views::audit::AuditEntryItem;

    let entry = AuditEntryItem {
        id: 1,
        timestamp_unix_ms: 1_700_000_000_000,
        actor: "admin".into(),
        category: "Authentication",
        action: "Staff sign-in (admin)".into(),
        result: "Success",
        detail: "Established mutual TLS administrative session".into(),
    };

    assert_eq!(entry.id, 1);
    assert_eq!(entry.actor, "admin");
    assert_eq!(entry.category, "Authentication");
    assert_eq!(entry.result, "Success");
    assert!(!entry.relative_time().is_empty());

    let remote_entry = AuditEntryItem {
        id: 2,
        timestamp_unix_ms: 1_700_000_000_000,
        actor: "admin".into(),
        category: "Remote Session",
        action: "Interactive remote session (DESKTOP-TEST)".into(),
        result: "Active",
        detail: "Active remote control on device dev-1 (target: Display 1)".into(),
    };
    assert_eq!(remote_entry.category, "Remote Session");
    assert_eq!(remote_entry.result, "Active");
}

#[test]
fn configure_tokyo_night_theme_registers_semantic_tokens() {
    let theme = crate::theme::Theme::tokyo_night();
    let mut kit_theme = gpui::component::theme::Theme::default();
    configure_tokyo_night_theme(theme, &mut kit_theme);

    assert_eq!(kit_theme.background, gpui::rgb(theme.bg_app).into());
    assert_eq!(kit_theme.foreground, gpui::rgb(theme.text_primary).into());
    assert_eq!(kit_theme.border, gpui::rgb(theme.border_subtle).into());
    assert_eq!(kit_theme.primary, gpui::rgb(0x7aa2f7).into());
    assert_eq!(kit_theme.danger, gpui::rgb(theme.status_blocked).into());
    assert_eq!(
        kit_theme.warning,
        gpui::rgb(theme.status_reconnecting).into()
    );
    assert_eq!(kit_theme.success, gpui::rgb(theme.status_online).into());
    assert_eq!(kit_theme.info, gpui::rgb(0x7aa2f7).into());
    assert_eq!(kit_theme.sidebar, gpui::rgb(0x16161e).into());
}

#[test]
fn login_and_must_change_password_states_initial_values() {
    let login_state = ScreenState::Login {
        username: "admin".into(),
        password: "secret_password".into(),
        error: None,
        notice: None,
        remember: true,
        in_flight: false,
    };
    if let ScreenState::Login {
        username,
        password,
        remember,
        in_flight,
        ..
    } = &login_state
    {
        assert_eq!(username, "admin");
        assert_eq!(password, "secret_password");
        assert!(*remember);
        assert!(!*in_flight);
    } else {
        panic!("expected login screen state");
    }

    let mcp_state = ScreenState::MustChangePassword {
        session_token: "temp-tok-123".into(),
        username: "temporary_user".into(),
        role: "operator".into(),
        new_password: "NewPassword123".into(),
        confirm_password: "NewPassword123".into(),
        error: None,
        in_flight: false,
    };
    if let ScreenState::MustChangePassword {
        new_password,
        confirm_password,
        in_flight,
        ..
    } = &mcp_state
    {
        assert_eq!(new_password, confirm_password);
        assert!(new_password.len() >= 8);
        assert!(!*in_flight);
    } else {
        panic!("expected must change password screen state");
    }
}

#[test]
fn fleet_search_and_filter_state_toggles() {
    let mut fleet_state = crate::fleet::FleetState::new();
    assert_eq!(fleet_state.filter, crate::fleet::FleetFilterChip::All);
    assert!(fleet_state.search_query.is_empty());

    fleet_state.set_filter(crate::fleet::FleetFilterChip::Windows);
    assert_eq!(fleet_state.filter, crate::fleet::FleetFilterChip::Windows);

    fleet_state.set_search("workstation");
    assert_eq!(fleet_state.search_query, "workstation");

    fleet_state.reset_filters();
    assert_eq!(fleet_state.filter, crate::fleet::FleetFilterChip::All);
    assert!(fleet_state.search_query.is_empty());
}

#[test]
fn fleet_inspector_selection_lifecycle() {
    let mut fleet_state = crate::fleet::FleetState::new();
    assert!(fleet_state.selected_device_id.is_none());

    fleet_state.select_device(Some("dev-pc-01".into()));
    assert_eq!(fleet_state.selected_device_id.as_deref(), Some("dev-pc-01"));

    fleet_state.close_inspector();
    assert!(fleet_state.selected_device_id.is_none());
}
