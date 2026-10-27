//! Staff session authorization and RPC middleware for the RustCtrl Server.
//!
//! # Domain Scope
//! This module handles request authentication and authorization for staff-facing gRPC RPCs.
//! It is responsible for extracting bearer tokens from gRPC metadata, validating staff sessions
//! against the persistence store (`DeviceStore`), enforcing mandatory password change gates,
//! validating role permissions (Admin vs Operator), and providing central activity audit logging
//! helpers for RPC handlers.
//!
//! # Canonical Terms (from [CONTEXT.md](../../../../CONTEXT.md))
//! - **Staff Account**: An individual IT staff member's identity in RustCtrl, with an Admin or
//!   Operator role. It is distinct from a component's connection identity. Avoid: shared account,
//!   Controller certificate as staff identity.
//! - **Staff Session**: A revocable period of access to RustCtrl through the Controller under a
//!   Staff Account. It is distinct from a Remote Session with a Device. Avoid: Remote Session,
//!   Agent connection.
//! - **Admin**: A staff member allowed to manage accounts, Devices, configuration, and Management
//!   Tasks, as well as open Remote Sessions. Avoid: shared account.
//! - **Operator**: A staff member allowed to monitor the Fleet and open Remote Sessions using an
//!   individual account. Avoid: endpoint user.
//! - **Remote Session**: A period during which one staff member can view and control a Device's
//!   screen. Distinct from a Staff Session.
//!
//! # Invariants and Architectural Guarantees
//! - **Staff Session vs Component Identity**: Staff operations require an active, valid Staff
//!   Session under a Staff Account. A valid client TLS certificate establishes transport identity
//!   but never substitutes for staff credentials (ADR 0003, ADR 0005).
//! - **Bearer Token Extraction**: Staff session tokens must be provided via either the standard
//!   `authorization: Bearer <token>` metadata or the `session-token: <token>` metadata header.
//!   Missing, whitespace-only, or non-ASCII headers yield `Unauthenticated("staff session required")`.
//! - **Durable Revocation & Expiry (ADR 0005)**: Every authenticated operation verifies that the
//!   session is unrevoked in the persistent store. Invalidation by explicit logout, account
//!   deactivation, password reset, or TTL expiration rejects further calls with
//!   `Unauthenticated("invalid or revoked staff session")`.
//! - **Mandatory Password Replacement Gate**: Accounts flagged with `must_change_password` (such
//!   as newly bootstrapped admins, created accounts, or reset accounts) are strictly restricted:
//!   any attempt to invoke protected operations is rejected with `PermissionDenied("password change
//!   required before accessing protected operations")` until credentials are replaced.
//! - **Role-Based Access Control**: Operations requiring administrative privileges strictly verify
//!   that `session.role == StaffRole::Admin`. If an Operator attempts an Admin operation, the call
//!   is rejected with `PermissionDenied("admin role required")`, and an audit log entry is
//!   recorded with outcome `"rejected"`.
//! - **Audit Logging without Secrets**: Activity log helpers record the actor, action, outcome,
//!   and descriptive detail without ever recording passwords, tokens, or sensitive secrets.
//!
//! # Applicable Architecture Decision Records (ADRs)
//! - [ADR 0003: Bootstrap staff administration locally](../../../../docs/adr/0003-bootstrap-staff-administration-locally.md):
//!   local admin credentials, password change enforcement, and initial setup.
//! - [ADR 0005: Keep remembered staff access revocable](../../../../docs/adr/0005-keep-remembered-staff-access-revocable.md):
//!   session token extraction, durable revocation on credential invalidation, and TTL expiration.
//!
//! # Repository Security Guidelines
//! - [Repository Instructions & Access Boundaries](../../../../AGENTS.md): separation of staff accounts from component certificates.

use crate::store::{DeviceStore, StaffRole, StaffSession};
use tonic::{Request, Status};

/// Standard HTTP authorization header name.
pub const AUTHORIZATION_HEADER: &str = "authorization";

/// Custom session token header name.
pub const SESSION_TOKEN_HEADER: &str = "session-token";

/// Extracts the raw staff session token string from incoming gRPC request metadata.
///
/// Inspects the `authorization` header (stripping an optional `Bearer ` prefix and trimming whitespace),
/// falling back to the `session-token` header. Returns `Unauthenticated("staff session required")`
/// if no non-empty token is found.
pub fn extract_session_token<T>(request: &Request<T>) -> Result<&str, Status> {
    let token = request
        .metadata()
        .get(AUTHORIZATION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.strip_prefix("Bearer ").unwrap_or(s).trim())
        .or_else(|| {
            request
                .metadata()
                .get(SESSION_TOKEN_HEADER)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim())
        });

    match token {
        Some(t) if !t.is_empty() => Ok(t),
        _ => Err(Status::unauthenticated("staff session required")),
    }
}

/// Authenticates an incoming request by extracting the session token and verifying it
/// against `DeviceStore`.
///
/// Returns the active `StaffSession` if valid and not revoked. Does not enforce the
/// `must_change_password` restriction (used by password replacement endpoints).
pub async fn authenticate_request<T>(
    store: &DeviceStore,
    request: &Request<T>,
) -> Result<StaffSession, Status> {
    let token = extract_session_token(request)?;
    match store.get_session(token).await {
        Ok(Some(session)) if !session.revoked => Ok(session),
        _ => Err(Status::unauthenticated("invalid or revoked staff session")),
    }
}

/// Authenticates an incoming request for general staff operations.
///
/// Ensures that the request contains a valid, unrevoked session and enforces that
/// mandatory temporary password replacement has already been performed.
pub async fn authenticate_staff<T>(
    store: &DeviceStore,
    request: &Request<T>,
) -> Result<StaffSession, Status> {
    let session = authenticate_request(store, request).await?;
    if session.must_change_password {
        return Err(Status::permission_denied(
            "password change required before accessing protected operations",
        ));
    }
    Ok(session)
}

/// Authenticates an incoming request for administrative operations.
///
/// Ensures the request contains a valid, unrevoked session with no pending password change,
/// and verifies that `session.role == StaffRole::Admin`. If an Operator attempts the operation,
/// an audit log rejection is recorded and `PermissionDenied("admin role required")` is returned.
pub async fn authenticate_admin<T>(
    store: &DeviceStore,
    request: &Request<T>,
    action: &str,
    target: Option<&str>,
) -> Result<StaffSession, Status> {
    let session = authenticate_staff(store, request).await?;
    require_admin(store, &session, action, target).await?;
    Ok(session)
}

/// Verifies that the staff session has `StaffRole::Admin`.
///
/// If the role is not `Admin`, an activity audit entry is recorded with outcome `"rejected"`
/// and `PermissionDenied("admin role required")` is returned.
pub async fn require_admin(
    store: &DeviceStore,
    session: &StaffSession,
    action: &str,
    target: Option<&str>,
) -> Result<(), Status> {
    if session.role != StaffRole::Admin {
        let detail = if let Some(tgt) = target {
            format!("operator cannot perform '{action}' on target '{tgt}'")
        } else {
            format!("operator cannot perform '{action}'")
        };
        record_rpc_activity(store, session.username.clone(), action, "rejected", detail).await;
        return Err(Status::permission_denied("admin role required"));
    }
    Ok(())
}

/// Helper utility to record an activity audit log entry for an RPC call.
///
/// Swallows persistence errors gracefully with tracing output, ensuring that logging
/// failures do not fail active application requests.
pub async fn record_rpc_activity(
    store: &DeviceStore,
    actor: impl Into<String>,
    action: impl Into<String>,
    outcome: impl Into<String>,
    detail: impl Into<String>,
) {
    let _ = store
        .record_activity(actor.into(), action.into(), outcome.into(), detail.into())
        .await;
}

/// Helper utility to record an access rejection in the activity audit log.
pub async fn record_rpc_rejection(
    store: &DeviceStore,
    actor: impl Into<String>,
    action: impl Into<String>,
    detail: impl Into<String>,
) {
    record_rpc_activity(store, actor, action, "rejected", detail).await;
}

/// Helper utility to record an operation failure in the activity audit log.
pub async fn record_rpc_failure(
    store: &DeviceStore,
    actor: impl Into<String>,
    action: impl Into<String>,
    detail: impl Into<String>,
) {
    record_rpc_activity(store, actor, action, "failed", detail).await;
}

/// Helper utility to record an operation success in the activity audit log.
pub async fn record_rpc_success(
    store: &DeviceStore,
    actor: impl Into<String>,
    action: impl Into<String>,
    detail: impl Into<String>,
) {
    record_rpc_activity(store, actor, action, "success", detail).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use tonic::metadata::MetadataValue;

    async fn create_test_store() -> DeviceStore {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        DeviceStore::open(&db_path).unwrap()
    }

    #[test]
    fn extract_session_token_from_bearer_authorization() {
        let mut request = Request::new(());
        request.metadata_mut().insert(
            AUTHORIZATION_HEADER,
            MetadataValue::from_static("Bearer test-token-123"),
        );
        assert_eq!(extract_session_token(&request).unwrap(), "test-token-123");
    }

    #[test]
    fn extract_session_token_from_raw_authorization() {
        let mut request = Request::new(());
        request.metadata_mut().insert(
            AUTHORIZATION_HEADER,
            MetadataValue::from_static("raw-token-abc"),
        );
        assert_eq!(extract_session_token(&request).unwrap(), "raw-token-abc");
    }

    #[test]
    fn extract_session_token_from_session_token_header() {
        let mut request = Request::new(());
        request.metadata_mut().insert(
            SESSION_TOKEN_HEADER,
            MetadataValue::from_static("custom-session-token-xyz"),
        );
        assert_eq!(
            extract_session_token(&request).unwrap(),
            "custom-session-token-xyz"
        );
    }

    #[test]
    fn extract_session_token_missing_or_empty_returns_unauthenticated() {
        let request = Request::new(());
        let err = extract_session_token(&request).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert_eq!(err.message(), "staff session required");

        let mut empty_req = Request::new(());
        empty_req
            .metadata_mut()
            .insert(AUTHORIZATION_HEADER, MetadataValue::from_static("   "));
        let err2 = extract_session_token(&empty_req).unwrap_err();
        assert_eq!(err2.code(), tonic::Code::Unauthenticated);
        assert_eq!(err2.message(), "staff session required");
    }

    #[tokio::test]
    async fn authenticate_request_lifecycle() {
        let store = create_test_store().await;
        let password_hash = crate::password::hash_password("SuperSecret123!").unwrap();
        store
            .bootstrap_admin("testadmin".into(), "SuperSecret123!".into())
            .await
            .unwrap();
        store
            .update_password("testadmin", password_hash.clone(), false)
            .await
            .unwrap();

        let session = store
            .create_login_session(
                "session-id-1".into(),
                "testadmin".into(),
                password_hash,
                None,
            )
            .await
            .unwrap()
            .unwrap();

        let mut request = Request::new(());
        request.metadata_mut().insert(
            AUTHORIZATION_HEADER,
            MetadataValue::from_str(&format!("Bearer {}", session.session_id)).unwrap(),
        );

        let authenticated = authenticate_request(&store, &request).await.unwrap();
        assert_eq!(authenticated.username, "testadmin");
        assert_eq!(authenticated.role, StaffRole::Admin);

        // Revoke session and verify it is rejected
        store.revoke_session(&session.session_id).await.unwrap();
        let err = authenticate_request(&store, &request).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert_eq!(err.message(), "invalid or revoked staff session");
    }

    #[tokio::test]
    async fn authenticate_staff_enforces_password_change() {
        let store = create_test_store().await;
        store
            .bootstrap_admin("initialadmin".into(), "AdminPass123!".into())
            .await
            .unwrap();
        // Account created with temporary password requires change
        store
            .create_staff_account(
                "temppassuser".into(),
                StaffRole::Operator,
                "TempPassword123!".into(),
            )
            .await
            .unwrap();

        let account = store
            .get_staff_account("temppassuser")
            .await
            .unwrap()
            .unwrap();
        let session = store
            .create_login_session(
                "session-temp-1".into(),
                "temppassuser".into(),
                account.password_hash,
                None,
            )
            .await
            .unwrap()
            .unwrap();
        assert!(session.must_change_password);

        let mut request = Request::new(());
        request.metadata_mut().insert(
            SESSION_TOKEN_HEADER,
            MetadataValue::from_str(&session.session_id).unwrap(),
        );

        // authenticate_request succeeds (needed for password replacement RPCs)
        assert!(authenticate_request(&store, &request).await.is_ok());

        // authenticate_staff rejects with PermissionDenied
        let err = authenticate_staff(&store, &request).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert_eq!(
            err.message(),
            "password change required before accessing protected operations"
        );
    }

    #[tokio::test]
    async fn authenticate_admin_role_enforcement_and_audit() {
        let store = create_test_store().await;
        let password_hash = crate::password::hash_password("OperatorPass123!").unwrap();
        store
            .bootstrap_admin("mainadmin".into(), "AdminPass123!".into())
            .await
            .unwrap();
        store
            .create_staff_account(
                "operator1".into(),
                StaffRole::Operator,
                "OperatorPass123!".into(),
            )
            .await
            .unwrap();
        store
            .update_password("operator1", password_hash.clone(), false)
            .await
            .unwrap();

        let session = store
            .create_login_session(
                "session-op-1".into(),
                "operator1".into(),
                password_hash,
                None,
            )
            .await
            .unwrap()
            .unwrap();

        let mut request = Request::new(());
        request.metadata_mut().insert(
            AUTHORIZATION_HEADER,
            MetadataValue::from_str(&format!("Bearer {}", session.session_id)).unwrap(),
        );

        // Operator accessing admin operation with target
        let err = authenticate_admin(&store, &request, "block_device", Some("target-device-1"))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert_eq!(err.message(), "admin role required");

        // Verify audit log captured rejection
        let activity = store.list_activity().await.unwrap();
        assert!(!activity.is_empty());
        let rejection = activity
            .iter()
            .find(|a| a.action == "block_device")
            .expect("rejection record must be logged");
        assert_eq!(rejection.actor, "operator1");
        assert_eq!(rejection.result, "rejected");
        assert_eq!(
            rejection.detail,
            "operator cannot perform 'block_device' on target 'target-device-1'"
        );
    }

    #[tokio::test]
    async fn record_rpc_helpers_insert_audit_entries() {
        let store = create_test_store().await;

        record_rpc_success(&store, "admin", "create_target", "created target tv-1").await;
        record_rpc_failure(&store, "admin", "login", "invalid password").await;
        record_rpc_rejection(&store, "operator", "delete_device", "unauthorized").await;

        let logs = store.list_activity().await.unwrap();
        assert_eq!(logs.len(), 3);
        assert_eq!(logs[0].result, "success");
        assert_eq!(logs[1].result, "failed");
        assert_eq!(logs[2].result, "rejected");
    }
}
