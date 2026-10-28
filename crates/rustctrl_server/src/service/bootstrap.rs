//! Bootstrap gRPC service handlers for Agent fleet communication and enrollment.
//!
//! # Domain Scope
//! This module implements the public `Bootstrap` gRPC service facilitating communication between
//! the Server and Agent endpoints. It handles public health checks (`get_health`), periodic
//! agent heartbeats (`send_heartbeat`), and new agent provisioning (`enroll_agent`) through
//! subordinate agent CA certificate issuance and installation authorization validation.
//!
//! # Canonical Terms (from [CONTEXT.md](../../../../CONTEXT.md))
//! - **Server**: The shared authority for staff accounts, inventory, Remote Sessions,
//!   Management Tasks, and activity history. Avoid: Controller.
//! - **Device**: A Windows computer or Android TV recorded in the fleet inventory. Its identity
//!   remains the same when its network address changes. Avoid: IP address as device identity.
//! - **Fleet**: All Devices managed by the IT team through RustCtrl. Avoid: IP list.
//! - **Agent**: The RustCtrl component representing a Windows Device in the Fleet. Avoid: Controller.
//! - **Provisioning**: The initial preparation that establishes a Device's identity and access
//!   within RustCtrl. Avoid: per-session approval.
//! - **Installation Authorization**: An Admin-granted permission for new Agents to join a specific
//!   RustCtrl Server through an Agent Installation Package. It is distinct from an already
//!   enrolled Device's permission to connect. Avoid: Device credentials, Staff Session.
//! - **Device Block**: An Admin-imposed restriction on a Device identity that denies operational
//!   Agent access while keeping the Device visible in the Fleet Inventory.
//! - **Inventory Cleanup**: An Admin's removal of an offline Device entry from the Fleet Inventory
//!   without revoking its Agent's access.
//!
//! # Invariants and Architectural Guarantees
//! - **Mutual TLS (ADR 0002)**: Operational RPCs (`send_heartbeat`) verify client certificate SAN
//!   matching the claiming `DeviceId`. Enrollment RPC (`enroll_agent`) verifies the scoped enrollment
//!   certificate.
//! - **Device Identity Binding**: An agent cannot report heartbeats for a device identity other
//!   than the one bound to its client certificate.
//! - **Replacement & Block Enforcement (ADR 0006)**: Replaced or blocked devices are denied heartbeat
//!   processing even over established TLS channels.
//! - **Subordinate Agent CA (ADR 0007)**: Leaf agent credentials are provisioned dynamically via a
//!   scoped issuing authority without exposing the root CA private key.
//! - **Resumption Protection (ADR 0004)**: Agents re-enrolling under the same authorization must present
//!   the matching resumption secret hash.
//!
//! # Forbidden Anti-Patterns
//! - Never use an IP address or ephemeral network address as a device's identity.
//! - Never treat an inventory cleanup as a device block or credential revocation.
//! - Never issue agent credentials without validating the installation authorization secret.
//!
//! # Applicable Architecture Decision Records (ADRs)
//! - [ADR 0001: Centralize Fleet Coordination](../../../../docs/adr/0001-centralize-fleet-coordination.md)
//! - [ADR 0002: Bootstrap an Offline Local CA](../../../../docs/adr/0002-bootstrap-an-offline-local-ca.md)
//! - [ADR 0004: Enroll Agents Through Trusted Installation](../../../../docs/adr/0004-enroll-agents-through-trusted-installation.md)
//! - [ADR 0006: Separate Inventory Cleanup From Device Blocking](../../../../docs/adr/0006-separate-inventory-cleanup-from-device-blocking.md)
//! - [ADR 0007: Provision Agent Credentials via Scoped Issuing Authority](../../../../docs/adr/0007-provision-agent-credentials-via-scoped-issuing-authority.md)

use super::{database_error, hash_secret};
use crate::{issuer::AgentIssuer, service::tls, store::DeviceStore};
use rustctrl_core::DeviceId;
use rustctrl_protocol::bootstrap::{
    EnrollAgentReply, EnrollAgentRequest, HealthReply, HealthRequest, HeartbeatReply,
    HeartbeatRequest, bootstrap_server::Bootstrap,
};
use std::sync::Arc;
use tonic::{Request, Response, Status};

/// Service implementing the gRPC `Bootstrap` protocol for fleet devices and agent enrollment.
pub struct BootstrapService {
    store: DeviceStore,
    issuer: Option<Arc<AgentIssuer>>,
}

impl BootstrapService {
    /// Creates a new `BootstrapService` instance backed by the provided persistence store.
    pub fn new(store: DeviceStore) -> Self {
        Self {
            store,
            issuer: None,
        }
    }

    /// Creates a new `BootstrapService` instance with an agent certificate issuer for dynamic enrollment.
    pub fn with_issuer(store: DeviceStore, issuer: Arc<AgentIssuer>) -> Self {
        Self {
            store,
            issuer: Some(issuer),
        }
    }
}

#[tonic::async_trait]
impl Bootstrap for BootstrapService {
    async fn get_health(
        &self,
        _request: Request<HealthRequest>,
    ) -> Result<Response<HealthReply>, Status> {
        let count = self.store.count().await.map_err(database_error)?;
        Ok(Response::new(HealthReply {
            version: env!("CARGO_PKG_VERSION").into(),
            registered_devices: count,
        }))
    }

    async fn send_heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatReply>, Status> {
        let body = request.get_ref();
        let id: DeviceId = body
            .device_id
            .parse()
            .map_err(|_| Status::invalid_argument("invalid device_id"))?;
        if body.name.trim().is_empty()
            || body.name.len() > 128
            || body.agent_version.is_empty()
            || body.agent_version.len() > 64
        {
            return Err(Status::invalid_argument("invalid name or agent_version"));
        }
        tls::verify_agent_certificate(&request, &id)?;

        if self
            .store
            .get_device_replacement(&id.to_string())
            .await
            .map_err(database_error)?
            .is_some()
        {
            return Err(Status::permission_denied("device has been replaced"));
        }

        if self
            .store
            .is_device_blocked(&id.to_string())
            .await
            .map_err(database_error)?
        {
            return Err(Status::permission_denied("device is blocked"));
        }

        let remote_address = request.remote_addr().map(|addr| addr.to_string());
        let body = request.into_inner();
        let timestamp = self
            .store
            .heartbeat(id, body.name, body.agent_version, remote_address)
            .await
            .map_err(database_error)?;
        tracing::debug!(device_id = %id, "heartbeat stored");
        Ok(Response::new(HeartbeatReply {
            received_at_unix_ms: timestamp,
        }))
    }

    async fn enroll_agent(
        &self,
        request: Request<EnrollAgentRequest>,
    ) -> Result<Response<EnrollAgentReply>, Status> {
        let body = request.get_ref();
        let id: DeviceId = body
            .device_id
            .parse()
            .map_err(|_| Status::invalid_argument("invalid device_id"))?;

        if body.name.trim().is_empty()
            || body.name.len() > 128
            || body.agent_version.is_empty()
            || body.agent_version.len() > 64
        {
            return Err(Status::invalid_argument("invalid name or agent_version"));
        }

        if body.installation_secret.trim().is_empty() {
            return Err(Status::unauthenticated("installation secret is required"));
        }
        tls::verify_enrollment_certificate(&request)?;

        let secret_hash = hash_secret(body.installation_secret.trim());
        let auth = match self
            .store
            .find_installation_authorization_by_hash(&secret_hash)
            .await
        {
            Ok(Some(auth)) => auth,
            Ok(None) => {
                let _ = self
                    .store
                    .record_activity(
                        id.to_string(),
                        "enroll_agent".into(),
                        "rejected".into(),
                        format!(
                            "enrollment rejected for device '{id}': invalid installation secret"
                        ),
                    )
                    .await;
                return Err(Status::unauthenticated(
                    "invalid installation authorization",
                ));
            }
            Err(e) => return Err(database_error(e)),
        };

        let resumption_secret = body.resumption_secret.trim();
        if resumption_secret.is_empty() {
            return Err(Status::invalid_argument("resumption_secret is required"));
        }
        let resumption_secret_hash = hash_secret(resumption_secret);

        let existing_enrollment = self
            .store
            .get_device_enrollment(&id.to_string())
            .await
            .map_err(database_error)?;

        let is_resuming = match &existing_enrollment {
            Some(rec) => {
                if rec.authorization_id != auth.authorization_id {
                    let _ = self
                        .store
                        .record_activity(
                            id.to_string(),
                            "enroll_agent".into(),
                            "rejected".into(),
                            format!(
                                "enrollment rejected for device '{id}': already enrolled under a different authorization"
                            ),
                        )
                        .await;
                    return Err(Status::permission_denied(
                        "device is already enrolled under a different authorization",
                    ));
                }
                if rec.resumption_secret_hash.as_deref() != Some(&resumption_secret_hash) {
                    let _ = self
                        .store
                        .record_activity(
                            id.to_string(),
                            "enroll_agent".into(),
                            "rejected".into(),
                            format!(
                                "enrollment rejected for device '{id}': invalid resumption secret"
                            ),
                        )
                        .await;
                    return Err(Status::permission_denied(
                        "resumption secret does not match enrolled device",
                    ));
                }
                true
            }
            None => false,
        };

        if auth.revoked_at_unix_ms.is_some() && !is_resuming {
            let _ = self
                .store
                .record_activity(
                    id.to_string(),
                    "enroll_agent".into(),
                    "rejected".into(),
                    format!("enrollment rejected for device '{id}': installation authorization has been revoked"),
                )
                .await;
            return Err(Status::permission_denied(
                "installation authorization has been revoked",
            ));
        }

        let remote_addr = request.remote_addr().map(|a| a.to_string());
        let enrolled_at = match self
            .store
            .record_device_enrollment(
                id,
                auth.authorization_id.clone(),
                body.name.clone(),
                body.agent_version.clone(),
                remote_addr,
                resumption_secret_hash,
            )
            .await
        {
            Ok(enrolled_at_ms) => enrolled_at_ms,
            Err(e) => {
                let err_msg = e.to_string();
                let _ = self
                    .store
                    .record_activity(
                        id.to_string(),
                        "enroll_agent".into(),
                        "rejected".into(),
                        format!("enrollment rejected for device '{id}': {err_msg}"),
                    )
                    .await;
                return Err(Status::permission_denied(err_msg));
            }
        };

        let issuer = self
            .issuer
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("agent issuer not configured"))?;

        let (cert_pem, key_pem) = issuer
            .issue_agent_certificate(id)
            .map_err(|e| Status::internal(format!("failed to issue agent certificate: {e}")))?;

        let _ = self
            .store
            .record_activity(
                id.to_string(),
                "enroll_agent".into(),
                "success".into(),
                format!(
                    "enrolled agent '{id}' using authorization '{}'",
                    auth.authorization_id
                ),
            )
            .await;

        Ok(Response::new(EnrollAgentReply {
            device_id: id.to_string(),
            certificate: cert_pem,
            private_key: key_pem,
            ca_certificate: issuer.ca_cert_pem.clone(),
            enrolled_at_unix_ms: enrolled_at,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn create_test_store() -> DeviceStore {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        DeviceStore::open(&db_path).unwrap()
    }

    #[tokio::test]
    async fn get_health_returns_version_and_device_count() {
        let store = create_test_store().await;
        let service = BootstrapService::new(store);

        let response = service
            .get_health(Request::new(HealthRequest {}))
            .await
            .expect("health check succeeds")
            .into_inner();

        assert_eq!(response.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(response.registered_devices, 0);
    }

    #[tokio::test]
    async fn send_heartbeat_rejects_invalid_device_id() {
        let store = create_test_store().await;
        let service = BootstrapService::new(store);

        let status = service
            .send_heartbeat(Request::new(HeartbeatRequest {
                device_id: "not-a-valid-uuid".into(),
                name: "Workstation-1".into(),
                agent_version: "0.1.0".into(),
            }))
            .await
            .unwrap_err();

        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert_eq!(status.message(), "invalid device_id");
    }

    #[tokio::test]
    async fn send_heartbeat_rejects_empty_name_or_version() {
        let store = create_test_store().await;
        let service = BootstrapService::new(store);
        let id = DeviceId::new();

        let status = service
            .send_heartbeat(Request::new(HeartbeatRequest {
                device_id: id.to_string(),
                name: "   ".into(),
                agent_version: "0.1.0".into(),
            }))
            .await
            .unwrap_err();

        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert_eq!(status.message(), "invalid name or agent_version");

        let status2 = service
            .send_heartbeat(Request::new(HeartbeatRequest {
                device_id: id.to_string(),
                name: "Workstation-1".into(),
                agent_version: "".into(),
            }))
            .await
            .unwrap_err();

        assert_eq!(status2.code(), tonic::Code::InvalidArgument);
        assert_eq!(status2.message(), "invalid name or agent_version");
    }

    #[tokio::test]
    async fn enroll_agent_rejects_missing_secrets() {
        let store = create_test_store().await;
        let service = BootstrapService::new(store);
        let id = DeviceId::new();

        let status = service
            .enroll_agent(Request::new(EnrollAgentRequest {
                device_id: id.to_string(),
                name: "Host".into(),
                agent_version: "0.1.0".into(),
                installation_secret: "  ".into(),
                resumption_secret: "resume123".into(),
            }))
            .await
            .unwrap_err();

        assert_eq!(status.code(), tonic::Code::Unauthenticated);
        assert_eq!(status.message(), "installation secret is required");
    }
}
