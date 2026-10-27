//! Mutual TLS transport certificate verification and SAN inspection for the RustCtrl Server.
//!
//! # Domain Scope
//! This module handles the transport security layer for gRPC connections, including client
//! certificate parsing, Subject Alternative Name (SAN) extraction, and client identity
//! validation. It establishes whether a connecting client is an enrolled Agent endpoint,
//! a bootstrap agent enrolling with temporary credentials, or a desktop Controller.
//!
//! # Canonical Terms (from [CONTEXT.md](../../../../CONTEXT.md))
//! - **Device**: A Windows computer or Android TV recorded in the fleet inventory. Its identity
//!   remains the same when its network address changes. Avoid: IP address as device identity.
//! - **Agent**: The RustCtrl component representing a Windows Device in the Fleet. Avoid: Controller.
//! - **Controller**: The staff application for accessing the Fleet and performing actions allowed
//!   by the staff member's role. Avoid: Server, Agent.
//! - **Staff Account**: An individual IT staff member's identity in RustCtrl, with an Admin or
//!   Operator role. It is distinct from a component's connection identity. Avoid: Controller
//!   certificate as staff identity.
//! - **Installation Authorization**: An Admin-granted permission for new Agents to join a specific
//!   RustCtrl Server through an Agent Installation Package. It is distinct from an already
//!   enrolled Device's permission to connect. Avoid: Device credentials, Staff Session.
//! - **Provisioning**: The initial preparation that establishes a Device's identity and access
//!   within RustCtrl. Avoid: per-session approval.
//!
//! # Invariants and Architectural Guarantees
//! - **Component Identity vs Staff Identity**: Mutual TLS client certificates identify connecting
//!   components (Agent endpoints, Controller binaries, or enrollment bootstrap clients), NOT
//!   individual staff members. Staff authentication requires a distinct, revocable Staff Session
//!   under a Staff Account. A Controller certificate never substitutes for staff credentials.
//! - **Strict Certificate-to-Device Binding**: An enrolled Agent's certificate SAN must strictly
//!   match `<device_id>.agent.rustctrl.internal`. This prevents an enrolled agent from impersonating
//!   another device or claiming another device's identity.
//! - **Scoped Enrollment Authority**: New agents enrolling via an installation package
//!   authenticate transport using a scoped enrollment certificate with SAN
//!   `enrollment.rustctrl.internal` alongside an installation authorization secret.
//! - **Controller Transport Identity**: Controllers authenticate transport with a client
//!   certificate having SAN `controller.rustctrl.internal`.
//! - **Precedence of Certificate Verification**: Identity verification via mTLS client certificates
//!   must precede any application-level device state checks (such as checking whether a device is
//!   replaced or blocked).
//! - **Explicit Error Separation**: Missing client certificates or unparseable certificates yield
//!   `Unauthenticated`. Valid certificates with unauthorized or mismatching SANs yield
//!   `PermissionDenied`.
//!
//! # Applicable Architecture Decision Records (ADRs)
//! - [ADR 0002: Bootstrap an offline local CA](../../../../docs/adr/0002-bootstrap-an-offline-local-ca.md):
//!   offline deployment trust, mutual TLS client authentication, and component identity.
//! - [ADR 0007: Provision Agent credentials via scoped issuing authority](../../../../docs/adr/0007-provision-agent-credentials-via-scoped-issuing-authority.md):
//!   scoped enrollment SAN, intermediate Agent Issuing CA, and certificate-to-device binding invariants.
//!
//! # Repository Security Guidelines
//! - [Deployment Security Guidelines](../../../../docs/deployment.md): CA private key containment and volume isolation.
//! - [Repository Instructions & Integrity Constraints](../../../../AGENTS.md): component boundaries and credential invariants.

use rustctrl_core::DeviceId;
use tonic::{Request, Status};
use x509_parser::{extensions::GeneralName, parse_x509_certificate};

/// Canonical SAN for Controller mutual TLS transport identity.
pub const CONTROLLER_SAN: &str = "controller.rustctrl.internal";

/// Canonical SAN for Agent enrollment mutual TLS transport identity.
pub const ENROLLMENT_SAN: &str = "enrollment.rustctrl.internal";

/// Suffix for enrolled Agent certificate SANs.
pub const AGENT_SAN_SUFFIX: &str = ".agent.rustctrl.internal";

/// Classified client transport identity extracted from mutual TLS client certificate SANs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientIdentity {
    /// An enrolled Agent endpoint with a verified Device ID binding (`<device_id>.agent.rustctrl.internal`).
    Agent(DeviceId),
    /// An enrollment bootstrap client presenting the scoped enrollment credential (`enrollment.rustctrl.internal`).
    Enrollment,
    /// A staff Controller desktop application (`controller.rustctrl.internal`).
    Controller,
    /// Another client certificate whose DNS SANs do not match standard RustCtrl identities.
    Other(Vec<String>),
}

/// Helper to invoke a closure with the raw leaf client certificate DER bytes from an incoming gRPC request.
fn with_leaf_cert<T, R, F>(request: &Request<T>, f: F) -> Result<R, Status>
where
    F: FnOnce(&[u8]) -> Result<R, Status>,
{
    let certs = request
        .peer_certs()
        .ok_or_else(|| Status::unauthenticated("client certificate required"))?;
    let leaf = certs
        .first()
        .ok_or_else(|| Status::unauthenticated("client certificate required"))?;
    f(leaf.as_ref())
}

/// Extracts all DNS Subject Alternative Names (SANs) from raw X.509 DER certificate bytes.
pub fn extract_sans_from_der(der: &[u8]) -> Result<Vec<String>, Status> {
    let (_, cert) = parse_x509_certificate(der)
        .map_err(|_| Status::unauthenticated("invalid client certificate"))?;
    let san = cert
        .subject_alternative_name()
        .map_err(|_| Status::unauthenticated("invalid certificate SAN"))?;

    let dns_names = san
        .map(|extension| {
            extension
                .value
                .general_names
                .iter()
                .filter_map(|name| match name {
                    GeneralName::DNSName(value) => Some((*value).to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(dns_names)
}

/// Extracts all DNS Subject Alternative Names (SANs) from the leaf client certificate of a gRPC request.
pub fn extract_client_sans<T>(request: &Request<T>) -> Result<Vec<String>, Status> {
    with_leaf_cert(request, extract_sans_from_der)
}

/// Inspects and classifies the client identity from raw X.509 DER certificate bytes.
pub fn inspect_identity_from_der(der: &[u8]) -> Result<ClientIdentity, Status> {
    let sans = extract_sans_from_der(der)?;
    for san in &sans {
        if san == CONTROLLER_SAN {
            return Ok(ClientIdentity::Controller);
        }
        if san == ENROLLMENT_SAN {
            return Ok(ClientIdentity::Enrollment);
        }
        if let Some(id) = san
            .strip_suffix(AGENT_SAN_SUFFIX)
            .and_then(|prefix| prefix.parse::<DeviceId>().ok())
        {
            return Ok(ClientIdentity::Agent(id));
        }
    }
    Ok(ClientIdentity::Other(sans))
}

/// Inspects and classifies the client transport identity from an incoming gRPC request's client certificate.
pub fn inspect_client_identity<T>(request: &Request<T>) -> Result<ClientIdentity, Status> {
    with_leaf_cert(request, inspect_identity_from_der)
}

/// Verifies that raw X.509 DER certificate bytes contain a DNS SAN matching `<device_id>.agent.rustctrl.internal`.
pub fn verify_agent_certificate_der(der: &[u8], expected_id: &DeviceId) -> Result<(), Status> {
    let sans = extract_sans_from_der(der)?;
    let expected = expected_id.certificate_name();
    if !sans.iter().any(|san| san == &expected) {
        return Err(Status::permission_denied(
            "certificate does not identify this device",
        ));
    }
    Ok(())
}

/// Verifies that the client certificate presented in the gRPC request matches the expected Device ID
/// (`<device_id>.agent.rustctrl.internal`).
pub fn verify_agent_certificate<T>(
    request: &Request<T>,
    expected_id: &DeviceId,
) -> Result<(), Status> {
    with_leaf_cert(request, |der| {
        verify_agent_certificate_der(der, expected_id)
    })
}

/// Verifies that raw X.509 DER certificate bytes contain a DNS SAN matching `enrollment.rustctrl.internal`.
pub fn verify_enrollment_certificate_der(der: &[u8]) -> Result<(), Status> {
    let sans = extract_sans_from_der(der)?;
    if !sans.iter().any(|san| san == ENROLLMENT_SAN) {
        return Err(Status::permission_denied(
            "certificate does not authorize agent enrollment",
        ));
    }
    Ok(())
}

/// Verifies that the client certificate presented in the gRPC request is an authorized enrollment certificate
/// (`enrollment.rustctrl.internal`).
pub fn verify_enrollment_certificate<T>(request: &Request<T>) -> Result<(), Status> {
    with_leaf_cert(request, verify_enrollment_certificate_der)
}

/// Verifies that raw X.509 DER certificate bytes contain a DNS SAN matching `controller.rustctrl.internal`.
pub fn verify_controller_certificate_der(der: &[u8]) -> Result<(), Status> {
    let sans = extract_sans_from_der(der)?;
    if !sans.iter().any(|san| san == CONTROLLER_SAN) {
        return Err(Status::permission_denied(
            "certificate does not identify a controller",
        ));
    }
    Ok(())
}

/// Verifies that the client certificate presented in the gRPC request is an authorized controller certificate
/// (`controller.rustctrl.internal`).
pub fn verify_controller_certificate<T>(request: &Request<T>) -> Result<(), Status> {
    with_leaf_cert(request, verify_controller_certificate_der)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};

    fn generate_test_cert(san: &str) -> Vec<u8> {
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "Test Client");
        params.subject_alt_names = vec![SanType::DnsName(san.to_string().try_into().unwrap())];
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        cert.der().to_vec()
    }

    #[test]
    fn verify_agent_certificate_success_and_mismatch() {
        let dev1 = DeviceId::new();
        let dev2 = DeviceId::new();
        let cert_der = generate_test_cert(&dev1.certificate_name());

        // Expected device ID matches certificate
        assert!(verify_agent_certificate_der(&cert_der, &dev1).is_ok());

        // Different device ID is rejected with PermissionDenied
        let err = verify_agent_certificate_der(&cert_der, &dev2).unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert_eq!(err.message(), "certificate does not identify this device");
    }

    #[test]
    fn verify_enrollment_certificate_success_and_rejection() {
        let enrollment_cert = generate_test_cert(ENROLLMENT_SAN);
        let dev = DeviceId::new();
        let agent_cert = generate_test_cert(&dev.certificate_name());

        assert!(verify_enrollment_certificate_der(&enrollment_cert).is_ok());

        // Agent certificate presented to enrollment endpoint is rejected
        let err = verify_enrollment_certificate_der(&agent_cert).unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert_eq!(
            err.message(),
            "certificate does not authorize agent enrollment"
        );
    }

    #[test]
    fn verify_controller_certificate_success_and_rejection() {
        let controller_cert = generate_test_cert(CONTROLLER_SAN);
        let dev = DeviceId::new();
        let agent_cert = generate_test_cert(&dev.certificate_name());

        assert!(verify_controller_certificate_der(&controller_cert).is_ok());

        let err = verify_controller_certificate_der(&agent_cert).unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert_eq!(err.message(), "certificate does not identify a controller");
    }

    #[test]
    fn inspect_identity_classifies_correctly() {
        let dev = DeviceId::new();
        let agent_der = generate_test_cert(&dev.certificate_name());
        let enroll_der = generate_test_cert(ENROLLMENT_SAN);
        let ctrl_der = generate_test_cert(CONTROLLER_SAN);
        let other_der = generate_test_cert("unknown.host.local");

        assert_eq!(
            inspect_identity_from_der(&agent_der).unwrap(),
            ClientIdentity::Agent(dev)
        );
        assert_eq!(
            inspect_identity_from_der(&enroll_der).unwrap(),
            ClientIdentity::Enrollment
        );
        assert_eq!(
            inspect_identity_from_der(&ctrl_der).unwrap(),
            ClientIdentity::Controller
        );
        assert_eq!(
            inspect_identity_from_der(&other_der).unwrap(),
            ClientIdentity::Other(vec!["unknown.host.local".to_string()])
        );
    }

    #[test]
    fn malformed_der_returns_unauthenticated() {
        let corrupt_bytes = [0xde, 0xad, 0xbe, 0xef];
        let dev = DeviceId::new();

        let err = verify_agent_certificate_der(&corrupt_bytes, &dev).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert_eq!(err.message(), "invalid client certificate");

        let err2 = verify_enrollment_certificate_der(&corrupt_bytes).unwrap_err();
        assert_eq!(err2.code(), tonic::Code::Unauthenticated);

        let err3 = extract_sans_from_der(&corrupt_bytes).unwrap_err();
        assert_eq!(err3.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn missing_request_peer_certs_returns_unauthenticated() {
        let request = Request::new(());
        let dev = DeviceId::new();

        let err = verify_agent_certificate(&request, &dev).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert_eq!(err.message(), "client certificate required");

        let err2 = verify_enrollment_certificate(&request).unwrap_err();
        assert_eq!(err2.code(), tonic::Code::Unauthenticated);
        assert_eq!(err2.message(), "client certificate required");

        let err3 = verify_controller_certificate(&request).unwrap_err();
        assert_eq!(err3.code(), tonic::Code::Unauthenticated);
        assert_eq!(err3.message(), "client certificate required");

        let err4 = extract_client_sans(&request).unwrap_err();
        assert_eq!(err4.code(), tonic::Code::Unauthenticated);
        assert_eq!(err4.message(), "client certificate required");
    }
}
