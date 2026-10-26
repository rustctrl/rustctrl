use anyhow::{Context, Result};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustctrl_core::DeviceId;

#[derive(Clone)]
pub struct AgentIssuer {
    pub ca_cert_pem: String,
    pub issuer_cert_pem: String,
    pub issuer_key_pem: String,
    pub enrollment_cert_pem: String,
    pub enrollment_key_pem: String,
    pub server_endpoint: String,
    pub domain_name: String,
}

impl AgentIssuer {
    pub fn new(
        server_endpoint: String,
        domain_name: String,
        ca_cert_pem: String,
        issuer_cert_pem: String,
        issuer_key_pem: String,
        enrollment_cert_pem: String,
        enrollment_key_pem: String,
    ) -> Self {
        Self {
            ca_cert_pem,
            issuer_cert_pem,
            issuer_key_pem,
            enrollment_cert_pem,
            enrollment_key_pem,
            server_endpoint,
            domain_name,
        }
    }

    pub fn issue_agent_certificate(&self, device_id: DeviceId) -> Result<(String, String)> {
        let issuer_key =
            KeyPair::from_pem(&self.issuer_key_pem).context("parse agent issuer private key")?;
        let issuer = rcgen::Issuer::from_ca_cert_pem(&self.issuer_cert_pem, issuer_key)
            .context("parse agent issuer CA certificate")?;

        let client_key = KeyPair::generate().context("generate client keypair")?;
        let identity = device_id.certificate_name();

        let mut client_params = CertificateParams::default();
        client_params.distinguished_name = DistinguishedName::new();
        client_params
            .distinguished_name
            .push(DnType::CommonName, &identity);
        client_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
        client_params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365);
        client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        client_params
            .subject_alt_names
            .push(SanType::DnsName(identity.try_into()?));

        let cert = client_params
            .signed_by(&client_key, &issuer)
            .context("sign client certificate")?;

        let cert_chain_pem = if self.issuer_cert_pem.trim() == self.ca_cert_pem.trim() {
            cert.pem()
        } else {
            format!("{}\n{}", cert.pem(), self.issuer_cert_pem.trim())
        };

        Ok((cert_chain_pem, client_key.serialize_pem()))
    }
}
