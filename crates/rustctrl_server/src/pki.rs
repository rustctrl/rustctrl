//! One-time local CA bootstrap. The CA private key belongs to the administrator, not the server.
use anyhow::{Context, Result, ensure};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, KeyPair, KeyUsagePurpose, NameConstraints,
    SanType,
};
use rustctrl_core::DeviceId;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    net::IpAddr,
    path::{Path, PathBuf},
};

pub struct PkiOptions {
    pub output: PathBuf,
    pub server_output: Option<PathBuf>,
    pub server_names: Vec<String>,
    pub server_ips: Vec<IpAddr>,
    pub endpoint: String,
    pub domain_name: String,
    pub device_id: DeviceId,
}

pub fn initialize(options: &PkiOptions) -> Result<()> {
    ensure!(
        options.endpoint.starts_with("https://"),
        "endpoint must use https://"
    );
    let ca_dir = options.output.join("ca");
    let server_dir = options
        .server_output
        .clone()
        .unwrap_or_else(|| options.output.join("server"));
    ensure!(
        !ca_dir.join("key.pem").exists() && !ca_dir.join("cert.pem").exists(),
        "CA already exists; initialization never overwrites existing keys"
    );
    ensure!(
        !server_dir.join("key.pem").exists() && !server_dir.join("cert.pem").exists(),
        "server identity already exists; initialization never overwrites existing keys"
    );
    for dir in [&options.output, &ca_dir, &server_dir] {
        private_dir(dir)?;
    }
    let mut ca_params = params("RustCtrl local CA", true);
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate()?)?;
    write_new(&ca_dir.join("cert.pem"), ca.pem().as_bytes())?;
    write_new(&ca_dir.join("key.pem"), ca.key().serialize_pem().as_bytes())?;

    let mut server_params = params("RustCtrl server", false);
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    for name in &options.server_names {
        server_params
            .subject_alt_names
            .push(SanType::DnsName(name.clone().try_into()?));
    }
    for ip in &options.server_ips {
        server_params
            .subject_alt_names
            .push(SanType::IpAddress(*ip));
    }
    ensure!(
        !server_params.subject_alt_names.is_empty(),
        "at least one server DNS name or IP is required"
    );
    issue(&server_dir, server_params, &ca)?;
    let health_dir = server_dir.join("health");
    issue_client(&health_dir, "health.rustctrl.internal", &ca)?;

    let enrollment_dir = server_dir.join("enrollment");
    issue_client(&enrollment_dir, "enrollment.rustctrl.internal", &ca)?;

    let agent_ca_dir = server_dir.join("agent-ca");
    private_dir(&agent_ca_dir)?;
    let mut agent_ca_params = params("RustCtrl Agent Issuing CA", true);
    agent_ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    agent_ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    agent_ca_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    agent_ca_params.name_constraints = Some(NameConstraints {
        permitted_subtrees: vec![GeneralSubtree::DnsName("agent.rustctrl.internal".into())],
        excluded_subtrees: vec![],
    });
    let agent_ca_key = KeyPair::generate()?;
    let agent_ca_cert = agent_ca_params.signed_by(&agent_ca_key, &ca)?;
    write_new(
        &agent_ca_dir.join("cert.pem"),
        agent_ca_cert.pem().as_bytes(),
    )?;
    write_new(
        &agent_ca_dir.join("key.pem"),
        agent_ca_key.serialize_pem().as_bytes(),
    )?;
    write_new(&agent_ca_dir.join("ca.pem"), ca.pem().as_bytes())?;

    let clients = options.output.join("clients");
    let controller_dir = clients.join("controller");
    let agent_dir = clients.join("agent");
    issue_client(&controller_dir, "controller.rustctrl.internal", &ca)?;
    issue_client(&agent_dir, &options.device_id.certificate_name(), &ca)?;
    let connection = format!(
        "[server]\nendpoint = {}\ndomain_name = {}\nca_certificate = \"ca.pem\"\ncertificate = \"cert.pem\"\nprivate_key = \"key.pem\"\n",
        quoted(&options.endpoint),
        quoted(&options.domain_name)
    );
    write_new(&controller_dir.join("config.toml"), connection.as_bytes())?;
    let agent = format!(
        "device_id = \"{}\"\nname = \"Bootstrap Windows device\"\nheartbeat_seconds = 10\n\n{connection}",
        options.device_id
    );
    write_new(&agent_dir.join("config.toml"), agent.as_bytes())?;
    let server_path = server_dir.canonicalize()?;
    let native_config = format!(
        "listen = \"127.0.0.1:9876\"\ndatabase = \"../rustctrl.db\"\n\n[tls]\ncertificate = {}\nprivate_key = {}\nclient_ca = {}\n\n[enrollment]\nserver_endpoint = {}\ndomain_name = {}\nagent_issuer_certificate = {}\nagent_issuer_private_key = {}\nenrollment_certificate = {}\nenrollment_private_key = {}\n",
        quoted(&server_path.join("cert.pem").to_string_lossy()),
        quoted(&server_path.join("key.pem").to_string_lossy()),
        quoted(&server_path.join("ca.pem").to_string_lossy()),
        quoted(&options.endpoint),
        quoted(&options.domain_name),
        quoted(&server_path.join("agent-ca/cert.pem").to_string_lossy()),
        quoted(&server_path.join("agent-ca/key.pem").to_string_lossy()),
        quoted(&server_path.join("enrollment/cert.pem").to_string_lossy()),
        quoted(&server_path.join("enrollment/key.pem").to_string_lossy())
    );
    write_new(
        &options.output.join("server.toml"),
        native_config.as_bytes(),
    )?;
    tracing::info!(output = %options.output.display(), device_id = %options.device_id,
        "PKI initialized; keep the ca directory private and distribute only each client's own bundle");
    Ok(())
}

fn params(common_name: &str, ca: bool) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
    params.not_after =
        time::OffsetDateTime::now_utc() + time::Duration::days(if ca { 3650 } else { 365 });
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params
}
fn issue_client(dir: &Path, identity: &str, ca: &CertifiedIssuer<'_, KeyPair>) -> Result<()> {
    let mut params = params(identity, false);
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params
        .subject_alt_names
        .push(SanType::DnsName(identity.to_owned().try_into()?));
    issue(dir, params, ca)
}
fn issue(dir: &Path, params: CertificateParams, ca: &CertifiedIssuer<'_, KeyPair>) -> Result<()> {
    private_dir(dir)?;
    let key = KeyPair::generate()?;
    let certificate = params.signed_by(&key, ca)?;
    write_new(&dir.join("cert.pem"), certificate.pem().as_bytes())?;
    write_new(&dir.join("key.pem"), key.serialize_pem().as_bytes())?;
    write_new(&dir.join("ca.pem"), ca.pem().as_bytes())?;
    Ok(())
}
fn private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
fn write_new(path: &Path, body: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .with_context(|| {
            format!(
                "create {} without overwriting existing files",
                path.display()
            )
        })?
        .write_all(body)?;
    Ok(())
}
fn quoted(value: &str) -> String {
    toml_string(value)
}
fn toml_string(value: &str) -> String {
    // TOML basic strings share these JSON-style escapes.
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
    )
}
