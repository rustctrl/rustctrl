//! Shared identities and configuration for the RustCtrl bootstrap.
#![forbid(unsafe_code)]

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    fmt, fs,
    path::{Path, PathBuf},
    str::FromStr,
};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeviceId(Uuid);

impl DeviceId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
    pub fn certificate_name(self) -> String {
        format!("{self}.agent.rustctrl.internal")
    }
}
impl Default for DeviceId {
    fn default() -> Self {
        Self::new()
    }
}
impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl FromStr for DeviceId {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        let id = Uuid::parse_str(value).context("device_id must be a UUID")?;
        ensure!(!id.is_nil(), "device_id must not be the nil UUID");
        Ok(Self(id))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub endpoint: String,
    pub domain_name: String,
    pub ca_certificate: PathBuf,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
}
impl ClientConfig {
    pub fn resolve_paths(&mut self, base: &Path) {
        resolve(base, &mut self.ca_certificate);
        resolve(base, &mut self.certificate);
        resolve(base, &mut self.private_key);
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.endpoint.starts_with("https://"),
            "server endpoint must use https://"
        );
        ensure!(
            !self.domain_name.trim().is_empty(),
            "TLS domain_name is required"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerConfig {
    pub server: ClientConfig,
}
impl ControllerConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let mut config: Self = read_config(path)?;
        config.server.resolve_paths(config_base(path));
        config.server.validate()?;
        Ok(config)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    pub device_id: DeviceId,
    pub name: String,
    #[serde(default = "default_heartbeat_seconds")]
    pub heartbeat_seconds: u64,
    #[serde(default = "default_log_file")]
    pub log_file: PathBuf,
    pub server: ClientConfig,
}
fn default_heartbeat_seconds() -> u64 {
    10
}
fn default_log_file() -> PathBuf {
    PathBuf::from("agent.log")
}
impl AgentConfig {
    pub fn save(&self, path: &Path) -> Result<()> {
        ensure!(
            !self.device_id.0.is_nil(),
            "device_id must not be the nil UUID"
        );
        ensure!(
            !self.name.trim().is_empty() && self.name.len() <= 128,
            "name must contain 1 to 128 bytes"
        );
        ensure!(
            (1..=3600).contains(&self.heartbeat_seconds),
            "heartbeat_seconds must be between 1 and 3600"
        );

        let content = toml::to_string_pretty(self).context("serialize agent config to toml")?;
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let temp_path = parent.join(format!(
            ".tmp.{}.{}",
            uuid::Uuid::new_v4(),
            path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("config.toml")
        ));

        let write_res = (|| -> Result<()> {
            fs::write(&temp_path, content.as_bytes())
                .context("write temporary agent config file")?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600));
            }
            fs::rename(&temp_path, path).context("atomically publish agent config file")?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
            }
            Ok(())
        })();

        if write_res.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        write_res
    }

    pub fn load(path: &Path) -> Result<Self> {
        let mut config: Self = read_config(path)?;
        ensure!(
            !config.device_id.0.is_nil(),
            "device_id must not be the nil UUID"
        );
        ensure!(
            !config.name.trim().is_empty() && config.name.len() <= 128,
            "name must contain 1 to 128 bytes"
        );
        ensure!(
            (1..=3600).contains(&config.heartbeat_seconds),
            "heartbeat_seconds must be between 1 and 3600"
        );
        config.server.resolve_paths(config_base(path));
        resolve(config_base(path), &mut config.log_file);
        config.server.validate()?;
        Ok(config)
    }
}

/// A deployment-specific installation artifact prepared by an Admin through the Controller.
///
/// Contains the server configuration, public trust material, an enrollment TLS credential,
/// and an Installation Authorization secret token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentInstallationArtifact {
    pub server_endpoint: String,
    pub domain_name: String,
    pub ca_certificate: String,
    pub enrollment_certificate: String,
    pub enrollment_private_key: String,
    pub authorization_id: String,
    pub installation_secret: String,
    pub created_at_unix_ms: i64,
}

impl AgentInstallationArtifact {
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let content =
            toml::to_string_pretty(self).context("serialize installation artifact to toml")?;
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, content.as_bytes())
            .with_context(|| format!("write installation artifact to {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    pub fn load_from_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("read installation artifact from {}", path.display()))?;
        toml::from_str::<Self>(&content)
            .with_context(|| format!("parse installation artifact from {}", path.display()))
    }
}

/// Returns true if the provided slice contains a valid Windows PE header (MZ at offset 0, valid PE signature at e_lfanew).
pub fn is_windows_pe_executable(data: &[u8]) -> bool {
    if data.len() < 64 {
        return false;
    }
    if data[0..2] != [0x4d, 0x5a] {
        return false;
    }
    let pe_offset = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap_or([0; 4])) as usize;
    if pe_offset.checked_add(4).is_none() || pe_offset + 4 > data.len() {
        return false;
    }
    data[pe_offset..pe_offset + 4] == [0x50, 0x45, 0x00, 0x00]
}

/// Generates a minimal valid mock Windows PE executable header for testing.
pub fn mock_windows_pe_binary() -> Vec<u8> {
    let mut bin = vec![0u8; 256];
    bin[0] = b'M';
    bin[1] = b'Z';
    bin[0x3c] = 0x80;
    bin[0x80] = b'P';
    bin[0x81] = b'E';
    bin[0x82] = 0;
    bin[0x83] = 0;
    bin
}

/// A ready-to-install Windows Agent package prepared by the Controller.
///
/// Contains the pinned Agent executable, the deployment's installation authorization artifact,
/// PowerShell installation and uninstallation scripts, and technician instructions.
#[derive(Debug, Clone)]
pub struct AgentInstallationPackage {
    pub artifact: AgentInstallationArtifact,
    pub agent_binary: Vec<u8>,
}

impl AgentInstallationPackage {
    pub fn new(artifact: AgentInstallationArtifact, agent_binary: Vec<u8>) -> Result<Self> {
        ensure!(!agent_binary.is_empty(), "agent binary must not be empty");
        ensure!(
            is_windows_pe_executable(&agent_binary),
            "agent binary must be a Windows PE executable (starting with MZ/PE header); Linux diagnostic binaries are not supported for Windows packages"
        );
        Ok(Self {
            artifact,
            agent_binary,
        })
    }

    pub fn files(&self) -> Result<Vec<(String, Vec<u8>)>> {
        let artifact_toml = toml::to_string_pretty(&self.artifact)
            .context("serialize installation artifact to toml")?;
        let install_ps1 = powershell_install_script();
        let uninstall_ps1 = powershell_uninstall_script();
        let readme = package_readme();

        Ok(vec![
            ("rustctrl-agent.exe".to_string(), self.agent_binary.clone()),
            ("artifact.toml".to_string(), artifact_toml.into_bytes()),
            ("install.ps1".to_string(), install_ps1.into_bytes()),
            ("uninstall.ps1".to_string(), uninstall_ps1.into_bytes()),
            ("README.txt".to_string(), readme.into_bytes()),
        ])
    }

    pub fn assemble_to_dir(&self, target_dir: &Path) -> Result<()> {
        fs::create_dir_all(target_dir)
            .with_context(|| format!("create package directory {}", target_dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(target_dir, fs::Permissions::from_mode(0o700));
        }
        for (name, content) in self.files()? {
            let file_path = target_dir.join(&name);
            #[cfg(unix)]
            {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let mode = if name == "rustctrl-agent.exe" || name.ends_with(".ps1") {
                    0o700
                } else {
                    0o600
                };
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(mode)
                    .open(&file_path)
                    .with_context(|| format!("create package file {}", file_path.display()))?;
                file.write_all(&content)
                    .with_context(|| format!("write package file {}", file_path.display()))?;
            }
            #[cfg(not(unix))]
            {
                fs::write(&file_path, &content)
                    .with_context(|| format!("write package file {}", file_path.display()))?;
            }
        }
        Ok(())
    }

    pub fn assemble_to_zip(&self, zip_path: &Path) -> Result<()> {
        if let Some(parent) = zip_path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        let files = self.files()?;
        let file_refs: Vec<(&str, &[u8])> = files
            .iter()
            .map(|(name, content)| (name.as_str(), content.as_slice()))
            .collect();
        write_zip_archive(zip_path, &file_refs)
    }

    pub fn export(&self, output_path: &Path) -> Result<()> {
        let is_zip = output_path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("zip"))
            .unwrap_or(false);

        if is_zip {
            self.assemble_to_zip(output_path)
        } else {
            self.assemble_to_dir(output_path)
        }
    }
}

/// Resolves the pinned Agent executable to package.
///
/// Checks explicit path first, then `RUSTCTRL_AGENT_BINARY` environment variable,
/// followed by executable-adjacent and workspace target directories.
pub fn resolve_agent_binary(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit.filter(|p| !p.as_os_str().is_empty()) {
        ensure!(
            path.exists(),
            "pinned agent executable not found at '{}'",
            path.display()
        );
        let data = fs::read(path)
            .with_context(|| format!("read candidate binary from '{}'", path.display()))?;
        ensure!(
            is_windows_pe_executable(&data),
            "specified binary '{}' is not a Windows PE executable",
            path.display()
        );
        return Ok(path.to_path_buf());
    }

    if let Some(val) = std::env::var_os("RUSTCTRL_AGENT_BINARY") {
        let path = PathBuf::from(val);
        if path.exists()
            && let Ok(data) = fs::read(&path)
            && is_windows_pe_executable(&data)
        {
            return Ok(path);
        }
    }

    if let Ok(current_exe) = std::env::current_exe()
        && let Some(parent) = current_exe.parent()
    {
        let candidate_exe = parent.join("rustctrl-agent.exe");
        if candidate_exe.exists()
            && let Ok(data) = fs::read(&candidate_exe)
            && is_windows_pe_executable(&data)
        {
            return Ok(candidate_exe);
        }
    }

    let search_paths = [
        "rustctrl-agent.exe",
        "target/x86_64-pc-windows-msvc/debug/rustctrl-agent.exe",
        "target/x86_64-pc-windows-msvc/release/rustctrl-agent.exe",
        "target/x86_64-pc-windows-gnu/debug/rustctrl-agent.exe",
        "target/x86_64-pc-windows-gnu/release/rustctrl-agent.exe",
        "target/debug/rustctrl-agent.exe",
        "target/release/rustctrl-agent.exe",
        ".local/bin/rustctrl-agent.exe",
    ];

    for rel in search_paths {
        let candidate = PathBuf::from(rel);
        if candidate.exists()
            && let Ok(data) = fs::read(&candidate)
            && is_windows_pe_executable(&data)
        {
            return Ok(candidate);
        }
    }

    anyhow::bail!(
        "pinned Windows agent executable not found; specify path via --agent-binary or RUSTCTRL_AGENT_BINARY"
    )
}

pub fn powershell_install_script() -> String {
    r#"<#
.SYNOPSIS
    Installs or updates the RustCtrl Agent Windows Service.
.DESCRIPTION
    Configures the RustCtrl Agent as a Windows Service with Automatic startup,
    restricts file permissions on credentials to SYSTEM and Administrators,
    and starts the service so it can automatically enroll and connect to the Server.
    If an existing installation is found, it updates the binary and preserves the
    existing Device ID and credentials.
.PARAMETER TargetDir
    The directory where the agent executable and configuration/state will be stored.
    Defaults to "$env:ProgramData\RustCtrl".
.PARAMETER ServiceName
    The name of the Windows service. Defaults to "RustCtrlAgent".
.PARAMETER DisplayName
    The display name of the Windows service. Defaults to "RustCtrl Agent Service".
#>
[CmdletBinding()]
param(
    [string]$TargetDir = "$env:ProgramData\RustCtrl",
    [string]$ServiceName = "RustCtrlAgent",
    [string]$DisplayName = "RustCtrl Agent Service"
)

$ErrorActionPreference = "Stop"

# Verify Administrator privileges
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator. Please run PowerShell as Administrator."
    exit 1
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SourceExe = Join-Path $ScriptDir "rustctrl-agent.exe"
$SourceArtifact = Join-Path $ScriptDir "artifact.toml"

if (-not (Test-Path $SourceExe)) {
    Write-Error "Agent binary 'rustctrl-agent.exe' not found in package directory ($ScriptDir)."
    exit 1
}

Write-Host "Installing/Updating RustCtrl Agent..." -ForegroundColor Cyan
Write-Host "Target Directory: $TargetDir"
Write-Host "Service Name:     $ServiceName"

# Create target directory if it does not exist
if (-not (Test-Path $TargetDir)) {
    New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
}

# Restrict permissions on TargetDir: Only SYSTEM (S-1-5-18) and BUILTIN\Administrators (S-1-5-32-544)
try {
    $acl = Get-Acl $TargetDir
    $acl.SetAccessRuleProtection($true, $false)
    $adminSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $systemSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule($adminSid, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule($systemSid, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.PurgeAccessRules($adminSid)
    $acl.PurgeAccessRules($systemSid)
    $acl.AddAccessRule($adminRule)
    $acl.AddAccessRule($systemRule)
    Set-Acl -Path $TargetDir -AclObject $acl
} catch {
    Write-Warning "Could not configure ACLs via Set-Acl: $_. Trying icacls..."
    icacls "$TargetDir" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" /grant:r "*S-1-5-32-544:(OI)(CI)F" | Out-Null
}

# Stop existing service if it exists and is running
$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Host "Existing service '$ServiceName' detected (Status: $($existingService.Status)). Stopping..."
    if ($existingService.Status -ne "Stopped") {
        Stop-Service -Name $ServiceName -Force
        $existingService.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(20))
    }
}

# Copy binary to TargetDir
$DestExe = Join-Path $TargetDir "rustctrl-agent.exe"
Copy-Item -Path $SourceExe -Destination $DestExe -Force

# Check for existing identity/config
$ConfigPath = Join-Path $TargetDir "config.toml"
$ArtifactPath = Join-Path $TargetDir "artifact.toml"

if (Test-Path $ConfigPath) {
    Write-Host "Existing configuration found at '$ConfigPath'. Preserving Device identity for update." -ForegroundColor Green
} else {
    if (Test-Path $SourceArtifact) {
        Write-Host "Copying fresh installation authorization artifact to '$ArtifactPath'..."
        Copy-Item -Path $SourceArtifact -Destination $ArtifactPath -Force
    } else {
        Write-Error "Neither existing 'config.toml' nor 'artifact.toml' found in package."
        exit 1
    }
}

# Register or update Windows Service
$binaryCommandLine = "`"$DestExe`" service --target-dir `"$TargetDir`" --artifact `"$ArtifactPath`""

if (-not $existingService) {
    Write-Host "Registering new Windows service '$ServiceName'..."
    New-Service -Name $ServiceName `
                -BinaryPathName $binaryCommandLine `
                -DisplayName $DisplayName `
                -StartupType Automatic `
                -Description "RustCtrl Windows Agent service for fleet management and monitoring" | Out-Null
} else {
    Write-Host "Updating existing Windows service '$ServiceName' configuration..."
    & sc.exe config $ServiceName "binPath=$binaryCommandLine" start= auto | Out-Null
}

# Configure failure actions to restart service automatically on crash
& sc.exe failure $ServiceName reset= 86400 "actions=restart/5000/restart/10000/restart/60000" | Out-Null

# Start the service
Write-Host "Starting '$ServiceName'..."
Start-Service -Name $ServiceName
$service = Get-Service -Name $ServiceName
$service.WaitForStatus("Running", [TimeSpan]::FromSeconds(20))

Write-Host "RustCtrl Agent service installed and started successfully!" -ForegroundColor Green
Write-Host "The service will automatically enroll and appear in the Fleet Inventory."
"#.to_string()
}

pub fn powershell_uninstall_script() -> String {
    r#"<#
.SYNOPSIS
    Stops and removes the RustCtrl Agent Windows Service.
.DESCRIPTION
    Stops the RustCtrl Agent service and deletes it from Service Control Manager.
    Local credentials and configuration are preserved so that subsequent
    installations can retain the same Device ID. The endpoint will appear offline
    in the RustCtrl Fleet Inventory until an Admin performs inventory cleanup.
.PARAMETER ServiceName
    The name of the Windows service. Defaults to "RustCtrlAgent".
.PARAMETER TargetDir
    The directory where the agent executable and credentials reside. Defaults to "$env:ProgramData\RustCtrl".
#>
[CmdletBinding()]
param(
    [string]$ServiceName = "RustCtrlAgent",
    [string]$TargetDir = "$env:ProgramData\RustCtrl"
)

$ErrorActionPreference = "Stop"

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator. Please run PowerShell as Administrator."
    exit 1
}

Write-Host "Uninstalling RustCtrl Agent service '$ServiceName'..." -ForegroundColor Cyan

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne "Stopped") {
        Write-Host "Stopping service '$ServiceName'..."
        Stop-Service -Name $ServiceName -Force
        $service.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(20))
    }
    Write-Host "Deleting service from Service Control Manager..."
    & sc.exe delete $ServiceName | Out-Null
    Write-Host "Service '$ServiceName' deleted." -ForegroundColor Green
} else {
    Write-Host "Service '$ServiceName' is not registered." -ForegroundColor Yellow
}

Write-Host "Local configuration and Device identity in '$TargetDir' preserved."
Write-Host "The Device will remain listed as offline in RustCtrl Fleet Inventory until an Admin performs inventory cleanup."
"#.to_string()
}

pub fn package_readme() -> String {
    r#"RustCtrl Windows Agent Installation Package
============================================

This package contains the RustCtrl Windows Agent and authorization to automatically
enroll this computer into the RustCtrl Fleet Inventory.

INSTALLATION:
1. Open PowerShell as Administrator (Right click -> Run as Administrator).
2. Navigate to this directory:
   cd <path-to-extracted-package>
3. Run the installation script:
   powershell -ExecutionPolicy Bypass -File .\install.ps1

The agent will be installed as a Windows service ('RustCtrlAgent') with Automatic startup,
secure local state in ProgramData\RustCtrl, automatically enroll with the RustCtrl Server,
and begin sending heartbeats.

UPDATING AN EXISTING AGENT:
Run the same install.ps1 script on a machine with an existing agent.
The installer will stop the service, update the binary, preserve the existing Device ID
and credentials, and restart the service.

UNINSTALLATION:
To stop and remove the agent service:
   powershell -ExecutionPolicy Bypass -File .\uninstall.ps1
Note: The computer will be shown as offline in the RustCtrl Fleet Inventory until an
Admin performs an inventory cleanup.
"#
    .to_string()
}

/// Computes ISO 3309 / PKZIP standard CRC-32.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xedb8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Creates a standard PKZIP 2.0 uncompressed (STORE) zip archive.
pub fn write_zip_archive(path: &Path, files: &[(&str, &[u8])]) -> Result<()> {
    let mut out = Vec::new();
    let mut central_directory = Vec::new();

    for (name, data) in files {
        let name_bytes = name.as_bytes();
        let crc = crc32(data);
        let size = data.len() as u32;
        let local_header_offset = out.len() as u32;

        // Local file header (30 bytes + name + data)
        out.extend_from_slice(&0x04034b50_u32.to_le_bytes()); // signature
        out.extend_from_slice(&20_u16.to_le_bytes()); // version needed: 2.0
        out.extend_from_slice(&0x0800_u16.to_le_bytes()); // bit flag: UTF-8
        out.extend_from_slice(&0_u16.to_le_bytes()); // compression method: 0 (STORE)
        out.extend_from_slice(&0_u16.to_le_bytes()); // last mod file time
        out.extend_from_slice(&0_u16.to_le_bytes()); // last mod file date
        out.extend_from_slice(&crc.to_le_bytes()); // crc-32
        out.extend_from_slice(&size.to_le_bytes()); // compressed size
        out.extend_from_slice(&size.to_le_bytes()); // uncompressed size
        out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes()); // filename length
        out.extend_from_slice(&0_u16.to_le_bytes()); // extra field length
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(data);

        // Central directory entry (46 bytes + name)
        central_directory.extend_from_slice(&0x02014b50_u32.to_le_bytes()); // signature
        central_directory.extend_from_slice(&0x003f_u16.to_le_bytes()); // version made by: DOS/Windows
        central_directory.extend_from_slice(&20_u16.to_le_bytes()); // version needed: 2.0
        central_directory.extend_from_slice(&0x0800_u16.to_le_bytes()); // bit flag: UTF-8
        central_directory.extend_from_slice(&0_u16.to_le_bytes()); // compression method: 0 (STORE)
        central_directory.extend_from_slice(&0_u16.to_le_bytes()); // last mod file time
        central_directory.extend_from_slice(&0_u16.to_le_bytes()); // last mod file date
        central_directory.extend_from_slice(&crc.to_le_bytes()); // crc-32
        central_directory.extend_from_slice(&size.to_le_bytes()); // compressed size
        central_directory.extend_from_slice(&size.to_le_bytes()); // uncompressed size
        central_directory.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes()); // filename length
        central_directory.extend_from_slice(&0_u16.to_le_bytes()); // extra field length
        central_directory.extend_from_slice(&0_u16.to_le_bytes()); // comment length
        central_directory.extend_from_slice(&0_u16.to_le_bytes()); // disk number start
        central_directory.extend_from_slice(&0_u16.to_le_bytes()); // internal file attributes
        central_directory.extend_from_slice(&0_u32.to_le_bytes()); // external file attributes
        central_directory.extend_from_slice(&local_header_offset.to_le_bytes()); // local header offset
        central_directory.extend_from_slice(name_bytes);
    }

    let cd_offset = out.len() as u32;
    let cd_size = central_directory.len() as u32;
    out.extend_from_slice(&central_directory);

    // End of central directory record (22 bytes)
    out.extend_from_slice(&0x06054b50_u32.to_le_bytes()); // signature
    out.extend_from_slice(&0_u16.to_le_bytes()); // number of this disk
    out.extend_from_slice(&0_u16.to_le_bytes()); // disk where central directory starts
    out.extend_from_slice(&(files.len() as u16).to_le_bytes()); // number of central directory records on this disk
    out.extend_from_slice(&(files.len() as u16).to_le_bytes()); // total number of central directory records
    out.extend_from_slice(&cd_size.to_le_bytes()); // size of central directory
    out.extend_from_slice(&cd_offset.to_le_bytes()); // offset of start of central directory
    out.extend_from_slice(&0_u16.to_le_bytes()); // comment length

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("create zip file {}", path.display()))?;
        file.write_all(&out)
            .with_context(|| format!("write zip archive to {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        fs::write(path, out).with_context(|| format!("write zip archive to {}", path.display()))?;
    }
    Ok(())
}

/// Reads uncompressed entries from a standard PKZIP archive.
pub fn read_zip_entries(path: &Path) -> Result<std::collections::HashMap<String, Vec<u8>>> {
    let data = fs::read(path).with_context(|| format!("read zip file {}", path.display()))?;
    ensure!(data.len() >= 22, "file too small to be a valid zip archive");

    // Scan backwards for End of Central Directory signature: 0x06054b50
    let mut eocd_pos = None;
    for i in (0..=data.len() - 22).rev() {
        if data[i..i + 4] == [0x50, 0x4b, 0x05, 0x06] {
            eocd_pos = Some(i);
            break;
        }
    }
    let eocd_pos = eocd_pos.context("end of central directory record not found")?;

    let total_entries = u16::from_le_bytes(data[eocd_pos + 10..eocd_pos + 12].try_into()?) as usize;
    let cd_offset = u32::from_le_bytes(data[eocd_pos + 16..eocd_pos + 20].try_into()?) as usize;

    let mut entries = std::collections::HashMap::new();
    let mut cd_ptr = cd_offset;

    for _ in 0..total_entries {
        ensure!(cd_ptr + 46 <= data.len(), "corrupted central directory");
        ensure!(
            data[cd_ptr..cd_ptr + 4] == [0x50, 0x4b, 0x01, 0x02],
            "invalid central directory header signature"
        );

        let compression = u16::from_le_bytes(data[cd_ptr + 10..cd_ptr + 12].try_into()?);
        ensure!(
            compression == 0,
            "only uncompressed zip entries are currently supported"
        );

        let expected_crc = u32::from_le_bytes(data[cd_ptr + 16..cd_ptr + 20].try_into()?);
        let uncompressed_size =
            u32::from_le_bytes(data[cd_ptr + 24..cd_ptr + 28].try_into()?) as usize;
        let filename_len = u16::from_le_bytes(data[cd_ptr + 28..cd_ptr + 30].try_into()?) as usize;
        let extra_len = u16::from_le_bytes(data[cd_ptr + 30..cd_ptr + 32].try_into()?) as usize;
        let comment_len = u16::from_le_bytes(data[cd_ptr + 32..cd_ptr + 34].try_into()?) as usize;
        let local_header_offset =
            u32::from_le_bytes(data[cd_ptr + 42..cd_ptr + 46].try_into()?) as usize;

        let filename_start = cd_ptr + 46;
        let filename_bytes = &data[filename_start..filename_start + filename_len];
        let filename = String::from_utf8_lossy(filename_bytes).into_owned();

        cd_ptr += 46 + filename_len + extra_len + comment_len;

        // Read data from local file header
        ensure!(
            local_header_offset + 30 <= data.len(),
            "corrupted local file header offset"
        );
        ensure!(
            data[local_header_offset..local_header_offset + 4] == [0x50, 0x4b, 0x03, 0x04],
            "invalid local file header signature"
        );
        let local_name_len = u16::from_le_bytes(
            data[local_header_offset + 26..local_header_offset + 28].try_into()?,
        ) as usize;
        let local_extra_len = u16::from_le_bytes(
            data[local_header_offset + 28..local_header_offset + 30].try_into()?,
        ) as usize;

        let data_start = local_header_offset + 30 + local_name_len + local_extra_len;
        let data_end = data_start + uncompressed_size;
        ensure!(data_end <= data.len(), "corrupted file data offset");

        let file_data = data[data_start..data_end].to_vec();
        ensure!(
            crc32(&file_data) == expected_crc,
            "crc32 mismatch for {}",
            filename
        );

        entries.insert(filename, file_data);
    }

    Ok(entries)
}

pub fn read_config<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let body = fs::read_to_string(path)
        .with_context(|| format!("read configuration {}", path.display()))?;
    toml::from_str(&body).with_context(|| format!("parse configuration {}", path.display()))
}
pub fn config_base(path: &Path) -> &Path {
    path.parent().unwrap_or_else(|| Path::new("."))
}
pub fn resolve(base: &Path, path: &mut PathBuf) {
    if path.is_relative() {
        *path = base.join(&*path);
    }
}
pub fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

pub fn init_file_logging(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open service log {}", path.display()))?;
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .with_writer(std::sync::Arc::new(file))
        .try_init()
        .map_err(|error| anyhow::anyhow!("initialize service logging: {error}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_config_save_and_load_escapes_special_characters() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("config.toml");
        let id = DeviceId::new();
        let special_name = r#"Office "Reception" \ A"#;

        let config = AgentConfig {
            device_id: id,
            name: special_name.into(),
            heartbeat_seconds: 15,
            log_file: PathBuf::from("agent.log"),
            server: ClientConfig {
                endpoint: "https://localhost:9876".into(),
                domain_name: "localhost".into(),
                ca_certificate: PathBuf::from("ca.pem"),
                certificate: PathBuf::from("cert.pem"),
                private_key: PathBuf::from("key.pem"),
            },
        };

        config.save(&path)?;

        let loaded = AgentConfig::load(&path)?;
        assert_eq!(loaded.device_id, id);
        assert_eq!(loaded.name, special_name);
        assert_eq!(loaded.heartbeat_seconds, 15);
        Ok(())
    }

    #[test]
    fn agent_config_save_validates_constraints() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("config.toml");

        let mut config = AgentConfig {
            device_id: DeviceId::new(),
            name: "Valid Agent".into(),
            heartbeat_seconds: 15,
            log_file: PathBuf::from("agent.log"),
            server: ClientConfig {
                endpoint: "https://localhost:9876".into(),
                domain_name: "localhost".into(),
                ca_certificate: PathBuf::from("ca.pem"),
                certificate: PathBuf::from("cert.pem"),
                private_key: PathBuf::from("key.pem"),
            },
        };

        config.heartbeat_seconds = 0;
        assert!(config.save(&path).is_err());
        assert!(!path.exists());

        config.heartbeat_seconds = 3601;
        assert!(config.save(&path).is_err());
        assert!(!path.exists());

        config.heartbeat_seconds = 10;
        config.name = "".into();
        assert!(config.save(&path).is_err());
        assert!(!path.exists());

        config.name = "A".repeat(129);
        assert!(config.save(&path).is_err());
        assert!(!path.exists());

        config.name = "Proper Agent".into();
        config.device_id = DeviceId(uuid::Uuid::nil());
        assert!(config.save(&path).is_err());
        assert!(!path.exists());

        config.device_id = DeviceId::new();
        config.save(&path)?;
        assert!(path.exists());

        Ok(())
    }

    #[test]
    fn agent_installation_package_exports_to_directory_and_zip() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let artifact = AgentInstallationArtifact {
            server_endpoint: "https://rustctrl.office.internal:9876".into(),
            domain_name: "rustctrl.office.internal".into(),
            ca_certificate: "TEST_CA_CERT".into(),
            enrollment_certificate: "TEST_ENROLL_CERT".into(),
            enrollment_private_key: "TEST_ENROLL_KEY".into(),
            authorization_id: "auth-win-42".into(),
            installation_secret: "secret-token-xyz".into(),
            created_at_unix_ms: 1700000000000,
        };
        let agent_binary = mock_windows_pe_binary();
        let package = AgentInstallationPackage::new(artifact.clone(), agent_binary.clone())?;

        // 1. Export to directory
        let package_dir = dir.path().join("pkg-dir");
        package.export(&package_dir)?;

        assert!(package_dir.join("rustctrl-agent.exe").exists());
        assert!(package_dir.join("artifact.toml").exists());
        assert!(package_dir.join("install.ps1").exists());
        assert!(package_dir.join("uninstall.ps1").exists());
        assert!(package_dir.join("README.txt").exists());

        assert_eq!(
            std::fs::read(package_dir.join("rustctrl-agent.exe"))?,
            agent_binary
        );
        let loaded_art =
            AgentInstallationArtifact::load_from_file(&package_dir.join("artifact.toml"))?;
        assert_eq!(loaded_art, artifact);

        let install_ps1 = std::fs::read_to_string(package_dir.join("install.ps1"))?;
        assert!(install_ps1.contains("RustCtrlAgent"));
        assert!(install_ps1.contains("New-Service"));
        assert!(install_ps1.contains("config.toml"));

        let uninstall_ps1 = std::fs::read_to_string(package_dir.join("uninstall.ps1"))?;
        assert!(uninstall_ps1.contains("RustCtrlAgent"));
        assert!(uninstall_ps1.contains("sc.exe delete"));

        // 2. Export to .zip file
        let zip_file = dir.path().join("agent-package.zip");
        package.export(&zip_file)?;
        assert!(zip_file.exists());
        assert!(std::fs::metadata(&zip_file)?.len() > 0);

        // Verify zip entries
        let entries = read_zip_entries(&zip_file)?;
        assert!(entries.contains_key("rustctrl-agent.exe"));
        assert!(entries.contains_key("artifact.toml"));
        assert!(entries.contains_key("install.ps1"));
        assert!(entries.contains_key("uninstall.ps1"));
        assert!(entries.contains_key("README.txt"));

        assert_eq!(entries.get("rustctrl-agent.exe").unwrap(), &agent_binary);

        // 3. Validation: empty agent binary rejected
        assert!(AgentInstallationPackage::new(artifact, vec![]).is_err());

        Ok(())
    }
}
