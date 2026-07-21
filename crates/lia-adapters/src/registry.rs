use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use lia_verify::resolve_and_hash_executable;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::Builder;
use thiserror::Error;

const REGISTRY_EVIDENCE_VERSION: &str = "lia-registry-evidence-v1";
const MAX_REGISTRY_BODY_BYTES: u64 = 1_048_576;
const MAX_CLIENT_OUTPUT_BYTES: usize = 65_536;

#[derive(Debug, Error)]
pub enum RegistryEvidenceError {
    #[error("invalid registry request: {0}")]
    Invalid(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RegistryEcosystem {
    CratesIo,
    Npm,
}

impl RegistryEcosystem {
    pub fn parse(value: &str) -> Result<Self, RegistryEvidenceError> {
        match value {
            "crates-io" | "crates.io" | "cargo" => Ok(Self::CratesIo),
            "npm" => Ok(Self::Npm),
            other => Err(RegistryEvidenceError::Invalid(format!(
                "unsupported ecosystem '{other}'; expected crates-io or npm"
            ))),
        }
    }

    fn default_base_url(self) -> &'static str {
        match self {
            Self::CratesIo => "https://index.crates.io",
            Self::Npm => "https://registry.npmjs.org",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RegistryEvidenceOptions {
    pub ecosystem: RegistryEcosystem,
    pub package: String,
    pub version: Option<String>,
    pub cache_dir: PathBuf,
    pub offline: bool,
    pub http_client: PathBuf,
    pub expected_http_client_sha256: Option<String>,
    pub timeout_seconds: u64,
    pub base_url: Option<String>,
    pub expected_response_sha256: Option<String>,
    pub expected_cache_manifest_sha256: Option<String>,
    pub max_cache_age_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegistryEvidenceReport {
    pub evidence_version: String,
    pub accepted: bool,
    pub reason_code: String,
    pub ecosystem: RegistryEcosystem,
    pub package: String,
    pub requested_version: Option<String>,
    pub package_exists: bool,
    pub version_exists: Option<bool>,
    pub versions: Vec<String>,
    pub source: String,
    pub source_url: String,
    pub fetched_at: String,
    pub http_status: u16,
    pub http_client_sha256: String,
    pub response_sha256: String,
    pub response_bytes: u64,
    pub cache_age_seconds: Option<u64>,
    pub cache_manifest_sha256: String,
    pub cache_body_path: PathBuf,
    pub cache_metadata_path: PathBuf,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheMetadata {
    evidence_version: String,
    ecosystem: RegistryEcosystem,
    package: String,
    source_url: String,
    fetched_at: String,
    http_status: u16,
    http_client_sha256: String,
    response_sha256: String,
    response_bytes: u64,
}

pub fn collect_registry_evidence(
    options: &RegistryEvidenceOptions,
) -> Result<RegistryEvidenceReport, RegistryEvidenceError> {
    validate_request(options)?;
    fs::create_dir_all(&options.cache_dir)?;
    let authoritative_base = options.ecosystem.default_base_url();
    let base = options
        .base_url
        .as_deref()
        .unwrap_or(authoritative_base)
        .trim_end_matches('/');
    if base != authoritative_base {
        return Err(RegistryEvidenceError::Invalid(format!(
            "custom registry origins cannot produce VERIFIED evidence; expected {authoritative_base}"
        )));
    }
    let source_url = registry_url(options.ecosystem, base, &options.package);
    let cache_key = sha256(
        format!(
            "{:?}\n{}\n{}",
            options.ecosystem, options.package, source_url
        )
        .as_bytes(),
    );
    let cache_body_path = options.cache_dir.join(format!("{cache_key}.body"));
    let cache_metadata_path = options.cache_dir.join(format!("{cache_key}.json"));

    if options.offline {
        return from_cache(options, &source_url, &cache_body_path, &cache_metadata_path);
    }

    let expected_client_sha256 =
        options
            .expected_http_client_sha256
            .as_deref()
            .ok_or_else(|| {
                RegistryEvidenceError::Invalid(
                    "live registry evidence requires expected_http_client_sha256".into(),
                )
            })?;
    if !is_sha256(expected_client_sha256) {
        return Err(RegistryEvidenceError::Invalid(
            "expected_http_client_sha256 must be a 64-character hex digest".into(),
        ));
    }
    let (resolved_http_client, http_client_sha256) =
        resolve_and_hash_executable(&options.http_client)
            .map_err(|error| RegistryEvidenceError::Invalid(error.to_string()))?;
    if !http_client_sha256.eq_ignore_ascii_case(expected_client_sha256) {
        return Err(RegistryEvidenceError::Invalid(format!(
            "REGISTRY_CLIENT_DIGEST_MISMATCH: expected {expected_client_sha256}, got {http_client_sha256}"
        )));
    }

    let temp = Builder::new()
        .prefix("lia-registry-")
        .suffix(".body")
        .tempfile_in(&options.cache_dir)?;
    let temp_path = temp.into_temp_path();
    let fetch = fetch_with_curl(options, &resolved_http_client, &source_url, &temp_path)?;
    if fetch.timed_out {
        return Ok(failure_report(
            options,
            source_url,
            "live",
            "REGISTRY_FETCH_TIMEOUT",
            "registry client exceeded its deadline",
            fetch.http_status,
            cache_body_path,
            cache_metadata_path,
        ));
    }
    if fetch.exit_code != Some(0) {
        return Ok(failure_report(
            options,
            source_url,
            "live",
            "REGISTRY_FETCH_FAILED",
            bounded_detail(&fetch.stderr),
            fetch.http_status,
            cache_body_path,
            cache_metadata_path,
        ));
    }

    let metadata = fs::metadata(&temp_path)?;
    if metadata.len() > MAX_REGISTRY_BODY_BYTES {
        return Ok(failure_report(
            options,
            source_url,
            "live",
            "REGISTRY_RESPONSE_TOO_LARGE",
            format!(
                "registry response {} bytes exceeds {} byte limit",
                metadata.len(),
                MAX_REGISTRY_BODY_BYTES
            ),
            fetch.http_status,
            cache_body_path,
            cache_metadata_path,
        ));
    }
    let body = fs::read(&temp_path)?;
    let response_sha256 = sha256(&body);
    let fetched_at = Utc::now().to_rfc3339();
    let cache_metadata = CacheMetadata {
        evidence_version: REGISTRY_EVIDENCE_VERSION.into(),
        ecosystem: options.ecosystem,
        package: options.package.clone(),
        source_url: source_url.clone(),
        fetched_at: fetched_at.clone(),
        http_status: fetch.http_status,
        http_client_sha256: http_client_sha256.clone(),
        response_sha256: response_sha256.clone(),
        response_bytes: body.len() as u64,
    };
    temp_path
        .persist(&cache_body_path)
        .map_err(|error| error.error)?;
    atomic_write_json(&cache_metadata_path, &cache_metadata)?;
    let cache_manifest_sha256 = sha256(&fs::read(&cache_metadata_path)?);
    build_report(
        options,
        source_url,
        "live",
        fetched_at,
        fetch.http_status,
        http_client_sha256,
        response_sha256,
        body,
        None,
        cache_manifest_sha256,
        cache_body_path,
        cache_metadata_path,
    )
}

struct FetchResult {
    exit_code: Option<i32>,
    timed_out: bool,
    http_status: u16,
    stderr: Vec<u8>,
}

fn fetch_with_curl(
    options: &RegistryEvidenceOptions,
    http_client: &Path,
    url: &str,
    output: &Path,
) -> Result<FetchResult, RegistryEvidenceError> {
    let mut command = Command::new(http_client);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command
        .args([
            "--silent",
            "--show-error",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--max-time",
            &options.timeout_seconds.to_string(),
            "--connect-timeout",
            &options.timeout_seconds.min(10).to_string(),
            "--max-filesize",
            &MAX_REGISTRY_BODY_BYTES.to_string(),
            "--output",
        ])
        .arg(output)
        .args(["--write-out", "%{http_code}", url])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().ok_or_else(|| {
        RegistryEvidenceError::Invalid("registry client stdout unavailable".into())
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        RegistryEvidenceError::Invalid("registry client stderr unavailable".into())
    })?;
    let (stdout_tx, stdout_rx) = mpsc::sync_channel(1);
    let (stderr_tx, stderr_rx) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = stdout_tx.send(read_capped(stdout));
    });
    thread::spawn(move || {
        let _ = stderr_tx.send(read_capped(stderr));
    });
    let started = Instant::now();
    let timeout = Duration::from_secs(options.timeout_seconds);
    let (exit_code, mut timed_out) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (status.code(), false),
            Ok(None) if started.elapsed() >= timeout => {
                let status = terminate_and_reap(&mut child);
                break (status.code(), true);
            }
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(error) => {
                terminate_and_reap(&mut child);
                return Err(RegistryEvidenceError::Io(error));
            }
        }
    };
    let mut stdout = match recv_until(&stdout_rx, started + timeout) {
        Ok(value) => value,
        Err(error) => {
            kill_process_group(child.id());
            return Err(error);
        }
    };
    let mut stderr = match recv_until(&stderr_rx, started + timeout) {
        Ok(value) => value,
        Err(error) => {
            kill_process_group(child.id());
            return Err(error);
        }
    };
    if stdout.is_none() || stderr.is_none() {
        timed_out = true;
        kill_process_group(child.id());
        let drain_deadline = Instant::now() + Duration::from_secs(1);
        if stdout.is_none() {
            stdout = recv_until(&stdout_rx, drain_deadline)?;
        }
        if stderr.is_none() {
            stderr = recv_until(&stderr_rx, drain_deadline)?;
        }
    }
    let stdout = stdout.unwrap_or_default();
    let stderr = stderr.unwrap_or_default();
    let http_status = String::from_utf8_lossy(&stdout)
        .trim()
        .parse::<u16>()
        .unwrap_or(0);
    Ok(FetchResult {
        exit_code,
        timed_out,
        http_status,
        stderr,
    })
}

fn from_cache(
    options: &RegistryEvidenceOptions,
    source_url: &str,
    body_path: &Path,
    metadata_path: &Path,
) -> Result<RegistryEvidenceReport, RegistryEvidenceError> {
    let expected_response_sha256 = options
        .expected_response_sha256
        .as_deref()
        .filter(|value| is_sha256(value));
    let Some(expected_response_sha256) = expected_response_sha256 else {
        return Ok(failure_report(
            options,
            source_url.into(),
            "cache",
            "REGISTRY_CACHE_DIGEST_UNPINNED",
            "offline cache acceptance requires an externally stored expected response digest",
            0,
            body_path.to_path_buf(),
            metadata_path.to_path_buf(),
        ));
    };
    let Some(expected_cache_manifest_sha256) = options
        .expected_cache_manifest_sha256
        .as_deref()
        .filter(|value| is_sha256(value))
    else {
        return Ok(failure_report(
            options,
            source_url.into(),
            "cache",
            "REGISTRY_CACHE_MANIFEST_UNPINNED",
            "offline cache acceptance requires an externally stored cache-manifest digest",
            0,
            body_path.to_path_buf(),
            metadata_path.to_path_buf(),
        ));
    };
    if !body_path.is_file() || !metadata_path.is_file() {
        return Ok(failure_report(
            options,
            source_url.into(),
            "cache",
            "REGISTRY_CACHE_MISSING",
            "offline mode requires both cached body and metadata",
            0,
            body_path.to_path_buf(),
            metadata_path.to_path_buf(),
        ));
    }
    let metadata_bytes = fs::read(metadata_path)?;
    let cache_manifest_sha256 = sha256(&metadata_bytes);
    if !cache_manifest_sha256.eq_ignore_ascii_case(expected_cache_manifest_sha256) {
        return Ok(failure_report(
            options,
            source_url.into(),
            "cache",
            "REGISTRY_CACHE_MANIFEST_PIN_MISMATCH",
            "cache metadata does not match the external manifest pin",
            0,
            body_path.to_path_buf(),
            metadata_path.to_path_buf(),
        ));
    }
    let metadata: CacheMetadata = serde_json::from_slice(&metadata_bytes)?;
    if metadata.evidence_version != REGISTRY_EVIDENCE_VERSION
        || metadata.ecosystem != options.ecosystem
        || metadata.package != options.package
        || metadata.source_url != source_url
    {
        return Ok(failure_report(
            options,
            source_url.into(),
            "cache",
            "REGISTRY_CACHE_METADATA_MISMATCH",
            "cache metadata does not match this request",
            metadata.http_status,
            body_path.to_path_buf(),
            metadata_path.to_path_buf(),
        ));
    }
    if !metadata
        .response_sha256
        .eq_ignore_ascii_case(expected_response_sha256)
    {
        return Ok(failure_report(
            options,
            source_url.into(),
            "cache",
            "REGISTRY_CACHE_EXTERNAL_PIN_MISMATCH",
            "cached response digest does not match the external pin",
            metadata.http_status,
            body_path.to_path_buf(),
            metadata_path.to_path_buf(),
        ));
    }
    let fetched_at = DateTime::parse_from_rfc3339(&metadata.fetched_at)
        .map_err(|error| RegistryEvidenceError::Invalid(format!("cache fetched_at: {error}")))?
        .with_timezone(&Utc);
    let now = Utc::now();
    if fetched_at.signed_duration_since(now).num_seconds() > 300 {
        return Ok(failure_report(
            options,
            source_url.into(),
            "cache",
            "REGISTRY_CACHE_TIME_INVALID",
            "cache fetched_at is more than five minutes in the future",
            metadata.http_status,
            body_path.to_path_buf(),
            metadata_path.to_path_buf(),
        ));
    }
    let cache_age_seconds = now.signed_duration_since(fetched_at).num_seconds().max(0) as u64;
    if cache_age_seconds > options.max_cache_age_seconds {
        return Ok(failure_report(
            options,
            source_url.into(),
            "cache",
            "REGISTRY_CACHE_STALE",
            format!(
                "cache age {cache_age_seconds}s exceeds {}s",
                options.max_cache_age_seconds
            ),
            metadata.http_status,
            body_path.to_path_buf(),
            metadata_path.to_path_buf(),
        ));
    }
    let body = fs::read(body_path)?;
    let actual_sha = sha256(&body);
    if actual_sha != metadata.response_sha256 || body.len() as u64 != metadata.response_bytes {
        return Ok(failure_report(
            options,
            source_url.into(),
            "cache",
            "REGISTRY_CACHE_HASH_MISMATCH",
            "cached response no longer matches its pinned digest and size",
            metadata.http_status,
            body_path.to_path_buf(),
            metadata_path.to_path_buf(),
        ));
    }
    build_report(
        options,
        source_url.into(),
        "cache",
        metadata.fetched_at,
        metadata.http_status,
        metadata.http_client_sha256,
        actual_sha,
        body,
        Some(cache_age_seconds),
        cache_manifest_sha256,
        body_path.to_path_buf(),
        metadata_path.to_path_buf(),
    )
}

fn terminate_and_reap(child: &mut std::process::Child) -> std::process::ExitStatus {
    kill_process_group(child.id());
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status,
            Ok(None) | Err(_) => {}
        }
        if child.kill().is_ok() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    loop {
        match child.wait() {
            Ok(status) => return status,
            Err(_) => thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn kill_process_group(child_id: u32) {
    #[cfg(unix)]
    {
        let process_group = -(child_id as i32);
        // SAFETY: the child was spawned into a new process group whose id is its pid.
        // A negative pid targets only that group; SIGKILL carries no Rust memory contract.
        unsafe {
            libc::kill(process_group, libc::SIGKILL);
        }
    }
    #[cfg(not(unix))]
    let _ = child_id;
}

#[allow(clippy::too_many_arguments)]
fn build_report(
    options: &RegistryEvidenceOptions,
    source_url: String,
    source: &str,
    fetched_at: String,
    http_status: u16,
    http_client_sha256: String,
    response_sha256: String,
    body: Vec<u8>,
    cache_age_seconds: Option<u64>,
    cache_manifest_sha256: String,
    cache_body_path: PathBuf,
    cache_metadata_path: PathBuf,
) -> Result<RegistryEvidenceReport, RegistryEvidenceError> {
    let (package_exists, versions) = match http_status {
        200..=299 => parse_versions(options.ecosystem, &body)?,
        404 | 410 | 451 => (false, Vec::new()),
        status => {
            return Ok(failure_report(
                options,
                source_url,
                source,
                "REGISTRY_HTTP_STATUS_UNEXPECTED",
                format!("registry returned HTTP {status}"),
                status,
                cache_body_path,
                cache_metadata_path,
            ))
        }
    };
    let version_exists = options
        .version
        .as_ref()
        .map(|requested| versions.iter().any(|version| version == requested));
    let (accepted, reason_code, detail) = if !package_exists {
        (
            false,
            "REGISTRY_PACKAGE_NOT_FOUND",
            "package is absent from the authoritative registry response",
        )
    } else if version_exists == Some(false) {
        (
            false,
            "REGISTRY_VERSION_NOT_FOUND",
            "requested version is absent or yanked",
        )
    } else if version_exists == Some(true) {
        if source == "cache" {
            (
                true,
                "REGISTRY_VERSION_PINNED_CACHE",
                "requested non-yanked version is present in the fresh externally pinned cache",
            )
        } else {
            (
                true,
                "REGISTRY_VERSION_VERIFIED",
                "package and requested non-yanked version are present in the authoritative live response",
            )
        }
    } else {
        if source == "cache" {
            (
                true,
                "REGISTRY_PACKAGE_PINNED_CACHE",
                "package is present in the fresh externally pinned cache",
            )
        } else {
            (
                true,
                "REGISTRY_PACKAGE_VERIFIED",
                "package is present in the authoritative live response",
            )
        }
    };
    Ok(RegistryEvidenceReport {
        evidence_version: REGISTRY_EVIDENCE_VERSION.into(),
        accepted,
        reason_code: reason_code.into(),
        ecosystem: options.ecosystem,
        package: options.package.clone(),
        requested_version: options.version.clone(),
        package_exists,
        version_exists,
        versions,
        source: source.into(),
        source_url,
        fetched_at,
        http_status,
        http_client_sha256,
        response_sha256,
        response_bytes: body.len() as u64,
        cache_age_seconds,
        cache_manifest_sha256,
        cache_body_path,
        cache_metadata_path,
        detail: detail.into(),
    })
}

fn parse_versions(
    ecosystem: RegistryEcosystem,
    body: &[u8],
) -> Result<(bool, Vec<String>), RegistryEvidenceError> {
    let mut versions = Vec::new();
    match ecosystem {
        RegistryEcosystem::CratesIo => {
            let text = std::str::from_utf8(body)
                .map_err(|error| RegistryEvidenceError::Invalid(error.to_string()))?;
            for line in text.lines().filter(|line| !line.trim().is_empty()) {
                let value: serde_json::Value = serde_json::from_str(line)?;
                if value.get("yanked").and_then(serde_json::Value::as_bool) == Some(true) {
                    continue;
                }
                if let Some(version) = value.get("vers").and_then(serde_json::Value::as_str) {
                    versions.push(version.to_string());
                }
            }
        }
        RegistryEcosystem::Npm => {
            let value: serde_json::Value = serde_json::from_slice(body)?;
            if let Some(map) = value.get("versions").and_then(serde_json::Value::as_object) {
                versions.extend(map.keys().cloned());
            }
        }
    }
    versions.sort();
    versions.dedup();
    Ok((!versions.is_empty(), versions))
}

fn validate_request(options: &RegistryEvidenceOptions) -> Result<(), RegistryEvidenceError> {
    if options.timeout_seconds == 0 || options.max_cache_age_seconds == 0 {
        return Err(RegistryEvidenceError::Invalid(
            "timeout_seconds and max_cache_age_seconds must be greater than zero".into(),
        ));
    }
    let valid = match options.ecosystem {
        RegistryEcosystem::CratesIo => {
            options.package.len() <= 64
                && options
                    .package
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_alphabetic())
                && options
                    .package
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        }
        RegistryEcosystem::Npm => {
            !options.package.is_empty()
                && options.package.len() <= 214
                && !options.package.bytes().any(|byte| byte.is_ascii_control())
                && !options.package.contains("..")
        }
    };
    if !valid {
        return Err(RegistryEvidenceError::Invalid(format!(
            "invalid package name '{}' for {:?}",
            options.package, options.ecosystem
        )));
    }
    Ok(())
}

fn registry_url(ecosystem: RegistryEcosystem, base: &str, package: &str) -> String {
    match ecosystem {
        RegistryEcosystem::CratesIo => {
            let name = package.to_ascii_lowercase();
            let prefix = match name.len() {
                1 => "1".into(),
                2 => "2".into(),
                3 => format!("3/{}", &name[..1]),
                _ => format!("{}/{}", &name[..2], &name[2..4]),
            };
            format!("{base}/{prefix}/{name}")
        }
        RegistryEcosystem::Npm => format!("{base}/{}", percent_encode(package)),
    }
}

fn percent_encode(value: &str) -> String {
    let mut output = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~' | b'@') {
            output.push(byte as char);
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
}

fn atomic_write_json(path: &Path, value: &CacheMetadata) -> Result<(), RegistryEvidenceError> {
    let parent = path.parent().ok_or_else(|| {
        RegistryEvidenceError::Invalid("cache metadata path has no parent".into())
    })?;
    let mut temp = Builder::new()
        .prefix("lia-registry-meta-")
        .suffix(".json")
        .tempfile_in(parent)?;
    serde_json::to_writer_pretty(&mut temp, value)?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|error| error.error)?;
    Ok(())
}

fn read_capped(mut reader: impl Read) -> Result<Vec<u8>, std::io::Error> {
    let mut output = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        let remaining = MAX_CLIENT_OUTPUT_BYTES.saturating_sub(output.len());
        if remaining > 0 {
            output.extend_from_slice(&chunk[..remaining.min(read)]);
        }
    }
    Ok(output)
}

fn recv_until(
    receiver: &mpsc::Receiver<Result<Vec<u8>, std::io::Error>>,
    deadline: Instant,
) -> Result<Option<Vec<u8>>, RegistryEvidenceError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Ok(None);
    }
    match receiver.recv_timeout(remaining) {
        Ok(result) => Ok(Some(result?)),
        Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(RegistryEvidenceError::Invalid(
            "registry output reader disconnected".into(),
        )),
    }
}

fn bounded_detail(stderr: &[u8]) -> String {
    let detail: String = String::from_utf8_lossy(stderr)
        .chars()
        .filter(|character| !character.is_control() || *character == '\n')
        .take(512)
        .collect();
    if detail.trim().is_empty() {
        "registry client exited nonzero".into()
    } else {
        detail
    }
}

#[allow(clippy::too_many_arguments)]
fn failure_report(
    options: &RegistryEvidenceOptions,
    source_url: String,
    source: &str,
    reason_code: &str,
    detail: impl Into<String>,
    http_status: u16,
    cache_body_path: PathBuf,
    cache_metadata_path: PathBuf,
) -> RegistryEvidenceReport {
    RegistryEvidenceReport {
        evidence_version: REGISTRY_EVIDENCE_VERSION.into(),
        accepted: false,
        reason_code: reason_code.into(),
        ecosystem: options.ecosystem,
        package: options.package.clone(),
        requested_version: options.version.clone(),
        package_exists: false,
        version_exists: options.version.as_ref().map(|_| false),
        versions: Vec::new(),
        source: source.into(),
        source_url,
        fetched_at: Utc::now().to_rfc3339(),
        http_status,
        http_client_sha256: options
            .expected_http_client_sha256
            .clone()
            .unwrap_or_default(),
        response_sha256: String::new(),
        response_bytes: 0,
        cache_age_seconds: None,
        cache_manifest_sha256: String::new(),
        cache_body_path,
        cache_metadata_path,
        detail: detail.into(),
    }
}

fn sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
