use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const MAX_VERIFIER_OUTPUT_BYTES: usize = 1_048_576;

#[derive(Debug, Error)]
pub enum PublicVerificationError {
    #[error("invalid public verification request: {0}")]
    Invalid(String),
    #[error("process io: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct PublicVerificationOptions {
    pub artifact: PathBuf,
    pub bundle: PathBuf,
    pub certificate_identity: String,
    pub certificate_oidc_issuer: String,
    pub cosign_bin: PathBuf,
    pub expected_cosign_sha256: String,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicVerificationReport {
    pub accepted: bool,
    pub reason_code: String,
    pub verifier: String,
    pub verifier_sha256: String,
    pub artifact: PathBuf,
    pub artifact_sha256: String,
    pub artifact_bytes: u64,
    pub bundle: PathBuf,
    pub bundle_sha256: String,
    pub bundle_bytes: u64,
    pub certificate_identity: String,
    pub certificate_oidc_issuer: String,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub output_truncated: bool,
    pub detail: String,
}

/// Optional Sigstore path. Verification remains delegated to the installed
/// `cosign` executable; LIA pins identity + issuer and never implements the
/// Sigstore bundle/rekor protocol itself.
pub fn verify_blob_with_cosign(
    options: &PublicVerificationOptions,
) -> Result<PublicVerificationReport, PublicVerificationError> {
    if !options.artifact.is_file() {
        return Err(PublicVerificationError::Invalid(format!(
            "artifact is not a file: {}",
            options.artifact.display()
        )));
    }
    if !options.bundle.is_file() {
        return Err(PublicVerificationError::Invalid(format!(
            "bundle is not a file: {}",
            options.bundle.display()
        )));
    }
    if options.certificate_identity.trim().is_empty()
        || options.certificate_oidc_issuer.trim().is_empty()
    {
        return Err(PublicVerificationError::Invalid(
            "certificate identity and OIDC issuer must both be pinned".into(),
        ));
    }
    if options.timeout_seconds == 0 {
        return Err(PublicVerificationError::Invalid(
            "timeout_seconds must be greater than zero".into(),
        ));
    }

    if !is_sha256(&options.expected_cosign_sha256) {
        return Err(PublicVerificationError::Invalid(
            "expected_cosign_sha256 must be a 64-character hex digest".into(),
        ));
    }
    let (resolved_cosign, verifier_sha256) = resolve_and_hash_executable(&options.cosign_bin)?;
    if !verifier_sha256.eq_ignore_ascii_case(&options.expected_cosign_sha256) {
        return Err(PublicVerificationError::Invalid(format!(
            "SIGSTORE_VERIFIER_DIGEST_MISMATCH: expected {}, got {}",
            options.expected_cosign_sha256, verifier_sha256
        )));
    }
    let (artifact_sha256, artifact_bytes) = sha256_file(&options.artifact)?;
    let (bundle_sha256, bundle_bytes) = sha256_file(&options.bundle)?;

    let mut command = Command::new(&resolved_cosign);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command
        .arg("verify-blob")
        .arg(&options.artifact)
        .arg("--bundle")
        .arg(&options.bundle)
        .arg(format!(
            "--certificate-identity={}",
            options.certificate_identity
        ))
        .arg(format!(
            "--certificate-oidc-issuer={}",
            options.certificate_oidc_issuer
        ))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| PublicVerificationError::Invalid("cosign stdout unavailable".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| PublicVerificationError::Invalid("cosign stderr unavailable".into()))?;
    let (stdout_tx, stdout_rx) = mpsc::sync_channel(1);
    let (stderr_tx, stderr_rx) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = stdout_tx.send(read_capped(stdout));
    });
    thread::spawn(move || {
        let _ = stderr_tx.send(read_capped(stderr));
    });

    let timeout = Duration::from_secs(options.timeout_seconds);
    let started = Instant::now();
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
                return Err(PublicVerificationError::Io(error));
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
    let (stdout, stdout_truncated) = stdout.unwrap_or_else(|| (Vec::new(), true));
    let (stderr, stderr_truncated) = stderr.unwrap_or_else(|| (Vec::new(), true));

    let (artifact_after_sha256, artifact_after_bytes) = sha256_file(&options.artifact)?;
    let (bundle_after_sha256, bundle_after_bytes) = sha256_file(&options.bundle)?;
    let inputs_stable = artifact_after_sha256 == artifact_sha256
        && artifact_after_bytes == artifact_bytes
        && bundle_after_sha256 == bundle_sha256
        && bundle_after_bytes == bundle_bytes;
    let accepted = !timed_out && exit_code == Some(0) && inputs_stable;
    let reason_code = if timed_out {
        "SIGSTORE_VERIFIER_TIMEOUT"
    } else if !inputs_stable {
        "SIGSTORE_INPUT_CHANGED"
    } else if accepted {
        "SIGSTORE_VERIFIED"
    } else {
        "SIGSTORE_VERIFICATION_FAILED"
    };
    let detail = if timed_out {
        format!("cosign exceeded {} seconds", options.timeout_seconds)
    } else if !inputs_stable {
        "artifact or bundle changed while cosign was running".into()
    } else if accepted {
        "digest-pinned cosign verified the hashed blob and bundle against the pinned identity and issuer"
            .into()
    } else {
        bounded_detail(&stderr)
    };
    Ok(PublicVerificationReport {
        accepted,
        reason_code: reason_code.into(),
        verifier: resolved_cosign.display().to_string(),
        verifier_sha256,
        artifact: options.artifact.clone(),
        artifact_sha256,
        artifact_bytes,
        bundle: options.bundle.clone(),
        bundle_sha256,
        bundle_bytes,
        certificate_identity: options.certificate_identity.clone(),
        certificate_oidc_issuer: options.certificate_oidc_issuer.clone(),
        exit_code,
        timed_out,
        stdout_sha256: sha256(&stdout),
        stderr_sha256: sha256(&stderr),
        output_truncated: stdout_truncated || stderr_truncated,
        detail,
    })
}

fn read_capped(mut reader: impl Read) -> Result<(Vec<u8>, bool), std::io::Error> {
    let mut output = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut truncated = false;
    loop {
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        let remaining = MAX_VERIFIER_OUTPUT_BYTES.saturating_sub(output.len());
        if remaining == 0 {
            truncated = true;
            continue;
        }
        let accepted = remaining.min(read);
        output.extend_from_slice(&chunk[..accepted]);
        truncated |= accepted < read;
    }
    Ok((output, truncated))
}

fn recv_until(
    receiver: &mpsc::Receiver<Result<(Vec<u8>, bool), std::io::Error>>,
    deadline: Instant,
) -> Result<Option<(Vec<u8>, bool)>, PublicVerificationError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Ok(None);
    }
    match receiver.recv_timeout(remaining) {
        Ok(result) => Ok(Some(result?)),
        Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(PublicVerificationError::Invalid(
            "cosign output reader disconnected".into(),
        )),
    }
}

fn bounded_detail(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let mut detail: String = text
        .chars()
        .filter(|ch| !ch.is_control() || *ch == '\n')
        .take(512)
        .collect();
    if detail.trim().is_empty() {
        detail = "cosign exited nonzero".into();
    }
    detail
}

fn sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub fn resolve_and_hash_executable(
    requested: &Path,
) -> Result<(PathBuf, String), PublicVerificationError> {
    let resolved = if requested.is_absolute() || requested.components().count() > 1 {
        requested.to_path_buf()
    } else {
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|dir| dir.join(requested))
            .find(|candidate| candidate.is_file())
            .ok_or_else(|| {
                PublicVerificationError::Invalid(format!(
                    "executable not found on PATH: {}",
                    requested.display()
                ))
            })?
    };
    let resolved = std::fs::canonicalize(resolved)?;
    if !resolved.is_file() {
        return Err(PublicVerificationError::Invalid(format!(
            "executable is not a regular file: {}",
            resolved.display()
        )));
    }
    let (digest, _) = sha256_file(&resolved)?;
    Ok((resolved, digest))
}

fn sha256_file(path: &Path) -> Result<(String, u64), std::io::Error> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut bytes = 0u64;
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        hasher.update(&chunk[..read]);
        bytes = bytes.saturating_add(read as u64);
    }
    Ok((hex::encode(hasher.finalize()), bytes))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn terminate_and_reap(child: &mut std::process::Child) -> std::process::ExitStatus {
    kill_process_group(child.id());
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return status;
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
