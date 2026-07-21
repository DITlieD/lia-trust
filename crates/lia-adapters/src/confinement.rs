use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Child;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::AdapterError;

const MAX_CREDENTIAL_BYTES: u64 = 64 * 1024;
const MAX_CREDENTIALS: usize = 16;
const MAX_CONTROL_BYTES: usize = 16 * 1024;
const MIN_LANDLOCK_ABI: u32 = 3;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredentialSpec {
    pub name: String,
    pub source_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LinuxConfinementOptions {
    pub unshare_bin: PathBuf,
    pub expected_unshare_sha256: String,
    pub lia_executable: PathBuf,
    #[serde(default)]
    pub credentials: Vec<CredentialSpec>,
    pub credential_ttl_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConfinementReport {
    pub backend: String,
    pub helper_path: PathBuf,
    pub helper_sha256: String,
    pub network_namespace: String,
    pub mount_namespace: String,
    pub pid_namespace: String,
    pub ip_egress_blocked: bool,
    pub host_path_writes_blocked: bool,
    pub evidence_artifacts_write_blocked: bool,
    pub host_filesystem_reads_confined: bool,
    pub pathname_unix_sockets_confined: bool,
    pub landlock_abi: u32,
    pub capabilities_dropped: bool,
    pub credential_names: Vec<String>,
    pub principal_isolation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChildReady {
    network_namespace: String,
    mount_namespace: String,
    pid_namespace: String,
    landlock_abi: u32,
    evidence_read_only: bool,
    root_mount_read_only: bool,
    capabilities_dropped: bool,
}

#[cfg(target_os = "linux")]
pub struct ConfinedChild {
    child: Child,
    control: std::os::unix::net::UnixStream,
    brokers: Vec<std::thread::JoinHandle<Result<(), String>>>,
    pub report: ConfinementReport,
}

#[cfg(target_os = "linux")]
impl ConfinedChild {
    pub fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    pub fn release(&mut self) -> Result<(), AdapterError> {
        self.control.write_all(b"GO\n").map_err(|error| {
            AdapterError::Invalid(format!("CONFINEMENT_RELEASE_FAILED: {error}"))
        })?;
        self.control.flush().map_err(|error| {
            AdapterError::Invalid(format!("CONFINEMENT_RELEASE_FAILED: {error}"))
        })?;
        Ok(())
    }

    pub fn finish_brokers(&mut self) -> Result<(), AdapterError> {
        let mut failures = Vec::new();
        for handle in self.brokers.drain(..) {
            match handle.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => failures.push(error),
                Err(_) => failures.push("credential broker panicked".into()),
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(AdapterError::Invalid(format!(
                "CREDENTIAL_BROKER_FAILED: {}",
                failures.join("; ")
            )))
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for ConfinedChild {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            terminate_unready(&mut self.child);
        }
        for handle in self.brokers.drain(..) {
            let _ = handle.join();
        }
    }
}

#[cfg(target_os = "linux")]
pub fn spawn_linux_confined(
    options: &LinuxConfinementOptions,
    worktree: &Path,
    evidence_dir: &Path,
    agent_argv: &[String],
    child_env: &BTreeMap<String, String>,
) -> Result<ConfinedChild, AdapterError> {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    if agent_argv.is_empty() {
        return Err(AdapterError::Invalid(
            "CONFINEMENT_INVALID_AGENT: empty argv".into(),
        ));
    }
    if options.credential_ttl_seconds == 0 || options.credential_ttl_seconds > 300 {
        return Err(AdapterError::Invalid(
            "CREDENTIAL_TTL_INVALID: expected 1..=300 seconds".into(),
        ));
    }
    if options.credentials.len() > MAX_CREDENTIALS {
        return Err(AdapterError::Invalid(format!(
            "CREDENTIAL_COUNT_INVALID: maximum is {MAX_CREDENTIALS}"
        )));
    }
    let mut normalized_names = std::collections::BTreeSet::new();
    for spec in &options.credentials {
        let name = credential_name(&spec.name)?;
        if !normalized_names.insert(name) {
            return Err(AdapterError::Invalid(
                "CREDENTIAL_DUPLICATE: normalized credential names must be unique".into(),
            ));
        }
    }
    if !options.unshare_bin.is_absolute() {
        return Err(AdapterError::Invalid(
            "CONFINEMENT_HELPER_TRUST_INVALID: helper path must be absolute".into(),
        ));
    }
    let helper_path = options
        .unshare_bin
        .canonicalize()
        .map_err(|error| AdapterError::Invalid(format!("CONFINEMENT_UNAVAILABLE: {error}")))?;
    validate_helper(&helper_path, &options.expected_unshare_sha256)?;
    let helper_sha256 = sha256_path(&helper_path)?;
    let lia_executable = options.lia_executable.canonicalize().map_err(|error| {
        AdapterError::Invalid(format!("CONFINEMENT_WRAPPER_UNAVAILABLE: {error}"))
    })?;
    validate_private_directory(evidence_dir)?;

    let host_network_namespace = namespace_id("/proc/self/ns/net")?;
    let host_mount_namespace = namespace_id("/proc/self/ns/mnt")?;
    let host_pid_namespace = namespace_id("/proc/self/ns/pid")?;
    let (control_parent, control_child) = UnixStream::pair()
        .map_err(|error| AdapterError::Invalid(format!("CONFINEMENT_CONTROL_FAILED: {error}")))?;
    clear_cloexec(control_child.as_raw_fd())?;

    let mut command = Command::new(&helper_path);
    command.args([
        "--user",
        "--map-root-user",
        "--mount",
        "--propagation",
        "private",
        "--net",
        "--pid",
        "--fork",
        "--kill-child=KILL",
        "--mount-proc",
        "--uts",
        "--ipc",
        "--",
    ]);
    command
        .arg(&lia_executable)
        .arg("__confined-exec")
        .arg("--worktree")
        .arg(worktree)
        .arg("--evidence-dir")
        .arg(evidence_dir)
        .arg("--control-fd")
        .arg(control_child.as_raw_fd().to_string());

    let mut brokers = Vec::new();
    let mut child_credential_streams = Vec::new();
    let mut credential_names = Vec::new();
    let mut credential_env = BTreeMap::new();
    for spec in &options.credentials {
        let prepared = prepare_credential(spec, worktree, options.credential_ttl_seconds)?;
        command.arg("--mask-path").arg(&prepared.source_path);
        credential_env.insert(prepared.env_name, prepared.child_fd.to_string());
        credential_names.push(spec.name.clone());
        child_credential_streams.push(prepared.child_stream);
        brokers.push(prepared.broker);
    }
    credential_names.sort();

    command.arg("--").args(agent_argv);
    command
        .current_dir(worktree)
        .env_clear()
        .envs(child_env)
        .envs(credential_env)
        .env(
            "LIA_CONFINEMENT_CONTROL_FD",
            control_child.as_raw_fd().to_string(),
        )
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .process_group(0);

    let spawned = command.spawn();
    drop(control_child);
    drop(child_credential_streams);
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => {
            join_brokers(&mut brokers);
            return Err(AdapterError::Invalid(format!(
                "CONFINEMENT_UNAVAILABLE: {error}"
            )));
        }
    };

    let post_spawn_sha256 = match sha256_path(&helper_path) {
        Ok(digest) => digest,
        Err(error) => {
            cleanup_unready(&mut child, &mut brokers);
            return Err(error);
        }
    };
    if post_spawn_sha256 != helper_sha256 {
        cleanup_unready(&mut child, &mut brokers);
        return Err(AdapterError::Invalid(
            "CONFINEMENT_HELPER_CHANGED_DURING_SPAWN".into(),
        ));
    }

    if let Err(error) = control_parent.set_read_timeout(Some(Duration::from_secs(5))) {
        cleanup_unready(&mut child, &mut brokers);
        return Err(AdapterError::Invalid(format!(
            "CONFINEMENT_CONTROL_FAILED: {error}"
        )));
    }
    let control_reader = match control_parent.try_clone() {
        Ok(reader) => reader,
        Err(error) => {
            cleanup_unready(&mut child, &mut brokers);
            return Err(AdapterError::Invalid(format!(
                "CONFINEMENT_CONTROL_FAILED: {error}"
            )));
        }
    };
    let mut reader = std::io::BufReader::new(control_reader);
    let mut line = String::new();
    let read = reader
        .by_ref()
        .take(MAX_CONTROL_BYTES as u64)
        .read_line(&mut line);
    let read = match read {
        Ok(read) => read,
        Err(error) => {
            cleanup_unready(&mut child, &mut brokers);
            return Err(AdapterError::Invalid(format!(
                "CONFINEMENT_UNAVAILABLE: no child attestation: {error}"
            )));
        }
    };
    if read == 0 || !line.ends_with('\n') {
        cleanup_unready(&mut child, &mut brokers);
        return Err(AdapterError::Invalid(
            "CONFINEMENT_UNAVAILABLE: child exited before bounded attestation".into(),
        ));
    }
    let ready: ChildReady = match serde_json::from_str(line.trim_end()) {
        Ok(ready) => ready,
        Err(error) => {
            cleanup_unready(&mut child, &mut brokers);
            return Err(AdapterError::Invalid(format!(
                "CONFINEMENT_ATTESTATION_INVALID: {error}"
            )));
        }
    };
    if ready.network_namespace == host_network_namespace
        || ready.mount_namespace == host_mount_namespace
        || ready.pid_namespace == host_pid_namespace
        || ready.landlock_abi < MIN_LANDLOCK_ABI
        || !ready.evidence_read_only
        || !ready.root_mount_read_only
        || !ready.capabilities_dropped
    {
        cleanup_unready(&mut child, &mut brokers);
        return Err(AdapterError::Invalid(
            "CONFINEMENT_ATTESTATION_MISMATCH: required namespaces/Landlock boundary absent".into(),
        ));
    }
    Ok(ConfinedChild {
        child,
        control: control_parent,
        brokers,
        report: ConfinementReport {
            backend: "linux-namespaces-landlock".into(),
            helper_path,
            helper_sha256,
            network_namespace: ready.network_namespace,
            mount_namespace: ready.mount_namespace,
            pid_namespace: ready.pid_namespace,
            ip_egress_blocked: true,
            host_path_writes_blocked: true,
            evidence_artifacts_write_blocked: true,
            host_filesystem_reads_confined: false,
            pathname_unix_sockets_confined: false,
            landlock_abi: ready.landlock_abi,
            capabilities_dropped: ready.capabilities_dropped,
            credential_names,
            principal_isolation: "same-uid namespace boundary; separate OS principal not claimed"
                .into(),
        },
    })
}

#[cfg(not(target_os = "linux"))]
pub fn spawn_linux_confined(
    _options: &LinuxConfinementOptions,
    _worktree: &Path,
    _evidence_dir: &Path,
    _agent_argv: &[String],
    _child_env: &BTreeMap<String, String>,
) -> Result<(), AdapterError> {
    Err(AdapterError::Invalid(
        "CONFINEMENT_UNAVAILABLE: Linux namespace backend requires Linux".into(),
    ))
}

#[cfg(target_os = "linux")]
pub fn internal_confined_exec(
    worktree: &Path,
    evidence_dir: &Path,
    mask_paths: &[PathBuf],
    control_fd: i32,
    agent_argv: &[String],
) -> Result<(), AdapterError> {
    use std::os::fd::FromRawFd;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    if control_fd < 3 || agent_argv.is_empty() {
        return Err(AdapterError::Invalid(
            "CONFINEMENT_CONTROL_INVALID: invalid fd or empty agent".into(),
        ));
    }
    make_mounts_private()?;
    bind_worktree(worktree)?;
    bind_read_only(evidence_dir, true)?;
    for path in mask_paths {
        bind_mask_file(path)?;
    }
    make_mount_tree_read_only()?;
    remount_worktree_writable(worktree)?;
    let landlock_abi = restrict_writes_to(worktree)?;
    drop_capabilities()?;
    let ready = ChildReady {
        network_namespace: namespace_id("/proc/self/ns/net")?,
        mount_namespace: namespace_id("/proc/self/ns/mnt")?,
        pid_namespace: namespace_id("/proc/self/ns/pid")?,
        landlock_abi,
        evidence_read_only: true,
        root_mount_read_only: true,
        capabilities_dropped: true,
    };
    // SAFETY: the fd is a dedicated inherited UnixStream endpoint and ownership transfers here.
    let mut control = unsafe { UnixStream::from_raw_fd(control_fd) };
    let mut bytes = serde_json::to_vec(&ready).map_err(|error| {
        AdapterError::Invalid(format!("CONFINEMENT_ATTESTATION_INVALID: {error}"))
    })?;
    bytes.push(b'\n');
    control
        .write_all(&bytes)
        .and_then(|_| control.flush())
        .map_err(|error| AdapterError::Invalid(format!("CONFINEMENT_CONTROL_FAILED: {error}")))?;
    control
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| AdapterError::Invalid(format!("CONFINEMENT_CONTROL_FAILED: {error}")))?;
    let mut release = [0u8; 3];
    control
        .read_exact(&mut release)
        .map_err(|error| AdapterError::Invalid(format!("CONFINEMENT_RELEASE_FAILED: {error}")))?;
    if &release != b"GO\n" {
        return Err(AdapterError::Invalid(
            "CONFINEMENT_RELEASE_INVALID: expected GO".into(),
        ));
    }
    drop(control);
    let error = Command::new(&agent_argv[0])
        .args(&agent_argv[1..])
        .current_dir(worktree)
        .env_remove("LIA_CONFINEMENT_CONTROL_FD")
        .exec();
    Err(AdapterError::Invalid(format!(
        "CONFINEMENT_AGENT_EXEC_FAILED: {error}"
    )))
}

#[cfg(not(target_os = "linux"))]
pub fn internal_confined_exec(
    _worktree: &Path,
    _evidence_dir: &Path,
    _mask_paths: &[PathBuf],
    _control_fd: i32,
    _agent_argv: &[String],
) -> Result<(), AdapterError> {
    Err(AdapterError::Invalid(
        "CONFINEMENT_UNAVAILABLE: Linux namespace backend requires Linux".into(),
    ))
}

#[cfg(target_os = "linux")]
pub fn credential_read(name: &str) -> Result<Zeroizing<Vec<u8>>, AdapterError> {
    use std::os::fd::FromRawFd;
    use std::os::unix::net::UnixStream;

    let normalized = credential_name(name)?;
    let env_name = format!("LIA_CREDENTIAL_FD_{}", normalized.to_ascii_uppercase());
    let fd: i32 = std::env::var(&env_name)
        .map_err(|_| AdapterError::Invalid("CREDENTIAL_UNAVAILABLE: broker fd absent".into()))?
        .parse()
        .map_err(|_| AdapterError::Invalid("CREDENTIAL_UNAVAILABLE: invalid broker fd".into()))?;
    if fd < 3 {
        return Err(AdapterError::Invalid(
            "CREDENTIAL_UNAVAILABLE: invalid broker fd".into(),
        ));
    }
    // SAFETY: the fd is a dedicated inherited UnixStream endpoint and this one-shot client owns it.
    let mut stream = unsafe { UnixStream::from_raw_fd(fd) };
    stream
        .write_all(format!("GET {normalized}\n").as_bytes())
        .and_then(|_| stream.flush())
        .map_err(|error| AdapterError::Invalid(format!("CREDENTIAL_EXPIRED_OR_USED: {error}")))?;
    let mut length = [0u8; 4];
    stream
        .read_exact(&mut length)
        .map_err(|error| AdapterError::Invalid(format!("CREDENTIAL_EXPIRED_OR_USED: {error}")))?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length as u64 > MAX_CREDENTIAL_BYTES {
        return Err(AdapterError::Invalid(
            "CREDENTIAL_RESPONSE_INVALID: invalid length".into(),
        ));
    }
    let mut secret = Zeroizing::new(vec![0u8; length]);
    stream
        .read_exact(&mut secret)
        .map_err(|error| AdapterError::Invalid(format!("CREDENTIAL_RESPONSE_INVALID: {error}")))?;
    Ok(secret)
}

#[cfg(not(target_os = "linux"))]
pub fn credential_read(_name: &str) -> Result<Zeroizing<Vec<u8>>, AdapterError> {
    Err(AdapterError::Invalid(
        "CREDENTIAL_UNAVAILABLE: fd broker requires Linux".into(),
    ))
}

#[cfg(target_os = "linux")]
struct PreparedCredential {
    source_path: PathBuf,
    env_name: String,
    child_fd: i32,
    child_stream: std::os::unix::net::UnixStream,
    broker: std::thread::JoinHandle<Result<(), String>>,
}

#[cfg(target_os = "linux")]
struct LockedSecret {
    bytes: Zeroizing<Vec<u8>>,
}

#[cfg(target_os = "linux")]
impl LockedSecret {
    fn new(bytes: Zeroizing<Vec<u8>>) -> Result<Self, AdapterError> {
        // SAFETY: the allocation is stable after read completion and the Drop implementation
        // performs a compiler-resistant wipe before unlocking this exact allocation range.
        if unsafe { libc::mlock(bytes.as_ptr().cast(), bytes.len()) } == -1 {
            return Err(AdapterError::Invalid(format!(
                "CREDENTIAL_MEMORY_LOCK_FAILED: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(Self { bytes })
    }
}

#[cfg(target_os = "linux")]
impl Drop for LockedSecret {
    fn drop(&mut self) {
        self.bytes.zeroize();
        // SAFETY: this is the same live allocation range locked in `new`, and it has already been
        // wiped with compiler-resistant zeroization before being unlocked.
        unsafe {
            libc::munlock(self.bytes.as_ptr().cast(), self.bytes.len());
        }
    }
}

#[cfg(target_os = "linux")]
fn prepare_credential(
    spec: &CredentialSpec,
    worktree: &Path,
    ttl_seconds: u64,
) -> Result<PreparedCredential, AdapterError> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::os::unix::net::UnixStream;

    let name = credential_name(&spec.name)?;
    let symlink_meta = fs::symlink_metadata(&spec.source_path)
        .map_err(|error| AdapterError::Invalid(format!("CREDENTIAL_SOURCE_INVALID: {error}")))?;
    if symlink_meta.file_type().is_symlink() || !symlink_meta.file_type().is_file() {
        return Err(AdapterError::Invalid(
            "CREDENTIAL_SOURCE_INVALID: source must be a regular non-symlink file".into(),
        ));
    }
    let source_path = spec
        .source_path
        .canonicalize()
        .map_err(|error| AdapterError::Invalid(format!("CREDENTIAL_SOURCE_INVALID: {error}")))?;
    if source_path.starts_with(worktree) {
        return Err(AdapterError::Invalid(
            "CREDENTIAL_SOURCE_SCOPE: source must be outside the child worktree".into(),
        ));
    }
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&source_path)
        .map_err(|error| AdapterError::Invalid(format!("CREDENTIAL_SOURCE_INVALID: {error}")))?;
    let metadata = file
        .metadata()
        .map_err(|error| AdapterError::Invalid(format!("CREDENTIAL_SOURCE_INVALID: {error}")))?;
    if metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > MAX_CREDENTIAL_BYTES
    {
        return Err(AdapterError::Invalid(
            "CREDENTIAL_SOURCE_PERMISSIONS: require current-owner 0600-like nonempty single-link file <=64KiB".into(),
        ));
    }
    let mut secret = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    file.read_to_end(&mut secret)
        .map_err(|error| AdapterError::Invalid(format!("CREDENTIAL_SOURCE_INVALID: {error}")))?;
    let (mut parent, child_stream) = UnixStream::pair()
        .map_err(|error| AdapterError::Invalid(format!("CREDENTIAL_BROKER_FAILED: {error}")))?;
    clear_cloexec(child_stream.as_raw_fd())?;
    let secret = LockedSecret::new(secret)?;
    let child_fd = child_stream.as_raw_fd();
    let request_name = name.clone();
    let broker = std::thread::Builder::new()
        .name(format!("lia-credential-{name}"))
        .spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(ttl_seconds);
            let request = match read_request_until(&mut parent, deadline) {
                Ok(Some(request)) => request,
                Ok(None) => return Ok(()),
                Err(error) => return Err(error.to_string()),
            };
            if request != format!("GET {request_name}\n") {
                return Err("credential request name mismatch".into());
            }
            let length = u32::try_from(secret.bytes.len()).map_err(|_| "credential too large")?;
            parent
                .write_all(&length.to_be_bytes())
                .and_then(|_| parent.write_all(secret.bytes.as_slice()))
                .and_then(|_| parent.flush())
                .map_err(|error| error.to_string())
        })
        .map_err(|error| AdapterError::Invalid(format!("CREDENTIAL_BROKER_FAILED: {error}")))?;
    Ok(PreparedCredential {
        source_path,
        env_name: format!("LIA_CREDENTIAL_FD_{}", name.to_ascii_uppercase()),
        child_fd,
        child_stream,
        broker,
    })
}

#[cfg(target_os = "linux")]
fn read_request_until(
    stream: &mut std::os::unix::net::UnixStream,
    deadline: Instant,
) -> std::io::Result<Option<String>> {
    let mut bytes = Vec::new();
    while bytes.len() < 256 {
        let now = Instant::now();
        if now >= deadline {
            return Ok(None);
        }
        stream.set_read_timeout(Some(deadline.saturating_duration_since(now)))?;
        let mut byte = [0u8; 1];
        match stream.read(&mut byte) {
            Ok(0) => return Ok(None),
            Ok(_) => {
                bytes.push(byte[0]);
                if byte[0] == b'\n' {
                    return String::from_utf8(bytes).map(Some).map_err(|error| {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, error)
                    });
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "credential request exceeds 256 bytes",
    ))
}

fn credential_name(name: &str) -> Result<String, AdapterError> {
    if name.is_empty()
        || name.len() > 32
        || !name
            .bytes()
            .enumerate()
            .all(|(index, byte)| byte.is_ascii_alphanumeric() || (index > 0 && byte == b'_'))
        || !name.as_bytes()[0].is_ascii_alphabetic()
    {
        return Err(AdapterError::Invalid(
            "CREDENTIAL_NAME_INVALID: expected [A-Za-z][A-Za-z0-9_]{0,31}".into(),
        ));
    }
    Ok(name.to_ascii_lowercase())
}

fn validate_helper(path: &Path, expected_sha256: &str) -> Result<(), AdapterError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let metadata = path
            .metadata()
            .map_err(|error| AdapterError::Invalid(format!("CONFINEMENT_UNAVAILABLE: {error}")))?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
            return Err(AdapterError::Invalid(
                "CONFINEMENT_UNAVAILABLE: helper is not an executable regular file".into(),
            ));
        }
        for component in path.ancestors() {
            let metadata = component.metadata().map_err(|error| {
                AdapterError::Invalid(format!("CONFINEMENT_HELPER_TRUST_INVALID: {error}"))
            })?;
            if metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
                return Err(AdapterError::Invalid(format!(
                    "CONFINEMENT_HELPER_TRUST_INVALID: {} must be root-owned and not group/world writable",
                    component.display()
                )));
            }
        }
    }
    if expected_sha256.len() != 64 || !expected_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(AdapterError::Invalid(
            "CONFINEMENT_HELPER_DIGEST_INVALID".into(),
        ));
    }
    if !sha256_path(path)?.eq_ignore_ascii_case(expected_sha256) {
        return Err(AdapterError::Invalid(
            "CONFINEMENT_HELPER_DIGEST_MISMATCH".into(),
        ));
    }
    Ok(())
}

fn sha256_path(path: &Path) -> Result<String, AdapterError> {
    let mut file = fs::File::open(path)
        .map_err(|error| AdapterError::Invalid(format!("CONFINEMENT_UNAVAILABLE: {error}")))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| AdapterError::Invalid(format!("CONFINEMENT_UNAVAILABLE: {error}")))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(target_os = "linux")]
fn validate_private_directory(path: &Path) -> Result<(), AdapterError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = path
        .metadata()
        .map_err(|error| AdapterError::Invalid(format!("EVIDENCE_DIRECTORY_INVALID: {error}")))?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(AdapterError::Invalid(
            "EVIDENCE_DIRECTORY_PERMISSIONS: require current-owner mode 0700-like directory".into(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn clear_cloexec(fd: i32) -> Result<(), AdapterError> {
    // SAFETY: fcntl only updates descriptor flags on the validated live descriptor.
    let result = unsafe { libc::fcntl(fd, libc::F_SETFD, 0) };
    if result == -1 {
        return Err(AdapterError::Invalid(format!(
            "CONFINEMENT_FD_FAILED: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn namespace_id(path: &str) -> Result<String, AdapterError> {
    fs::read_link(path)
        .map(|value| value.display().to_string())
        .map_err(|error| AdapterError::Invalid(format!("CONFINEMENT_ATTESTATION_FAILED: {error}")))
}

#[cfg(target_os = "linux")]
fn terminate_unready(child: &mut Child) {
    // The unshare helper owns a PID namespace with --kill-child=KILL, so terminating the helper
    // also terminates and reaps namespace descendants.
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(target_os = "linux")]
fn join_brokers(brokers: &mut Vec<std::thread::JoinHandle<Result<(), String>>>) {
    for handle in brokers.drain(..) {
        let _ = handle.join();
    }
}

#[cfg(target_os = "linux")]
fn cleanup_unready(
    child: &mut Child,
    brokers: &mut Vec<std::thread::JoinHandle<Result<(), String>>>,
) {
    terminate_unready(child);
    join_brokers(brokers);
}

#[cfg(target_os = "linux")]
fn make_mounts_private() -> Result<(), AdapterError> {
    // SAFETY: this process is already in a private mount namespace created by the pinned helper.
    let result = unsafe {
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong,
            std::ptr::null(),
        )
    };
    if result == -1 {
        return Err(AdapterError::Invalid(format!(
            "CONFINEMENT_MOUNT_PRIVATE_FAILED: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

#[cfg(target_os = "linux")]
fn make_mount_tree_read_only() -> Result<(), AdapterError> {
    const AT_RECURSIVE: u32 = 0x8000;
    const MOUNT_ATTR_RDONLY: u64 = 0x0000_0001;
    let attr = MountAttr {
        attr_set: MOUNT_ATTR_RDONLY,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    // SAFETY: mount_setattr applies a per-mount read-only attribute recursively inside the
    // already-private mount namespace. It cannot propagate to the host mount namespace.
    let result = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            libc::AT_FDCWD,
            c"/".as_ptr(),
            AT_RECURSIVE,
            &attr,
            std::mem::size_of::<MountAttr>(),
        )
    };
    if result < 0 {
        return Err(AdapterError::Invalid(format!(
            "CONFINEMENT_ROOT_READONLY_FAILED: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn bind_read_only(path: &Path, recursive: bool) -> Result<(), AdapterError> {
    use std::os::unix::ffi::OsStrExt;
    let target = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| AdapterError::Invalid("CONFINEMENT_PATH_INVALID: NUL byte".into()))?;
    let bind_flags = if recursive {
        libc::MS_BIND | libc::MS_REC
    } else {
        libc::MS_BIND
    };
    // SAFETY: source and target are the same canonical path inside the private mount namespace.
    let bind = unsafe {
        libc::mount(
            target.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            bind_flags as libc::c_ulong,
            std::ptr::null(),
        )
    };
    if bind == -1 {
        return Err(AdapterError::Invalid(format!(
            "CONFINEMENT_READONLY_BIND_FAILED: {}",
            std::io::Error::last_os_error()
        )));
    }
    let flags = libc::MS_BIND
        | libc::MS_REMOUNT
        | libc::MS_RDONLY
        | libc::MS_NOSUID
        | libc::MS_NODEV
        | libc::MS_NOEXEC;
    // SAFETY: remount applies only to the private bind created above.
    let remount = unsafe {
        libc::mount(
            std::ptr::null(),
            target.as_ptr(),
            std::ptr::null(),
            flags as libc::c_ulong,
            std::ptr::null(),
        )
    };
    if remount == -1 {
        return Err(AdapterError::Invalid(format!(
            "CONFINEMENT_READONLY_REMOUNT_FAILED: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn bind_worktree(path: &Path) -> Result<(), AdapterError> {
    use std::os::unix::ffi::OsStrExt;
    let target = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| AdapterError::Invalid("CONFINEMENT_PATH_INVALID: NUL byte".into()))?;
    // SAFETY: this creates an explicit worktree submount in the private mount namespace. The
    // later recursive evidence bind preserves it as a separately remountable child mount.
    let result = unsafe {
        libc::mount(
            target.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            (libc::MS_BIND | libc::MS_REC) as libc::c_ulong,
            std::ptr::null(),
        )
    };
    if result == -1 {
        return Err(AdapterError::Invalid(format!(
            "CONFINEMENT_WORKTREE_BIND_FAILED: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn remount_worktree_writable(path: &Path) -> Result<(), AdapterError> {
    use std::os::unix::ffi::OsStrExt;
    let target = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| AdapterError::Invalid("CONFINEMENT_PATH_INVALID: NUL byte".into()))?;
    let flags = libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NODEV;
    // SAFETY: this clears per-mount read-only state only on the explicit worktree submount.
    let result = unsafe {
        libc::mount(
            std::ptr::null(),
            target.as_ptr(),
            std::ptr::null(),
            flags as libc::c_ulong,
            std::ptr::null(),
        )
    };
    if result == -1 {
        return Err(AdapterError::Invalid(format!(
            "CONFINEMENT_WORKTREE_REMOUNT_FAILED: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn bind_mask_file(path: &Path) -> Result<(), AdapterError> {
    use std::os::unix::ffi::OsStrExt;
    let target = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| AdapterError::Invalid("CONFINEMENT_PATH_INVALID: NUL byte".into()))?;
    // SAFETY: /dev/null is bind-mounted over the exact credential source inside this mount ns.
    let bind = unsafe {
        libc::mount(
            c"/dev/null".as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND as libc::c_ulong,
            std::ptr::null(),
        )
    };
    if bind == -1 {
        return Err(AdapterError::Invalid(format!(
            "CREDENTIAL_MASK_FAILED: {}",
            std::io::Error::last_os_error()
        )));
    }
    bind_read_only(path, false)
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

#[cfg(target_os = "linux")]
fn restrict_writes_to(worktree: &Path) -> Result<u32, AdapterError> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;

    const CREATE_RULESET_VERSION: u32 = 1;
    const RULE_PATH_BENEATH: u32 = 1;
    const WRITE_FILE: u64 = 1 << 1;
    const REMOVE_DIR: u64 = 1 << 4;
    const REMOVE_FILE: u64 = 1 << 5;
    const MAKE_CHAR: u64 = 1 << 6;
    const MAKE_DIR: u64 = 1 << 7;
    const MAKE_REG: u64 = 1 << 8;
    const MAKE_SOCK: u64 = 1 << 9;
    const MAKE_FIFO: u64 = 1 << 10;
    const MAKE_BLOCK: u64 = 1 << 11;
    const MAKE_SYM: u64 = 1 << 12;
    const REFER: u64 = 1 << 13;
    const TRUNCATE: u64 = 1 << 14;

    // SAFETY: null attr with VERSION flag is the documented ABI query.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<LandlockRulesetAttr>(),
            0usize,
            CREATE_RULESET_VERSION,
        )
    };
    if abi < MIN_LANDLOCK_ABI as libc::c_long {
        return Err(AdapterError::Invalid(format!(
            "CONFINEMENT_LANDLOCK_UNAVAILABLE: ABI {abi}, require >= {MIN_LANDLOCK_ABI}"
        )));
    }
    let handled = WRITE_FILE
        | REMOVE_DIR
        | REMOVE_FILE
        | MAKE_CHAR
        | MAKE_DIR
        | MAKE_REG
        | MAKE_SOCK
        | MAKE_FIFO
        | MAKE_BLOCK
        | MAKE_SYM
        | REFER
        | TRUNCATE;
    let ruleset_attr = LandlockRulesetAttr {
        handled_access_fs: handled,
    };
    // SAFETY: pointer and size match the v1 ruleset attribute.
    let ruleset_fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &ruleset_attr,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0u32,
        )
    };
    if ruleset_fd < 0 {
        return Err(AdapterError::Invalid(format!(
            "CONFINEMENT_LANDLOCK_RULESET_FAILED: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: successful syscall returned an owned descriptor.
    let ruleset = unsafe { OwnedFd::from_raw_fd(ruleset_fd as i32) };
    let worktree_c = std::ffi::CString::new(worktree.as_os_str().as_bytes())
        .map_err(|_| AdapterError::Invalid("CONFINEMENT_PATH_INVALID: NUL byte".into()))?;
    // SAFETY: O_PATH opens the directory as a Landlock parent handle without reading it.
    let parent_fd = unsafe { libc::open(worktree_c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if parent_fd < 0 {
        return Err(AdapterError::Invalid(format!(
            "CONFINEMENT_LANDLOCK_PATH_FAILED: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: successful open returned an owned descriptor.
    let parent = unsafe { OwnedFd::from_raw_fd(parent_fd) };
    let path_attr = LandlockPathBeneathAttr {
        allowed_access: handled,
        parent_fd: parent.as_raw_fd(),
    };
    // SAFETY: pointers and rule type match the documented PATH_BENEATH ABI.
    let add = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset.as_raw_fd(),
            RULE_PATH_BENEATH,
            &path_attr,
            0u32,
        )
    };
    if add < 0 {
        return Err(AdapterError::Invalid(format!(
            "CONFINEMENT_LANDLOCK_RULE_FAILED: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: no_new_privs is required by Landlock and is irreversible for this process tree.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == -1 {
        return Err(AdapterError::Invalid(format!(
            "CONFINEMENT_NO_NEW_PRIVS_FAILED: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: restrict_self installs the fully constructed ruleset on this process and descendants.
    let restrict =
        unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0u32) };
    if restrict < 0 {
        return Err(AdapterError::Invalid(format!(
            "CONFINEMENT_LANDLOCK_RESTRICT_FAILED: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(abi as u32)
}

#[cfg(target_os = "linux")]
fn drop_capabilities() -> Result<(), AdapterError> {
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let header = CapHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let data = [
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    // SAFETY: structures match Linux capability ABI v3 and clear all current sets.
    let result = unsafe { libc::syscall(libc::SYS_capset, &header, &data) };
    if result < 0 {
        return Err(AdapterError::Invalid(format!(
            "CONFINEMENT_CAPABILITY_DROP_FAILED: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}
