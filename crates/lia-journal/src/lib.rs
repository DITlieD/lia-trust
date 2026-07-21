use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use blake3::Hasher;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use lia_protocol::{
    canonical_json, canonicalize_event, Event, JournalMeta, JournalRow, ProtocolError, Receipt,
    SignerIdentity, GATE_MANIFEST_VERSION, PROTOCOL_VERSION,
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use uuid::Uuid;

/// Head/tail anchors for shareable truncated journals (P2-4).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnchorRow {
    pub seq: u64,
    pub row_hash: String,
    pub prev_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShareableAnchors {
    pub total_rows: u64,
    pub head: Vec<AnchorRow>,
    pub tail: Vec<AnchorRow>,
    pub head_chain_ok: bool,
    pub tail_chain_ok: bool,
    pub truncated_middle: bool,
}

pub const SHAREABLE_ANCHORS_VERSION: &str = "lia-shareable-anchors-v1";
const ROTATION_STATE_VERSION: &str = "lia-journal-rotation-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedShareableAnchors {
    pub version: String,
    pub anchors: ShareableAnchors,
    pub signer: SignerIdentity,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JournalRotationReport {
    pub rotated: bool,
    pub archive_path: Option<PathBuf>,
    pub archived_rows: u64,
    pub active_rows: u64,
    pub prior_head_hash: Option<String>,
    pub measured_bytes: u64,
    pub measured_age_seconds: u64,
    pub stale_replacements_removed: u64,
    pub recovered_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SignedRotationState {
    version: String,
    db: PathBuf,
    archive: PathBuf,
    replacement: PathBuf,
    archived_rows: u64,
    prior_head_hash: String,
    signer: SignerIdentity,
    signature_hex: String,
}

fn anchors_chain_ok(rows: &[AnchorRow]) -> bool {
    if rows.is_empty() {
        return true;
    }
    let mut prev = rows[0].prev_hash.as_str();
    let mut expect_seq = rows[0].seq;
    for (i, r) in rows.iter().enumerate() {
        if r.seq != expect_seq {
            return false;
        }
        if i > 0 && r.prev_hash != prev {
            return false;
        }
        prev = r.row_hash.as_str();
        let Some(next_seq) = r.seq.checked_add(1) else {
            return false;
        };
        expect_seq = next_seq;
    }
    true
}

pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Error)]
pub enum JournalError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("protocol: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("integrity: {0}")]
    Integrity(String),
    #[error("journal write failed (fail-closed): {0}")]
    WriteFailed(String),
    #[error("journal is read-only; append refused (fail-closed)")]
    ReadOnly,
    #[error("invalid key: {0}")]
    InvalidKey(String),
}

pub struct Journal {
    path: PathBuf,
    operation_lock: Mutex<()>,
    read_only: bool,
    lifecycle_already_locked: bool,
    immutable: bool,
}

struct LifecycleLock {
    connection: Connection,
}

impl Drop for LifecycleLock {
    fn drop(&mut self) {
        let _ = self.connection.execute_batch("ROLLBACK");
    }
}

pub struct SigningIdentity {
    pub key_id: String,
    pub signing_key: SigningKey,
}

impl SigningIdentity {
    pub fn from_secret_key_hex(
        key_id: impl Into<String>,
        secret_hex: &str,
    ) -> Result<Self, JournalError> {
        let bytes = hex::decode(secret_hex.trim())?;
        if bytes.len() != 32 {
            return Err(JournalError::InvalidKey(format!(
                "expected 32-byte secret key, got {} bytes",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self {
            key_id: key_id.into(),
            signing_key: SigningKey::from_bytes(&arr),
        })
    }

    pub fn generate(key_id: impl Into<String>) -> Self {
        let mut rng = rand::rngs::OsRng;
        Self {
            key_id: key_id.into(),
            signing_key: SigningKey::generate(&mut rng),
        }
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    pub fn signer_identity(&self) -> SignerIdentity {
        SignerIdentity {
            key_id: self.key_id.clone(),
            public_key_hex: self.public_key_hex(),
        }
    }

    /// Detached Ed25519 signature over arbitrary bytes, hex-encoded. Used to bind
    /// out-of-journal bundle artifacts (the manifest) to the signing identity.
    pub fn sign_hex(&self, message: &[u8]) -> String {
        hex::encode(self.signing_key.sign(message).to_bytes())
    }
}

/// A fresh 32-byte secret as hex, drawn from the OS CSPRNG. FAILS HARD if the OS RNG is
/// unavailable rather than falling back to a predictable source: a low-entropy signing key
/// silently undermines every signature the kernel produces.
pub fn random_secret_hex() -> Result<String, JournalError> {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| JournalError::Crypto(format!("OS CSPRNG unavailable: {e}")))?;
    Ok(hex::encode(bytes))
}

/// Verify a detached hex Ed25519 signature over `message` against a hex public key.
/// Uses `verify_strict` (rejects malleable/non-canonical signatures and small-order keys).
pub fn verify_detached(
    public_key_hex: &str,
    message: &[u8],
    signature_hex: &str,
) -> Result<(), JournalError> {
    verify_ed25519_signature(public_key_hex, message, signature_hex)
}

impl Journal {
    pub fn create(path: impl AsRef<Path>) -> Result<Self, JournalError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let _lifecycle_lock = acquire_lifecycle_lock(&path)?;
        if rotation_state_path(&path).exists() || !replacement_candidates(&path)?.is_empty() {
            return Err(JournalError::WriteFailed(
                "refusing to create a fresh journal while rotation recovery artifacts exist".into(),
            ));
        }
        let conn = Connection::open(&path)?;
        configure_connection(&conn)?;
        init_schema(&conn)?;
        drop(conn);
        Ok(Self {
            path,
            operation_lock: Mutex::new(()),
            read_only: false,
            lifecycle_already_locked: false,
            immutable: false,
        })
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, JournalError> {
        let path = path.as_ref().to_path_buf();
        let _lifecycle_lock = acquire_lifecycle_lock(&path)?;
        let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        configure_connection(&conn)?;
        init_schema(&conn)?;
        drop(conn);
        Ok(Self {
            path,
            operation_lock: Mutex::new(()),
            read_only: false,
            lifecycle_already_locked: false,
            immutable: false,
        })
    }

    pub fn open_readonly(path: impl AsRef<Path>) -> Result<Self, JournalError> {
        let path = path.as_ref().to_path_buf();
        let _lifecycle_lock = acquire_lifecycle_lock(&path)?;
        let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        drop(conn);
        Ok(Self {
            path,
            operation_lock: Mutex::new(()),
            read_only: true,
            lifecycle_already_locked: false,
            immutable: false,
        })
    }

    /// Open a stable offline archive/copy without creating any adjacent lifecycle or SQLite
    /// sidecars. The caller must guarantee that the file cannot be concurrently changed or
    /// renamed. WAL/SHM/rollback sidecars are rejected because SQLite immutable mode ignores them.
    pub fn open_immutable_readonly(path: impl AsRef<Path>) -> Result<Self, JournalError> {
        let path = std::fs::canonicalize(path.as_ref())?;
        ensure_no_sqlite_sidecars(&path)?;
        let conn = open_immutable_connection(&path)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        drop(conn);
        Ok(Self {
            path,
            operation_lock: Mutex::new(()),
            read_only: true,
            lifecycle_already_locked: false,
            immutable: true,
        })
    }

    fn open_with_existing_lifecycle_lock(path: impl AsRef<Path>) -> Result<Self, JournalError> {
        let path = path.as_ref().to_path_buf();
        let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        configure_connection(&conn)?;
        init_schema(&conn)?;
        drop(conn);
        Ok(Self {
            path,
            operation_lock: Mutex::new(()),
            read_only: false,
            lifecycle_already_locked: true,
            immutable: false,
        })
    }

    fn open_readonly_with_existing_lifecycle_lock(
        path: impl AsRef<Path>,
    ) -> Result<Self, JournalError> {
        let path = path.as_ref().to_path_buf();
        let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        drop(conn);
        Ok(Self {
            path,
            operation_lock: Mutex::new(()),
            read_only: true,
            lifecycle_already_locked: true,
            immutable: false,
        })
    }

    fn with_connection<T>(
        &self,
        operation: impl FnOnce(&Connection) -> Result<T, JournalError>,
    ) -> Result<T, JournalError> {
        let _operation_lock = self
            .operation_lock
            .lock()
            .map_err(|_| JournalError::Integrity("journal operation lock poisoned".into()))?;
        let _lifecycle_lock = if self.lifecycle_already_locked || self.immutable {
            None
        } else {
            Some(acquire_lifecycle_lock(&self.path)?)
        };
        if !self.path.is_file() {
            return Err(JournalError::WriteFailed(
                "journal disappeared; reopen or run journal-maintain recovery".into(),
            ));
        }
        let flags = if self.read_only {
            OpenFlags::SQLITE_OPEN_READ_ONLY
        } else {
            OpenFlags::SQLITE_OPEN_READ_WRITE
        };
        let conn = if self.immutable {
            ensure_no_sqlite_sidecars(&self.path)?;
            open_immutable_connection(&self.path)?
        } else {
            Connection::open_with_flags(&self.path, flags)?
        };
        if self.read_only || self.immutable {
            conn.busy_timeout(Duration::from_secs(5))?;
        } else {
            configure_connection(&conn)?;
        }
        operation(&conn)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append_signed(
        &self,
        run_id: Uuid,
        event: Event,
        identity: &SigningIdentity,
    ) -> Result<JournalRow, JournalError> {
        if self.read_only {
            return Err(JournalError::ReadOnly);
        }

        let event_canonical_json = canonicalize_event(&event)?;
        let event_json = serde_json::to_string(&event).map_err(ProtocolError::from)?;
        let signer = identity.signer_identity();
        self.with_connection(move |conn| {
            conn.execute_batch("BEGIN IMMEDIATE")
                .map_err(|e| JournalError::WriteFailed(e.to_string()))?;

            let outcome = (|| -> Result<JournalRow, JournalError> {
                let (seq, prev_hash) = next_seq_and_prev(conn)?;
                let row_hash = compute_row_hash(seq, run_id, &prev_hash, &event_canonical_json)?;
                let signed_payload = signing_payload(
                    GATE_MANIFEST_VERSION,
                    &signer,
                    seq,
                    run_id,
                    &prev_hash,
                    &row_hash,
                    &event_canonical_json,
                )?;
                let signature = identity.signing_key.sign(signed_payload.as_bytes());
                let signature_hex = hex::encode(signature.to_bytes());
                let receipt = Receipt {
                    receipt_id: Uuid::new_v4(),
                    run_id,
                    gate_manifest_version: GATE_MANIFEST_VERSION.to_string(),
                    signer: signer.clone(),
                    event_row_hash: row_hash.clone(),
                    prev_hash: prev_hash.clone(),
                    signature_hex: signature_hex.clone(),
                    timestamp: Utc::now(),
                };
                let receipt_json = serde_json::to_string(&receipt).map_err(ProtocolError::from)?;

                conn.execute(
                    "INSERT INTO journal_rows (
                        seq, run_id, event_json, event_canonical_json, row_hash, prev_hash,
                        receipt_json, gate_manifest_version, signer_key_id, signer_public_key_hex,
                        signature_hex
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                    params![
                        seq as i64,
                        run_id.to_string(),
                        event_json,
                        &event_canonical_json,
                        &row_hash,
                        &prev_hash,
                        receipt_json,
                        GATE_MANIFEST_VERSION,
                        &signer.key_id,
                        &signer.public_key_hex,
                        &signature_hex,
                    ],
                )
                .map_err(|e| JournalError::WriteFailed(e.to_string()))?;

                Ok(JournalRow {
                    seq,
                    run_id,
                    event,
                    event_canonical_json,
                    row_hash,
                    prev_hash,
                    receipt: Some(receipt),
                })
            })();

            match outcome {
                Ok(row) => {
                    conn.execute_batch("COMMIT")
                        .map_err(|e| JournalError::WriteFailed(e.to_string()))?;
                    Ok(row)
                }
                Err(error) => {
                    let _ = conn.execute_batch("ROLLBACK");
                    Err(error)
                }
            }
        })
    }

    pub fn verify_chain(&self) -> Result<(), JournalError> {
        self.with_connection(|conn| {
            let mut stmt = conn.prepare(
                "SELECT seq, run_id, event_json, event_canonical_json, row_hash, prev_hash,
                    receipt_json, gate_manifest_version, signer_key_id, signer_public_key_hex,
                    signature_hex
             FROM journal_rows ORDER BY seq ASC",
            )?;

            let mut rows = stmt.query([])?;
            let mut expected_prev = GENESIS_PREV_HASH.to_string();
            let mut expected_seq: u64 = 1;

            while let Some(row) = rows.next()? {
                let seq: i64 = row.get(0)?;
                let run_id_str: String = row.get(1)?;
                let event_json: String = row.get(2)?;
                let event_canonical_json: String = row.get(3)?;
                let row_hash: String = row.get(4)?;
                let prev_hash: String = row.get(5)?;
                let receipt_json: String = row.get(6)?;
                let gate_manifest_version: String = row.get(7)?;
                let signer_key_id: String = row.get(8)?;
                let signer_public_key_hex: String = row.get(9)?;
                let signature_hex: String = row.get(10)?;

                let seq = seq as u64;
                if seq != expected_seq {
                    return Err(JournalError::Integrity(format!(
                        "sequence gap: expected {expected_seq}, got {seq}"
                    )));
                }
                if prev_hash != expected_prev {
                    return Err(JournalError::Integrity(format!(
                        "prev_hash mismatch at seq {seq}"
                    )));
                }

                let run_id: Uuid = run_id_str
                    .parse()
                    .map_err(|e| JournalError::Integrity(format!("bad run_id: {e}")))?;

                let event: Event =
                    serde_json::from_str(&event_json).map_err(ProtocolError::from)?;
                let recomputed_canon = canonicalize_event(&event)?;
                if recomputed_canon != event_canonical_json {
                    return Err(JournalError::Integrity(format!(
                        "event_canonical_json mismatch at seq {seq}"
                    )));
                }

                let recomputed_hash =
                    compute_row_hash(seq, run_id, &prev_hash, &event_canonical_json)?;
                if recomputed_hash != row_hash {
                    return Err(JournalError::Integrity(format!(
                        "row_hash mismatch at seq {seq}"
                    )));
                }

                let signer = SignerIdentity {
                    key_id: signer_key_id,
                    public_key_hex: signer_public_key_hex,
                };
                let payload = signing_payload(
                    &gate_manifest_version,
                    &signer,
                    seq,
                    run_id,
                    &prev_hash,
                    &row_hash,
                    &event_canonical_json,
                )?;
                verify_ed25519_signature(
                    &signer.public_key_hex,
                    payload.as_bytes(),
                    &signature_hex,
                )?;

                let receipt: Receipt =
                    serde_json::from_str(&receipt_json).map_err(ProtocolError::from)?;
                if receipt.event_row_hash != row_hash
                || receipt.prev_hash != prev_hash
                || receipt.signature_hex != signature_hex
                || receipt.gate_manifest_version != gate_manifest_version
                || receipt.signer != signer
                // bind the receipt envelope's run_id to the row's signed run_id, so a
                // forged receipt.run_id (a field consumers key off) cannot disagree.
                || receipt.run_id != run_id
                {
                    return Err(JournalError::Integrity(format!(
                        "receipt fields disagree with row at seq {seq}"
                    )));
                }

                expected_prev = row_hash;
                expected_seq += 1;
            }

            Ok(())
        })
    }

    pub fn row_count(&self) -> Result<u64, JournalError> {
        self.with_connection(|conn| {
            let n: i64 = conn.query_row("SELECT COUNT(*) FROM journal_rows", [], |r| r.get(0))?;
            Ok(n as u64)
        })
    }

    pub fn checkpoint_truncate(&self) -> Result<(), JournalError> {
        if self.read_only {
            return Err(JournalError::ReadOnly);
        }
        self.with_connection(|conn| {
            let (busy, _, _): (i64, i64, i64) = conn
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })
                .map_err(|error| JournalError::WriteFailed(error.to_string()))?;
            if busy != 0 {
                return Err(JournalError::WriteFailed(
                    "journal checkpoint refused because another connection is busy".into(),
                ));
            }
            Ok(())
        })
    }

    /// Shareable truncation policy (P2-4): keep head+tail anchors with hashes.
    /// Full chain verify still applies to retained contiguous segments when
    /// exported as separate mini-journals; this returns an anchor receipt that
    /// offline tools can check without the middle rows.
    pub fn shareable_anchors(
        &self,
        head: usize,
        tail: usize,
    ) -> Result<ShareableAnchors, JournalError> {
        let rows = self.load_rows()?;
        let n = rows.len();
        let head_n = if n == 0 { 0 } else { head.max(1).min(n) };
        let remaining = n.saturating_sub(head_n);
        let tail_n = if remaining == 0 {
            0
        } else {
            tail.max(1).min(remaining)
        };
        let head_rows: Vec<AnchorRow> = rows[..head_n]
            .iter()
            .map(|r| AnchorRow {
                seq: r.seq,
                row_hash: r.row_hash.clone(),
                prev_hash: r.prev_hash.clone(),
            })
            .collect();
        let tail_start = n.saturating_sub(tail_n);
        let tail_rows: Vec<AnchorRow> = rows[tail_start..]
            .iter()
            .map(|r| AnchorRow {
                seq: r.seq,
                row_hash: r.row_hash.clone(),
                prev_hash: r.prev_hash.clone(),
            })
            .collect();
        let head_ok = anchors_chain_ok(&head_rows);
        let tail_ok = anchors_chain_ok(&tail_rows);
        Ok(ShareableAnchors {
            total_rows: n as u64,
            head: head_rows,
            tail: tail_rows,
            head_chain_ok: head_ok,
            tail_chain_ok: tail_ok,
            truncated_middle: n > head_n + tail_n,
        })
    }

    pub fn signed_shareable_anchors(
        &self,
        head: usize,
        tail: usize,
        identity: &SigningIdentity,
    ) -> Result<SignedShareableAnchors, JournalError> {
        self.verify_chain()?;
        let anchors = self.shareable_anchors(head, tail)?;
        validate_shareable_anchors(&anchors)?;
        let signer = identity.signer_identity();
        let payload = shareable_anchors_payload(SHAREABLE_ANCHORS_VERSION, &anchors, &signer)?;
        Ok(SignedShareableAnchors {
            version: SHAREABLE_ANCHORS_VERSION.into(),
            anchors,
            signer,
            signature_hex: identity.sign_hex(payload.as_bytes()),
        })
    }

    pub fn load_rows(&self) -> Result<Vec<JournalRow>, JournalError> {
        self.with_connection(|conn| {
            let mut stmt = conn.prepare(
            "SELECT seq, run_id, event_json, event_canonical_json, row_hash, prev_hash, receipt_json
             FROM journal_rows ORDER BY seq ASC",
            )?;

            let mut rows = stmt.query([])?;
            let mut out = Vec::new();
            while let Some(row) = rows.next()? {
                let seq: i64 = row.get(0)?;
                let run_id_str: String = row.get(1)?;
                let event_json: String = row.get(2)?;
                let event_canonical_json: String = row.get(3)?;
                let row_hash: String = row.get(4)?;
                let prev_hash: String = row.get(5)?;
                let receipt_json: String = row.get(6)?;

                let run_id: Uuid = run_id_str
                    .parse()
                    .map_err(|e| JournalError::Integrity(format!("bad run_id: {e}")))?;
                let event: Event =
                    serde_json::from_str(&event_json).map_err(ProtocolError::from)?;
                let receipt: Receipt =
                    serde_json::from_str(&receipt_json).map_err(ProtocolError::from)?;

                out.push(JournalRow {
                    seq: seq as u64,
                    run_id,
                    event,
                    event_canonical_json,
                    row_hash,
                    prev_hash,
                    receipt: Some(receipt),
                });
            }
            Ok(out)
        })
    }
}

pub fn verify_chain(path: impl AsRef<Path>) -> Result<(), JournalError> {
    let journal = Journal::open_readonly(path)?;
    journal.verify_chain()
}

pub fn verify_chain_immutable(path: impl AsRef<Path>) -> Result<(), JournalError> {
    let journal = Journal::open_immutable_readonly(path)?;
    journal.verify_chain()
}

pub fn verify_signed_shareable_anchors(
    manifest: &SignedShareableAnchors,
    expected_public_key_hex: Option<&str>,
) -> Result<(), JournalError> {
    if manifest.version != SHAREABLE_ANCHORS_VERSION {
        return Err(JournalError::Integrity(format!(
            "unsupported anchor manifest version {}",
            manifest.version
        )));
    }
    if let Some(expected) = expected_public_key_hex {
        if manifest.signer.public_key_hex != expected {
            return Err(JournalError::Integrity(
                "anchor signer does not match expected public key".into(),
            ));
        }
    }
    validate_shareable_anchors(&manifest.anchors)?;
    let payload =
        shareable_anchors_payload(&manifest.version, &manifest.anchors, &manifest.signer)?;
    verify_detached(
        &manifest.signer.public_key_hex,
        payload.as_bytes(),
        &manifest.signature_hex,
    )
}

pub fn rotate_journal_if_needed(
    db: impl AsRef<Path>,
    archive_dir: impl AsRef<Path>,
    max_rows: u64,
    max_bytes: u64,
    max_age_seconds: u64,
    run_id: Uuid,
    identity: &SigningIdentity,
) -> Result<JournalRotationReport, JournalError> {
    let db = db.as_ref();
    let archive_dir = archive_dir.as_ref();
    let _lifecycle_lock = acquire_lifecycle_lock(db)?;
    let recovered_active = recover_interrupted_rotation(db, archive_dir)?;
    if !db.is_file() {
        return Err(JournalError::WriteFailed(format!(
            "journal does not exist: {}",
            db.display()
        )));
    }
    let stale_replacements_removed = cleanup_stale_replacements(db)?;
    let journal = Journal::open_with_existing_lifecycle_lock(db)?;
    journal.verify_chain()?;
    let archived_rows = journal.row_count()?;
    let measured_bytes = journal_storage_bytes(db)?;
    let rows = journal.load_rows()?;
    let measured_age_seconds = rows
        .first()
        .map(|row| signed_event_age_seconds(row, Utc::now()))
        .unwrap_or(0);
    let should_rotate = archived_rows > max_rows
        || measured_bytes > max_bytes
        || measured_age_seconds >= max_age_seconds;
    if !should_rotate {
        return Ok(JournalRotationReport {
            rotated: false,
            archive_path: None,
            archived_rows: 0,
            active_rows: archived_rows,
            prior_head_hash: None,
            measured_bytes,
            measured_age_seconds,
            stale_replacements_removed,
            recovered_active,
        });
    }

    let prior_head_hash = rows
        .last()
        .map(|row| row.row_hash.clone())
        .unwrap_or_else(|| GENESIS_PREV_HASH.into());
    journal.checkpoint_truncate()?;
    drop(journal);
    remove_checkpointed_sidecars(db)?;

    std::fs::create_dir_all(archive_dir)?;
    sync_parent(archive_dir)?;
    std::fs::File::open(archive_dir)?.sync_all()?;
    let unique = format!(
        "journal-{}-{}.db",
        Utc::now().format("%Y%m%dT%H%M%S%3fZ"),
        Uuid::new_v4()
    );
    let archive_path = archive_dir.join(unique);
    let replacement = db.with_extension(format!("rotate-{}.tmp", Uuid::new_v4()));
    let replacement_journal = Journal::create(&replacement)?;
    let (_, checkpoint_result) = journal_then(
        &replacement_journal,
        run_id,
        Event::JournalMeta(JournalMeta {
            run_id,
            gate_manifest_version: GATE_MANIFEST_VERSION.into(),
            protocol_version: PROTOCOL_VERSION.into(),
            note: Some(format!(
                "rotation bridge: archive={} archived_rows={} prior_head_hash={}",
                archive_path.display(),
                archived_rows,
                prior_head_hash
            )),
            timestamp: Utc::now(),
        }),
        identity,
        || replacement_journal.checkpoint_truncate(),
    )?;
    checkpoint_result?;
    drop(replacement_journal);
    remove_checkpointed_sidecars(&replacement)?;
    remove_lifecycle_lock_artifacts(&replacement)?;

    let rotation_state = create_rotation_state(
        db,
        &archive_path,
        &replacement,
        archived_rows,
        &prior_head_hash,
        identity,
    )?;
    let state_path = rotation_state_path(db);
    write_rotation_state(&state_path, &rotation_state)?;

    if let Err(error) = std::fs::rename(db, &archive_path) {
        return Err(JournalError::Io(error));
    }
    sync_parent(db)?;
    sync_parent(&archive_path)?;
    if let Err(error) = std::fs::rename(&replacement, db) {
        let rollback = std::fs::rename(&archive_path, db);
        return match rollback {
            Ok(()) => {
                sync_parent(db)?;
                Err(JournalError::WriteFailed(format!(
                    "rotation replacement failed and original was restored: {error}"
                )))
            }
            Err(rollback_error) => Err(JournalError::WriteFailed(format!(
                "rotation replacement failed ({error}); original remains at {} and rollback failed ({rollback_error})",
                archive_path.display()
            ))),
        };
    }
    sync_parent(db)?;

    verify_chain(&archive_path)?;
    Journal::open_readonly_with_existing_lifecycle_lock(db)?.verify_chain()?;
    let final_bridge = load_rotation_bridge_with_existing_lifecycle_lock(db)?;
    if final_bridge.archive != archive_path
        || final_bridge.archived_rows != archived_rows
        || final_bridge.prior_head_hash != prior_head_hash
    {
        return Err(JournalError::Integrity(
            "completed rotation bridge disagrees with archived journal".into(),
        ));
    }
    validate_bridge_archive(&final_bridge)?;
    remove_lifecycle_lock_artifacts(&replacement)?;
    std::fs::remove_file(&state_path)?;
    sync_parent(&state_path)?;
    Ok(JournalRotationReport {
        rotated: true,
        archive_path: Some(archive_path),
        archived_rows,
        active_rows: 1,
        prior_head_hash: Some(prior_head_hash),
        measured_bytes,
        measured_age_seconds,
        stale_replacements_removed,
        recovered_active,
    })
}

pub fn append_signed(
    journal: &Journal,
    run_id: Uuid,
    event: Event,
    identity: &SigningIdentity,
) -> Result<JournalRow, JournalError> {
    journal.append_signed(run_id, event, identity)
}

pub fn journal_then<T, F>(
    journal: &Journal,
    run_id: Uuid,
    event: Event,
    identity: &SigningIdentity,
    action: F,
) -> Result<(JournalRow, T), JournalError>
where
    F: FnOnce() -> T,
{
    let row = journal.append_signed(run_id, event, identity)?;
    Ok((row, action()))
}

fn configure_connection(conn: &Connection) -> Result<(), JournalError> {
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=FULL;
         PRAGMA foreign_keys=ON;",
    )?;
    Ok(())
}

fn ensure_no_sqlite_sidecars(path: &Path) -> Result<(), JournalError> {
    for sidecar in [
        sqlite_sidecar_path(path, "-wal"),
        sqlite_sidecar_path(path, "-shm"),
        sqlite_sidecar_path(path, "-journal"),
    ] {
        match std::fs::symlink_metadata(&sidecar) {
            Ok(_) => {
                return Err(JournalError::Integrity(format!(
                    "immutable verification refuses SQLite sidecar {}",
                    sidecar.display()
                )))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(JournalError::Io(error)),
        }
    }
    Ok(())
}

fn sqlite_sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn open_immutable_connection(path: &Path) -> Result<Connection, JournalError> {
    let canonical = std::fs::canonicalize(path)?;
    #[cfg(unix)]
    let bytes = {
        use std::os::unix::ffi::OsStrExt;
        canonical.as_os_str().as_bytes().to_vec()
    };
    #[cfg(not(unix))]
    let bytes = canonical
        .to_str()
        .ok_or_else(|| JournalError::Integrity("immutable path is not valid Unicode".into()))?
        .as_bytes()
        .to_vec();
    let mut encoded = String::with_capacity(bytes.len());
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[(byte >> 4) as usize]));
            encoded.push(char::from(HEX[(byte & 0x0f) as usize]));
        }
    }
    let uri = format!("file:{encoded}?immutable=1&mode=ro");
    Connection::open_with_flags(
        Path::new(&uri),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(JournalError::from)
}

fn lifecycle_lock_path(db: &Path) -> PathBuf {
    db.with_extension("lifecycle-lock.db")
}

fn acquire_lifecycle_lock(db: &Path) -> Result<LifecycleLock, JournalError> {
    let path = lifecycle_lock_path(db);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let connection = Connection::open(path)
        .map_err(|error| JournalError::WriteFailed(format!("lifecycle lock open: {error}")))?;
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(|error| JournalError::WriteFailed(format!("lifecycle lock timeout: {error}")))?;
    connection
        .execute_batch(
            "PRAGMA journal_mode=DELETE;
             PRAGMA synchronous=FULL;
             BEGIN EXCLUSIVE;",
        )
        .map_err(|error| JournalError::WriteFailed(format!("lifecycle lock acquire: {error}")))?;
    Ok(LifecycleLock { connection })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RotationBridge {
    archive: PathBuf,
    archived_rows: u64,
    prior_head_hash: String,
    signer: SignerIdentity,
}

fn event_timestamp(event: &Event) -> &DateTime<Utc> {
    match event {
        Event::ProcessContractDeclared(value) => &value.timestamp,
        Event::ActionAttempted(value) => &value.timestamp,
        Event::ActionObserved(value) => &value.timestamp,
        Event::GateVerdict(value) => &value.timestamp,
        Event::EvidenceCaptured(value) => &value.timestamp,
        Event::ClaimSubmitted(value) => &value.timestamp,
        Event::JournalMeta(value) => &value.timestamp,
        Event::RawHarness(value) => &value.timestamp,
    }
}

fn signed_event_age_seconds(row: &JournalRow, now: DateTime<Utc>) -> u64 {
    let seconds = now
        .signed_duration_since(event_timestamp(&row.event))
        .num_seconds();
    seconds.max(0) as u64
}

fn rotation_state_path(db: &Path) -> PathBuf {
    db.with_extension("rotation.json")
}

fn rotation_state_payload(state: &SignedRotationState) -> Result<String, JournalError> {
    Ok(canonical_json(&json!({
        "version": state.version,
        "db": state.db,
        "archive": state.archive,
        "replacement": state.replacement,
        "archived_rows": state.archived_rows,
        "prior_head_hash": state.prior_head_hash,
        "signer": state.signer,
    }))?)
}

fn create_rotation_state(
    db: &Path,
    archive: &Path,
    replacement: &Path,
    archived_rows: u64,
    prior_head_hash: &str,
    identity: &SigningIdentity,
) -> Result<SignedRotationState, JournalError> {
    let mut state = SignedRotationState {
        version: ROTATION_STATE_VERSION.into(),
        db: db.to_path_buf(),
        archive: archive.to_path_buf(),
        replacement: replacement.to_path_buf(),
        archived_rows,
        prior_head_hash: prior_head_hash.into(),
        signer: identity.signer_identity(),
        signature_hex: String::new(),
    };
    let payload = rotation_state_payload(&state)?;
    state.signature_hex = identity.sign_hex(payload.as_bytes());
    Ok(state)
}

fn verify_rotation_state(state: &SignedRotationState) -> Result<(), JournalError> {
    if state.version != ROTATION_STATE_VERSION {
        return Err(JournalError::Integrity(format!(
            "unsupported rotation state version {}",
            state.version
        )));
    }
    let payload = rotation_state_payload(state)?;
    verify_detached(
        &state.signer.public_key_hex,
        payload.as_bytes(),
        &state.signature_hex,
    )
}

fn write_rotation_state(path: &Path, state: &SignedRotationState) -> Result<(), JournalError> {
    let bytes = serde_json::to_vec_pretty(state).map_err(ProtocolError::from)?;
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    sync_parent(path)
}

fn parse_rotation_bridge(
    note: &str,
    signer: SignerIdentity,
) -> Result<RotationBridge, JournalError> {
    let body = note
        .strip_prefix("rotation bridge: archive=")
        .ok_or_else(|| {
            JournalError::Integrity("replacement lacks a rotation bridge note".into())
        })?;
    let (left, prior_head_hash) = body
        .rsplit_once(" prior_head_hash=")
        .ok_or_else(|| JournalError::Integrity("rotation bridge lacks prior head hash".into()))?;
    let (archive, archived_rows) = left.rsplit_once(" archived_rows=").ok_or_else(|| {
        JournalError::Integrity("rotation bridge lacks archived row count".into())
    })?;
    let archived_rows = archived_rows.parse::<u64>().map_err(|error| {
        JournalError::Integrity(format!("invalid rotation bridge row count: {error}"))
    })?;
    if !valid_hash(prior_head_hash) {
        return Err(JournalError::Integrity(
            "rotation bridge prior head hash is invalid".into(),
        ));
    }
    Ok(RotationBridge {
        archive: PathBuf::from(archive),
        archived_rows,
        prior_head_hash: prior_head_hash.into(),
        signer,
    })
}

fn load_rotation_bridge(path: &Path) -> Result<RotationBridge, JournalError> {
    let journal = Journal::open_readonly(path)?;
    load_rotation_bridge_from_journal(&journal)
}

fn load_rotation_bridge_with_existing_lifecycle_lock(
    path: &Path,
) -> Result<RotationBridge, JournalError> {
    let journal = Journal::open_readonly_with_existing_lifecycle_lock(path)?;
    load_rotation_bridge_from_journal(&journal)
}

fn load_rotation_bridge_from_journal(journal: &Journal) -> Result<RotationBridge, JournalError> {
    journal.verify_chain()?;
    let rows = journal.load_rows()?;
    if rows.len() != 1 {
        return Err(JournalError::Integrity(
            "rotation replacement must contain exactly one bridge row".into(),
        ));
    }
    let row = &rows[0];
    let Event::JournalMeta(meta) = &row.event else {
        return Err(JournalError::Integrity(
            "rotation replacement row is not journal metadata".into(),
        ));
    };
    if meta.run_id != row.run_id {
        return Err(JournalError::Integrity(
            "rotation bridge run identity mismatch".into(),
        ));
    }
    let signer = row
        .receipt
        .as_ref()
        .map(|receipt| receipt.signer.clone())
        .ok_or_else(|| JournalError::Integrity("rotation bridge lacks signer".into()))?;
    parse_rotation_bridge(meta.note.as_deref().unwrap_or_default(), signer)
}

fn journal_identity(path: &Path) -> Result<(u64, String), JournalError> {
    let journal = Journal::open_readonly(path)?;
    journal_identity_from_journal(&journal)
}

fn journal_identity_with_existing_lifecycle_lock(
    path: &Path,
) -> Result<(u64, String), JournalError> {
    let journal = Journal::open_readonly_with_existing_lifecycle_lock(path)?;
    journal_identity_from_journal(&journal)
}

fn journal_identity_from_journal(journal: &Journal) -> Result<(u64, String), JournalError> {
    journal.verify_chain()?;
    let rows = journal.load_rows()?;
    let head = rows
        .last()
        .map(|row| row.row_hash.clone())
        .unwrap_or_else(|| GENESIS_PREV_HASH.into());
    Ok((rows.len() as u64, head))
}

fn validate_bridge_archive(bridge: &RotationBridge) -> Result<(), JournalError> {
    let (rows, head) = journal_identity(&bridge.archive)?;
    if rows != bridge.archived_rows || head != bridge.prior_head_hash {
        return Err(JournalError::Integrity(
            "rotation bridge does not match archived journal identity".into(),
        ));
    }
    Ok(())
}

fn replacement_candidates(db: &Path) -> Result<Vec<PathBuf>, JournalError> {
    let parent = db.parent().unwrap_or_else(|| Path::new("."));
    let stem = db
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or_else(|| JournalError::WriteFailed("journal filename is not valid UTF-8".into()))?;
    let prefix = format!("{stem}.rotate-");
    let mut candidates = Vec::new();
    for entry in std::fs::read_dir(parent)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.starts_with(&prefix) && name.ends_with(".tmp") {
            candidates.push(entry.path());
        }
    }
    candidates.sort();
    Ok(candidates)
}

fn recover_interrupted_rotation(db: &Path, archive_dir: &Path) -> Result<bool, JournalError> {
    let state_path = rotation_state_path(db);
    if state_path.exists() {
        let state: SignedRotationState =
            serde_json::from_slice(&std::fs::read(&state_path)?).map_err(ProtocolError::from)?;
        verify_rotation_state(&state)?;
        if state.db != db {
            return Err(JournalError::Integrity(
                "rotation state targets a different active journal".into(),
            ));
        }
        if state.archive.parent() != Some(archive_dir) {
            return Err(JournalError::Integrity(
                "rotation state archive is outside the requested archive directory".into(),
            ));
        }
        if db.exists() && state.archive.exists() && state.replacement.exists() {
            return Err(JournalError::Integrity(
                "rotation state is ambiguous: active and replacement both exist".into(),
            ));
        }
        let bridge_path = if db.exists() && state.archive.exists() {
            db
        } else {
            state.replacement.as_path()
        };
        let bridge = if bridge_path == db {
            load_rotation_bridge_with_existing_lifecycle_lock(bridge_path)?
        } else {
            load_rotation_bridge(bridge_path)?
        };
        if bridge.archive != state.archive
            || bridge.archived_rows != state.archived_rows
            || bridge.prior_head_hash != state.prior_head_hash
            || bridge.signer != state.signer
        {
            return Err(JournalError::Integrity(
                "signed rotation state disagrees with bridge".into(),
            ));
        }
        if state.archive.exists() {
            validate_bridge_archive(&bridge)?;
            if !db.exists() {
                remove_checkpointed_sidecars(&state.replacement)?;
                std::fs::rename(&state.replacement, db)?;
                sync_parent(db)?;
                Journal::open_readonly_with_existing_lifecycle_lock(db)?.verify_chain()?;
            }
            remove_lifecycle_lock_artifacts(&state.replacement)?;
            std::fs::remove_file(&state_path)?;
            sync_parent(&state_path)?;
            return Ok(true);
        }

        let (rows, head) = journal_identity_with_existing_lifecycle_lock(db)?;
        if rows != state.archived_rows || head != state.prior_head_hash {
            return Err(JournalError::Integrity(
                "pre-rename active journal disagrees with rotation state".into(),
            ));
        }
        remove_checkpointed_sidecars(&state.replacement)?;
        std::fs::remove_file(&state.replacement)?;
        remove_lifecycle_lock_artifacts(&state.replacement)?;
        std::fs::remove_file(&state_path)?;
        sync_parent(db)?;
        return Ok(false);
    }

    if db.exists() {
        return Ok(false);
    }
    let candidates = replacement_candidates(db)?;
    if candidates.len() != 1 {
        return Ok(false);
    }
    let replacement = &candidates[0];
    let bridge = load_rotation_bridge(replacement)?;
    let archive_root = std::fs::canonicalize(archive_dir)?;
    let archive = std::fs::canonicalize(&bridge.archive)?;
    if !archive.starts_with(&archive_root) {
        return Err(JournalError::Integrity(
            "orphaned rotation bridge points outside the archive directory".into(),
        ));
    }
    validate_bridge_archive(&bridge)?;
    remove_checkpointed_sidecars(replacement)?;
    std::fs::rename(replacement, db)?;
    sync_parent(db)?;
    Journal::open_readonly_with_existing_lifecycle_lock(db)?.verify_chain()?;
    remove_lifecycle_lock_artifacts(replacement)?;
    Ok(true)
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<(), JournalError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> Result<(), JournalError> {
    Ok(())
}

fn shareable_anchors_payload(
    version: &str,
    anchors: &ShareableAnchors,
    signer: &SignerIdentity,
) -> Result<String, JournalError> {
    Ok(canonical_json(&json!({
        "version": version,
        "anchors": anchors,
        "signer": signer,
    }))?)
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_shareable_anchors(anchors: &ShareableAnchors) -> Result<(), JournalError> {
    if anchors
        .head
        .iter()
        .chain(anchors.tail.iter())
        .any(|row| !valid_hash(&row.row_hash) || !valid_hash(&row.prev_hash))
    {
        return Err(JournalError::Integrity(
            "anchor row contains an invalid hash".into(),
        ));
    }
    let head_ok = anchors_chain_ok(&anchors.head);
    let tail_ok = anchors_chain_ok(&anchors.tail);
    if !head_ok || !tail_ok || anchors.head_chain_ok != head_ok || anchors.tail_chain_ok != tail_ok
    {
        return Err(JournalError::Integrity(
            "anchor segment chain metadata is invalid".into(),
        ));
    }
    if anchors.total_rows == 0 {
        if !anchors.head.is_empty() || !anchors.tail.is_empty() || anchors.truncated_middle {
            return Err(JournalError::Integrity(
                "empty journal anchor metadata is inconsistent".into(),
            ));
        }
        return Ok(());
    }
    let Some(first) = anchors.head.first() else {
        return Err(JournalError::Integrity(
            "non-empty journal anchors must include the genesis head".into(),
        ));
    };
    if first.seq != 1 || first.prev_hash != GENESIS_PREV_HASH {
        return Err(JournalError::Integrity(
            "anchor head does not start at the journal genesis".into(),
        ));
    }
    let last_seq = anchors
        .tail
        .last()
        .or_else(|| anchors.head.last())
        .map(|row| row.seq)
        .unwrap_or_default();
    if last_seq != anchors.total_rows {
        return Err(JournalError::Integrity(
            "anchor tail does not bind the journal head".into(),
        ));
    }
    let retained = anchors.head.len() as u64 + anchors.tail.len() as u64;
    if anchors.truncated_middle != (retained < anchors.total_rows) {
        return Err(JournalError::Integrity(
            "anchor truncation marker disagrees with retained rows".into(),
        ));
    }
    if let (Some(head_last), Some(tail_first)) = (anchors.head.last(), anchors.tail.first()) {
        let next_head_seq = head_last
            .seq
            .checked_add(1)
            .ok_or_else(|| JournalError::Integrity("anchor sequence overflows u64".into()))?;
        if anchors.truncated_middle {
            if next_head_seq >= tail_first.seq {
                return Err(JournalError::Integrity(
                    "truncated anchor segments overlap or leave no omitted middle".into(),
                ));
            }
        } else if tail_first.seq != next_head_seq || tail_first.prev_hash != head_last.row_hash {
            return Err(JournalError::Integrity(
                "non-truncated anchor segments are not contiguous".into(),
            ));
        }
    }
    Ok(())
}

fn journal_storage_bytes(path: &Path) -> Result<u64, JournalError> {
    let mut total = std::fs::metadata(path)?.len();
    let wal = PathBuf::from(format!("{}-wal", path.display()));
    if wal.exists() {
        total = total.saturating_add(std::fs::metadata(wal)?.len());
    }
    Ok(total)
}

fn remove_checkpointed_sidecars(path: &Path) -> Result<(), JournalError> {
    let wal = PathBuf::from(format!("{}-wal", path.display()));
    if wal.exists() {
        let bytes = std::fs::metadata(&wal)?.len();
        if bytes != 0 {
            return Err(JournalError::WriteFailed(format!(
                "refusing rotation with non-empty WAL sidecar: {} bytes",
                bytes
            )));
        }
        std::fs::remove_file(wal)?;
    }
    let shm = PathBuf::from(format!("{}-shm", path.display()));
    if shm.exists() {
        std::fs::remove_file(shm)?;
    }
    Ok(())
}

fn remove_lifecycle_lock_artifacts(path: &Path) -> Result<(), JournalError> {
    let lock = lifecycle_lock_path(path);
    for candidate in [
        lock.clone(),
        PathBuf::from(format!("{}-journal", lock.display())),
        PathBuf::from(format!("{}-wal", lock.display())),
        PathBuf::from(format!("{}-shm", lock.display())),
    ] {
        if candidate.exists() {
            std::fs::remove_file(candidate)?;
        }
    }
    Ok(())
}

fn cleanup_stale_replacements(db: &Path) -> Result<u64, JournalError> {
    let mut removed = 0;
    let (active_rows, active_head) = journal_identity_with_existing_lifecycle_lock(db)?;
    for stale in replacement_candidates(db)? {
        let bridge = load_rotation_bridge(&stale)?;
        if bridge.archive.exists()
            || bridge.archived_rows != active_rows
            || bridge.prior_head_hash != active_head
        {
            return Err(JournalError::Integrity(
                "stale replacement cannot be proven redundant with active journal".into(),
            ));
        }
        remove_checkpointed_sidecars(&stale)?;
        for candidate in [
            stale.clone(),
            PathBuf::from(format!("{}-wal", stale.display())),
            PathBuf::from(format!("{}-shm", stale.display())),
        ] {
            if candidate.exists() {
                std::fs::remove_file(candidate)?;
            }
        }
        remove_lifecycle_lock_artifacts(&stale)?;
        removed += 1;
    }
    Ok(removed)
}

fn init_schema(conn: &Connection) -> Result<(), JournalError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS journal_rows (
            seq INTEGER PRIMARY KEY,
            run_id TEXT NOT NULL,
            event_json TEXT NOT NULL,
            event_canonical_json TEXT NOT NULL,
            row_hash TEXT NOT NULL UNIQUE,
            prev_hash TEXT NOT NULL,
            receipt_json TEXT NOT NULL,
            gate_manifest_version TEXT NOT NULL,
            signer_key_id TEXT NOT NULL,
            signer_public_key_hex TEXT NOT NULL,
            signature_hex TEXT NOT NULL
        );
        CREATE TRIGGER IF NOT EXISTS journal_rows_no_update
        BEFORE UPDATE ON journal_rows
        BEGIN
            SELECT RAISE(ABORT, 'lia-journal is append-only: UPDATE refused');
        END;
        CREATE TRIGGER IF NOT EXISTS journal_rows_no_delete
        BEFORE DELETE ON journal_rows
        BEGIN
            SELECT RAISE(ABORT, 'lia-journal is append-only: DELETE refused');
        END;",
    )?;
    Ok(())
}

fn next_seq_and_prev(conn: &Connection) -> Result<(u64, String), JournalError> {
    let last: Option<(i64, String)> = conn
        .query_row(
            "SELECT seq, row_hash FROM journal_rows ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    match last {
        Some((seq, hash)) => Ok((seq as u64 + 1, hash)),
        None => Ok((1, GENESIS_PREV_HASH.to_string())),
    }
}

fn compute_row_hash(
    seq: u64,
    run_id: Uuid,
    prev_hash: &str,
    event_canonical_json: &str,
) -> Result<String, JournalError> {
    let payload = canonical_json(&json!({
        "seq": seq,
        "run_id": run_id.to_string(),
        "prev_hash": prev_hash,
        "event_canonical_json": event_canonical_json,
    }))?;
    let mut hasher = Hasher::new();
    hasher.update(payload.as_bytes());
    Ok(hasher.finalize().to_hex().to_string())
}

fn signing_payload(
    gate_manifest_version: &str,
    signer: &SignerIdentity,
    seq: u64,
    run_id: Uuid,
    prev_hash: &str,
    row_hash: &str,
    event_canonical_json: &str,
) -> Result<String, JournalError> {
    Ok(canonical_json(&json!({
        "gate_manifest_version": gate_manifest_version,
        "signer": {
            "key_id": signer.key_id,
            "public_key_hex": signer.public_key_hex,
        },
        "seq": seq,
        "run_id": run_id.to_string(),
        "prev_hash": prev_hash,
        "row_hash": row_hash,
        "event_canonical_json": event_canonical_json,
    }))?)
}

fn verify_ed25519_signature(
    public_key_hex: &str,
    message: &[u8],
    signature_hex: &str,
) -> Result<(), JournalError> {
    let pk_bytes = hex::decode(public_key_hex)?;
    if pk_bytes.len() != 32 {
        return Err(JournalError::Crypto(format!(
            "expected 32-byte public key, got {}",
            pk_bytes.len()
        )));
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&pk_bytes);
    let vk = VerifyingKey::from_bytes(&pk).map_err(|e| JournalError::Crypto(e.to_string()))?;

    let sig_bytes = hex::decode(signature_hex)?;
    if sig_bytes.len() != 64 {
        return Err(JournalError::Crypto(format!(
            "expected 64-byte signature, got {}",
            sig_bytes.len()
        )));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);

    vk.verify_strict(message, &sig)
        .map_err(|e| JournalError::Integrity(format!("ed25519 verify failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration as ChronoDuration, Utc};
    use lia_protocol::{ActionAttempted, ActionKind, ActionPayload, RawHarnessEvent};
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::thread;

    fn sample_event() -> Event {
        Event::ActionAttempted(ActionAttempted {
            action_id: Uuid::new_v4(),
            kind: ActionKind::Shell,
            payload: ActionPayload {
                command: Some("echo hi".into()),
                path: None,
                content_sha256: None,
                argv: Some(vec!["echo".into(), "hi".into()]),
                cwd: Some("/tmp".into()),
                package: None,
                version: None,
                claim: None,
            },
            timestamp: Utc::now(),
        })
    }

    #[test]
    fn age_is_derived_from_the_signed_event_not_unsigned_receipt_metadata() {
        let event_time = Utc::now() - ChronoDuration::hours(2);
        let event = Event::RawHarness(RawHarnessEvent {
            harness: "age-test".into(),
            raw: json!({}),
            timestamp: event_time,
        });
        let td = tempfile::tempdir().expect("tempdir");
        let path = td.path().join("j.db");
        let journal = Journal::create(&path).expect("create");
        let id = SigningIdentity::generate("age-test");
        journal
            .append_signed(Uuid::new_v4(), event, &id)
            .expect("append");
        let rows = journal.load_rows().expect("rows");
        assert!(signed_event_age_seconds(&rows[0], Utc::now()) >= 7_100);
    }

    #[test]
    fn malformed_anchor_sequence_cannot_overflow() {
        let anchors = ShareableAnchors {
            total_rows: u64::MAX,
            head: vec![AnchorRow {
                seq: 1,
                row_hash: "a".repeat(64),
                prev_hash: GENESIS_PREV_HASH.into(),
            }],
            tail: vec![AnchorRow {
                seq: u64::MAX,
                row_hash: "b".repeat(64),
                prev_hash: "c".repeat(64),
            }],
            head_chain_ok: true,
            tail_chain_ok: true,
            truncated_middle: true,
        };
        assert!(validate_shareable_anchors(&anchors).is_err());
    }

    #[test]
    fn lifecycle_lock_serializes_cross_connection_appends() {
        let td = tempfile::tempdir().expect("tempdir");
        let path = td.path().join("j.db");
        Journal::create(&path).expect("create");
        let lock = acquire_lifecycle_lock(&path).expect("hold lifecycle lock");
        let (sender, receiver) = mpsc::channel();
        let thread_path = path.clone();
        let worker = thread::spawn(move || {
            let journal = Journal::open(thread_path).expect("open");
            let identity = SigningIdentity::generate("worker");
            let result = journal.append_signed(Uuid::new_v4(), sample_event(), &identity);
            sender.send(result.is_ok()).expect("send");
        });
        assert!(
            receiver.recv_timeout(Duration::from_millis(100)).is_err(),
            "append bypassed lifecycle lock"
        );
        drop(lock);
        assert!(
            receiver
                .recv_timeout(Duration::from_secs(2))
                .expect("append result"),
            "append failed after lifecycle lock release"
        );
        worker.join().expect("worker");
    }

    #[test]
    fn open_missing_journal_never_creates_a_new_genesis() {
        let td = tempfile::tempdir().expect("tempdir");
        let path = td.path().join("missing.db");
        assert!(Journal::open(&path).is_err());
        assert!(!path.exists(), "open recreated a missing active journal");
    }

    #[test]
    fn immutable_verification_does_not_require_a_lifecycle_sidecar() {
        let td = tempfile::tempdir().expect("tempdir");
        let path = td.path().join("readonly.db");
        let identity = SigningIdentity::generate("readonly");
        let journal = Journal::create(&path).expect("create");
        journal
            .append_signed(Uuid::new_v4(), sample_event(), &identity)
            .expect("append");
        remove_lifecycle_lock_artifacts(&path).expect("remove setup lock");
        let lock_path = lifecycle_lock_path(&path);
        assert!(!lock_path.exists());

        let readonly = Journal::open_immutable_readonly(&path).expect("open immutable");
        readonly.verify_chain().expect("verify readonly");
        assert!(
            !lock_path.exists(),
            "read-only verification created a lifecycle sidecar"
        );

        std::fs::write(format!("{}-wal", path.display()), b"not-a-real-wal")
            .expect("write sidecar marker");
        assert!(
            Journal::open_immutable_readonly(&path).is_err(),
            "immutable verification accepted an ignored WAL sidecar"
        );
        #[cfg(unix)]
        {
            let alias = td.path().join("readonly-alias.db");
            std::os::unix::fs::symlink(&path, &alias).expect("create stable alias");
            assert!(
                Journal::open_immutable_readonly(&alias).is_err(),
                "immutable verification missed a WAL beside the canonical target"
            );
            let wal = sqlite_sidecar_path(&path, "-wal");
            std::fs::remove_file(&wal).expect("remove WAL marker");
            std::os::unix::fs::symlink(td.path().join("missing-wal-target"), &wal)
                .expect("create dangling WAL marker");
            assert!(
                Journal::open_immutable_readonly(&path).is_err(),
                "immutable verification treated a dangling WAL entry as absent"
            );
        }
    }

    #[test]
    fn handle_opened_before_rotation_follows_the_active_path() {
        let td = tempfile::tempdir().expect("tempdir");
        let path = td.path().join("journal.db");
        let archive_dir = td.path().join("archive");
        let identity = SigningIdentity::generate("rotation-handle");
        let run_id = Uuid::new_v4();
        let seed = Journal::create(&path).expect("create");
        seed.append_signed(run_id, sample_event(), &identity)
            .expect("append one");
        seed.append_signed(run_id, sample_event(), &identity)
            .expect("append two");
        let pre_rotation_handle = Journal::open(&path).expect("open before rotation");

        let report = rotate_journal_if_needed(
            &path,
            &archive_dir,
            1,
            u64::MAX,
            u64::MAX,
            run_id,
            &identity,
        )
        .expect("rotate");
        assert!(report.rotated);
        assert_eq!(pre_rotation_handle.row_count().expect("active rows"), 1);
        pre_rotation_handle
            .append_signed(run_id, sample_event(), &identity)
            .expect("append through pre-rotation handle");
        assert_eq!(pre_rotation_handle.row_count().expect("active rows"), 2);

        let archive =
            Journal::open_readonly(report.archive_path.expect("archive")).expect("open archive");
        assert_eq!(archive.row_count().expect("archived rows"), 2);
        archive.verify_chain().expect("archive chain");
        pre_rotation_handle.verify_chain().expect("active chain");
    }

    fn raw_event(n: u64) -> Event {
        Event::RawHarness(RawHarnessEvent {
            harness: "test".into(),
            raw: json!({"n": n}),
            timestamp: Utc::now(),
        })
    }

    #[test]
    fn append_and_verify_clean_chain() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("clean.db");
        let journal = Journal::create(&path).expect("create");
        let id = SigningIdentity::generate("test-key");
        let run_id = Uuid::new_v4();
        journal
            .append_signed(run_id, sample_event(), &id)
            .expect("append1");
        journal
            .append_signed(run_id, sample_event(), &id)
            .expect("append2");
        journal.verify_chain().expect("verify");
    }

    #[test]
    fn single_byte_tamper_fails_verify() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("tamper.db");
        let journal = Journal::create(&path).expect("create");
        let id = SigningIdentity::generate("test-key");
        let run_id = Uuid::new_v4();
        journal
            .append_signed(run_id, sample_event(), &id)
            .expect("append");
        drop(journal);

        {
            let conn = Connection::open(&path).expect("open");
            conn.execute_batch(
                "DROP TRIGGER IF EXISTS journal_rows_no_update;
                 DROP TRIGGER IF EXISTS journal_rows_no_delete;",
            )
            .expect("drop triggers for adversarial tamper");
            let row_hash: String = conn
                .query_row("SELECT row_hash FROM journal_rows WHERE seq = 1", [], |r| {
                    r.get(0)
                })
                .expect("row");
            let mut bytes = row_hash.into_bytes();
            bytes[0] ^= 0x01;
            let tampered = String::from_utf8(bytes).expect("utf8");
            conn.execute(
                "UPDATE journal_rows SET row_hash = ?1 WHERE seq = 1",
                params![tampered],
            )
            .expect("tamper");
        }

        let err = verify_chain(&path).expect_err("must fail");
        assert!(
            matches!(err, JournalError::Integrity(_)),
            "expected integrity failure, got {err}"
        );
    }

    #[test]
    fn tamper_each_signed_field_fails_verify() {
        let fields = [
            "event_canonical_json",
            "prev_hash",
            "signature_hex",
            "gate_manifest_version",
            "signer_public_key_hex",
            "event_json",
        ];
        for field in fields {
            let dir = tempfile::tempdir().expect("tmpdir");
            let path = dir.path().join(format!("tamper-{field}.db"));
            let journal = Journal::create(&path).expect("create");
            let id = SigningIdentity::generate("test-key");
            journal
                .append_signed(Uuid::new_v4(), sample_event(), &id)
                .expect("append");
            drop(journal);

            {
                let conn = Connection::open(&path).expect("open");
                conn.execute_batch(
                    "DROP TRIGGER IF EXISTS journal_rows_no_update;
                     DROP TRIGGER IF EXISTS journal_rows_no_delete;",
                )
                .expect("drop triggers");
                let value: String = conn
                    .query_row(
                        &format!("SELECT {field} FROM journal_rows WHERE seq = 1"),
                        [],
                        |r| r.get(0),
                    )
                    .expect("read");
                let mut bytes = value.into_bytes();
                let idx = bytes.len().saturating_sub(1);
                bytes[idx] ^= 0x01;
                let tampered = String::from_utf8_lossy(&bytes).into_owned();
                conn.execute(
                    &format!("UPDATE journal_rows SET {field} = ?1 WHERE seq = 1"),
                    params![tampered],
                )
                .expect("tamper");
            }

            assert!(
                verify_chain(&path).is_err(),
                "tampering {field} must fail verify"
            );
        }
    }

    #[test]
    fn append_only_triggers_reject_update_and_delete() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("append-only.db");
        let journal = Journal::create(&path).expect("create");
        let id = SigningIdentity::generate("k");
        journal
            .append_signed(Uuid::new_v4(), sample_event(), &id)
            .expect("append");
        drop(journal);

        let conn = Connection::open(&path).expect("open");
        let upd = conn.execute(
            "UPDATE journal_rows SET row_hash = row_hash WHERE seq = 1",
            [],
        );
        assert!(upd.is_err(), "UPDATE must be refused");
        let del = conn.execute("DELETE FROM journal_rows WHERE seq = 1", []);
        assert!(del.is_err(), "DELETE must be refused");
    }

    #[test]
    fn journal_then_skips_action_on_write_failure() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("abort.db");
        {
            let journal = Journal::create(&path).expect("create");
            let id = SigningIdentity::generate("k");
            journal
                .append_signed(Uuid::new_v4(), sample_event(), &id)
                .expect("seed");
        }
        let journal = Journal::open_readonly(&path).expect("ro");
        let id = SigningIdentity::generate("k2");
        let mut ran = false;
        let err = journal_then(&journal, Uuid::new_v4(), sample_event(), &id, || {
            ran = true;
            42
        })
        .expect_err("must fail closed");
        assert!(matches!(err, JournalError::ReadOnly));
        assert!(!ran, "action must not run after journal failure");
    }

    #[test]
    fn journal_then_runs_action_after_successful_append() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("then.db");
        let journal = Journal::create(&path).expect("create");
        let id = SigningIdentity::generate("k");
        let mut ran = false;
        let (row, val) = journal_then(&journal, Uuid::new_v4(), sample_event(), &id, || {
            ran = true;
            7
        })
        .expect("ok");
        assert!(ran);
        assert_eq!(val, 7);
        assert_eq!(row.seq, 1);
        journal.verify_chain().expect("verify");
    }

    #[test]
    fn concurrent_append() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("concurrent.db");
        {
            let _ = Journal::create(&path).expect("create");
        }
        let path = Arc::new(path);
        let secret = hex::encode(SigningIdentity::generate("k").signing_key.to_bytes());
        let run_id = Uuid::new_v4();

        let mut handles = Vec::new();
        for t in 0..2 {
            let path = Arc::clone(&path);
            let secret = secret.clone();
            handles.push(thread::spawn(move || {
                let journal = Journal::open(path.as_ref()).expect("open");
                let id = SigningIdentity::from_secret_key_hex("k", &secret).expect("key");
                for i in 0..40u64 {
                    let event = raw_event((t * 1000) + i);
                    journal
                        .append_signed(run_id, event, &id)
                        .expect("append under contention");
                }
            }));
        }
        for h in handles {
            h.join().expect("thread");
        }

        let journal = Journal::open(path.as_ref()).expect("reopen");
        assert_eq!(journal.row_count().expect("count"), 80);
        journal
            .verify_chain()
            .expect("chain intact after concurrent writers");
    }

    #[test]
    fn append_on_readonly_db_fails_closed() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("ro.db");
        {
            let journal = Journal::create(&path).expect("create");
            let id = SigningIdentity::generate("k");
            journal
                .append_signed(Uuid::new_v4(), sample_event(), &id)
                .expect("seed");
        }
        let journal = Journal::open_readonly(&path).expect("ro");
        let id = SigningIdentity::generate("k2");
        let err = journal
            .append_signed(Uuid::new_v4(), sample_event(), &id)
            .expect_err("must not proceed");
        assert!(matches!(err, JournalError::ReadOnly));
    }

    #[test]
    fn rfc8032_ed25519_test_vectors() {
        assert_rfc8032_vector(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            concat!(
                "e5564300c360ac729086e2cc806e828a",
                "84877f1eb8e5d974d873e06522490155",
                "5fb8821590a33bacc61e39701cf9b46b",
                "d25bf5f0595bbe24655141438e7a100b"
            ),
        );
        assert_rfc8032_vector(
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            concat!(
                "92a009a9f0d4cab8720e820b5f642540",
                "a2b27b5416503f8fb3762223ebdb69da",
                "085ac1e43e15996e458f3613d0f11d8c",
                "387b2eaeb4302aeeb00d291612bb0c00"
            ),
        );
    }

    fn assert_rfc8032_vector(sk_hex: &str, pk_hex: &str, msg_hex: &str, sig_hex: &str) {
        let sk_bytes = hex::decode(sk_hex).expect("sk");
        let mut sk_arr = [0u8; 32];
        sk_arr.copy_from_slice(&sk_bytes);
        let sk = SigningKey::from_bytes(&sk_arr);
        let pk_bytes = hex::decode(pk_hex).expect("pk");
        assert_eq!(
            sk.verifying_key().to_bytes().as_slice(),
            pk_bytes.as_slice()
        );

        let msg = if msg_hex.is_empty() {
            Vec::new()
        } else {
            hex::decode(msg_hex).expect("msg")
        };
        let sig_bytes = hex::decode(sig_hex).expect("sig");
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = Signature::from_bytes(&sig_arr);

        sk.verifying_key()
            .verify_strict(&msg, &sig)
            .expect("RFC 8032 vector must verify");

        let produced = sk.sign(&msg);
        assert_eq!(produced.to_bytes().as_slice(), sig_bytes.as_slice());
    }
}
