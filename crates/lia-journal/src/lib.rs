use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use blake3::Hasher;
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use lia_protocol::{
    canonical_json, canonicalize_event, Event, JournalRow, ProtocolError, Receipt, SignerIdentity,
    GATE_MANIFEST_VERSION,
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde_json::json;
use thiserror::Error;
use uuid::Uuid;

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
    conn: Mutex<Connection>,
    read_only: bool,
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
}

impl Journal {
    pub fn create(path: impl AsRef<Path>) -> Result<Self, JournalError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let conn = Connection::open(&path)?;
        configure_connection(&conn)?;
        init_schema(&conn)?;
        Ok(Self {
            path,
            conn: Mutex::new(conn),
            read_only: false,
        })
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, JournalError> {
        let path = path.as_ref().to_path_buf();
        let conn = Connection::open(&path)?;
        configure_connection(&conn)?;
        init_schema(&conn)?;
        Ok(Self {
            path,
            conn: Mutex::new(conn),
            read_only: false,
        })
    }

    pub fn open_readonly(path: impl AsRef<Path>) -> Result<Self, JournalError> {
        let path = path.as_ref().to_path_buf();
        let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        Ok(Self {
            path,
            conn: Mutex::new(conn),
            read_only: true,
        })
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

        let conn = self
            .conn
            .lock()
            .map_err(|_| JournalError::WriteFailed("journal lock poisoned".into()))?;

        conn.execute_batch("BEGIN IMMEDIATE")
            .map_err(|e| JournalError::WriteFailed(e.to_string()))?;

        let outcome = (|| -> Result<JournalRow, JournalError> {
            let (seq, prev_hash) = next_seq_and_prev(&conn)?;
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
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    pub fn verify_chain(&self) -> Result<(), JournalError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| JournalError::Integrity("journal lock poisoned".into()))?;

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

            let event: Event = serde_json::from_str(&event_json).map_err(ProtocolError::from)?;
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
            verify_ed25519_signature(&signer.public_key_hex, payload.as_bytes(), &signature_hex)?;

            let receipt: Receipt =
                serde_json::from_str(&receipt_json).map_err(ProtocolError::from)?;
            if receipt.event_row_hash != row_hash
                || receipt.prev_hash != prev_hash
                || receipt.signature_hex != signature_hex
                || receipt.gate_manifest_version != gate_manifest_version
                || receipt.signer != signer
            {
                return Err(JournalError::Integrity(format!(
                    "receipt fields disagree with row at seq {seq}"
                )));
            }

            expected_prev = row_hash;
            expected_seq += 1;
        }

        Ok(())
    }

    pub fn row_count(&self) -> Result<u64, JournalError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| JournalError::Integrity("journal lock poisoned".into()))?;
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM journal_rows", [], |r| r.get(0))?;
        Ok(n as u64)
    }

    pub fn load_rows(&self) -> Result<Vec<JournalRow>, JournalError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| JournalError::Integrity("journal lock poisoned".into()))?;

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
            let event: Event = serde_json::from_str(&event_json).map_err(ProtocolError::from)?;
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
    }
}

pub fn verify_chain(path: impl AsRef<Path>) -> Result<(), JournalError> {
    let journal = Journal::open_readonly(path)?;
    journal.verify_chain()
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
    use chrono::Utc;
    use lia_protocol::{ActionAttempted, ActionKind, ActionPayload, RawHarnessEvent};
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
                .query_row(
                    "SELECT row_hash FROM journal_rows WHERE seq = 1",
                    [],
                    |r| r.get(0),
                )
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
        let err = journal_then(
            &journal,
            Uuid::new_v4(),
            sample_event(),
            &id,
            || {
                ran = true;
                42
            },
        )
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
        let (row, val) = journal_then(
            &journal,
            Uuid::new_v4(),
            sample_event(),
            &id,
            || {
                ran = true;
                7
            },
        )
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
        assert_eq!(sk.verifying_key().to_bytes().as_slice(), pk_bytes.as_slice());

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
