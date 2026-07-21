use std::fs;
use std::path::PathBuf;
use std::process::Command;

use serde_json::{json, Value};

const SECRET_HEX: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn lia_bin() -> PathBuf {
    std::env::var_os("CARGO_BIN_EXE_lia")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/lia"))
}

fn replacement_lock_path(path: &std::path::Path) -> PathBuf {
    path.with_extension("lifecycle-lock.db")
}

fn append_event(db: &std::path::Path, event: &str, run_id: Option<&str>) -> Value {
    let mut args = vec![
        "journal-append",
        "--db",
        db.to_str().expect("db"),
        "--event",
        event,
        "--secret-key-hex",
        SECRET_HEX,
        "--key-id",
        "lifecycle-test",
    ];
    if let Some(run_id) = run_id {
        args.extend(["--run-id", run_id]);
    }
    let output = Command::new(lia_bin()).args(args).output().expect("append");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("append JSON")
}

fn append_rows(db: &std::path::Path, count: u64) -> Value {
    let mut last = Value::Null;
    for index in 0..count {
        let event = json!({
            "family": "raw_harness",
            "harness": "lifecycle-test",
            "raw": {"index": index},
            "timestamp": "2026-07-22T00:00:00Z"
        })
        .to_string();
        last = append_event(db, &event, None);
    }
    last
}

#[test]
fn signed_shareable_anchors_and_rotation_preserve_verifiable_evidence() {
    let temp = tempfile::tempdir().expect("tempdir");
    let db = temp.path().join("journal.db");
    let anchors = temp.path().join("anchors.json");
    let archive_dir = temp.path().join("archive");
    append_rows(&db, 6);

    let create = Command::new(lia_bin())
        .args([
            "journal-anchors",
            "--db",
            db.to_str().expect("db"),
            "--head",
            "2",
            "--tail",
            "2",
            "--secret-key-hex",
            SECRET_HEX,
            "--key-id",
            "lifecycle-test",
            "--out",
            anchors.to_str().expect("anchors"),
        ])
        .output()
        .expect("anchors");
    assert!(
        create.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&create.stderr)
    );
    let manifest: Value = serde_json::from_slice(&create.stdout).expect("anchor json");
    let public_key = manifest["signer"]["public_key_hex"]
        .as_str()
        .expect("public key");
    let verify = Command::new(lia_bin())
        .args([
            "journal-anchors-verify",
            anchors.to_str().expect("anchors"),
            "--expected-public-key-hex",
            public_key,
        ])
        .output()
        .expect("verify anchors");
    assert!(
        verify.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&verify.stderr)
    );

    let mut tampered: Value =
        serde_json::from_slice(&fs::read(&anchors).expect("read anchors")).expect("json");
    tampered["anchors"]["tail"][0]["row_hash"] = Value::String("0".repeat(64));
    fs::write(
        &anchors,
        serde_json::to_vec_pretty(&tampered).expect("tampered json"),
    )
    .expect("write tamper");
    let rejected = Command::new(lia_bin())
        .args([
            "journal-anchors-verify",
            anchors.to_str().expect("anchors"),
            "--expected-public-key-hex",
            public_key,
        ])
        .output()
        .expect("reject anchors");
    assert!(!rejected.status.success(), "tampered anchors verified");

    let rotate = Command::new(lia_bin())
        .args([
            "journal-maintain",
            "--db",
            db.to_str().expect("db"),
            "--archive-dir",
            archive_dir.to_str().expect("archive"),
            "--max-rows",
            "3",
            "--max-bytes",
            "1048576",
            "--secret-key-hex",
            SECRET_HEX,
            "--key-id",
            "lifecycle-test",
        ])
        .output()
        .expect("rotate");
    assert!(
        rotate.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&rotate.stderr)
    );
    let report: Value = serde_json::from_slice(&rotate.stdout).expect("rotation json");
    assert_eq!(report["rotated"], true);
    let archive = report["archive_path"].as_str().expect("archive path");
    for path in [db.to_str().expect("db"), archive] {
        let verify = Command::new(lia_bin())
            .args(["journal-verify", path])
            .output()
            .expect("verify journal");
        assert!(
            verify.status.success(),
            "path={path} stderr={}",
            String::from_utf8_lossy(&verify.stderr)
        );
    }
    assert_eq!(report["archived_rows"], 6);
    assert_eq!(report["active_rows"], 1);
    assert!(!temp.path().join("journal.rotation.json").exists());
    let orphan_locks: Vec<_> = fs::read_dir(temp.path())
        .expect("read tempdir")
        .filter_map(Result::ok)
        .filter(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name.contains(".rotate-") && name.ends_with(".lifecycle-lock.db")
        })
        .collect();
    assert!(
        orphan_locks.is_empty(),
        "rotation left replacement lifecycle lock artifacts"
    );
}

#[test]
fn maintenance_cleans_verified_stale_replacement_without_rotating_active_evidence() {
    let temp = tempfile::tempdir().expect("tempdir");
    let db = temp.path().join("journal.db");
    let stale = temp.path().join("journal.rotate-stale.tmp");
    let archive_dir = temp.path().join("archive");
    let last = append_rows(&db, 2);
    let future_archive = archive_dir.join("not-created.db");
    let run_id = "00000000-0000-4000-8000-000000000097";
    let bridge = json!({
        "family": "journal_meta",
        "run_id": run_id,
        "gate_manifest_version": "lia-gate-manifest-v1",
        "protocol_version": "lia-protocol-v1",
        "note": format!(
            "rotation bridge: archive={} archived_rows=2 prior_head_hash={}",
            future_archive.display(),
            last["row_hash"].as_str().expect("head")
        ),
        "timestamp": "2026-07-22T00:00:00Z"
    })
    .to_string();
    append_event(&stale, &bridge, Some(run_id));

    let maintain = Command::new(lia_bin())
        .args([
            "journal-maintain",
            "--db",
            db.to_str().expect("db"),
            "--archive-dir",
            archive_dir.to_str().expect("archive"),
            "--max-rows",
            "100",
            "--max-bytes",
            "1048576",
            "--max-age-seconds",
            "86400",
            "--secret-key-hex",
            SECRET_HEX,
            "--key-id",
            "lifecycle-test",
        ])
        .output()
        .expect("maintain");
    assert!(
        maintain.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&maintain.stderr)
    );
    let report: Value = serde_json::from_slice(&maintain.stdout).expect("report");
    assert_eq!(report["rotated"], false);
    assert_eq!(report["active_rows"], 2);
    assert_eq!(report["stale_replacements_removed"], 1);
    assert!(
        !stale.exists(),
        "verified stale replacement was not cleaned"
    );
    assert!(
        !replacement_lock_path(&stale).exists(),
        "stale replacement lifecycle lock was not cleaned"
    );

    let verify = Command::new(lia_bin())
        .args(["journal-verify", db.to_str().expect("db")])
        .output()
        .expect("verify active");
    assert!(verify.status.success(), "active evidence was damaged");
}

#[test]
fn maintenance_recovers_verified_bridge_after_interrupted_rotation() {
    let temp = tempfile::tempdir().expect("tempdir");
    let db = temp.path().join("journal.db");
    let archive_dir = temp.path().join("archive");
    fs::create_dir_all(&archive_dir).expect("archive dir");
    let archive = archive_dir.join("journal-crash.db");
    let stale = temp.path().join("journal.rotate-crash.tmp");
    let last = append_rows(&db, 2);
    let prior_head = last["row_hash"].as_str().expect("head");
    fs::rename(&db, &archive).expect("simulate first rotation rename");

    let run_id = "00000000-0000-4000-8000-000000000099";
    let bridge = json!({
        "family": "journal_meta",
        "run_id": run_id,
        "gate_manifest_version": "lia-gate-manifest-v1",
        "protocol_version": "lia-protocol-v1",
        "note": format!(
            "rotation bridge: archive={} archived_rows=2 prior_head_hash={}",
            archive.display(),
            prior_head
        ),
        "timestamp": "2026-07-22T00:00:00Z"
    })
    .to_string();
    append_event(&stale, &bridge, Some(run_id));

    let recover = Command::new(lia_bin())
        .args([
            "journal-maintain",
            "--db",
            db.to_str().expect("db"),
            "--archive-dir",
            archive_dir.to_str().expect("archive"),
            "--max-rows",
            "100",
            "--max-bytes",
            "1048576",
            "--max-age-seconds",
            "31536000",
            "--secret-key-hex",
            SECRET_HEX,
            "--key-id",
            "lifecycle-test",
        ])
        .output()
        .expect("recover");
    assert!(
        recover.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&recover.stderr)
    );
    let report: Value = serde_json::from_slice(&recover.stdout).expect("report");
    assert_eq!(report["recovered_active"], true);
    assert!(db.exists(), "verified replacement was not promoted");
    assert!(!stale.exists(), "promoted replacement still exists");
    assert!(
        !replacement_lock_path(&stale).exists(),
        "promoted replacement lifecycle lock was not cleaned"
    );
    for path in [&db, &archive] {
        let verify = Command::new(lia_bin())
            .args(["journal-verify", path.to_str().expect("journal")])
            .output()
            .expect("verify recovered journal");
        assert!(verify.status.success(), "journal failed after recovery");
    }
}

#[test]
fn maintenance_refuses_replacement_whose_bridge_does_not_match_archive() {
    let temp = tempfile::tempdir().expect("tempdir");
    let db = temp.path().join("journal.db");
    let archive_dir = temp.path().join("archive");
    fs::create_dir_all(&archive_dir).expect("archive dir");
    let archive = archive_dir.join("journal-crash.db");
    let stale = temp.path().join("journal.rotate-crash.tmp");
    append_rows(&db, 1);
    fs::rename(&db, &archive).expect("simulate first rotation rename");
    let run_id = "00000000-0000-4000-8000-000000000098";
    let false_bridge = json!({
        "family": "journal_meta",
        "run_id": run_id,
        "gate_manifest_version": "lia-gate-manifest-v1",
        "protocol_version": "lia-protocol-v1",
        "note": format!(
            "rotation bridge: archive={} archived_rows=1 prior_head_hash={}",
            archive.display(),
            "0".repeat(64)
        ),
        "timestamp": "2026-07-22T00:00:00Z"
    })
    .to_string();
    append_event(&stale, &false_bridge, Some(run_id));

    let refused = Command::new(lia_bin())
        .args([
            "journal-maintain",
            "--db",
            db.to_str().expect("db"),
            "--archive-dir",
            archive_dir.to_str().expect("archive"),
            "--max-rows",
            "100",
            "--max-bytes",
            "1048576",
            "--secret-key-hex",
            SECRET_HEX,
        ])
        .output()
        .expect("refuse");
    assert!(!refused.status.success(), "false bridge was promoted");
    assert!(!db.exists(), "a fresh unrelated active journal was created");
    assert!(archive.exists(), "archived evidence was removed");
    assert!(
        stale.exists(),
        "failed recovery evidence was silently deleted"
    );
}
