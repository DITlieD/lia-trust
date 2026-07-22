use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FreezeError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("config: {0}")]
    Config(String),
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Modified,
    Added,
    Deleted,
    MissingBaseline,
}

#[derive(Debug, Clone, Serialize)]
pub struct Change {
    pub path: String,
    pub kind: ChangeKind,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckReport {
    pub ok: bool,
    pub changes: Vec<Change>,
}

pub fn read_manifest(manifest: &Path) -> Result<Vec<String>, FreezeError> {
    let text = fs::read_to_string(manifest)
        .map_err(|e| FreezeError::Config(format!("manifest {}: {e}", manifest.display())))?;
    let mut out = Vec::new();
    for raw in text.lines() {
        let ln = raw.trim();
        if ln.is_empty() || ln.starts_with('#') {
            continue;
        }
        out.push(ln.replace('\\', "/"));
    }
    if out.is_empty() {
        return Err(FreezeError::Config(format!(
            "manifest {} is empty",
            manifest.display()
        )));
    }
    Ok(out)
}

pub fn hash_file(path: &Path) -> Result<String, FreezeError> {
    let bytes = fs::read(path)?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

pub fn read_lock(lock_file: &Path) -> BTreeMap<String, (String, String)> {
    let mut out = BTreeMap::new();
    let Ok(text) = fs::read_to_string(lock_file) else {
        return out;
    };
    for raw in text.lines() {
        let ln = raw.trim_end();
        if ln.is_empty() || ln.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = ln.split('\t').collect();
        if parts.len() == 3 {
            out.insert(
                parts[0].replace('\\', "/"),
                (parts[1].to_string(), parts[2].to_string()),
            );
        }
    }
    out
}

pub fn write_lock(lock_file: &Path, rows: &BTreeMap<String, String>) -> Result<(), FreezeError> {
    let mut lines = vec![
        "# gate-manifest.lock — frozen wiring-gate baseline (R8). Do NOT edit by hand.".to_string(),
        "# Regenerate out-of-band: cargo run -p lia_gate_freeze -- --lock".to_string(),
        "# format: relpath<TAB>algo<TAB>hexdigest".to_string(),
    ];
    for (rel, digest) in rows {
        lines.push(format!("{rel}\tblake3\t{digest}"));
    }
    if let Some(parent) = lock_file.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(lock_file, lines.join("\n") + "\n")?;
    Ok(())
}

pub fn lock_baseline(
    root: &Path,
    manifest: &Path,
    lock_file: &Path,
) -> Result<BTreeMap<String, String>, FreezeError> {
    let entries = read_manifest(manifest)?;
    let mut rows = BTreeMap::new();
    for rel in entries {
        let path = root.join(&rel);
        if !path.is_file() {
            return Err(FreezeError::Config(format!(
                "manifest path missing on --lock: {rel}"
            )));
        }
        rows.insert(rel, hash_file(&path)?);
    }
    write_lock(lock_file, &rows)?;
    Ok(rows)
}

pub fn check_baseline(
    root: &Path,
    manifest: &Path,
    lock_file: &Path,
) -> Result<CheckReport, FreezeError> {
    if !lock_file.is_file() {
        return Ok(CheckReport {
            ok: false,
            changes: vec![Change {
                path: lock_file
                    .strip_prefix(root)
                    .unwrap_or(lock_file)
                    .to_string_lossy()
                    .into(),
                kind: ChangeKind::MissingBaseline,
                detail: "no gate-manifest.lock — run lia_gate_freeze --lock out-of-band first"
                    .into(),
            }],
        });
    }
    let expected = read_lock(lock_file);
    let listed = read_manifest(manifest)?;
    let listed_set: BTreeSet<_> = listed.iter().cloned().collect();
    let mut changes = Vec::new();

    for rel in &listed {
        let path = root.join(rel);
        match expected.get(rel) {
            None => changes.push(Change {
                path: rel.clone(),
                kind: ChangeKind::Added,
                detail: "in manifest but not in lock baseline".into(),
            }),
            Some((algo, digest)) => {
                if algo != "blake3" {
                    changes.push(Change {
                        path: rel.clone(),
                        kind: ChangeKind::Modified,
                        detail: format!("lock algo {algo} != blake3"),
                    });
                    continue;
                }
                if !path.is_file() {
                    changes.push(Change {
                        path: rel.clone(),
                        kind: ChangeKind::Deleted,
                        detail: "manifest path missing on disk".into(),
                    });
                    continue;
                }
                let now = hash_file(&path)?;
                if &now != digest {
                    changes.push(Change {
                        path: rel.clone(),
                        kind: ChangeKind::Modified,
                        detail: format!("blake3 mismatch (baseline {digest}, now {now})"),
                    });
                }
            }
        }
    }

    for rel in expected.keys() {
        if !listed_set.contains(rel) {
            changes.push(Change {
                path: rel.clone(),
                kind: ChangeKind::Deleted,
                detail: "in lock baseline but removed from manifest".into(),
            });
        }
    }

    Ok(CheckReport {
        ok: changes.is_empty(),
        changes,
    })
}

pub fn default_paths(root: &Path) -> (PathBuf, PathBuf) {
    (
        root.join("tools/gate-manifest.txt"),
        root.join("tools/gate-manifest.lock"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_rejects_touched_frozen_file() {
        let dir = std::env::temp_dir().join(format!("lia_gate_freeze_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("tools")).unwrap();
        let frozen = dir.join("tools/frozen.txt");
        fs::write(&frozen, "v1\n").unwrap();
        let manifest = dir.join("tools/gate-manifest.txt");
        fs::write(&manifest, "tools/frozen.txt\n").unwrap();
        let lock = dir.join("tools/gate-manifest.lock");
        lock_baseline(&dir, &manifest, &lock).unwrap();
        fs::write(&frozen, "v2\n").unwrap();
        let report = check_baseline(&dir, &manifest, &lock).unwrap();
        assert!(!report.ok);
        assert!(report
            .changes
            .iter()
            .any(|c| c.kind == ChangeKind::Modified));
    }
}
