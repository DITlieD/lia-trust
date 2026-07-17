use lia_protocol::{RiskTier, Verdict};
use serde_json::json;

use crate::{make_outcome, GateConfig, GateError, GateOutcome, GateRequest};

pub fn check_dependency_reality(
    request: &GateRequest,
    config: &GateConfig,
) -> Result<GateOutcome, GateError> {
    let package = request
        .payload
        .package
        .as_deref()
        .ok_or_else(|| GateError::Invalid("dependency-reality requires package".into()))?;
    let version = request.payload.version.as_deref();

    let evidence = json!({
        "package": package,
        "version": version,
        "registry_keys": config.registry.keys().collect::<Vec<_>>(),
    });

    if looks_typosquat(package, &config.registry) {
        return Ok(make_outcome(
            "dependency-reality",
            request.action_id,
            Verdict::Deny,
            "DEP_TYPOSQUAT",
            RiskTier::Security,
            Some("package name looks like typosquat/slopsquat of a known package".into()),
            Some(package.to_string()),
            &evidence,
        ));
    }

    let Some(versions) = config.registry.get(package) else {
        return Ok(make_outcome(
            "dependency-reality",
            request.action_id,
            Verdict::Deny,
            "DEP_NOT_FOUND",
            RiskTier::Security,
            Some("package absent from registry snapshot".into()),
            Some(package.to_string()),
            &evidence,
        ));
    };

    if let Some(ver) = version {
        if !versions.iter().any(|v| v == ver) {
            return Ok(make_outcome(
                "dependency-reality",
                request.action_id,
                Verdict::Deny,
                "DEP_VERSION_MISSING",
                RiskTier::Security,
                Some(format!("version {ver} not in registry for {package}")),
                Some(format!("{package}@{ver}")),
                &evidence,
            ));
        }
    }

    Ok(make_outcome(
        "dependency-reality",
        request.action_id,
        Verdict::Allow,
        "GATE_ALLOW",
        RiskTier::Security,
        Some("package and version present in registry snapshot".into()),
        None,
        &evidence,
    ))
}

fn looks_typosquat(name: &str, registry: &std::collections::BTreeMap<String, Vec<String>>) -> bool {
    if registry.contains_key(name) {
        return false;
    }
    let n = name.to_ascii_lowercase();
    for known in registry.keys() {
        let k = known.to_ascii_lowercase();
        if k == n {
            continue;
        }
        if edit_distance_one_or_transpose(&n, &k) {
            return true;
        }
        if n.len() > 3 && k.len() > 3 && (n.contains(&k) || k.contains(&n)) && n != k {
            return true;
        }
    }
    false
}

fn edit_distance_one_or_transpose(a: &str, b: &str) -> bool {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (la, lb) = (a.len(), b.len());
    if la.abs_diff(lb) > 1 {
        return false;
    }
    if la == lb {
        let mut diff = 0usize;
        let mut i = 0;
        while i < la {
            if a[i] != b[i] {
                if i + 1 < la && a[i] == b[i + 1] && a[i + 1] == b[i] {
                    i += 2;
                    diff += 1;
                    continue;
                }
                diff += 1;
                if diff > 1 {
                    return false;
                }
            }
            i += 1;
        }
        return diff == 1;
    }
    let (longer, shorter) = if la > lb { (&a, &b) } else { (&b, &a) };
    let mut i = 0;
    let mut j = 0;
    let mut skipped = false;
    while i < longer.len() && j < shorter.len() {
        if longer[i] == shorter[j] {
            i += 1;
            j += 1;
        } else if !skipped {
            skipped = true;
            i += 1;
        } else {
            return false;
        }
    }
    true
}
