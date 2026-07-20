use std::path::{Component, Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ExpandError {
    #[error("command substitution refused: {0}")]
    CommandSubstitution(String),
    #[error("empty command")]
    EmptyCommand,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpandedCommand {
    pub original: String,
    pub tokens: Vec<String>,
    pub path_tokens: Vec<ExpandedPath>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpandedPath {
    pub original: String,
    pub expanded: String,
    pub kind: PathKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    Concrete,
    GlobBase,
}

const GLOB_METACHARS: &[char] = &['*', '?', '[', ']', '{', '}'];

pub fn expand_command_paths(
    command: &str,
    home_dir: Option<&Path>,
    env: &std::collections::BTreeMap<String, String>,
    cwd: &Path,
) -> Result<ExpandedCommand, ExpandError> {
    let command = command.trim();
    if command.is_empty() {
        return Err(ExpandError::EmptyCommand);
    }
    reject_command_substitution(command)?;

    let tokens = tokenize_shellish(command);
    let mut path_tokens = Vec::new();
    for tok in &tokens {
        if looks_path_like(tok) {
            path_tokens.push(expand_path_token(tok, home_dir, env, cwd)?);
        }
    }
    Ok(ExpandedCommand {
        original: command.to_string(),
        tokens,
        path_tokens,
    })
}

pub fn expand_path_token(
    token: &str,
    home_dir: Option<&Path>,
    env: &std::collections::BTreeMap<String, String>,
    cwd: &Path,
) -> Result<ExpandedPath, ExpandError> {
    reject_command_substitution(token)?;
    let after_env = substitute_env_vars(token, env);
    let after_tilde = expand_tilde(&after_env, home_dir);
    if after_tilde.chars().any(|c| GLOB_METACHARS.contains(&c)) {
        let base = literal_glob_base(&after_tilde);
        let joined = join_cwd(cwd, &base);
        return Ok(ExpandedPath {
            original: token.to_string(),
            expanded: joined.to_string_lossy().into_owned(),
            kind: PathKind::GlobBase,
        });
    }
    let joined = join_cwd(cwd, Path::new(&after_tilde));
    Ok(ExpandedPath {
        original: token.to_string(),
        expanded: joined.to_string_lossy().into_owned(),
        kind: PathKind::Concrete,
    })
}

/// Refuse real shell command substitution while allowing backticks / `$` that appear
/// only as data inside single quotes or single-quoted heredoc bodies (e.g. Go struct tags).
///
/// Rules (bash-aligned for the cases we care about):
/// - Inside single quotes: no substitution → ALLOW backticks and `$(...)` text.
/// - Unquoted or double-quoted: `$()` and backticks are substitution → DENY.
/// - Heredoc with `<<'DELIM'` / `<<"DELIM"`: body is not scanned for substitution.
/// - Heredoc with unquoted `<<DELIM`: body is scanned (unquoted heredoc expands).
pub fn reject_command_substitution(s: &str) -> Result<(), ExpandError> {
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0usize;
    let mut in_single = false;
    let mut in_double = false;

    while i < chars.len() {
        let c = chars[i];

        // Heredoc start only when not inside quotes.
        if !in_single && !in_double && c == '<' && i + 1 < chars.len() && chars[i + 1] == '<' {
            i += 2;
            // optional <<-
            if i < chars.len() && chars[i] == '-' {
                i += 1;
            }
            // skip whitespace
            while i < chars.len() && (chars[i] == ' ' || chars[i] == '\t') {
                i += 1;
            }
            let mut quoted = false;
            let mut delim = String::new();
            if i < chars.len() && (chars[i] == '\'' || chars[i] == '"') {
                quoted = true;
                let q = chars[i];
                i += 1;
                while i < chars.len() && chars[i] != q {
                    delim.push(chars[i]);
                    i += 1;
                }
                if i < chars.len() && chars[i] == q {
                    i += 1;
                }
            } else {
                while i < chars.len()
                    && !chars[i].is_whitespace()
                    && chars[i] != ';'
                    && chars[i] != '|'
                    && chars[i] != '&'
                {
                    delim.push(chars[i]);
                    i += 1;
                }
            }
            if delim.is_empty() {
                continue;
            }
            // consume rest of opener line
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            if i < chars.len() && chars[i] == '\n' {
                i += 1;
            }
            // body until a line that is exactly delim
            let delim_chars: Vec<char> = delim.chars().collect();
            while i < chars.len() {
                let line_start = i;
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
                let line = &chars[line_start..i];
                // strip trailing CR
                let line = if line.last() == Some(&'\r') {
                    &line[..line.len().saturating_sub(1)]
                } else {
                    line
                };
                let is_end = line == delim_chars.as_slice();
                if is_end {
                    if i < chars.len() && chars[i] == '\n' {
                        i += 1;
                    }
                    break;
                }
                // unquoted heredoc bodies expand; scan for substitution
                if !quoted {
                    let body: String = line.iter().collect();
                    if has_active_substitution(&body) {
                        return Err(ExpandError::CommandSubstitution(s.to_string()));
                    }
                }
                if i < chars.len() && chars[i] == '\n' {
                    i += 1;
                }
            }
            continue;
        }

        if !in_double && c == '\'' {
            in_single = !in_single;
            i += 1;
            continue;
        }
        if !in_single && c == '"' {
            in_double = !in_double;
            i += 1;
            continue;
        }
        if in_single {
            i += 1;
            continue;
        }
        // escapes outside single quotes
        if c == '\\' && i + 1 < chars.len() {
            i += 2;
            continue;
        }
        if c == '$' && i + 1 < chars.len() && chars[i + 1] == '(' {
            return Err(ExpandError::CommandSubstitution(s.to_string()));
        }
        if c == '`' {
            return Err(ExpandError::CommandSubstitution(s.to_string()));
        }
        i += 1;
    }
    Ok(())
}

fn has_active_substitution(s: &str) -> bool {
    // body line already outside single quotes context of outer parse
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    let mut in_single = false;
    let mut in_double = false;
    while i < chars.len() {
        let c = chars[i];
        if !in_double && c == '\'' {
            in_single = !in_single;
            i += 1;
            continue;
        }
        if !in_single && c == '"' {
            in_double = !in_double;
            i += 1;
            continue;
        }
        if in_single {
            i += 1;
            continue;
        }
        if c == '\\' && i + 1 < chars.len() {
            i += 2;
            continue;
        }
        if c == '$' && i + 1 < chars.len() && chars[i + 1] == '(' {
            return true;
        }
        if c == '`' {
            return true;
        }
        i += 1;
    }
    false
}

fn expand_tilde(token: &str, home_dir: Option<&Path>) -> String {
    if token == "~" {
        return home_dir
            .map(|h| h.to_string_lossy().into_owned())
            .unwrap_or_else(|| "~".to_string());
    }
    if let Some(rest) = token.strip_prefix("~/") {
        return match home_dir {
            Some(h) => h.join(rest).to_string_lossy().into_owned(),
            None => token.to_string(),
        };
    }
    token.to_string()
}

fn substitute_env_vars(s: &str, env: &std::collections::BTreeMap<String, String>) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() {
            if bytes[i + 1] == b'{' {
                if let Some(end) = s[i + 2..].find('}') {
                    let name = &s[i + 2..i + 2 + end];
                    if let Some(val) = env.get(name) {
                        out.push_str(val);
                    }
                    i = i + 2 + end + 1;
                    continue;
                }
            } else {
                let name_start = i + 1;
                let mut j = name_start;
                while j < bytes.len()
                    && (bytes[j] == b'_' || bytes[j].is_ascii_alphanumeric())
                    && !(j == name_start && bytes[j].is_ascii_digit())
                {
                    j += 1;
                }
                if j > name_start {
                    let name = &s[name_start..j];
                    if let Some(val) = env.get(name) {
                        out.push_str(val);
                    }
                    i = j;
                    continue;
                }
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn literal_glob_base(expanded: &str) -> PathBuf {
    let first_meta = expanded
        .char_indices()
        .find(|(_, c)| GLOB_METACHARS.contains(c))
        .map(|(idx, _)| idx)
        .unwrap_or(expanded.len());
    let literal = &expanded[..first_meta];
    let cut = literal
        .rfind(['/', '\\'])
        .map(|idx| &literal[..idx])
        .unwrap_or("");
    PathBuf::from(cut)
}

fn join_cwd(cwd: &Path, p: &Path) -> PathBuf {
    if p.as_os_str().is_empty() {
        return cwd.to_path_buf();
    }
    if p.is_absolute() {
        return normalize_lexical(p);
    }
    normalize_lexical(&cwd.join(p))
}

/// Lexically normalize `.` / `..` without touching the filesystem.
/// Parent of root stays root (`/..` → `/`). Relative `..` past the start yields empty components popped.
pub fn normalize_lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::RootDir => {
                out.push(comp.as_os_str());
            }
            Component::Prefix(prefix) => {
                out.push(prefix.as_os_str());
            }
            Component::Normal(part) => {
                out.push(part);
            }
        }
    }
    out
}

fn looks_path_like(tok: &str) -> bool {
    tok.starts_with('/')
        || tok.starts_with('.')
        || tok.starts_with('~')
        || tok.starts_with('$')
        || tok.contains('/')
        || tok.contains('*')
        || tok.contains('?')
}

fn tokenize_shellish(command: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut chars = command.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;
    while let Some(c) = chars.next() {
        match c {
            '\'' if !in_double => {
                in_single = !in_single;
            }
            '"' if !in_single => {
                in_double = !in_double;
            }
            ' ' | '\t' | '\n' if !in_single && !in_double => {
                if !cur.is_empty() {
                    tokens.push(std::mem::take(&mut cur));
                }
            }
            ';' | '|' | '&' | '<' | '>' if !in_single && !in_double => {
                if !cur.is_empty() {
                    tokens.push(std::mem::take(&mut cur));
                }
                tokens.push(c.to_string());
            }
            '\\' if !in_single => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn rejects_unquoted_command_substitution() {
        assert!(reject_command_substitution("rm -rf $(pwd)").is_err());
        assert!(reject_command_substitution("echo `whoami`").is_err());
        assert!(reject_command_substitution("echo $(rm -rf /)").is_err());
        assert!(reject_command_substitution("echo \"$(rm -rf /)\"").is_err());
        assert!(reject_command_substitution("echo \"`rm -rf /`\"").is_err());
    }

    #[test]
    fn allows_backticks_inside_single_quotes() {
        // Go struct tags as data
        assert!(reject_command_substitution(
            r#"echo 'type X struct { Rate int `header:"Rate"` }'"#
        )
        .is_ok());
        assert!(reject_command_substitution(
            r#"cat > binding/header.go <<'EOF'
type Rate struct {
    Rate int `header:"Rate"`
}
EOF"#
        )
        .is_ok());
        // $() inside single quotes is data, not substitution
        assert!(reject_command_substitution(r#"echo '$(rm -rf /)'"#).is_ok());
    }

    #[test]
    fn unquoted_heredoc_still_rejects_substitution() {
        assert!(reject_command_substitution(
            "cat <<EOF\necho $(whoami)\nEOF"
        )
        .is_err());
    }

    #[test]
    fn expands_tilde_not_via_canonicalize() {
        let home = PathBuf::from("/home/agent");
        let env = BTreeMap::new();
        let cwd = PathBuf::from("/work/repo");
        let exp = expand_path_token("~/secrets", Some(&home), &env, &cwd).expect("ok");
        assert_eq!(exp.expanded, "/home/agent/secrets");
    }

    #[test]
    fn parent_path_normalize_is_deterministic() {
        let cwd = PathBuf::from("/testbed");
        let env = BTreeMap::new();
        // ../jq from /testbed → /jq (escapes root)
        let exp = expand_path_token("../jq", None, &env, &cwd).expect("ok");
        assert_eq!(exp.expanded, "/jq");
        // relative within root
        let cwd2 = PathBuf::from("/testbed/src");
        let exp2 = expand_path_token("../jq", None, &env, &cwd2).expect("ok");
        assert_eq!(exp2.expanded, "/testbed/jq");
        // absolute stays absolute after normalize
        let exp3 = expand_path_token("/app/../app/bin", None, &env, &cwd).expect("ok");
        assert_eq!(exp3.expanded, "/app/bin");
    }

    #[test]
    fn expand_command_allows_app_paths() {
        let env = BTreeMap::from([("HOME".into(), "/home/agent".into())]);
        let cwd = PathBuf::from("/app");
        let exp = expand_command_paths("ls -la /app", Some(Path::new("/home/agent")), &env, &cwd)
            .expect("ok");
        assert!(exp
            .path_tokens
            .iter()
            .any(|p| p.expanded == "/app" || p.expanded.starts_with("/app")));
    }
}
