#!/usr/bin/env bash
# LIA Trust Kernel — one-line installer (GitHub / curl | bash style)
#
# One-liners:
#   # From a clone:
#   bash install.sh
#
#   # Remote (after this file is on a public URL / raw GitHub):
#   curl -fsSL https://raw.githubusercontent.com/<org>/lia-trust/main/install.sh | bash
#
#   # Local absolute path:
#   bash /path/to/lia-trust/install.sh
#
# Environment (optional):
#   LIA_PREFIX          install prefix (default: $HOME/.local) → bin/lia
#   LIA_BIN_DIR         override binary dir (default: $LIA_PREFIX/bin)
#   LIA_NO_WIRE=1       install binary only (skip Claude Code / Codex wiring)
#   LIA_DRY_RUN=1       wire with --dry-run (no live config writes)
#   LIA_NO_APPLY_LIVE=1 wire without --apply-live (refuses real ~/.claude|~/.codex)
#   LIA_REPO_URL        git clone URL when not already inside the repo
#   LIA_REPO_REF        git ref to clone (default: main)
#   LIA_SKIP_BUILD=1    use existing release binary only (fail if missing)
#   LIA_FORCE_BUILD=1   always cargo build --release even if binary exists
#
# Requires: bash, curl (remote), cargo+rustc (build-from-source), git (clone).
set -euo pipefail

VERSION_HINT="0.1.0"
DEFAULT_REPO_URL="${LIA_REPO_URL:-https://github.com/DITlieD/lia-trust.git}"
DEFAULT_REF="${LIA_REPO_REF:-main}"

# All human logs go to stderr so $(...) captures only return values (paths).
info()  { printf '==> %s\n' "$*" >&2; }
warn()  { printf 'warning: %s\n' "$*" >&2; }
die()   { printf 'error: %s\n' "$*" >&2; exit 1; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

# Resolve directory of this script when executed as a file (not curl|bash).
script_dir() {
  local src="${BASH_SOURCE[0]:-}"
  if [[ -n "$src" && -f "$src" ]]; then
    cd "$(dirname "$src")" && pwd
  else
    echo ""
  fi
}

# True if CWD (or given path) looks like the lia-trust workspace root.
is_lia_root() {
  local d="${1:-.}"
  [[ -f "$d/Cargo.toml" ]] && [[ -d "$d/crates/lia-cli" ]] && [[ -f "$d/crates/lia-cli/src/main.rs" ]]
}

ensure_path_note() {
  local bindir="$1"
  case ":${PATH}:" in
    *":${bindir}:"*) ;;
    *)
      warn "${bindir} is not on PATH"
      printf '\nAdd this to your shell profile (~/.bashrc / ~/.zshrc):\n'
      printf '  export PATH="%s:$PATH"\n\n' "$bindir"
      ;;
  esac
}

find_or_fetch_src() {
  # 1) Already in repo
  if is_lia_root "."; then
    pwd
    return
  fi
  # 2) Script lives in repo
  local sd
  sd="$(script_dir)"
  if [[ -n "$sd" ]] && is_lia_root "$sd"; then
    echo "$sd"
    return
  fi
  # 3) Parent of script
  if [[ -n "$sd" ]] && is_lia_root "$sd/.."; then
    (cd "$sd/.." && pwd)
    return
  fi
  # 4) Clone
  need_cmd git
  local dest="${LIA_SRC_DIR:-$HOME/.lia-trust/src}"
  if [[ -d "$dest/.git" ]] && is_lia_root "$dest"; then
    info "updating existing source at $dest"
    git -C "$dest" fetch --depth 1 origin "$DEFAULT_REF" 2>/dev/null || true
    git -C "$dest" checkout "$DEFAULT_REF" 2>/dev/null || true
    git -C "$dest" pull --ff-only 2>/dev/null || true
    echo "$dest"
    return
  fi
  info "cloning ${DEFAULT_REPO_URL} (${DEFAULT_REF}) → ${dest}"
  rm -rf "$dest"
  mkdir -p "$(dirname "$dest")"
  git clone --depth 1 --branch "$DEFAULT_REF" "$DEFAULT_REPO_URL" "$dest" \
    || git clone --depth 1 "$DEFAULT_REPO_URL" "$dest"
  is_lia_root "$dest" || die "clone does not look like lia-trust: $dest"
  echo "$dest"
}

build_lia() {
  local root="$1"
  local out="$root/target/release/lia"
  if [[ "${LIA_FORCE_BUILD:-0}" != "1" && -x "$out" ]]; then
    info "using existing release binary: $out"
    echo "$out"
    return
  fi
  if [[ "${LIA_SKIP_BUILD:-0}" == "1" ]]; then
    [[ -x "$out" ]] || die "LIA_SKIP_BUILD=1 but missing $out"
    echo "$out"
    return
  fi
  need_cmd cargo
  info "building lia (cargo build -p lia-cli --release)…"
  (cd "$root" && cargo build -p lia-cli --release)
  [[ -x "$out" ]] || die "build finished but binary missing: $out"
  echo "$out"
}

install_binary() {
  local built="$1"
  local bindir="${LIA_BIN_DIR:-${LIA_PREFIX:-$HOME/.local}/bin}"
  mkdir -p "$bindir"
  local dest="$bindir/lia"
  info "installing binary → $dest"
  # Atomic-ish replace
  cp -f "$built" "$dest.tmp.$$"
  chmod 755 "$dest.tmp.$$"
  mv -f "$dest.tmp.$$" "$dest"
  echo "$dest"
}

wire_harnesses() {
  local lia_bin="$1"
  if [[ "${LIA_NO_WIRE:-0}" == "1" ]]; then
    info "LIA_NO_WIRE=1 — skipping Claude Code / Codex wiring"
    return
  fi
  local args=(install --lia-bin "$lia_bin")
  if [[ "${LIA_DRY_RUN:-0}" == "1" ]]; then
    args+=(--dry-run)
    info "wiring harnesses (dry-run)…"
  elif [[ "${LIA_NO_APPLY_LIVE:-0}" == "1" ]]; then
    info "wiring harnesses without --apply-live (fixture/safe mode)…"
  else
    args+=(--apply-live)
    info "wiring Claude Code + Codex (--apply-live)…"
  fi
  "$lia_bin" "${args[@]}"
  echo
  "$lia_bin" status || true
}

print_done() {
  local dest="$1"
  cat <<EOF

LIA Trust Kernel installed.

  binary:  $dest
  version: $("$dest" --help 2>/dev/null | head -1 || echo "lia ${VERSION_HINT}")

Kernel boundary (honest):
  • protocol + journal + Ed25519 + seven gates + offline verify
  • Claude Code: PreToolUse hook
  • Codex: MCP stdio (Content-Length + initialize)
  • assurance: GATE where hooks/MCP fire — not CONFINE

Next:
  lia status
  lia journal-verify ~/.lia-trust/journal/default.db
  lia uninstall --apply-live    # remove harness wiring (keeps journal/keys)

EOF
  ensure_path_note "$(dirname "$dest")"
}

main() {
  info "LIA Trust Kernel installer"
  local root built dest
  root="$(find_or_fetch_src)"
  info "source: $root"
  built="$(build_lia "$root")"
  dest="$(install_binary "$built")"
  wire_harnesses "$dest"
  print_done "$dest"
}

main "$@"
