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
#   LIA_INSTALL_MODE    auto|prebuilt|source (default: auto)
#   LIA_RELEASE_TAG     release tag (default: v0.3.0)
#   LIA_RELEASE_BASE_URL override release asset base URL (advanced/testing)
#   LIA_REPO_REF        source fallback ref (default: LIA_RELEASE_TAG)
#   LIA_SKIP_BUILD=1    use existing release binary only (fail if missing)
#   LIA_FORCE_BUILD=1   always cargo build --release even if binary exists
#   LIA_INSTALL_OS/ARCH override platform detection (advanced/testing)
#
# Requires: bash + curl + tar + sha256sum (prebuilt); cargo+rustc + git (source fallback).
set -euo pipefail

VERSION_HINT="0.3.0"
RELEASE_TAG="${LIA_RELEASE_TAG:-v${VERSION_HINT}}"
INSTALL_MODE="${LIA_INSTALL_MODE:-auto}"
DEFAULT_REPO_URL="${LIA_REPO_URL:-https://github.com/DITlieD/lia-trust.git}"
DEFAULT_REF="${LIA_REPO_REF:-$RELEASE_TAG}"
DEFAULT_RELEASE_BASE_URL="https://github.com/DITlieD/lia-trust/releases/download/${RELEASE_TAG}"

# All human logs go to stderr so $(...) captures only return values (paths).
info()  { printf '==> %s\n' "$*" >&2; }
warn()  { printf 'warning: %s\n' "$*" >&2; }
die()   { printf 'error: %s\n' "$*" >&2; exit 1; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

validate_install_options() {
  case "$INSTALL_MODE" in
    auto | prebuilt | source) ;;
    *) die "LIA_INSTALL_MODE must be auto, prebuilt, or source" ;;
  esac
  [[ "$RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    || die "invalid LIA_RELEASE_TAG: $RELEASE_TAG"
}

release_target() {
  local os arch
  os="${LIA_INSTALL_OS:-$(uname -s)}"
  arch="${LIA_INSTALL_ARCH:-$(uname -m)}"
  case "${os}:${arch}" in
    Linux:x86_64 | Linux:amd64)
      echo "x86_64-unknown-linux-gnu"
      ;;
    *)
      return 1
      ;;
  esac
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
  local sd=""
  # Explicit source mode is the development path and may build the checked-out worktree.
  # Automatic fallback never trusts ambient source; it resolves the exact requested remote ref.
  if [[ "$INSTALL_MODE" == "source" ]]; then
    if is_lia_root "."; then
      pwd
      return
    fi
    sd="$(script_dir)"
    if [[ -n "$sd" ]] && is_lia_root "$sd"; then
      echo "$sd"
      return
    fi
    if [[ -n "$sd" ]] && is_lia_root "$sd/.."; then
      (cd "$sd/.." && pwd)
      return
    fi
  fi

  need_cmd git
  git check-ref-format --branch "$DEFAULT_REF" >/dev/null 2>&1 \
    || die "invalid source ref: $DEFAULT_REF"
  local dest="${LIA_SRC_DIR:-$HOME/.lia-trust/src}"
  if [[ -d "$dest/.git" ]] && is_lia_root "$dest"; then
    info "resolving exact source ref ${DEFAULT_REF} at $dest"
    if [[ "$DEFAULT_REF" == "$RELEASE_TAG" ]]; then
      git -C "$dest" fetch --depth 1 origin \
        "refs/tags/${DEFAULT_REF}:refs/tags/${DEFAULT_REF}" \
        || die "could not fetch exact release tag ${DEFAULT_REF}"
      git -C "$dest" checkout --detach "refs/tags/${DEFAULT_REF}^{commit}" \
        || die "could not checkout exact release tag ${DEFAULT_REF}"
    else
      git -C "$dest" fetch --depth 1 origin "$DEFAULT_REF" \
        || die "could not fetch exact source ref ${DEFAULT_REF}"
      git -C "$dest" checkout --detach FETCH_HEAD \
        || die "could not checkout exact source ref ${DEFAULT_REF}"
    fi
    verify_source_ref "$dest"
    echo "$dest"
    return
  fi
  info "cloning ${DEFAULT_REPO_URL} (${DEFAULT_REF}) → ${dest}"
  [[ ! -e "$dest" ]] || die "source destination exists but is not a valid lia-trust clone: $dest"
  mkdir -p "$(dirname "$dest")"
  git clone --depth 1 --branch "$DEFAULT_REF" "$DEFAULT_REPO_URL" "$dest" \
    || die "could not clone exact source ref ${DEFAULT_REF}"
  is_lia_root "$dest" || die "clone does not look like lia-trust: $dest"
  verify_source_ref "$dest"
  echo "$dest"
}

verify_source_ref() {
  local root="$1" actual expected
  actual="$(git -C "$root" rev-parse 'HEAD^{commit}')" \
    || die "could not resolve cloned source HEAD"
  if [[ "$DEFAULT_REF" == "$RELEASE_TAG" ]]; then
    expected="$(git -C "$root" rev-parse "refs/tags/${RELEASE_TAG}^{commit}")" \
      || die "release tag ${RELEASE_TAG} is absent after clone"
  else
    expected="$(git -C "$root" rev-parse "${DEFAULT_REF}^{commit}" 2>/dev/null \
      || git -C "$root" rev-parse 'FETCH_HEAD^{commit}')" \
      || die "could not resolve requested source ref ${DEFAULT_REF}"
  fi
  [[ "$actual" == "$expected" ]] \
    || die "source HEAD does not match requested ref ${DEFAULT_REF}"
}

build_lia() {
  local root="$1"
  local out="$root/target/release/lia"
  if [[ "${LIA_FORCE_BUILD:-0}" != "1" && -x "$out" ]]; then
    if [[ "$("$out" --version 2>/dev/null || true)" == "lia ${VERSION_HINT}" ]]; then
      info "using existing release binary: $out"
      echo "$out"
      return
    fi
    info "existing binary is not lia ${VERSION_HINT}; rebuilding"
  fi
  if [[ "${LIA_SKIP_BUILD:-0}" == "1" ]]; then
    die "LIA_SKIP_BUILD=1 but no existing lia ${VERSION_HINT} binary is available"
  fi
  need_cmd cargo
  info "building lia (cargo build -p lia-cli --release)…"
  (cd "$root" && cargo build -p lia-cli --release) \
    || die "cargo release build failed"
  [[ -x "$out" ]] || die "build finished but binary missing: $out"
  [[ "$("$out" --version 2>/dev/null || true)" == "lia ${VERSION_HINT}" ]] \
    || die "source build did not produce lia ${VERSION_HINT}"
  echo "$out"
}

install_binary() {
  local built="$1"
  local bindir="${LIA_BIN_DIR:-${LIA_PREFIX:-$HOME/.local}/bin}"
  mkdir -p "$bindir"
  local dest="$bindir/lia"
  info "installing binary → $dest"
  # Atomic-ish replace
  cp -f "$built" "$dest.tmp.$$" || {
    warn "could not copy binary into install directory"
    return 1
  }
  chmod 755 "$dest.tmp.$$" || {
    warn "could not mark staged binary executable"
    rm -f -- "$dest.tmp.$$"
    return 1
  }
  mv -f "$dest.tmp.$$" "$dest" || {
    warn "could not atomically replace installed binary"
    rm -f -- "$dest.tmp.$$"
    return 1
  }
  echo "$dest"
}

install_prebuilt() (
  set -euo pipefail
  local target asset base work checksum_line expected recorded listing binary_version
  target="$(release_target)" || {
    warn "no verified prebuilt release target for ${LIA_INSTALL_OS:-$(uname -s)}/${LIA_INSTALL_ARCH:-$(uname -m)}"
    return 30
  }
  asset="lia-${RELEASE_TAG}-${target}.tar.gz"
  base="${LIA_RELEASE_BASE_URL:-$DEFAULT_RELEASE_BASE_URL}"

  need_cmd curl
  need_cmd tar
  need_cmd sha256sum
  need_cmd grep
  need_cmd head
  need_cmd mktemp

  work="$(mktemp -d "${TMPDIR:-/tmp}/lia-prebuilt-XXXXXX")"
  trap 'rm -rf -- "$work"' EXIT
  info "downloading ${RELEASE_TAG} release asset: ${asset}"
  if ! curl -fsSL --retry 2 --connect-timeout 15 --max-time 180 \
    "${base}/${asset}" -o "$work/$asset"; then
    warn "release asset unavailable: ${base}/${asset}"
    return 20
  fi
  if ! curl -fsSL --retry 2 --connect-timeout 15 --max-time 60 \
    "${base}/SHA256SUMS" -o "$work/SHA256SUMS"; then
    warn "release checksum file unavailable: ${base}/SHA256SUMS"
    return 20
  fi

  checksum_line="$(grep -E "^[0-9a-fA-F]{64}[[:space:]]+\\*?${asset}$" \
    "$work/SHA256SUMS" | head -n 1 || true)"
  if [[ -z "$checksum_line" ]]; then
    warn "SHA256SUMS has no exact entry for ${asset}"
    return 21
  fi
  read -r expected recorded <<<"$checksum_line"
  recorded="${recorded#\*}"
  if [[ "$recorded" != "$asset" ]] || ! (
    cd "$work"
    printf '%s  %s\n' "$expected" "$asset" | sha256sum -c - >/dev/null
  ); then
    warn "checksum verification failed for ${asset}"
    return 21
  fi

  listing="$(tar -tzf "$work/$asset")" || {
    warn "release archive is unreadable: ${asset}"
    return 22
  }
  if [[ "$listing" != "lia" ]]; then
    warn "release archive must contain exactly one root entry named lia"
    return 22
  fi
  tar -xzf "$work/$asset" -C "$work" || {
    warn "release archive extraction failed: ${asset}"
    return 22
  }
  [[ -x "$work/lia" ]] || {
    warn "release archive did not contain an executable lia binary"
    return 22
  }
  binary_version="$("$work/lia" --version 2>/dev/null || true)"
  if [[ "$binary_version" != "lia ${VERSION_HINT}" ]]; then
    warn "release binary version mismatch: expected lia ${VERSION_HINT}, got ${binary_version:-<none>}"
    return 22
  fi
  install_binary "$work/lia" || return 23
)

install_from_source() {
  local root built
  root="$(find_or_fetch_src)" || return $?
  [[ -n "$root" ]] || return 1
  info "source: $root"
  built="$(build_lia "$root")" || return $?
  [[ -n "$built" ]] || return 1
  install_binary "$built" || return $?
}

wire_harnesses() {
  local lia_bin="$1"
  if [[ "${LIA_NO_WIRE:-0}" == "1" ]]; then
    info "LIA_NO_WIRE=1 — skipping Claude Code / Codex / Gemini CLI / Cursor wiring"
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
    info "wiring Claude Code + Codex + Gemini CLI + Cursor (--apply-live)…"
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
  version: $("$dest" --version 2>/dev/null || echo "lia ${VERSION_HINT}")

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
  validate_install_options
  local dest="" prebuilt_status=0
  if [[ "${LIA_FORCE_BUILD:-0}" == "1" ]]; then
    INSTALL_MODE="source"
  fi

  if [[ "$INSTALL_MODE" != "source" ]]; then
    if dest="$(install_prebuilt)"; then
      :
    else
      prebuilt_status=$?
      case "$prebuilt_status" in
        20 | 30)
          if [[ "$INSTALL_MODE" == "prebuilt" ]]; then
            die "verified prebuilt installation unavailable (status ${prebuilt_status})"
          fi
          warn "falling back to source build at ${DEFAULT_REF}"
          ;;
        21)
          die "release checksum verification failed; refusing source fallback"
          ;;
        22)
          die "release archive verification failed; refusing source fallback"
          ;;
        23)
          die "release binary installation failed"
          ;;
        *)
          die "unexpected prebuilt installation failure (status ${prebuilt_status})"
          ;;
      esac
    fi
  fi

  if [[ -z "$dest" ]]; then
    if dest="$(install_from_source)"; then
      [[ -n "$dest" ]] || die "source installation returned no binary path"
    else
      die "source installation failed for exact ref ${DEFAULT_REF}"
    fi
  fi
  wire_harnesses "$dest"
  print_done "$dest"
}

main "$@"
