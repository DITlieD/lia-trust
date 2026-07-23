#!/usr/bin/env bash
# Smoke: install.sh puts a working lia binary under a temp prefix (no live wire).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/lia-install-sh-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

export LIA_PREFIX="$WORK/prefix"
export LIA_NO_WIRE=1
export LIA_INSTALL_MODE=source
export LIA_SKIP_BUILD=0
# Prefer existing release build if present (fast); still installs into prefix
bash "$ROOT/install.sh"

LIA="$LIA_PREFIX/bin/lia"
test -x "$LIA"
"$LIA" --help >/dev/null
test "$("$LIA" --version)" = "lia 0.2.2"
"$LIA" install --help >/dev/null 2>&1 || "$LIA" install --dry-run --json >/dev/null
echo "install_sh_smoke OK bin=$LIA"
