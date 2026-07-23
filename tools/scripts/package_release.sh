#!/usr/bin/env bash
# Build the deterministic release archive contract from an already-audited lia binary.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VERSION="0.3.0"
TAG="v${VERSION}"
TARGET="${LIA_PACKAGE_TARGET:-x86_64-unknown-linux-gnu}"
BUILT="${CARGO_TARGET_DIR:-$ROOT/target}/release/lia"
OUT="${1:-$ROOT/target/release-artifacts/$TAG}"

if [[ "$TARGET" != "x86_64-unknown-linux-gnu" ]]; then
  echo "unsupported release target: $TARGET" >&2
  exit 2
fi
if [[ "$(uname -s)" != "Linux" ]] || [[ "$(uname -m)" != "x86_64" ]]; then
  echo "release packaging is verified only on Linux x86_64" >&2
  exit 2
fi
test -x "$BUILT"
test "$($BUILT --version)" = "lia ${VERSION}"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/lia-package-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
install -m 0755 "$BUILT" "$WORK/lia"

mkdir -p "$OUT"
ASSET="lia-${TAG}-${TARGET}.tar.gz"
tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
  -C "$WORK" -czf "$OUT/$ASSET" lia
test "$(tar -tzf "$OUT/$ASSET")" = "lia"
(
  cd "$OUT"
  sha256sum "$ASSET" >SHA256SUMS
)

echo "release package ready: $OUT/$ASSET"
echo "release checksums ready: $OUT/SHA256SUMS"
