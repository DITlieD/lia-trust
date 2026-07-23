#!/usr/bin/env bash
# Release-path contract: verified v0.2.0 prebuilt install plus fail-closed negatives.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VERSION="0.2.2"
TAG="v${VERSION}"
TARGET="x86_64-unknown-linux-gnu"
ASSET="lia-${TAG}-${TARGET}.tar.gz"
BUILT="${CARGO_TARGET_DIR:-$ROOT/target}/release/lia"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/lia-release-install-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

test -x "$BUILT"
test "$($BUILT --version)" = "lia ${VERSION}"

FIXTURE="$WORK/release"
bash "$ROOT/tools/scripts/package_release.sh" "$FIXTURE"

# Copy the installer away from the source tree to reproduce curl|bash context.
REMOTE="$WORK/remote"
mkdir -p "$REMOTE"
cp "$ROOT/install.sh" "$REMOTE/install.sh"

run_prebuilt() {
  local name="$1"
  local arch="$2"
  local release_dir="$3"
  local prefix="$WORK/$name/prefix"
  local home="$WORK/$name/home"
  mkdir -p "$prefix/bin" "$home"
  printf '%s\n' old-install >"$prefix/bin/lia"
  chmod 755 "$prefix/bin/lia"
  (
    cd "$WORK/$name"
    HOME="$home" \
      LIA_PREFIX="$prefix" \
      LIA_NO_WIRE=1 \
      LIA_INSTALL_MODE=prebuilt \
      LIA_RELEASE_TAG="$TAG" \
      LIA_RELEASE_BASE_URL="file://$release_dir" \
      LIA_INSTALL_OS=Linux \
      LIA_INSTALL_ARCH="$arch" \
      LIA_REPO_URL="$WORK/no-source.git" \
      bash "$REMOTE/install.sh"
  )
  test -x "$prefix/bin/lia"
  test "$($prefix/bin/lia --version)" = "lia ${VERSION}"
}

expect_prebuilt_failure() {
  local name="$1"
  local arch="$2"
  local release_dir="$3"
  local prefix="$WORK/$name/prefix"
  local home="$WORK/$name/home"
  mkdir -p "$prefix" "$home" "$WORK/$name"
  if (
    cd "$WORK/$name"
    HOME="$home" \
      LIA_PREFIX="$prefix" \
      LIA_NO_WIRE=1 \
      LIA_INSTALL_MODE=prebuilt \
      LIA_RELEASE_TAG="$TAG" \
      LIA_RELEASE_BASE_URL="file://$release_dir" \
      LIA_INSTALL_OS=Linux \
      LIA_INSTALL_ARCH="$arch" \
      LIA_REPO_URL="$WORK/no-source.git" \
      bash "$REMOTE/install.sh"
  ); then
    echo "expected prebuilt install failure: $name" >&2
    exit 1
  fi
  test ! -e "$prefix/bin/lia"
}

# Both common x86_64 spellings map to the one verified target.
run_prebuilt x86_64 x86_64 "$FIXTURE"
run_prebuilt amd64 amd64 "$FIXTURE"

# Missing assets, checksum tampering, and unsupported targets fail without replacement.
mkdir -p "$WORK/missing"
expect_prebuilt_failure missing x86_64 "$WORK/missing"

BAD="$WORK/bad-checksum"
cp -R "$FIXTURE" "$BAD"
printf '%s' tamper >>"$BAD/$ASSET"
expect_prebuilt_failure checksum x86_64 "$BAD"
expect_prebuilt_failure unsupported aarch64 "$FIXTURE"

# Build tiny source remotes containing the audited binary. Auto fallback must resolve the exact tag,
# and must not escape to a same-version default branch when that tag is absent.
SOURCE_FIXTURE="$WORK/source-fixture"
mkdir -p "$SOURCE_FIXTURE/crates/lia-cli/src" "$SOURCE_FIXTURE/target/release"
printf '%s\n' '[workspace]' 'members = ["crates/lia-cli"]' >"$SOURCE_FIXTURE/Cargo.toml"
printf '%s\n' 'fn main() {}' >"$SOURCE_FIXTURE/crates/lia-cli/src/main.rs"
cp "$BUILT" "$SOURCE_FIXTURE/target/release/lia"
chmod 755 "$SOURCE_FIXTURE/target/release/lia"
git -C "$SOURCE_FIXTURE" init -q
git -C "$SOURCE_FIXTURE" config user.email release-smoke@lia.local
git -C "$SOURCE_FIXTURE" config user.name release-smoke
git -C "$SOURCE_FIXTURE" add -f .
git -C "$SOURCE_FIXTURE" commit -q -m release-fixture
git -C "$SOURCE_FIXTURE" tag "$TAG"
TAGGED_REPO="$WORK/tagged.git"
git clone -q --bare "$SOURCE_FIXTURE" "$TAGGED_REPO"
git -C "$SOURCE_FIXTURE" tag -d "$TAG" >/dev/null
MISSING_TAG_REPO="$WORK/missing-tag.git"
git clone -q --bare "$SOURCE_FIXTURE" "$MISSING_TAG_REPO"

# Auto mode may fall back only to the exact same-version tag when an asset is unavailable.
AUTO_PREFIX="$WORK/auto-fallback/prefix"
AUTO_HOME="$WORK/auto-fallback/home"
mkdir -p "$AUTO_HOME"
(
  cd "$WORK/auto-fallback"
  HOME="$AUTO_HOME" \
    LIA_PREFIX="$AUTO_PREFIX" \
    LIA_NO_WIRE=1 \
    LIA_SKIP_BUILD=1 \
    LIA_INSTALL_MODE=auto \
    LIA_RELEASE_TAG="$TAG" \
    LIA_RELEASE_BASE_URL="file://$WORK/missing" \
    LIA_REPO_URL="file://$TAGGED_REPO" \
    LIA_SRC_DIR="$WORK/auto-fallback/src" \
    LIA_INSTALL_OS=Linux \
    LIA_INSTALL_ARCH=x86_64 \
    bash "$REMOTE/install.sh"
)
test "$($AUTO_PREFIX/bin/lia --version)" = "lia ${VERSION}"
test "$(git -C "$WORK/auto-fallback/src" rev-parse 'HEAD^{commit}')" \
  = "$(git --git-dir="$TAGGED_REPO" rev-parse "refs/tags/${TAG}^{commit}")"

MISSING_TAG_PREFIX="$WORK/missing-tag/prefix"
MISSING_TAG_HOME="$WORK/missing-tag/home"
MISSING_TAG_LOG="$WORK/missing-tag/install.log"
mkdir -p "$MISSING_TAG_HOME" "$WORK/missing-tag"
if (
  cd "$WORK/missing-tag"
  HOME="$MISSING_TAG_HOME" \
    LIA_PREFIX="$MISSING_TAG_PREFIX" \
    LIA_NO_WIRE=1 \
    LIA_SKIP_BUILD=1 \
    LIA_INSTALL_MODE=auto \
    LIA_RELEASE_TAG="$TAG" \
    LIA_RELEASE_BASE_URL="file://$WORK/missing" \
    LIA_REPO_URL="file://$MISSING_TAG_REPO" \
    LIA_SRC_DIR="$WORK/missing-tag/src" \
    LIA_INSTALL_OS=Linux \
    LIA_INSTALL_ARCH=x86_64 \
    bash "$REMOTE/install.sh"
) >"$MISSING_TAG_LOG" 2>&1; then
  echo "expected exact-tag source fallback failure" >&2
  cat "$MISSING_TAG_LOG" >&2
  exit 1
fi
test ! -e "$MISSING_TAG_PREFIX/bin/lia"
if grep -q "LIA Trust Kernel installed" "$MISSING_TAG_LOG"; then
  echo "failed install printed success footer" >&2
  cat "$MISSING_TAG_LOG" >&2
  exit 1
fi

echo "install_release_smoke OK version=$VERSION target=$TARGET"
