#!/usr/bin/env bash
# Runs the pinned cargo-deny binary. The only place that names its version and checksums;
# CI calls this script, and so can you.
#
#   scripts/cargo-deny.sh            cargo deny --locked check bans advisories sources
#   scripts/cargo-deny.sh ARGS...    cargo deny ARGS... (used by scripts/test-deny-bans.sh)
#
#   - Uses .local/bin/cargo-deny (gitignored) if its sha256 is BIN_SHA256, the hash of the
#     binary inside the pinned release. It is hashed again on every run.
#   - Otherwise downloads the pinned release, checks the archive against TAR_SHA256 before
#     unpacking it and the unpacked binary against BIN_SHA256, then installs it. Any
#     mismatch stops before the binary is installed or run.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

VERSION="0.20.2"
TARGET="x86_64-unknown-linux-musl"
TAR_SHA256="9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f"
BIN_SHA256="b329e25933d01c36dd7c47d84ea5716694f9b7caf53a5003d45674703a8ed54a"
NAME="cargo-deny-${VERSION}-${TARGET}"
URL="https://github.com/EmbarkStudios/cargo-deny/releases/download/${VERSION}/${NAME}.tar.gz"
BIN_DIR=".local/bin"
BIN="${BIN_DIR}/cargo-deny"

if [[ "$(uname -s)-$(uname -m)" != "Linux-x86_64" ]]; then
  echo "cargo-deny.sh: the pinned binary is for Linux x86_64 only" >&2
  exit 1
fi

if ! [[ -x "$BIN" ]] || ! echo "$BIN_SHA256  $BIN" | sha256sum --check --quiet --status; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  echo "cargo-deny.sh: installing cargo-deny $VERSION into $BIN_DIR" >&2
  curl --proto '=https' --tlsv1.2 -sSfL -o "$tmp/deny.tar.gz" "$URL"
  echo "$TAR_SHA256  $tmp/deny.tar.gz" | sha256sum --check --quiet
  tar -xzf "$tmp/deny.tar.gz" -C "$tmp" "$NAME/cargo-deny"
  echo "$BIN_SHA256  $tmp/$NAME/cargo-deny" | sha256sum --check --quiet
  mkdir -p "$BIN_DIR"
  install -m 0755 "$tmp/$NAME/cargo-deny" "$BIN"
fi

if (($# == 0)); then
  set -- --locked check bans advisories sources
fi
"$BIN" "$@"
