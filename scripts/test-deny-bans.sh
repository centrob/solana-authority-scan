#!/usr/bin/env bash
# Shows that `cargo deny check bans` refuses a banned crate, without the network.
#
#   1. Copies the crate (manifest, lockfile, sources, deny.toml) into a temp dir and
#      expects `check bans` to pass on the unmodified copy.
#   2. For each crate in PROBES, adds an empty local crate with that name as a path
#      dependency of the copy, and expects `check bans` to fail with "banned".
#
# Only `check bans` runs: it needs the crate graph alone (`cargo metadata --offline`, from
# crates already in the local cargo cache), not the advisory database. CI runs it after
# the build, so the cache is full. The binary is the pinned one from scripts/cargo-deny.sh.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
ROOT="$PWD"

# One signing crate and one seed-phrase crate from deny.toml's list.
PROBES=(ed25519-dalek bip39)

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fresh_copy() { # dir
  local ws="$1"
  mkdir -p "$ws"
  cp "$ROOT/Cargo.toml" "$ROOT/Cargo.lock" "$ROOT/deny.toml" "$ws/"
  # Sources as committed, without build output.
  tar -C "$ROOT" -cf - src | tar -C "$ws" -xf -
}

deny_bans() { # dir, extra cargo-deny flags...
  local ws="$1"
  shift
  "$ROOT/scripts/cargo-deny.sh" --manifest-path "$ws/Cargo.toml" --config "$ws/deny.toml" \
    "$@" check bans
}

# 1. The unmodified copy passes, with the lockfile unchanged.
fresh_copy "$tmp/clean"
if ! out="$(deny_bans "$tmp/clean" --frozen 2>&1)"; then
  echo "$out" >&2
  echo "test-deny-bans: the unmodified crate failed check bans" >&2
  exit 1
fi
echo "test-deny-bans: unmodified crate passes check bans"

# 2. Each probe is refused. The lockfile gains the probe crates, so only --offline.
for probe in "${PROBES[@]}"; do
  ws="$tmp/$probe/ws"
  fake="$tmp/$probe/fake"
  fresh_copy "$ws"
  mkdir -p "$fake/src"
  : >"$fake/src/lib.rs"
  printf '[package]\nname = "%s"\nversion = "0.0.1"\nedition = "2024"\npublish = false\n' \
    "$probe" >"$fake/Cargo.toml"
  # A versioned path dependency, so the only thing wrong with it is its name.
  printf '\n[dependencies.%s]\nversion = "=0.0.1"\npath = "%s"\n' \
    "$probe" "$fake" >>"$ws/Cargo.toml"
  if out="$(deny_bans "$ws" --offline 2>&1)"; then
    echo "$out" >&2
    echo "test-deny-bans: check bans accepted $probe" >&2
    exit 1
  fi
  if ! grep -q "banned" <<<"$out" || ! grep -q "$probe" <<<"$out"; then
    echo "$out" >&2
    echo "test-deny-bans: check bans failed for $probe, but not because it is banned" >&2
    exit 1
  fi
  echo "test-deny-bans: $probe is refused (banned)"
done
echo "test-deny-bans: passed"
