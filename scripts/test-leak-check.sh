#!/usr/bin/env bash
# Offline tests for scripts/leak-check.sh: each rule fails on a planted case, and the
# placeholders the tests and docs use pass. The commit-metadata rules (author and
# committer addresses, messages) are not exercised here, since that needs commits.
#
# Each case is a fresh git repository in a temp directory holding the leak check and one
# file. Planted text is built from pieces at run time, so this file does not trip the
# check itself.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
ROOT="$PWD"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

failures=0
n=0

repo() { # dir
  mkdir -p "$1/scripts"
  cp "$ROOT/scripts/leak-check.sh" "$1/scripts/"
  git -C "$1" init -q -b main
}

expect() { # want(pass|fail), name, text, [rule substring]
  local want="$1" name="$2" text="$3" rule="${4:-}"
  n=$((n + 1))
  local dir="$tmp/case-$n"
  repo "$dir"
  printf '%s\n' "$text" >"$dir/planted.txt"
  local out status=0
  out="$(cd "$dir" && scripts/leak-check.sh 2>&1)" || status=$?
  if [[ "$want" == pass && "$status" -ne 0 ]]; then
    echo "FAIL (should pass): $name"$'\n'"$out" >&2
    failures=$((failures + 1))
  elif [[ "$want" == fail && "$status" -eq 0 ]]; then
    echo "FAIL (should fail): $name"$'\n'"$out" >&2
    failures=$((failures + 1))
  elif [[ "$want" == fail && -n "$rule" ]] && ! grep -q -- "$rule" <<<"$out"; then
    echo "FAIL (wrong rule, wanted $rule): $name"$'\n'"$out" >&2
    failures=$((failures + 1))
  else
    echo "ok: $name"
  fi
}

S="SPI""NE"
expect fail "plan id" "see $S-005" "planning id"
expect fail "task number" "done in ta""sk 09" "planning id"
expect fail "agent settings path" "read .clau""de/plans" "private workspace path"
expect fail "instruction file" "see CLAU""DE.md" "private workspace path"
expect fail "home directory" "/ho""me/someone/projects" "private workspace path"
expect fail "pem private key" "-----BEGIN ""PRIVATE KEY-----" "private key"
keypair="[$(printf '1,%.0s' $(seq 63))1]"
expect fail "keypair array" "$keypair" "private key"
expect fail "github token" "gh""p_$(printf 'a%.0s' $(seq 36))" "api token"
expect fail "aws key" "AK""IA$(printf 'A%.0s' $(seq 16))" "api token"
expect fail "url with user info" "https://user:pw""@rpc.provider.io/x" "url with credentials"
expect fail "url with api key" "https://rpc.provider.io/?api-""key=abcd" "url with credentials"
expect fail "provider key in path" "https://x.quik""node.pro/$(printf 'b%.0s' $(seq 24))/" "url with credentials"
expect fail "email" "write to someone""@mail.provider.io" "email address"
expect fail "a long file" "$(seq 1001)" "longer than"
expect pass "placeholder url" "https://user:pass@rpc.example.com/v2/x?api-key=y"
expect pass "local url" "https://user:pw@127.0.0.1:8899/?api-key=x"
expect pass "single-label host" "https://user:secret@h/path"
expect pass "public endpoint" "https://api.devnet.solana.com"
expect pass "security contact" "security@centrob.co"

# Cargo.lock may be long.
n=$((n + 1))
dir="$tmp/case-$n"
repo "$dir"
seq 1500 >"$dir/Cargo.lock"
if ! out="$(cd "$dir" && scripts/leak-check.sh 2>&1)"; then
  echo "FAIL (should pass): a long Cargo.lock"$'\n'"$out" >&2
  failures=$((failures + 1))
else
  echo "ok: a long Cargo.lock"
fi

# A private pattern file, kept outside the repository.
n=$((n + 1))
dir="$tmp/case-$n"
repo "$dir"
printf 'a word only the owner knows: zanzibarite\n' >"$dir/planted.txt"
printf '# private words\nzanzibar\\w+\n' >"$tmp/private-patterns"
if out="$(cd "$dir" && LEAK_CHECK_PATTERNS="$tmp/private-patterns" scripts/leak-check.sh 2>&1)"; then
  echo "FAIL (should fail): private pattern"$'\n'"$out" >&2
  failures=$((failures + 1))
elif ! grep -q "private pattern (line 2)" <<<"$out" || grep -q zanzibarite <<<"$out"; then
  echo "FAIL (private pattern reported wrongly)"$'\n'"$out" >&2
  failures=$((failures + 1))
else
  echo "ok: private pattern, and the match is not printed in full"
fi

if ((failures)); then
  echo "test-leak-check: $failures failed" >&2
  exit 1
fi
echo "test-leak-check: passed"
