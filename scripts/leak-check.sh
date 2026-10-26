#!/usr/bin/env bash
# Fails if a file or a commit in this repository holds text that must not be published.
#
#   scripts/leak-check.sh
#   LEAK_CHECK_PATTERNS=/path/outside/the/repo scripts/leak-check.sh
#
# Scans every file git would commit (tracked, plus untracked files that are not
# ignored), each file's path, and every commit's message, author and committer, for:
#
#   - planning ids: `SPINE-<n>`, `task <nn>`, `invariant <n>`;
#   - paths of a private workspace: agent settings and instruction files, and home
#     directories (`/home/<user>/`, `/Users/<user>/`);
#   - private keys: PEM private-key blocks and 64-number keypair arrays;
#   - API tokens in well-known formats (GitHub, AWS, Slack, OpenAI-style, GitLab, npm);
#   - URLs with credentials: user info, or a key-like query parameter, or a provider
#     key in the path, on any host that is not a placeholder (`example.com`,
#     `example.org`, `example.net`, `localhost`, `127.0.0.1`, `[::1]`, or a name with
#     no dot);
#   - email addresses other than the security contact and placeholder domains, in files
#     and in commit metadata (`<user>@users.noreply.github.com` is allowed in commits);
#   - files over 1,000 lines (Cargo.lock and LICENSE excepted).
#
# LEAK_CHECK_PATTERNS names a file of extra patterns, one Perl regular expression per
# line (case-insensitive; blank lines and lines starting with # are skipped). Keep it
# outside the repository: it is for words that should never appear here, which is why
# it is not published. A match prints the file, the line, the rule and a shortened
# excerpt, never the whole match, so a secret is not copied into a CI log.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

patterns_file="${LEAK_CHECK_PATTERNS:-}"
if [[ -n "$patterns_file" && ! -r "$patterns_file" ]]; then
  echo "leak-check: LEAK_CHECK_PATTERNS names $patterns_file, which cannot be read" >&2
  exit 2
fi

list="$(mktemp)"
trap 'rm -f "$list"' EXIT
git ls-files -z --cached --others --exclude-standard >"$list"

commits=0
if git rev-parse --verify --quiet HEAD >/dev/null; then
  commits="$(git rev-list --count HEAD)"
fi

LIST="$list" PATTERNS="$patterns_file" COMMITS="$commits" perl -e '
use strict;
use warnings;

my @rules = (
  ["planning id", qr/\bSPINE-\d|\b[Tt]ask \d{2}\b|\binvariants? \d/],
  ["private workspace path", qr{\.clau[d]e/|\bCLAUDE\.md\b|/home/[\w.-]+/|/Users/[\w.-]+/}],
  ["private key", qr/-----BEGIN [A-Z ]*PRIVATE KEY-----|\[\s*(?:\d{1,3}\s*,\s*){63}\d{1,3}\s*\]/],
  ["api token", qr/\bgh[pousr]_[A-Za-z0-9]{30,}|\bgithub_pat_\w{20,}|\bAKIA[0-9A-Z]{16}\b|\bxox[abposr]-[\w-]{10,}|\bsk-(?:proj-|ant-|live-)?[A-Za-z0-9_-]{20,}|\bsk_live_\w{10,}|\bglpat-[\w-]{20,}|\bnpm_[A-Za-z0-9]{36}/],
);

my @private;
if ($ENV{PATTERNS} ne "") {
  open(my $fh, "<", $ENV{PATTERNS}) or die "leak-check: cannot read patterns: $!\n";
  my $n = 0;
  while (my $line = <$fh>) {
    $n++;
    chomp $line;
    next if $line =~ /^\s*(#|$)/;
    my $re = eval { qr/$line/i } or die "leak-check: pattern line $n is not a regex\n";
    push @private, ["private pattern (line $n)", $re];
  }
}

my $allowed_email = qr/^(?:security\@centrob\.co|[^@\s]+\@(?:[\w-]+\.)*example\.(?:com|org|net))$/i;
my $placeholder_host = qr/^(?:(?:[\w-]+\.)*example\.(?:com|org|net)|localhost|127\.0\.0\.1|\[::1\]|[^.]*)$/i;
my $provider = qr/helius|quiknode|alchemy|rpcpool|triton|ankr|chainstack|syndica|extrnode|getblock|blockdaemon|shyft|drpc/i;

my $found = 0;
sub excerpt {
  my ($text) = @_;
  $text =~ s/\s+/ /g;
  return length($text) > 8 ? substr($text, 0, 6) . "..." : substr($text, 0, 3) . "...";
}
sub report {
  my ($where, $rule, $match) = @_;
  print "$where: $rule: " . excerpt($match) . "\n";
  $found++;
}

sub check_line {
  my ($where, $line, $emails) = @_;
  for my $r (@rules, @private) {
    my ($name, $re) = @$r;
    report($where, $name, $&) if $line =~ $re;
  }
  my @urls = $line =~ m{(https?://[^\s"\x27`<>()\\]+)}g;
  my %in_url;
  for my $url (@urls) {
    my ($authority, $rest) = $url =~ m{^https?://([^/?#]*)(.*)$};
    next unless defined $authority;
    $in_url{$_} = 1 for $authority =~ /([^\s:\/]+\@[^\s:\/]+)/g;
    my $host = $authority;
    $host =~ s/^.*\@//;
    $host =~ s/:\d*$//;
    next if $host =~ $placeholder_host || $host =~ /[{}\$]/;
    my $creds = $authority =~ /\@/
      || $rest =~ /[?&](?:api[-_]?key|key|token|access[-_]?token|secret|auth|password)=/i
      || ($host =~ $provider && $rest =~ m{/[A-Za-z0-9_-]{16,}});
    report($where, "url with credentials", $url) if $creds;
  }
  if ($emails) {
    while ($line =~ /([A-Za-z0-9._%+-]+\@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})/g) {
      my $email = $1;
      next if $email =~ $allowed_email;
      next if $in_url{$email};
      report($where, "email address", $email);
    }
  }
}

open(my $list, "<", $ENV{LIST}) or die "leak-check: $!\n";
local $/ = "\0";
my @files = grep { length } map { s/\0$//r } <$list>;
close $list;
local $/ = "\n";

my $scanned = 0;
for my $file (@files) {
  next unless -f $file;
  check_line("$file (path)", $file, 1);
  open(my $fh, "<", $file) or die "leak-check: cannot read $file: $!\n";
  binmode $fh;
  my $head = "";
  read($fh, $head, 8000);
  next if $head =~ /\0/;
  seek($fh, 0, 0);
  $scanned++;
  my $n = 0;
  while (my $line = <$fh>) {
    $n++;
    check_line("$file:$n", $line, 1);
  }
  close $fh;
  if ($n > 1000 && $file ne "Cargo.lock" && $file ne "LICENSE") {
    print "$file: longer than 1,000 lines ($n)\n";
    $found++;
  }
}

my $commits = $ENV{COMMITS};
if ($commits > 0) {
  my $sep = "\x1e";
  my $log = `git log --format="%H%x1f%ae%x1f%ce%x1f%B$sep" HEAD`;
  for my $entry (split /$sep\n?/, $log) {
    next unless length $entry;
    my ($sha, $author, $committer, $body) = split /\x1f/, $entry, 4;
    my $short = substr($sha, 0, 12);
    for my $email ($author, $committer) {
      next if $email =~ $allowed_email || $email =~ /\@users\.noreply\.github\.com$/i;
      report("commit $short (identity)", "email address", $email);
    }
    my $n = 0;
    for my $line (split /\n/, $body // "") {
      $n++;
      # Attribution trailers name the tool that helped, by its no-reply address.
      next if $line =~ /^Co-Authored-By: .*<noreply\@anthropic\.com>$/;
      check_line("commit $short message:$n", $line, 1);
    }
  }
}

my $extra = @private ? scalar(@private) . " private patterns" : "no private patterns";
print "leak-check: $scanned files and $commits commits scanned, $extra\n";
if ($found) {
  print STDERR "leak-check: $found problems (above)\n";
  exit 1;
}
print "leak-check: clean\n";
'
