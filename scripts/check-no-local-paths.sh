#!/usr/bin/env bash
# Refuse content that would publish the author's machine.
#
# A public repository is forever: a path or hostname committed once stays
# retrievable through `git show` after it is removed from HEAD, and only a
# history rewrite plus a force-push takes it back. This runs in CI over the
# whole tree and locally over the staged diff, so the string never lands.
#
#   ./scripts/check-no-local-paths.sh            # staged changes (pre-commit)
#   ./scripts/check-no-local-paths.sh --tree     # every tracked file (CI)
set -euo pipefail

mode="${1:---staged}"

# The identity of the machine running this, resolved at run time rather than
# hardcoded, so the check protects whoever runs it and needs no edit to move.
#
# Deliberately NOT a generic `/home/<any>/` pattern: a plugin that matches
# credential paths legitimately carries `/home/dev/.aws/credentials` in its
# fixtures, and a check that cries wolf on its own test data gets disabled.
# What must never ship is *this* user and *this* host.
patterns=()
user="${USER:-$(id -un 2>/dev/null || true)}"
if [ -n "$user" ]; then
  patterns+=("/home/${user}\\b" "/Users/${user}\\b" "C:\\\\\\\\Users\\\\\\\\${user}\\b")
fi
home_real="${HOME:-}"
if [ -n "$home_real" ] && [ "$home_real" != "/home/${user}" ]; then
  patterns+=("$(printf '%s' "$home_real" | sed 's/[][\.*^$(){}?+|/]/\\&/g')")
fi
host="$(hostname 2>/dev/null || true)"
[ -n "$host" ] && patterns+=("\\b${host}\\b")
short="${host%%.*}"
[ -n "$short" ] && [ "$short" != "$host" ] && patterns+=("\\b${short}\\b")

if [ "${#patterns[@]}" -eq 0 ]; then
  echo "warning: could not resolve a user or hostname to check for" >&2
  exit 0
fi

# This script necessarily contains the patterns it looks for.
exclude_paths=':(exclude)scripts/check-no-local-paths.sh'

case "$mode" in
  --tree)
    files=$(git ls-files -- . "$exclude_paths")
    ;;
  --staged)
    files=$(git diff --cached --name-only --diff-filter=ACMR -- . "$exclude_paths")
    ;;
  *)
    echo "usage: $0 [--staged|--tree]" >&2
    exit 2
    ;;
esac

[ -z "$files" ] && exit 0

status=0
for pattern in "${patterns[@]}"; do
  # -I skips binary files; the pattern set is deliberately small so this stays
  # fast enough to run on every commit.
  if hits=$(printf '%s\n' "$files" | xargs -r grep -InE -- "$pattern" 2>/dev/null); then
    if [ -n "$hits" ]; then
      echo "::error::content matching '$pattern' must not be committed" >&2
      printf '%s\n' "$hits" >&2
      status=1
    fi
  fi
done

if [ "$status" -ne 0 ]; then
  cat >&2 <<'MSG'

Refusing: this content names a local filesystem path or this machine.

Use a relative path, an environment variable, or a documentation placeholder
(`/path/to/workspace`, `app-01.example.test`). For test fixtures prefer the
reserved names: RFC 5737 addresses, `.invalid` and `.test` TLDs, `example.com`.
MSG
fi

exit "$status"
