#!/usr/bin/env bash
# ts-git-hook launcher (installed at .git/hooks/ts-git-hook).
#
# Written by misc/install-git-hooks.go from the canonical copy embedded
# in tailscale.com/misc/git_hook/githook. On every invocation it:
#
#   1. Compares misc/git_hook/HOOK_VERSION against the binary's version.
#   2. If stale or missing: rebuilds .git/hooks/ts-git-hook-bin and runs
#      `ts-git-hook-bin install` to refresh the launcher and per-hook
#      wrappers.
#   3. Execs the binary with the hook's args.
#
# Any change to this file or the binary must bump HOOK_VERSION.
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo "git-hook: not in a git repo" >&2
  exit 1
}

HOOK_DIR="$(git -C "$REPO_ROOT" rev-parse --git-path hooks)"
case "$HOOK_DIR" in
/*) ;;
*) HOOK_DIR="$REPO_ROOT/$HOOK_DIR" ;;
esac

# Windows (Git for Windows / MSYS2) needs .exe suffixes.
EXE=""
case "$(uname -s)" in MINGW* | MSYS* | CYGWIN*) EXE=".exe" ;; esac

BINARY="$HOOK_DIR/ts-git-hook-bin$EXE"
WANT="$(cat "$REPO_ROOT/misc/git_hook/HOOK_VERSION" 2>/dev/null || echo 0)"
HAVE="$("$BINARY" version 2>/dev/null || echo none)"

if [ "$WANT" != "$HAVE" ]; then
  GO="$REPO_ROOT/tool/go$EXE"
  if [ ! -x "$GO" ]; then GO=go; fi
  echo "git-hook: rebuilding ts-git-hook-bin..." >&2
  (cd "$REPO_ROOT" && GOWORK=off "$GO" build -o "$BINARY" ./misc/git_hook) || {
    echo "git-hook: rebuild failed, run: ./tool/go run ./misc/install-git-hooks.go" >&2
    exit 1
  }
  "$BINARY" install
fi

exec "$BINARY" "$@"

