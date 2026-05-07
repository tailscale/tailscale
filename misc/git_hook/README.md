# git_hook

Tailscale's git hooks.

The shared logic lives in the `githook/` package and is also imported by
`tailscale/corp`.

## Install

From the repo root:

    ./tool/go run ./misc/install-git-hooks.go

The script auto-updates in the future.


## Adding your own hooks

Create an executable `.git/hooks/<hook-name>.local` to chain a custom
script after a built-in hook. For example, put a custom check in
`.git/hooks/pre-commit.local` and `chmod +x` it. The local hook runs
only if the built-in hook succeeds; failure aborts the git operation.


## Version bumps

The launcher rebuilds when the installed binary's version differs from
the concatenation of two files:

* `githook/HOOK_VERSION` (shared): bump when changing anything under
  `githook/` or `git-hook.go`. Downstream repos pick it up after
  bumping their `tailscale.com` dependency.
* `misc/git_hook/HOOK_VERSION` (repo-local, optional): bump to force a
  rebuild for repo-specific config changes without touching the shared
  version. This repo does not use one.
