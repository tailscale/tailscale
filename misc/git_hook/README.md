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


## Changing the shared code

When you change anything under `githook/` or `launcher.sh`, bump
`HOOK_VERSION` in the same commit so every dev auto rebuilds on their next
git operation.

Because `tailscale/corp` imports `githook/`, also plan the downstream
update: after landing here, bump corp's `tailscale.com` dependency and
bump corp's own `misc/git_hook/HOOK_VERSION` on a separate commit. Both are
required.
