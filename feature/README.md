# Modular Tailscale features

This directory contains Tailscale's modular feature system. The Tailscale
client has grown large; not every user wants every feature (an IoT device on
a few-dollar chip does not need Taildrop, WebDAV, ACME, or SSH). The
`feature/` tree is how we make individual features conditionally linkable so
that resource-constrained builds can omit them, and so that new code lives
in small self-contained packages instead of being dumped into
`LocalBackend`.

## New code lives here

**The preferred home for new functionality is a `feature/<name>` package.**
If there is any plausible user who might not want your feature in their
build (which is almost always the case), it should be modular from the
start. A feature package should install itself into the rest of Tailscale
via hooks, extensions, and registrations from its own `init` (see
"Hooks and registration" below). It should not export API used by callers
elsewhere in the tree; callers reach the feature through the hook, not by
importing it.

Think your functionality is so core that it must always be linked in?
Imagine any plausible user who might not want it. If you cannot,
[ask](#asking-questions) before dumping code into `ipn/ipnlocal` or
similar.

## The half-migrated reality

Much of the tree is in a **half-migrated state**. A given feature may:

- Have a `ts_omit_<name>` build tag declared in
  [`featuretags/featuretags.go`](featuretags/featuretags.go), and
- Have some of its code moved to `feature/<name>/`, but
- Still have significant code living in `ipn/ipnlocal`, `cmd/tailscaled`,
  or elsewhere, either:
  - Behind a build-tag-conditional file (a whole `.go` file gated with
    `//go:build !ts_omit_<name>`), or
  - Guarded at runtime by an `if buildfeatures.HasFoo { ... }` block that
    the compiler and linker dead-code-eliminate when the tag is set.

When you touch one of these features, prefer to keep migrating code into
its `feature/<name>` package rather than adding more to the old location.
But do not feel obligated to finish the migration in one PR.

## The registry: `feature/featuretags`

[`featuretags/featuretags.go`](featuretags/featuretags.go) is the single
source of truth. It declares the [`Features`](https://pkg.go.dev/tailscale.com/feature/featuretags#Features)
map: for each feature tag (a
lowercase string like `acme` or `taildrop`), it records the exported symbol
name used by generated constants, a human-readable description, and any
other features it depends on (forming a DAG).

Adding a new feature starts with adding an entry there. See the top of the
file for the tag naming convention: feature `foo` corresponds to build tag
`ts_omit_foo` (opt-out). The one exception is `cli`, which is opt-in via
`ts_include_cli`; see [`FeatureTag.IsOmittable`](https://pkg.go.dev/tailscale.com/feature/featuretags#FeatureTag.IsOmittable).

Features can be marked [`ImplementationDetail: true`](https://pkg.go.dev/tailscale.com/feature/featuretags#FeatureMeta)
when they are internal
plumbing (e.g. `dbus`, `c2n`) that users would not select directly; they
exist only so that user-visible features can depend on them.

## Generated constants: `feature/buildfeatures`

After editing `featuretags.go`, run:

    ./tool/go generate ./feature/buildfeatures

(or the meta `make generate`). That regenerates two files per feature in
[`buildfeatures/`](buildfeatures/): `feature_<name>_enabled.go` and
`feature_<name>_disabled.go`, gated with `//go:build !ts_omit_<name>` and
`//go:build ts_omit_<name>` respectively. Each pair exports a single
boolean constant, e.g. `HasACME`. Because these are Go constants, code of
the form:

    if buildfeatures.HasACME {
        // ...
    }

is dead-code-eliminated by the compiler and linker when the feature is
omitted. Constants can eliminate *code* but they cannot remove *imports*;
for that you still need a build-tag-gated file.

Use constants when moving code to `feature/<name>` is impractical (e.g.
the code has to sit inside `LocalBackend`), or when a small conditional
inside otherwise-shared logic is clearer than splitting into two files.
Prefer separate packages when you can.

## `feature/condregister`: opt-out registration

[`condregister/`](condregister/) is the one central package that
`tailscaled` (and the macOS/iOS closed-source client) empty-imports so
that all "on by default" features get registered. Every feature that
should ship in `tailscaled` by default has a `maybe_<name>.go` file here
of the form:

    //go:build !ts_omit_<name>

    package condregister

    import _ "tailscale.com/feature/<name>"

That is the whole file. The build tag is the only mechanism that decides
whether the feature is compiled in. Because `tailscaled` imports
`condregister`, all these `maybe_*` files pull in their respective
`feature/<name>` packages by default; adding `ts_omit_<name>` to the
build removes the file, and with it the import, and with it the
package's `init` and everything it transitively depends on.

Some `maybe_*` files carry additional build tags (e.g.
`//go:build !ios && !ts_omit_capture`) when a feature should be excluded
on specific platforms.

### The `feature/<name>` package should not carry `ts_omit_*` tags

The `ts_omit_<name>` tag lives only on the `condregister/maybe_<name>.go`
(and analogous `tsnet/maybe_<name>.go`) import shim, not on the
`feature/<name>/*.go` files themselves. Keeping the feature package
free of its own omit tag lets any program directly opt in with a blank
import regardless of what `ts_omit_*` tags are set on the top-level
build:

    import _ "tailscale.com/feature/foo"

That is how a `tsnet`-using application pulls a feature in on its own
terms without having to reason about which `ts_omit_*` tags are in
effect.

OS-specific build tags inside `feature/<name>/` are fine, and often
desirable: if the feature only makes sense on some platforms, gating
its files with `//go:build linux` (or `!ios`, etc.) both keeps
`go test ./...` passing on every GOOS and prevents a `tsnet` user on an
unsupported platform from accidentally blank-importing a package that
would fail to compile or run there.

## `tsnet` does NOT depend on `condregister`

`tsnet` is a library, not a daemon, and it links in a different (and
generally smaller) default feature set than `tailscaled`. `tsnet` has its
own top-level `maybe_*.go` files that decide which features it opts in
to, and its own `depaware.txt`.

**Consequence:** you cannot assume `buildfeatures.HasFoo == true` means
feature `foo` was actually linked. In a `tsnet` build, `ts_omit_foo` may
not be set (so `HasFoo` is `true`), yet `tsnet` may have never imported
`feature/foo`, so its `init` never ran and no hooks were installed.

`buildfeatures.HasFoo` really means "not explicitly omitted by build
tag." Whether the feature is actually present is
[`feature.IsRegistered("foo")`](https://pkg.go.dev/tailscale.com/feature#IsRegistered).
The idiom is:

    buildfeatures.HasFoo && feature.IsRegistered("foo")

`HasFoo` lets the compiler DCE the whole expression in `ts_omit_foo`
builds; `IsRegistered` guards against the `tsnet` case where the tag is
unset but the package was never imported.

## The `feature` API

Package [`feature`](https://pkg.go.dev/tailscale.com/feature) itself
exposes the small runtime API used by feature packages and their callers:

- [`feature.Register(name)`](https://pkg.go.dev/tailscale.com/feature#Register):
  a feature package calls this from its `init` to record that it was
  linked in. Callers use
  [`feature.IsRegistered(name)`](https://pkg.go.dev/tailscale.com/feature#IsRegistered)
  to check.
- [`feature.Hook[Func]`](https://pkg.go.dev/tailscale.com/feature#Hook):
  a single-writer, single-reader hook. The
  extension point declares a `var HookX feature.Hook[func(...)]`, the
  feature package `Set`s it once from `init`, and callers use
  `GetOk`/`GetOrNil`/`IsSet` to invoke it. `Set` panics if called twice.
- [`feature.Hooks[Func]`](https://pkg.go.dev/tailscale.com/feature#Hooks):
  a slice of hooks for extension points that may
  legitimately have multiple registrants.
- Common cross-feature hooks (auto-update, proxy, TPM, SSH host keys,
  hardware attestation) live in [`hooks.go`](hooks.go) alongside their
  small dispatcher functions like
  [`feature.CanAutoUpdate()`](https://pkg.go.dev/tailscale.com/feature#CanAutoUpdate)
  and
  [`feature.TPMAvailable()`](https://pkg.go.dev/tailscale.com/feature#TPMAvailable).
  Add hooks here only sparingly: every hook in this package is loaded
  by every consumer of `feature`, so its function signature must not
  reference types from "heavy" packages. By heavy we mean any package
  whose presence in this signature would unnecessarily grow
  [`cmd/tailscaled/depaware-min.txt`](../cmd/tailscaled/depaware-min.txt):
  packages with a large API/dependency footprint (e.g. `net/http`,
  `crypto/tls`, `golang.org/x/crypto/ssh`, `k8s.io/...`), or packages
  that trigger expensive runtime features like `reflect`-based
  registration. The minimal build's depaware file is sacred and must
  not grow without good reason. Prefer primitives, small `types/...`
  packages, or interfaces. If your hook needs a wide type, keep the
  hook (and its dispatcher) in the caller's package instead of
  promoting it here.

[`ipnext.RegisterExtension`](https://pkg.go.dev/tailscale.com/ipn/ipnext#RegisterExtension)
(in `ipn/ipnext`) is the corresponding
mechanism for features that need to hook into `LocalBackend`; see the
next section.

## IPN extensions: `ipn/ipnext`

For features that need to attach state and behavior to `LocalBackend`,
the plain `feature.Hook` mechanism is not enough; you also need
per-`LocalBackend` state and a well-defined lifecycle. That is what
[`ipn/ipnext`](https://pkg.go.dev/tailscale.com/ipn/ipnext) provides.

Per-`LocalBackend` state matters because a single process can have more
than one `LocalBackend` alive at once: a `tsnet` program can host many
`tsnet.Server` nodes concurrently, each with its own `LocalBackend`.
Package-global variables in a feature package would be shared across all
of them, which should be avoided unless it is otherwise infeasible. An
[`ipnext.Extension`](https://pkg.go.dev/tailscale.com/ipn/ipnext#Extension)
is instantiated once *per* `LocalBackend`, so each node gets its own
copy of the extension's state.

(A related, not-yet-realized goal is letting different `tsnet` nodes in
the same process opt in to different sets of hooks. Today the hook
registration is still process-global (the `init` runs once and the hook
is on for every `LocalBackend`), but the extension design leaves room to
make this per-node in the future. Don't rely on the process-global
behavior; keep state on the extension instance, not in globals.)

An `ipnext.Extension` is created once per `LocalBackend`. From `init`, a
feature package registers a factory:

    func init() {
        feature.Register("taildrop")
        ipnext.RegisterExtension("taildrop", newExtension)
    }

When `LocalBackend.Start` runs, it instantiates each registered
extension and calls its
`Init(host `[`ipnext.Host`](https://pkg.go.dev/tailscale.com/ipn/ipnext#Host)`) error`
method. `Init` is where the extension wires up its per-backend hooks
against `host.Hooks()`:

    func (e *extension) Init(h ipnext.Host) error {
        h.Hooks().ProfileStateChange.Add(e.onChangeProfile)
        h.Hooks().OnSelfChange.Add(e.onSelfChange)
        h.Hooks().MutateNotifyLocked.Add(e.setNotifyFilesWaiting)
        h.Hooks().SetPeerStatus.Add(e.setPeerStatus)
        h.Hooks().BackendStateChange.Add(e.onBackendStateChange)
        return nil
    }

[`ipnext.Hooks`](https://pkg.go.dev/tailscale.com/ipn/ipnext#Hooks)
is a struct of `feature.Hook`/`feature.Hooks` fields
covering `LocalBackend`'s extension points: backend and profile state
changes, netmap toggles, self-node changes, notify mutation, peer
status, packet-filter hooks, audit logging, and more. Read the type in
`ipn/ipnext/ipnext.go` for the current list; new hooks are added there
as needed.

Extension hooks run synchronously with the triggering `LocalBackend`
operation and can influence its outcome. Because multiple extensions may
touch the same shared state (prefs, active profile, exit node, etc.),
new hooks should be designed with a clear conflict-resolution story
rather than assuming a single writer.

To get back to your extension from a `LocalBackend` inside a LocalAPI or
C2N handler, use
[`ipnlocal.GetExt[*yourExtType](b)`](https://pkg.go.dev/tailscale.com/ipn/ipnlocal#GetExt).

Canonical examples:

- [`feature/taildrop/ext.go`](taildrop/ext.go): full extension with
  per-backend state.
- [`feature/acme/acme.go`](acme/acme.go): extension that also `Set`s a
  handful of `ipnlocal.Hook*` singletons.

The `ipnext` mechanism is a work in progress and not every part of
`LocalBackend` has been converted to hooks yet. If you need a new
extension point, [ask](#asking-questions).

## Tests: `featuretags` and `depaware` / `depchecker`

Tests come in three flavors:

1. **`feature/featuretags` self-tests** ([`featuretags_test.go`](featuretags/featuretags_test.go))
   validate the registry itself: that every declared dependency exists,
   that there are no cycles, that `Requires`/`RequiredBy` return the
   expected sets, and that every `ts_omit_*` string that appears
   anywhere in the tree (via `git grep`) is declared in the map.

2. **`depaware`** ([github.com/tailscale/depaware](https://github.com/tailscale/depaware))
   snapshots the full set of Go packages linked into each binary into
   a checked-in `depaware.txt` file. Its job is right there in the
   name: to force us to be *aware of our deps*. Every change to the
   dependency graph shows up as a diff to `depaware.txt` in the same
   PR that introduced it, so reviewers can see, prominently, exactly
   what got pulled in or dropped. We use this to have an auditable
   history of the dependency footprint of key programs and libraries.
   We track several flavors:
   - full `tailscaled` on all GOOSes
   - full `tailscale` CLI on all GOOSes
   - `cmd/derper`
   - minimal `tailscaled`+CLI (`depaware-min.txt`, `depaware-minbox.txt`)
   - `tsnet` (has its own `depaware.txt`)
   - `k8s-operator`, which uses `tsnet`

   When reviewing a PR, look at the depaware diff to see what got pulled
   in or dropped, and make sure the changes make sense.

3. **[`deptest.DepChecker`](https://pkg.go.dev/tailscale.com/tstest/deptest#DepChecker)**
   lets you *lock down* omissions once you've
   achieved them. Rather than hoping nobody accidentally adds a
   `taildrop` import back into a `ts_omit_taildrop` build, you write:

        func TestOmitACME(t *testing.T) {
            deptest.DepChecker{
                GOOS:   "linux",
                GOARCH: "amd64",
                Tags:   "ts_omit_acme,ts_include_cli",
                OnDep: func(dep string) {
                    if strings.Contains(dep, "/acme") {
                        t.Errorf("unexpected dep with ts_omit_acme: %q", dep)
                    }
                },
            }.Check(t)
        }

   `cmd/tailscaled/deps_test.go` has many examples; add new ones there
   or wherever they fit. `tsnet` has its own `TestDeps` in
   [`tsnet_test.go`](../tsnet/tsnet_test.go) with a `BadDeps` map
   asserting that things like `feature/remoteconfig`,
   `feature/syspolicy`, and `x/crypto/ssh` never sneak into `tsnet`.

## Tooling

- `cmd/featuretags` constructs valid sets of Go omit build tags. Start
  from a minimal build and add features with `--min --add=...`, or start
  from a full build and remove with `--remove=...`; either way it
  respects the declared dependency DAG.
- `build_dist.sh` uses `cmd/featuretags` under the hood, so you do not
  need to hand-maintain its build-tag lists as new features are added.

## Summary of what to do for a new feature

1. Add an entry to `Features` in `feature/featuretags/featuretags.go`,
   including any `Deps`.
2. Run `./tool/go generate ./feature/buildfeatures` (or `make generate`).
3. Create `feature/<name>/` with the code, and register hooks and any
   `ipnext.Extension` from its `init`. Call `feature.Register("<name>")`
   from `init` too.
4. If the feature should be on by default in `tailscaled`, add
   `feature/condregister/maybe_<name>.go` with `//go:build !ts_omit_<name>`
   and a blank import of `tailscale.com/feature/<name>`.
5. If `tsnet` should also link it, add an equivalent `maybe_<name>.go`
   under `tsnet/`. Otherwise remember `buildfeatures.HasFoo` alone is not
   enough; pair it with `feature.IsRegistered("foo")`.
6. Add a `deptest.DepChecker` test to lock down what does *not* get
   linked when the feature is omitted.
7. Regenerate depaware and review the diff.

## Asking questions

If something in this document is unclear, if you are not sure whether
your work should be modular, or if you need a new extension point:

- **Tailscale employees:** ask in the `#client` Slack channel.
- **Open source contributors:** file a public GitHub issue with your
  proposal or question at
  [github.com/tailscale/tailscale/issues](https://github.com/tailscale/tailscale/issues).
