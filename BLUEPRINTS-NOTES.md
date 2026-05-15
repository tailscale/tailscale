# Blueprints v1 — OSS Reconnaissance Notes (tailscale/tailscale)

Read-only snapshot of the existing system, taken on branch `kabir/blueprints-v1` at HEAD `894ff5d8e` (main). Working notes — not user-facing docs.

## 1. Tag parsing and validation

**File:** `tailcfg/tailcfg.go:704-741`

**Key:** `CheckTag(tag string) error` validates a single ACL tag. Rules today:
- Must have `tag:` prefix (line 723, via `strings.CutPrefix`).
- Tag name after the prefix must be non-empty (line 728).
- Must start with a letter (line 730).
- Body must be alphanumerics and dashes only (lines 734-737).
- The forward slash `/` is rejected by the existing character set.

`Hostinfo.CheckRequestTags()` (line ~749) iterates `RequestTags` and calls `CheckTag` on each.

**Slot for `tag:bp//<id>`:** narrow exception inside `CheckTag` — if the remainder after `tag:` starts with `bp//`, strip exactly that prefix and validate the rest as a normal tag name. This keeps the `/` rejection intact for every other namespace.

## 2. tagOwners validation

Not in OSS — corp's `control/policy/policy_parse.go:674` is where tagOwners gets validated against grants. OSS only validates tag format.

No OSS-side changes needed for the tagOwners exemption.

## 3. CLI structure (`cmd/tailscale/cli/`)

- `cli.go:252-340` — `newRootCmd()` wires up subcommands. New `joinCmd` registered alongside `upCmd`, `setCmd`, `logoutCmd` in the `Subcommands` slice (lines 273-309).
- `up.go:47-251` — `upCmd` + `newUpFlagSet()` flag declaration. Template for `joinCmd`.
- `set.go:32-129` — `setCmd` + `newSetFlagSet()`. `runSet()` `:131` is where blueprint-locked-field rejection slots in.
- `logout.go:1-45` — `logoutCmd`. Template for `leaveCmd` if implemented as a separate command, or extend it to detect blueprint-bound state.
- `down.go:1-65` — pattern for short verb commands.

All subcommands use `*ffcli.Command` with a flag set and a run function.

## 4. `tailscale set` flag validation

`runSet()` in `set.go:131` builds a `MaskedPrefs` from flags, fetches current `Status` (line 136), then calls `localClient.EditPrefs()`.

No existing precedent for "reject this set based on node state." The check needs to happen after the `MaskedPrefs` is built and before `EditPrefs` is called: if the locally-stored "brought up via join" bit is set AND any locked field is in the mask, return the verbatim spec error and increment `blueprint_set_rejected`.

## 5. `ipn/ipnlocal/` node state and prefs

- `ipn/prefs.go:58-250+` — `Prefs` struct. New field needed: `BlueprintID string` (or a `BlueprintBinding` sub-struct) to record both the binding and the "was-this-join" bit.
- `ipn/ipnlocal/local.go:5948` — `applyPrefsToHostinfoLocked()`. Today: `AdvertiseTags` → `Hostinfo.RequestTags`, `AdvertiseRoutes` → `Hostinfo.RoutableIPs`. When blueprint-bound, the projected tags/routes come from the control plane via MapResponse and should NOT be written back to `Hostinfo` from prefs (they live in `Node.BlueprintConfig` already).

## 6. `tailcfg` types

- `Node` `tailcfg.go:348-535` — add `BlueprintID string` and `BlueprintConfig *BlueprintConfig` (new type) here per the decision to put binding on top-level fields, not in `CapMap`.
- `Hostinfo` `:845-900+` — likely no changes; blueprint binding is server-to-client, and the prefs change in `Prefs.BlueprintID` is enough to let the server identify a join-mode node on registration.
- `MapResponse` `:1968-2177` — no new top-level field needed; everything goes on `Node`.
- `NodeCapMap` `:2451-2463` — alternate path we chose not to take.
- Capability version comments `:50-188` — bump for the new fields.
- `Node.Equal()` `:2359-2399` — must include `BlueprintID` and `BlueprintConfig`.

## 7. `clientmetric` conventions

- `util/clientmetric/clientmetric.go:1-481`. `NewCounter(name)`, `NewGauge(name)`. Globally registered, names must be unique.
- Pattern: module-level `var` declarations. Naming: package-prefixed snake_case (e.g. `localbackend_metric_name`).

`clientmetric` does NOT support labels. The spec's `blueprint_join_attempts_total{result}` becomes four separate counters: `blueprint_join_success`, `blueprint_join_failure_not_found`, `blueprint_join_failure_scope_mismatch`, `blueprint_join_failure_auth`. Document in `BLUEPRINTS.md`.

## 8. `ipn/ipnstate/`

- `ipnstate.go:31-150+` — `Status` struct has `Self *PeerStatus`. Add `BlueprintID string` to `PeerStatus` so `tailscale status` can surface "bound to bp:<id>".

## 9. App-connector / advertise-routes / advertise-tags precedent

- `types/appctype/appconnector.go:1-113` — `AppConnectorConfig` and `AppConnectorAttr` types. App-connector config arrives via `Node.CapMap`. Useful **shape** precedent but we're not using `CapMap` for blueprint binding (decision: top-level fields).
- `ipn/ipnlocal/local.go:5948-6023` — `applyPrefsToHostinfoLocked()`. Current pattern: user prefs → Hostinfo → MapRequest → control returns Node config → client applies.
- Blueprint pattern inverts this: control sends `Node.BlueprintConfig` → client applies WITHOUT mutating `Prefs`. `Prefs.BlueprintID` records the binding; everything else flows top-down.

## Known unknowns

1. **Storing the OAuth secret locally.** After `tailscale join` the secret should NOT persist on disk (one-shot exchange). Confirm the existing auth-key path discards the secret after the auth-key trade.
2. **Status surface details.** Does `tailscale status` JSON output need a separate field, or just the binding in `PeerStatus`?
3. **`tailscale leave` vs `tailscale logout`.** Spec says `leave`. Decide: new command, or alias for `logout` with blueprint-aware behavior. Leaning toward a thin `leaveCmd` that calls into the same backend path as `logout` but with a different telemetry tag.
4. **Local persistence of "was-this-join" bit.** `Prefs` is persisted to disk; adding the field there is the natural home. Confirm Prefs serialization round-trip preserves it.
5. **Every tag-parsing callsite.** `CheckTag` is the main one; need to grep for `strings.Contains(..., "tag:")`, regex matches on `^tag:`, etc. Will surface during Phase 1.
