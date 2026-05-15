# Blueprints v1 — Implementation Checklist

Derived from `/home/ubuntu/code/tmp/BLUEPRINTS-SPEC.md`. Every line below is a thing that must be true before v1 is done.

## Tag namespace (NEW)

- [ ] `tag:bp//<id>` parses as a valid tag everywhere in the codebase. Note the double-slash.
- [ ] `<id>` validation matches the regular tag-name character set: letter-start, alphanumerics and dashes only.
- [ ] `tag:bp//*` is exempt from requiring a `tagOwners` entry. Control plane is the implicit owner.
- [ ] Every existing call site that does substring/regex matching on `tag:` strings is audited; tests added for each.
- [ ] ACL grants can reference `tag:bp//foo` as src or dst with semantics identical to a regular tag.
- [ ] Round-trips through JSON/HuJSON serialization, MapResponse encoding, and policy storage.

## ACL schema (`blueprints` block)

- [ ] New top-level `blueprints` key in the HuJSON policy file.
- [ ] Each blueprint object supports v1 fields only: `description` (required), `tags`, `serves.apps`, `serves.ipsets`, `attrs`.
- [ ] v2-deferred fields explicitly rejected at parse time (or silently ignored, document the choice): `serves.services`, `serves.exitNode`, `serves.funnel`, `posture`, `prefs`, `includes`.
- [ ] Blueprint creation auto-generates the paired `tag:bp//<id>` tag.
- [ ] Blueprint deletion revokes the paired OAuth client.
- [ ] At least one example blueprint in `deploy/acls/` test fixtures.
- [ ] ACL-CI validates the example.

## OAuth lifecycle

- [ ] Blueprint creation auto-generates a paired OAuth client.
- [ ] Paired client has `auth_keys.read` + `auth_keys.write` scopes.
- [ ] Paired client is pinned to mint keys only with `tag:bp//<id>`.
- [ ] Client secret is surfaced once at creation. Re-fetch is rotation, not display.
- [ ] Mint attempt for a tag the client is not scoped to fails with a clear error.
- [ ] Blueprint deletion revokes the paired client.
- [ ] Rotation is per-blueprint; touching one client does not affect others.

## CLI (`tailscale join` / `tailscale leave` / `tailscale set`)

- [ ] New subcommand `tailscale join --blueprint=<id> --auth-key=<oauth-secret>`.
- [ ] `join` has no `--advertise-tags`, `--advertise-routes`, `--advertise-exit-node`, `--advertise-connector` flags.
- [ ] `join` accepts node-local flags: `--hostname`, `--state-dir`, `--operator`, `--ssh`.
- [ ] Under the hood, `join` performs the existing OAuth secret → auth key exchange; no new auth path.
- [ ] Joining with a non-existent blueprint fails clearly.
- [ ] Joining with a secret that doesn't match the blueprint's paired client fails clearly.
- [ ] One bit ("was this node brought up via `join`?") is persisted in local prefs / state.
- [ ] `tailscale set` rejects every locked-field set when the bit is set, with the EXACT spec error message:
      `Error: this node is bound to bp:<id>. <Field> are managed by the blueprint. Edit the blueprint in the ACL to change what this node serves, or run 'tailscale leave' to detach.`
- [ ] Locked-field set covers: `advertise-tags`, `advertise-routes`, `advertise-exit-node`, `advertise-connector`, serves, funnel, `hostname`, `operator`, `ssh`, `accept-dns`.
- [ ] `tailscale leave` detaches the node, logs it out, and (server-side) deletes it.

## Propagation

- [ ] Blueprint-bound nodes carry blueprint state in their `Node` (top-level fields, per design decision).
- [ ] Map response projects blueprint's `tags`, `serves.apps`, `serves.ipsets`, `attrs` into the bound node's MapResponse atomically.
- [ ] Editing the blueprint in the ACL triggers reconvergence: all bound nodes receive new config on next map poll.
- [ ] `tailcfg` capability version is bumped to mark the new field set.
- [ ] No new wire protocol — reuse the existing MapResponse mechanism.

## Approval & ephemerality

- [ ] Blueprint joins follow the tailnet's existing device-approval settings. No new approval path.
- [ ] Blueprint-bound nodes are ephemeral; `tailscale leave` deletes them server-side.
- [ ] Re-joining mints a fresh node; no local state is preserved.

## Metrics

### Server (corp, expvar)

- [ ] `gauge_blueprints_defined_total{tailnet_id}` — gauge of defined blueprints.
- [ ] `gauge_blueprint_oauth_clients_total{tailnet_id}` — gauge of paired clients.
- [ ] `counter_blueprint_join_attempts_total{tailnet_id,blueprint_id,result}` — `result ∈ {success, blueprint_not_found, scope_mismatch, auth_failed}`.
- [ ] `gauge_blueprint_bound_nodes{tailnet_id,blueprint_id}` — currently-bound node count.
- [ ] `histogram_blueprint_edit_propagation_seconds{tailnet_id}` — ACL-save to last bound node receiving updated config.

### Client (OSS, clientmetric)

- [ ] `blueprint_join_success` counter.
- [ ] `blueprint_join_failure` counter.
- [ ] `blueprint_set_rejected` counter.
- [ ] `blueprint_leave` counter.
- [ ] `blueprint_bound` gauge.

## Admin HTTP API

- [ ] `GET /admin/api/blueprints` — list blueprints with bound-node counts.
- [ ] `GET /admin/api/blueprints/{id}` — single blueprint detail + bound nodes.
- [ ] Endpoint to reveal the paired client secret once (creation) and to rotate it.
- [ ] Permissioned by the same actor model as ACLs (`perm.ACLs.CanRead/WriteTailnet()`).

## Build variants

- [ ] `HasBlueprints()` gate in `control/controltags/controltags.go` returning `IsSaaS`.
- [ ] All blueprint code paths gated on `HasBlueprints()`.
- [ ] Tests pass under all four CI matrix tags: saas, onprem, onprem_coral, compliance_us.

## Tests

- [ ] Unit tests on every new function (table-driven where the repo uses table-driven).
- [ ] Integration test: define blueprint → mint key → `tailscale join` → bound node observes correct config → edit ACL → node reconverges → `tailscale leave` cleans up.
- [ ] Negative tests:
  - [ ] `tailscale set --advertise-routes` on a bound node fails with the verbatim spec error.
  - [ ] OAuth client minting for an unscoped tag fails.
  - [ ] Join with non-existent blueprint fails clearly.
  - [ ] Join with mismatched secret fails clearly.
  - [ ] Grant references `tag:bp//foo` but no such blueprint: surfaces a warning/error (decide and test).
- [ ] Tag parser tests: round-trip `tag:bp//foo` through serialization, grant compilation, MapResponse encoding.
- [ ] Coverage of new code ≥ 80% in both repos.

## CI

- [ ] OSS: `./tool/go test ./...` green.
- [ ] OSS: staticcheck, vet, gofmt, depaware green per `.github/workflows/`.
- [ ] Corp: `./tool/go test ./...` green across all build tags.
- [ ] Corp: `make pr` (staticcheck, test, depaware, gofmt, vet) green.
- [ ] Corp: ACL-CI on `deploy/acls/` green.

## Docs

- [ ] `BLUEPRINTS.md` at root of each branch: scope (v1 in vs out), metrics paths, how to run the integration test locally, known limitations.
- [ ] `BLUEPRINTS-NOTES.md` retained as scratch.
- [ ] `BLUEPRINTS-FOLLOWUPS.md` lists every deferred item (composability, services, tsnet, versioning, partial overrides, per-deployment secrets, etc.).

## Anti-scope-creep checks

- [ ] No `includes` field on blueprints (composability deferred).
- [ ] Blueprints are NOT ACL destinations (`tag:bp//foo` is, but the blueprint object itself is not a grant target).
- [ ] No services-auto-generating-blueprints code.
- [ ] No tsnet integration.
- [ ] No versioning, rollback, or pinning.
- [ ] No partial overrides.
- [ ] No per-deployment secrets.

## Iterative loops (per the prompt)

- [ ] **Loop 1: make it work.** End-to-end MVS green with passing tests.
- [ ] **Loop 2: make it right.** Style consistency, error messages, metric verification.
- [ ] **Loop 3: make it observable and ergonomic.** Fresh-checkout integration test, metrics visible, full local CI re-run.

## Done criteria

- [ ] Both branches pushed.
- [ ] Both branches show green local CI.
- [ ] ≥ 80% coverage of new code (numbers reported).
- [ ] Three loops visible in commit history.
- [ ] Metrics observable in the scrape path.
- [ ] End-to-end integration test passes.
- [ ] No scope creep beyond MVS (anything wanted-but-deferred is in FOLLOWUPS).
- [ ] `BLUEPRINTS.md` exists in both repos.
