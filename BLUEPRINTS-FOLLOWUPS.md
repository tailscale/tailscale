# Blueprints — v2+ Follow-ups

Things explicitly out of scope for v1. Added here whenever the v1 implementation surfaces a tempting expansion.

## From the spec (deferred from day one)

- **Composability (`includes`).** Blueprint A includes Blueprint B's fields. No transitive `tag:bp//` inheritance; design TBD.
- **Blueprints as ACL destinations.** Grants directly targeting `blueprint:foo` rather than `tag:bp//foo`. Currently solved by the auto-generated tag.
- **Services auto-generating blueprints.** A `svc:` definition would imply a paired blueprint.
- **tsnet integration.** Embedding blueprint-bound behavior inside a tsnet-hosted Go program.
- **Versioning / rollback / per-node blueprint pins.** Today edits propagate everywhere.
- **Partial overrides.** Per-node opt-out of specific blueprint fields.
- **Per-deployment secrets.** Different secrets per environment for the same blueprint.
- **Super-ephemeral nodes.** Nodes that vanish on idle, not just on leave.
- **Separate wire protocol.** Blueprint propagation currently piggybacks on the existing map-poll.

## Surfaced during v1 build

(Add items as they come up, with one-line rationale.)
