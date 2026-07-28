# Tailscale CLI evolution guidelines

This document offers guidance for evolving the Tailscale core command-line
interface(s), principally `tailscale` (and, where relevant, `tailscaled`). It
is intentionally lightweight. It describes the *spirit* we want to preserve as
the CLI grows, not a rigid specification. As with all style guides, some of it
is subjective and exists mainly to codify existing conventions and promote
consistency; other parts have stronger reasoning, such as compatibility,
accessibility, or long-term maintenance burden.

When a guideline here conflicts with good judgement in a specific case,
prefer good judgement, but raise the conflict so the guidance can be improved.
These are defaults and tie-breakers, not laws.

## Collaboration and design review

CLI design is a collaborative process, and these guidelines are best applied in
conversation rather than in isolation.

Tailscalars should seek collaboration in the **#cli** channel in Slack for
design reviews early, before significant implementation work, while a design is
still easy to change.

Open-source contributors should anticipate feedback on CLI changes and expect to
be asked to approach design review collaboratively and thoughtfully. CLI surface
is long-lived and hard to change once shipped, so a proposed change may go
through more discussion than a typical bug fix. This is not a barrier; it is how
we keep the CLI coherent. Engaging openly with that review process is the fastest
path to getting a change merged.

## Influences and non-goals

Some good concepts and vocabulary here are drawn from the Fuchsia CLI
guidelines:

* https://fuchsia.dev/fuchsia-src/development/api/cli
* https://fuchsia.dev/fuchsia-src/development/api/cli_help

We borrow ideas, not rules. Those documents are more prescriptive than we want
to be, and several of their specifics do not apply to us. In particular:

* We are **not** adopting their `--help` output format. Our help output has its
  own history and conventions, and we will not switch formats arbitrarily.
* We have many **pre-existing** commands and behaviors that predate any of
  this guidance. We accept them as-is. This document is about how we *grow*
  from here, not a mandate to retrofit existing surfaces.

## Guiding principles

The Tailscale CLI is one of the most visible parts of the product. It is used
interactively by humans, embedded in scripts and pipelines, read by screen
readers, and depended on for automation. Small decisions compound. We would
rather do the harder work of getting a surface right than take the easier
short-term path of adding one more toggle.

### Keep overall configurability low

We aim to keep the overall configurability of the Tailscale client *low*. It is
strongly preferred to identify broadly common solutions to heterogeneous user
challenges and apply them holistically, rather than exposing large configuration
surfaces.

Wide configuration surfaces are deceptively expensive: they invite users to
spend effort tuning them, they increase the support load, they multiply the
combinations we must test and reason about, and they tend to ossify into
compatibility obligations. Prefer doing the hard work of getting the default
right over the easy "now" work of adding another option.

This is a default bias, not an absolute prohibition. When a setting is genuinely
necessary, add it deliberately and in the right place (see below).

## Command structure

### Top-level commands

The top-level command surface (`tailscale <command>`) is precious. Every
addition there is effectively permanent and competes for the user's attention
and memory. We want it to grow slowly.

Some commands earn a place at the top level because they are used so frequently
that the brevity is worth it:

* `tailscale set` and `tailscale get` are fine as independent top-level
  commands, in large part *because their usage is so frequent*. The cost of an
  extra level of nesting would be paid constantly.

### Prefer `tailscale <noun> <verb>` for features

For new "feature"-oriented designs, we will generally prefer a
`tailscale <noun> <verb>` structure (for example `tailscale <feature> status`,
`tailscale <feature> enable`). This lets a feature's surface grow over time
without growing the top-level CLI surface too quickly. New verbs and options
live under the noun, where they are discoverable in context and do not crowd the
root.

This is a guideline, not a cage. Do not force a design into
`<noun> <verb>` if there is wide consensus that the resulting structure is
awkward. Naturalness and usability win over structural purity.

### Noun naming

Prefer **singular** nouns (`tailscale cert`, `tailscale ip`) unless a singular
form is strongly unnatural for the concept. Consistency in number makes commands
easier to predict and remember.

### `tailscale up` is closed for extension

`tailscale up` is now effectively **closed for extension**. New configuration
features should prefer to go into `set` rather than `up`.

The reason is historical and concrete: `up` has the long-standing problem that
its flags describe a desired *complete* state, so a later invocation must repeat
(or carefully manage) all of the earlier flags or risk resetting them. `set` was
introduced precisely to allow incremental, additive configuration changes
without that footgun. New knobs belong there.

### Extend existing surfaces when it fits the spirit

Existing surfaces should be extended where appropriate, provided the extension
does not substantially change the *spirit* of the surface.

For example, adding new target query types to `tailscale ip` is a good fit where
those targets are sufficiently visible to clients: it is the same operation
("resolve a thing to an IP") applied to more inputs. That is extension in the
spirit of the command, not scope creep.

### Avoid arbitrary growth in complexity

Resist the temptation to grow a command to match the full surface of some
external tool it resembles. For example, `tailscale ssh` does **not** intend to
reimplement the full flag surface of `ssh` over time. Doing so would be an
enormous and open-ended maintenance burden, and `ssh` itself is essentially
ubiquitously available and already serves that purpose. A Tailscale command
should do its job well, not absorb an entire adjacent ecosystem.

## Debug commands

Heavily used `debug` subcommands should, over time, graduate into proper
features of the main program when they prove broadly useful.

`debug` subcommands are explicitly **not** subject to our usual compatibility
promises. They are best-effort and may change or be removed. Treat them as a
staging ground and a power-user/diagnostic surface, not as a stable API. If a
debug command becomes load-bearing for users, that is a signal to promote and
stabilize it deliberately rather than to quietly grant it stability by neglect.

## Configuration: where settings live

### Profile-local preferences are the default home

Most configuration should be **profile-local** preferences, set and read via
`set`/`get`, and modifiable at runtime. This is where the overwhelming majority
of user-facing configuration belongs.

### `tailscaled` flags are a last resort

Daemon (`tailscaled`) command-line flags should ideally be added **only** when a
setting is truly *process-global* and *immutable after launch*. If something can
reasonably be a profile-local preference that is changeable via `set`/`get`, it
should be, not a daemon flag.

Daemon flags are sticky and global; they are the wrong place for anything a user
might want to change per-profile or at runtime.

Daemon flags are also, in practice, **almost Linux-only**. Most GUI platforms
(for example macOS, Windows, and mobile) make it very difficult for a user to
adjust how the tailscale backend (e.g. `tailscaled`) is launched, so a setting
that lives only in a daemon flag is effectively unreachable for most of our
users. This is another reason to prefer profile-local preferences via
`set`/`get`, which work uniformly across platforms.

### Prefer preferences over environment variables

For both `tailscale` and `tailscaled` configuration surfaces, prefer
preferences (`set`/`get`) over environment variables. Environment variables are
hard to discover, hard to deprecate, and tend to leak into permanence.

### `TS_DEBUG` environment knobs

Add `TS_DEBUG`-style env knobs freely as development work requires them. These
are explicitly **for development only**. They are not intended for end users and
should not be documented or encouraged for public use.

A cautionary note: we already have cases of debug env knobs that became
load-bearing for someone and which we may never be able to remove. That is an
undesirable outcome. Keeping these clearly internal and undocumented is what
preserves our freedom to change or delete them.

## Output and streams

### `--json` and stable machine output

Commands should offer a **stable** JSON format behind a `--json` flag. Once a
feature is generally available (GA), that JSON format is maintained in a
backward-compatible way as much as possible, in keeping with Tailscale's broad
compatibility policy.

Backward compatibility here means existing fields keep their meaning. **Adding
new fields is allowed** and expected; consumers must tolerate unknown fields.

### Human-readable (non-JSON) output

Non-JSON command output is the default and should be optimized, first and
foremost, for *easy reading by sighted humans*, and, where possible, to *read
well with a screen reader*. Concretely:

* Avoid decorative Unicode output. Prefer plain ASCII.
* Convey information in the **text**, not only via color or position. Do not
  rely on color to communicate meaning (see "Color and decoration" below).
* Keep output uncluttered and scannable.

The `grep`/`awk`-ability of stdout output should be considered and maintained on
a **best-effort** basis, but it is **not** a hard compatibility guarantee when
readability or usability would suffer substantially as a result.

In practice this means being conservative with the *shape* of stable output. For
example:

* Adding a **new column** in the middle of already-stable tabular output should
  only be done after strongly weighing the tradeoffs, and most often should not
  be done, because it breaks naive positional parsers.
* Adding **new in-column behavior** can be done with care. A good example: the
  idle/connected/DERP/relay status field was extended to describe relays
  *within the existing column* rather than by adding a new column. That
  technically introduced new parsable content into the column (so the strictest
  parsers might notice), but it avoided breaking the common case, and *not*
  conveying the information would have been too large a usability and
  readability loss.

The principle: prefer changes that preserve the common parser and the human
reader simultaneously; when forced to choose, protect the human reader, and make
machine consumers use `--json`.

### stdout vs. stderr

**stderr is the standard *information* stream.** It is not only for errors. It
carries all informational, diagnostic, and progress output that is not the
direct intended output of the command.

**stdout** should contain (within reason) the command's *intended* output — the
thing the user actually asked for — or nothing. Everything else (status notes,
progress, warnings, diagnostics) goes to stderr.

This separation is what makes the CLI usable in pipelines: a user can pipe
stdout into another tool without having diagnostic chatter corrupt the data
stream.

A couple of implications worth calling out:

* `--help` is *intended* output: when the user asks for help, help text should
  go to **stdout**.
* An *error* about bad flags that happens to print usage as part of a
  diagnostic message is diagnostic output and should go to **stderr**, not
  stdout.

  (At the time of writing, our handling of this distinction for help output is
  an existing bug. New code should follow the correct behavior, and we should
  fix the existing behavior over time.)

### TTY-dependent behavior

Altering behavior based on whether stdout is a TTY is sometimes genuinely
helpful (for example, suppressing a spinner when not interactive). Use it
sparingly.

Major changes in behavior or output based on TTY detection are an impediment to
use and should not be added arbitrarily. Requiring something like
`tailscale foo | less` in order to *discover* a behavior should not become a
standard pattern: it is a usability issue that excludes many users, including
those using screen readers and automation.

### Color and decoration

Support for, and further discussion of, colored or heavily decorated output is
**deferred at this time** and should not be added until guidance is clarified.

The primary concern is accessibility: colored and decorated output is often
hostile to screen-reader users, and information encoded only in color is
invisible to many people. Until we have clear guidance, keep output plain and
ensure all meaning is present in the text itself.

## Summary checklist

When adding or changing CLI surface, ask:

* Tailscalars can raise a thread in #cli
* Could this be a profile-local preference via `set`/`get` instead of a new
  top-level command, a `up` flag, a daemon flag, or an env var? Usually it
  should be.
* Does it fit a `tailscale <noun> <verb>` shape without being awkward?
* Is the noun singular (unless that's strongly unnatural)?
* Does it provide stable `--json` output, and is the human output plain,
  screen-reader-friendly, and free of color-only meaning?
* Does intended output go to stdout and everything else to stderr?
* Are you extending an existing surface in its spirit, rather than growing
  complexity arbitrarily?
* If it's a debug command, is it clearly best-effort and not silently becoming
  a stable dependency?
