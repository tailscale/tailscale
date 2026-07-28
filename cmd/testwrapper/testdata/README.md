# Race-output test corpus

This directory is a corpus of captured Go test binary outputs that
exercise the various ways the `-race` detector's `WARNING: DATA RACE`
text can land relative to `=== RUN` / `--- PASS:` / `--- FAIL:` /
`=== NAME` lines, and how `cmd/internal/test2json` attributes that
output to tests.

Each scenario subdirectory contains:

- `src.go` — the Go source code that was compiled and run to produce
  the captured output. Reproduce via
  `go test -race -c -o /tmp/scenario.test ./<dir>/`.
- `raw.txt` (or scenario-specific name) — the raw stdout+stderr of
  the resulting test binary when run as `./scenario.test -test.v`.
  This is the byte stream that `go test -json` feeds to
  `go tool test2json` in production.

`go test -json` adds two things on top of what `test2json` sees,
which are NOT in these captures: a `FAIL\t<pkg>\t<time>` output line
and a corresponding `fail` action event when the binary exits with a
non-zero status (e.g. the race detector's exit code 66). Consumers
that simulate the `go test -json` view from these files need to
append those.

To turn a `raw.txt` into the JSON `testwrapper` would consume:

```
go tool test2json -p <pkgname> < raw.txt
```

## Scenarios

### A_baseline — no race

Two trivial passing tests, no `-race` involvement at all. Useful as a
sanity-check for parsers; demonstrates the standard mapping from
`=== RUN`/`--- PASS:`/bare `PASS` lines to JSON events.

### B_inbody — race during a test's own body

A single test spawns racing goroutines and `wg.Wait()`s for them.
The race fires while the test is still running, so
`testing.checkRaces` sees `race.Errors()` increment between the
test's start and end and the test is marked `--- FAIL:` with a
`testing.go:1712: race detected during execution of test` line.

This is the well-behaved case: the race output and the failure marker
are both attributed to a single, clearly-failed test.

### C_spawnwait — race in goroutines that outlive a test

`TestSpawn` spawns racing goroutines and returns immediately;
`TestWait` blocks until they finish. Where the race report lands is
timing-dependent. Two captured variants:

- `pass.raw.txt` — both `TestSpawn` and `TestWait` end up marked
  `--- PASS:`, with the entire `WARNING: DATA RACE` report
  attributed to `TestWait` (the test whose `=== RUN` line was the
  most recent thing emitted when TSan printed). Neither test's
  `checkRaces` saw `race.Errors()` increment within its window. The
  binary still exits non-zero, producing only a bare trailing
  `FAIL`. **This is the case where testwrapper currently drops the
  race report on the floor.**

- `caught.raw.txt` — `TestSpawn`'s `checkRaces` happened to fire
  after the goroutines raced, so it emits the standard
  `testing.go:1712:` + `--- FAIL: TestSpawn` markers. Race report is
  attributed to `TestSpawn`, and the failure is attributed to
  `TestSpawn` too. Well-behaved.

### D_delayed — race delayed into the next test's body

Like `C_spawnwait` but the spawned goroutines block on a channel that
the second test closes, then sleeps. This forces the race counter
delta to land between the second test's `resetRaces` and
`checkRaces`, so the framework reliably attributes a failure to the
sleeping test. Compare with `B_inbody`: same end shape, but the
failure is attributed to a test that doesn't *contain* the racing
code.

### E_testmain — race in `TestMain` after `m.Run()`

The race-producing goroutines are spawned by `TestMain` after
`m.Run()` returns. By that point the framework has already printed
its top-level `PASS` summary, so `test2json`'s `c.testName` is reset
to `""` and the entire race report shows up at **package level** —
all of its `output` events have an empty `Test` field. The bare
`PASS` line earlier in the output also causes `test2json` to set
`c.result = "pass"`, which means `go tool test2json` in isolation
ends up emitting `{"Action":"pass","Package":"..."}` for the
package; only `go test`'s own exit-code post-processing turns it
into the visible package-level failure.

### F_parallel — racing parallel tests

Two `t.Parallel()` tests both increment the same global. The
captured `split.raw.txt` shows the report **split across two tests**
via a `=== NAME  TestParB` redirect line emitted by the framework:

```
--- PASS: TestParA (0.00s)
==================
WARNING: DATA RACE
   ... full race report ...
==================
=== NAME  TestParB
    testing.go:1712: race detected during execution of test
--- FAIL: TestParB (0.00s)
```

`test2json` attributes the `WARNING: DATA RACE` block plus the full
stack trace to `TestParA` (which passes), then sees the
`=== NAME  TestParB` directive and switches attribution, so the
trailing `race detected` line and `--- FAIL` end up under
`TestParB` (which fails). A consumer that only flushes failed tests'
logs sees the `race detected` line but loses the stack trace.

## How these were captured

```
# For each scenario directory <name>/ (e.g. C_spawnwait):
go test -race -c -o /tmp/<name>.test ./testdata/<name>/
/tmp/<name>.test -test.v >./testdata/<name>/raw.txt 2>&1
```

For scenarios where the race detector's attribution is
timing-dependent (C, F), the binary was run repeatedly and the
interesting variants saved with distinct names.

The captured outputs contain absolute file paths from the machine
they were recorded on (e.g. `/tmp/racesurvey/...`). Tests that
match against these files should not depend on those paths.
