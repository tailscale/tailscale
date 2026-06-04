# Permanent `tsnet.Server` leak: `Close()` racing an in-flight `Start()`

This documents the bug reproduced by `tsnet/leakrepro_test.go`
(`TestLeak_CloseRacingStart`).

## Summary

A `tsnet.Server` — and the whole subsystem graph it owns: the `netstack.Impl`,
the `wgengine` engine, the `magicsock.Conn`, the wireguard device and its 64 KiB
packet-buffer pools, and the netmap — is **never garbage collected** after
`Close()` when `Close()` raced an in-flight `Start()`. The orphaned objects
accumulate for the life of the process, so a program that brings tsnet servers
up and tears them down repeatedly (e.g. a supervisor that restarts a failing
instance on a deadline) grows without bound.

The leak is invisible to the usual checks: no goroutine is leaked, and
`go test -race` is silent (this is a logical teardown race, not a data race).
The only external symptom is steadily climbing RSS.

## Root cause

`Server.start()` creates the heavy subsystems but assigns them to `Server`
fields only late:

- `netstack.Create(...)` (`tsnet.go:868`) immediately does
  `stacksForMetrics.Store(ns)` (`wgengine/netstack/netstack.go:445`).
- `s.netstack = ns` isn't until `tsnet.go:886`; `s.lb = lb` at `:937`.

`Server.close()` (`tsnet.go:614`) tears a subsystem down **only if its field is
non-nil**, and it cancels `s.shutdownCtx`, which the in-flight `start()` is
using:

```go
if s.shutdownCancel != nil { s.shutdownCancel() } // tsnet.go:645
if s.netstack != nil       { s.netstack.Close() } // :648  (Impl.Close does stacksForMetrics.Delete)
if s.lb != nil             { s.lb.Shutdown() }     // :651
if s.netMon != nil         { s.netMon.Close() }    // :654
```

Nothing makes `start()` notice that a `close()` already ran, and the netstack is
**not** registered in `start()`'s error-cleanup `closePool`. So when `Close()`
lands while `start()` is mid-flight, `close()` snapshots `s.netstack` / `s.lb` /
`s.netMon` as nil and skips them, while `start()` goes on to create and store the
subsystems. The result is orphaned forever:

- the `netstack.Impl` stays in the package-global `netstack.stacksForMetrics`
  map (its `Impl.Close()`, which would call `stacksForMetrics.Delete`, never
  runs);
- `magicsock`'s per-endpoint timers keep running and are held alive by the
  runtime timer heap;
- the `wgengine` stays registered as a `netMon` change callback.

(There is also a narrower window: a `Close()` landing in *very* early `start()`,
before `s.sys` is initialized, nil-panics in `close()` at `tsnet.go:667`,
`s.sys.Bus.Get().Close()`. The same coordination fix covers both.)

## This is not the wireguard-go finalizer leak

This branch is current `main` plus the proposed non-leaking wireguard-go
(`github.com/tailscale/wireguard-go@v0.0.0-20260603160903-21fba1928adc`). The
test still fails on it, so that wireguard-go fix is **necessary but not
sufficient** — this leak lives entirely in `tailscale.com/tsnet` and is not
addressed by the wireguard-go change.

## Why a real tailnet is required

The vulnerable window is the wall-clock duration of `start()`. Against an
in-process test control server `start()` finishes in tens of milliseconds, so
the window is essentially never hit and the leak does not appear. Against a real
control server `start()` takes hundreds of milliseconds to seconds (DERP connect
+ login), so a `Close()` fired during it reliably lands in the window. This is
exactly the production scenario: a startup deadline (or context cancellation)
firing `Close()` while a slow connect is still in progress.

That is why the test is gated on `TS_AUTHKEY` and connects to a real control
server.

## Running it

```
TS_AUTHKEY=tskey-auth-... go test ./tsnet/ -run TestLeak_CloseRacingStart -v
```

- Optionally set `TS_CONTROL_URL` to point at a specific control server.
- Use an **ephemeral** auth key; the test registers nodes named `leakrepro-N`.

The test loops, launching `Up()` in a goroutine and calling `Close()` a short,
swept delay later so some iterations land inside `start()`. It detects leaks with
a `weak.Pointer[Server]`: a Server that is collected after `Close()` is healthy;
one that survives GC is orphaned. It asserts the correct invariant (every Server
is collected), so it is **red on today's code and green once fixed**.

### Interpreting the output

The race is probabilistic (~45–55% per attempt on the tail of `start()`), so a
single `Close()` rarely shows it. The test reports, e.g.:

```
FINAL: 12/20 Servers leaked, 1/20 Close() panics; heapInuse 36 -> 340 MiB
```

It reproduces on every run (a few leaks each), and in a process that restarts
repeatedly it accumulates without bound — the production symptom is hundreds of
orphaned `Impl`s in `stacksForMetrics` and RSS that climbs for as long as the
process runs.

The test self-calibrates to the machine: it first times `Start()`'s build phase
(the vulnerable window, whose absolute position scales with how fast this
machine reaches control), then sweeps the `Close()` delay across that interval —
so it works on a fast workstation and a slow CI box alike. If a run still
observes 0 leaks, raise `iters` for denser sampling.

The detection deliberately keys only on Go GC of the in-process `*Server`, never
on tailnet state, so neither node-name collisions nor a flaky registration can
produce a false positive or false negative.

## Suggested fix direction

Make `Close()` and `start()` coordinate so subsystems can't be orphaned:

- a "closing" state that `start()` checks (and unwinds what it has already
  built) after each subsystem it creates; and/or
- register the netstack in `start()`'s `closePool`, and have `close()` wait for
  an in-flight `start()` to finish rather than snapshotting nil fields and
  returning.

Either approach also fixes the early-`start()` `close()` nil-panic at
`tsnet.go:667`.
