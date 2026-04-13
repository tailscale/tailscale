# Flaky Test Fixes Report

This report documents the flaky tests identified and fixed on the `flake` branch.

## Summary

- **Total tests fixed**: ~45 tests across 7 tiers
- **Commits**: 8 commits
- **Root causes**: Global state leakage, race conditions, timeout issues, tool bugs

## Commits

| Commit | Description |
|--------|-------------|
| `88739bc52` | Fix Tier 1: global state isolation issues |
| `b9d2a85e7` | Fix Tier 2: skip Example tests in deflake tool |
| `0da82d362` | Fix Tier 3: race conditions and timeouts |
| `adb9f2402` | Fix Tier 4: multiple packages + deflake timeout fix |
| `7d5ffcfe2` | Fix Tier 5: slow test timeouts |
| `2094e06cf` | Fix Tier 6: race-only flakes |
| `6a046e946` | Fix Tier 7: TestPeerRelayPing race |

---

## Tier 1: Completely Broken (0-1 passes out of 10)

### TestLookupMetric (`tailscale.com/cmd/derper`)
**Symptom**: 0/10 passes, EOF on response body

**Root Cause**: Test called `getBootstrapDNS()` without initializing the global DNS caches (`dnsCache` and `dnsCacheBytes`). The handler returns `dnsCacheBytes.Load()` when no match is found, which was empty.

**Fix**: Added initialization of `dnsCache` and `dnsCacheBytes` at test start, following the pattern in `TestUnpublishedDNSEmptyList`.

**File**: `cmd/derper/bootstrap_dns_test.go`

---

### TestRouteStoreMetrics (`tailscale.com/appc`)
**Symptom**: 1/10 passes, metric counts doubled

**Root Cause**: Test checked absolute metric values, but `clientmetric.Metric` counters are global singletons that persist across test runs with `-count=N`.

**Fix**: Capture initial metric values before test actions, then verify the delta (change) rather than absolute values.

**File**: `appc/appconnector_test.go`

---

### TestNoDups (`tailscale.com/cmd/tailscale/cli`)
**Symptom**: 1/10 passes

**Root Cause**: `noDupFlagify` wrapped flag values with `onceFlagValue` wrappers that track if a flag has been set. Since flag sets are package-level variables, the wrapper's `set` field persisted between test runs, causing double-wrapping.

**Fix**: Modified `noDupFlagify` to check if a flag value is already wrapped, and reset the `set` field instead of double-wrapping.

**File**: `cmd/tailscale/cli/cli.go`

---

### TestVarzHandler (`tailscale.com/tsweb/varz`)
**Symptom**: 1/10 passes, panic on "Reuse of exported var name: foo"

**Root Cause**: Test used `expvar.NewString("foo")` which publishes globally. On repeated runs, registration of "foo" panics.

**Fix**: Use `new(expvar.String)` to create an unpublished expvar.

**File**: `tsweb/varz/varz_test.go`

---

### TestTCPForwardLimits_PerClient (`tailscale.com/wgengine/netstack`)
**Symptom**: 1/10 passes

**Root Cause**: Test checked absolute value of `metricPerClientForwardLimit` (expecting 1), but the counter accumulates across test runs.

**Fix**: Capture initial value and check that metric increased by 1.

**File**: `wgengine/netstack/netstack_test.go`

---

### TestDNSTrampleRecovery (`tailscale.com/net/dns`)
**Symptom**: 1/10 passes, panic on "Set on already-set feature hook"

**Root Cause**: Used `HookWatchFile.Set()` which panics when called on an already-set hook.

**Fix**: Use `HookWatchFile.SetForTest()` with deferred restore.

**File**: `net/dns/direct_linux_test.go`

---

## Tier 2: Broken Example Functions (8 tests)

### All Example tests showing 1/10 passes

**Symptom**: ExampleUserTimeout, ExampleMiddlewareStack, ExampleDeferredInit, etc. all showed 1/10 passes.

**Root Cause**: **False positive in deflake tool**. Go's `go test -count=N` always runs Example functions exactly once, regardless of N. The deflake tool counted pass lines and expected N passes, so Examples always appeared as 1/N.

**Fix**: Modified `cmd/deflake/main.go` to skip Example tests (mark as "pass" immediately) since they can't be flake-detected with `-count=N`.

**File**: `cmd/deflake/main.go`

---

## Tier 3: Moderately Broken (2-8 passes out of 10)

### TestTailnetLock (`tailscale.com/tstest/integration`)
**Symptom**: 2/10 passes (390ms baseline)

**Root Cause**: Missing `tstest.Shard(t)` and `tstest.Parallel(t)` calls at the top level.

**Fix**: Added the missing calls at the beginning of the test function.

**File**: `tstest/integration/integration_test.go`

---

### TestGetCertPEMWithValidity (`tailscale.com/ipn/ipnlocal`)
**Symptom**: 1/10 passes

**Root Cause**: `TS_CERT_SHARE_MODE` environment variable was only set when `tt.readOnlyMode` was true, but never reset when false. State leaked between subtests.

**Fix**: Added `else` branch to explicitly reset `TS_CERT_SHARE_MODE` to empty when `readOnlyMode` is false.

**File**: `ipn/ipnlocal/cert_test.go`

---

### TestContainerBoot (`tailscale.com/cmd/containerboot`)
**Symptom**: 6/10 passes (1.6s baseline)

**Root Cause**: Wait loops had 2-second timeouts. When 40+ parallel subtests run simultaneously, containerboot processes take longer, causing intermittent timeouts.

**Fix**: Increased all four timeout values from 2 seconds to 10 seconds.

**File**: `cmd/containerboot/main_test.go`

---

### TestClientSideJailing (`tailscale.com/tstest/integration`)
**Symptom**: 8/10 passes (3.4s baseline)

**Root Cause**: IPN bus watchers were created once at the start and reused across subtests. Race condition between `SetJailed` sending updates and watchers listening.

**Fix**: Create fresh IPN bus watchers for each subtest with 5-second timeout, start watchers before calling `SetJailed`.

**File**: `tstest/integration/integration_test.go`

---

## Tier 4: Moderately Broken, Slower Tests

### TestNoUDPNilGetReportOpts, TestWorksWhenUDPBlocked (`tailscale.com/net/netcheck`)
**Symptom**: 9/10 passes (3s baseline)

**Root Cause**: Captive portal detection made real network calls and could block indefinitely.

**Fix**:
1. Stop captive portal timer before waiting on its channel
2. Set `testCaptivePortalDelay: time.Hour` in test client
3. Add context check in captive detection interface iteration

**Files**: `net/netcheck/netcheck.go`, `net/netcheck/netcheck_test.go`, `net/captivedetection/captivedetection.go`

---

### TestNewConn, TestDERPActiveFuncCalledAfterConnect (`tailscale.com/wgengine/magicsock`)
**Symptom**: 9/10 passes (3s baseline)

**Root Cause**: TOCTOU race in port selection - `pickPort` would bind, close, then hope to rebind to the same port.

**Fix**:
1. Use `Port: 0` and read assigned port after connection
2. Add 10-second timeout to DERPActiveFunc callback wait
3. Remove unused `pickPort` helper

**File**: `wgengine/magicsock/magicsock_test.go`

---

### TestDirectoryListing (`tailscale.com/drive/driveimpl`)
**Symptom**: 5/10 passes (5s baseline)

**Root Cause**: Used `http.Serve(ln, r)` which doesn't properly shut down active connections, leaving goroutines running.

**Fix**: Use `http.Server` with `Serve()` and `Close()` for proper cleanup.

**File**: `drive/driveimpl/drive_test.go`

---

### TestServer_getNextVNILocked (`tailscale.com/net/udprelay`)
**Symptom**: 3/10 passes (14.3s baseline)

**Root Cause**: Test iterated through all 16,777,215 VNIs, taking ~14 seconds per run.

**Fix**: Rewrote test to check key behaviors directly without iterating all VNIs.

**File**: `net/udprelay/server_test.go`

---

### All tsconsensus tests (8 tests)
**Symptom**: 3-7/10 passes (4-23s baseline)

**Root Cause**:
1. `waitFor` function had infinite loop with no timeout
2. Global `netns` state race when tests run in parallel

**Fix**:
1. Added 2-minute deadline to `waitFor` that fails fast
2. Use `sync.Once` to disable netns once per package

**File**: `tsconsensus/tsconsensus_test.go`

---

### All tsnet tests (9 tests)
**Symptom**: 4-7/10 passes (5-10s baseline)

**Root Cause**: **False positive in deflake tool**. Timeout calculation was `baseline * multiplier` but should be `baseline * count * multiplier` since all N iterations must complete.

**Fix**: Modified deflake timeout calculation to multiply by count.

**File**: `cmd/deflake/main.go`

---

## Tier 5: Slow Broken Tests (>60s baseline)

### TestRefreshAdvertiseServices (`tailscale.com/cmd/containerboot`)
**Symptom**: 4/10 passes (60s baseline)

**Root Cause**: `services.EnsureServicesAdvertised` has hardcoded 20-second wait. With 3 subtests, each iteration took 60 seconds.

**Fix**: Added `SetWaitDurationForTest()` to make wait configurable (1ms in tests).

**Files**: `kube/services/services.go`, `cmd/containerboot/serve_test.go`

---

### TestListenService (`tailscale.com/tsnet`)
**Symptom**: 5/10 passes (67.7s baseline)

**Root Cause**: Test waited only for DNS records before dialing. Route propagation for service VIP can lag behind DNS.

**Fix**: Wait for service VIP prefix to appear in `AllowedIPs` of service host peer before proceeding.

**File**: `tsnet/tsnet_test.go`

---

## Tier 6: Race-Only Flakes, Fast (<1s baseline)

### TestInQemu (`tailscale.com/tstest/archtest`)
**Symptom**: Passes without -race, "flaky" with -race

**Root Cause**: Test had `//go:build linux && amd64 && !race` - it never ran with race detector, causing deflake tool to flag it.

**Fix**: Removed `!race` from build constraint.

**File**: `tstest/archtest/qemu_test.go`

---

### TestArrayAllocs (`tailscale.com/util/deephash`)
**Symptom**: Passes without -race, flaky with -race

**Root Cause**: Test wrote to package-level `sink` variable which raced with parallel tests.

**Fix**: Use local `localSink` variable, remove `version.IsRace()` skip.

**File**: `util/deephash/deephash_test.go`

---

### TestUpdateEvent (`tailscale.com/net/portmapper`)
**Symptom**: 12/20 passes with -race

**Root Cause**: `eventbustest.Watcher.done()` could be called from multiple places, causing double-close of channel.

**Fix**: Use `sync.Once` to ensure channel is only closed once.

**File**: `util/eventbus/eventbustest/eventbustest.go`

---

### TestInsertCompare (`tailscale.com/net/art`)
**Symptom**: 18/20 passes with -race

**Root Cause**: Used `math/rand` global functions which are not thread-safe.

**Fix**: Switch from `math/rand` to `math/rand/v2` which has thread-safe globals.

**File**: `net/art/table_test.go`

---

### Integration tests (10 tests)
**Symptom**: 11-19/20 passes with -race

**Root Cause**: Already fixed by prior commits on this branch (Tier 3 and earlier fixes).

**Status**: No additional changes needed.

---

## Tier 7: Race-Only Flakes, Slower (1-4s baseline)

### TestAutoUpdateDefaults, TestAutoUpdateDefaults_cap
**Symptom**: 13/20 passes with -race

**Status**: Already fixed by prior commits. Tests now pass consistently.

---

### TestPeerRelayPing (`tailscale.com/tstest/integration`)
**Symptom**: 13/20 passes with -race (1.6s baseline)

**Root Cause**: Test called `MustStatus()` from goroutines. `MustStatus()` calls `t.Fatal()` on error, which races with test cleanup when called from non-test goroutines.

**Fix**: Replace `MustStatus()` with `Status()` and propagate errors through error channel.

**File**: `tstest/integration/integration_test.go`

---

### TestTaildropIntegration, TestTaildropIntegration_Fresh
**Symptom**: 14-17/20 passes with -race

**Status**: Already fixed by prior commits. Tests now pass consistently.

---

## Deflake Tool Fixes

Two bugs were found and fixed in `cmd/deflake/main.go`:

1. **Example test false positives**: Go only runs Example functions once regardless of `-count=N`, making them appear as 1/N passes. Fixed by skipping Example tests.

2. **Timeout calculation bug**: Timeout was `baseline * multiplier` but should be `baseline * count * multiplier` since all N iterations must complete within the timeout. This caused slow tests to timeout and appear flaky.

---

## Common Patterns

### Global State Leakage
- **Metrics**: Use delta checks instead of absolute values
- **Expvars**: Use `new(expvar.Type)` instead of `expvar.NewType("name")`
- **Feature hooks**: Use `SetForTest()` with deferred restore
- **Flag values**: Reset state between runs
- **Environment variables**: Always restore original values

### Race Conditions
- **t.Fatal from goroutines**: Use error channels instead
- **Package-level variables**: Use local variables or sync primitives
- **Double-close channels**: Use `sync.Once`
- **Non-thread-safe rand**: Use `math/rand/v2`

### Timeout Issues
- **Hardcoded waits**: Make configurable for tests
- **Insufficient timeouts**: Account for parallel load
- **Missing timeouts**: Add deadlines to prevent hangs

### Port Allocation
- **TOCTOU races**: Use `Port: 0` and read assigned port after binding

---

## Verification

All fixes were verified with:
```bash
./tool/go test -count=10 -race -run '^TestName$' package
```

Tests must pass all 10 iterations with the race detector enabled before committing.
