# Flaky Test Fix Plan - Status Update

## Summary (2026-04-13)

The original 28 "flaky" tests identified by `cmd/deflake` have been fixed. The root cause was **not** actual test flakiness but **/tmp exhaustion**.

## Root Cause & Fix

When running many parallel integration tests, each subtest copied ~70MB of binaries (tailscale + tailscaled) to its temp directory. With 24+ parallel subtests, this quickly exhausted /tmp space, causing "no space left on device" errors that looked like test flakes.

### Fixes Applied

1. **Hard links instead of copies** (`tstest/integration/integration.go`)
   - `BinaryInfo.CopyTo()` now tries `os.Link()` first
   - Falls back to copying only if hard link fails (cross-device)
   - Result: No additional disk space consumed per subtest

2. **Isolated TMPDIR per deflake run** (`cmd/deflake/main.go`)
   - Creates `/tmp/deflake-<pid>-*/` for each run
   - Automatically cleaned up on exit
   - Prevents accumulation across runs

3. **Old temp dir cleanup** (`cmd/deflake/main.go`)
   - Removes `/tmp/Test*` directories older than 1 hour at startup
   - Handles leftovers from crashed/timed-out tests

4. **Proper timeout hierarchy** (`cmd/deflake/main.go`)
   - `go test -timeout` set higher than context timeout
   - Context fires first with cleaner error messages

## Verification

All 28 tests now pass consistently:
```bash
# Full integration suite, 10 iterations, no race
./tool/go test -v -count=10 ./tstest/integration  # PASS

# Full integration suite, 2 iterations, with race
./tool/go test -v -race -count=2 ./tstest/integration  # PASS
```

## Other Fixes in This Branch

Beyond the /tmp exhaustion fix:

- **TestPeerRelayPing** - Fixed race: avoid `t.Fatal` from goroutine (commit `6a046e946`)
- **TestKernelVersion** - Handle `+` suffix in kernel version strings (commit `0a1e6e248`)

## Remaining Work

None currently identified. If new flakes appear, use deflake to identify them:

```bash
go build ./cmd/deflake
./deflake -packages=./... -count=10
```

## How to Validate Future Fixes

```bash
# Single test validation
./tool/go test -v -count=20 -run '^TestName$' ./path/to/package
./tool/go test -v -race -count=20 -run '^TestName$' ./path/to/package

# Full deflake run
./deflake -packages=tailscale.com/tstest/integration -count=20
```
