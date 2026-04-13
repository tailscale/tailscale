# Slow Tests That Appear Flaky Under Load

These tests pass consistently when run individually but show intermittent failures when run in parallel with many other tests (e.g., via `cmd/deflake` with `-parallel=12`).

The root cause is **timeout-based flakiness**, not logic bugs. Under heavy parallel load with the race detector enabled, resource contention causes these tests to exceed their expected timeouts.

## Affected Tests

### tailscale.com/tstest/integration

| Test | Baseline (ms) | With Race | Pass Rate (parallel) | Notes |
|------|---------------|-----------|---------------------|-------|
| TestAutoUpdateDefaults | 1020 | ~25s | 5/6 | 3 subtests, each ~8-9s |
| TestAutoUpdateDefaults_cap | 370 | ~25s | 5/6 | Similar to above |
| TestNATPing | 2000 | ~70s+ | 3/6 | Very slow with race detector |
| TestPeerRelayPing | 1790 | ~20-25s | 5/6 | 3-node relay test |
| TestTailnetLock | 1290 | ~12s | 2/6 | Flaky even without race |

### tailscale.com/tsconsensus

| Test | Baseline (ms) | With Race | Pass Rate (parallel) | Notes |
|------|---------------|-----------|---------------------|-------|
| TestRejoin | ~4000 | ~15s+ | 4/5 | Raft consensus test |

## Conditions Observed

- **Machine**: Linux 6.12.41+deb13-amd64
- **Parallelism**: 12 packages tested concurrently (`-parallel=12`)
- **Race detector**: Enabled (`-race=true`)
- **Iterations**: 3-5 per test (`-count=3` or `-count=5`)

## Commands to Run Tests Successfully

### Individual test (passes reliably)

```bash
# Without race detector
./tool/go test -v -count=5 -run '^TestAutoUpdateDefaults$' ./tstest/integration

# With race detector (slower but still passes)
./tool/go test -v -race -count=5 -run '^TestAutoUpdateDefaults$' ./tstest/integration
```

### All integration tests (reduced parallelism)

```bash
# Reduce parallelism to avoid resource contention
./tool/go test -v -race -count=3 -parallel=4 ./tstest/integration
```

### Using deflake with longer timeouts

```bash
# Build deflake
go build ./cmd/deflake

# Run with reduced parallelism
./deflake -packages=tailscale.com/tstest/integration -count=3 -parallel=4
```

## Recommendations

1. **For CI**: Run integration tests with reduced parallelism or longer timeouts
2. **For local development**: Run individual tests rather than full suites
3. **For deflake tool**: Consider adding a `-slow` flag that uses more conservative timeouts for integration tests
4. **Long-term**: Some tests could be optimized to run faster (e.g., TestNATPing takes 70s+ with race detector)

## Not Actual Flakes

These tests do NOT have logic bugs causing flakiness. The underlying test logic is correct. The "failures" are purely due to timeouts being exceeded under heavy load.

Evidence: When run individually with `./tool/go test -v -race -count=5`, all tests pass 5/5 times.
