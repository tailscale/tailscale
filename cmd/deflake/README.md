# deflake

A tool for detecting flaky tests by running them repeatedly.

## Usage

```bash
# Run from repo root
go build ./cmd/deflake && ./deflake [flags]
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-count` | 10 | Number of iterations per test |
| `-race` | true | Also run tests with `-race` (doubles iterations) |
| `-parallel` | NumCPU | Number of packages to test in parallel |
| `-timeout` | 5 | Timeout multiplier over baseline time |
| `-min-timeout` | 30s | Minimum timeout per test |
| `-baseline` | "" | Path to baseline.json (runs baseline if empty) |
| `-csv` | "" | Path to existing tests.csv to resume from |
| `-output` | tests.csv | Path to output CSV |
| `-packages` | ./... | Package pattern to test |
| `-flake-log` | flakes.log | Path to detailed flake output |
| `-go` | ./tool/go | Path to go command |

## Examples

### Full run from scratch

```bash
./deflake
```

This will:
1. Run the full test suite once to get baseline timing
2. Run each test 10x without race detection
3. Run each test 10x with race detection
4. Output results to `tests.csv` and `flakes.log`

### Resume from existing baseline

```bash
./deflake -csv tests.csv
```

Useful if a previous run was interrupted. Only tests with status "pending" will be run.

### Higher confidence run

```bash
./deflake -count=100 -csv tests.csv
```

Run 100 iterations per test instead of 10.

### Skip race detection

```bash
./deflake -race=false
```

Only run tests without the race detector (faster, but misses race-only flakes).

### Test specific packages

```bash
./deflake -packages=./tsnet/...
```

## Output

### tests.csv

CSV with columns:
- `package`: Full package path
- `test`: Test function name
- `baseline_ms`: Baseline execution time in milliseconds
- `pass_count`: Number of successful iterations (0-20 with default settings)
- `status`: One of:
  - `pending`: Not yet tested
  - `pass`: All iterations passed
  - `flake`: Failed without race detection
  - `flake-race`: Passed without race, failed with race

### flakes.log

Detailed output for each flaky test, including:
- Test name and package
- Timeout used
- Pass count
- Full test output

## Integration with flakytest

Tests that flake should be marked using the `flakytest` package:

```go
import "tailscale.com/cmd/testwrapper/flakytest"

func TestSomething(t *testing.T) {
    flakytest.Mark(t, "https://github.com/tailscale/tailscale/issues/XXXXX")
    // ... test code
}
```

This allows `cmd/testwrapper` to automatically retry flaky tests in CI.
