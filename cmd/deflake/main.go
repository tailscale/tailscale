// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Command deflake runs tests repeatedly to detect flaky tests.
//
// Usage:
//
//	deflake [flags]
//
// Flags:
//
//	-count      Number of iterations per test (default 10)
//	-race       Also run tests with -race (doubles iterations)
//	-parallel   Number of packages to test in parallel (default: NumCPU)
//	-timeout    Timeout multiplier (default 5x baseline)
//	-min-timeout Minimum timeout per test (default 10s)
//	-baseline   Path to baseline.json (if empty, runs baseline first)
//	-output     Path to output CSV (default tests.csv)
//	-packages   Package pattern to test (default ./...)
package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	countFlag    = flag.Int("count", 10, "number of iterations per test")
	raceFlag     = flag.Bool("race", true, "also run tests with -race")
	parallelFlag = flag.Int("parallel", runtime.NumCPU(), "number of packages to test in parallel")
	maxBaseline  = flag.Duration("max-baseline", 60*time.Second, "max baseline time; tests exceeding this are marked as flakes")
	baselineFile   = flag.String("baseline", "", "path to baseline.json (runs baseline if empty)")
	csvFile        = flag.String("csv", "", "path to existing tests.csv to resume from")
	outputFile     = flag.String("output", "tests.csv", "path to output CSV")
	packagesFlag   = flag.String("packages", "./...", "package pattern to test")
	flakeLogFile   = flag.String("flake-log", "flakes.log", "path to flake log file")
	goToolFlag     = flag.String("go", "./tool/go", "path to go command")
)

// TestEvent represents a single JSON event from go test -json
type TestEvent struct {
	Time    time.Time `json:"Time"`
	Action  string    `json:"Action"`
	Package string    `json:"Package"`
	Test    string    `json:"Test"`
	Output  string    `json:"Output"`
	Elapsed float64   `json:"Elapsed"`
}

// TestInfo holds baseline info for a test
type TestInfo struct {
	Package     string
	Test        string
	BaselineMS  float64 // baseline time in milliseconds
	PassCount   int
	Status      string // "pending", "pass", "flake", "flake-race"
}

func main() {
	flag.Parse()

	// Clean up old test temp directories before starting
	cleanupOldTestDirs()

	// Create an isolated TMPDIR for this run so cleanup is easy
	tmpDir, err := os.MkdirTemp("", fmt.Sprintf("deflake-%d-", os.Getpid()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating temp dir: %v\n", err)
		os.Exit(1)
	}
	os.Setenv("TMPDIR", tmpDir)
	fmt.Printf("Using TMPDIR=%s\n", tmpDir)
	defer func() {
		// Clean up our temp directory on exit
		if err := os.RemoveAll(tmpDir); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to clean up %s: %v\n", tmpDir, err)
		} else {
			fmt.Printf("Cleaned up %s\n", tmpDir)
		}
	}()

	// Find go tool
	goTool := *goToolFlag
	if _, err := os.Stat(goTool); os.IsNotExist(err) {
		goTool = "go" // fallback to system go
	}

	// Phase 1: Get baseline
	var tests []*TestInfo
	var loadErr error

	if *csvFile != "" {
		fmt.Printf("Loading tests from CSV %s...\n", *csvFile)
		tests, loadErr = loadCSV(*csvFile)
	} else if *baselineFile != "" {
		fmt.Printf("Loading baseline from %s...\n", *baselineFile)
		tests, loadErr = loadBaseline(*baselineFile)
	} else {
		fmt.Println("Running baseline test suite...")
		tests, loadErr = runBaseline(goTool, *packagesFlag)
	}
	if loadErr != nil {
		fmt.Fprintf(os.Stderr, "Error getting baseline: %v\n", loadErr)
		os.Exit(1)
	}

	fmt.Printf("Found %d tests\n", len(tests))

	// Write initial CSV
	if err := writeCSV(*outputFile, tests); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing CSV: %v\n", err)
		os.Exit(1)
	}

	// Open flake log
	flakeLog, err := os.Create(*flakeLogFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating flake log: %v\n", err)
		os.Exit(1)
	}
	defer flakeLog.Close()

	// Phase 2: Run flake detection
	fmt.Printf("Running flake detection with -count=%d, -race=%v, -parallel=%d\n",
		*countFlag, *raceFlag, *parallelFlag)

	// Group tests by package for more efficient execution
	// Only include tests that are still pending
	// Skip Example tests - Go only runs them once regardless of -count flag
	// Mark tests exceeding max-baseline as flakes (too slow)
	byPackage := make(map[string][]*TestInfo)
	pendingCount := 0
	skippedExamples := 0
	tooSlow := 0
	maxBaselineMS := float64(*maxBaseline) / float64(time.Millisecond)
	for _, t := range tests {
		if strings.HasPrefix(t.Test, "Example") {
			// Example tests can't be flake-detected with -count=N
			// because Go always runs them exactly once
			t.Status = "pass"
			skippedExamples++
			continue
		}
		if t.Status == "pending" && t.BaselineMS > maxBaselineMS {
			// Test is too slow - mark as flake
			t.Status = "flake-slow"
			tooSlow++
			fmt.Fprintf(flakeLog, "\n=== FLAKE (TOO SLOW): %s:%s ===\n", t.Package, t.Test)
			fmt.Fprintf(flakeLog, "Baseline: %.2fms exceeds max-baseline: %v\n", t.BaselineMS, *maxBaseline)
			flakeLog.Sync()
			fmt.Printf("FLAKE (TOO SLOW): %s:%s - baseline %.2fs exceeds %v\n", t.Package, t.Test, t.BaselineMS/1000, *maxBaseline)
			continue
		}
		if t.Status == "pending" {
			byPackage[t.Package] = append(byPackage[t.Package], t)
			pendingCount++
		}
	}
	if skippedExamples > 0 {
		fmt.Printf("Skipped %d Example tests (Go only runs them once)\n", skippedExamples)
	}
	if tooSlow > 0 {
		fmt.Printf("Marked %d tests as flake-slow (baseline > %v)\n", tooSlow, *maxBaseline)
	}
	fmt.Printf("Running %d pending tests (skipping %d already processed)\n", pendingCount, len(tests)-pendingCount)

	// Create work queue
	type workItem struct {
		pkg   string
		tests []*TestInfo
	}
	var work []workItem
	for pkg, pkgTests := range byPackage {
		work = append(work, workItem{pkg: pkg, tests: pkgTests})
	}
	// Sort for deterministic ordering
	sort.Slice(work, func(i, j int) bool {
		return work[i].pkg < work[j].pkg
	})

	// Process packages in parallel
	var wg sync.WaitGroup
	workChan := make(chan workItem)
	var mu sync.Mutex
	completed := 0
	total := pendingCount

	// Progress reporter
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			mu.Lock()
			c := completed
			mu.Unlock()
			if c >= total {
				return
			}
			fmt.Printf("Progress: %d/%d tests completed\n", c, total)
		}
	}()

	for i := 0; i < *parallelFlag; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range workChan {
				runPackageTests(goTool, item.pkg, item.tests, flakeLog, &mu)
				mu.Lock()
				completed += len(item.tests)
				// Update CSV after each package
				if err := writeCSV(*outputFile, tests); err != nil {
					fmt.Fprintf(os.Stderr, "Error updating CSV: %v\n", err)
				}
				mu.Unlock()
			}
		}()
	}

	for _, item := range work {
		workChan <- item
	}
	close(workChan)
	wg.Wait()

	// Final CSV write
	if err := writeCSV(*outputFile, tests); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing final CSV: %v\n", err)
		os.Exit(1)
	}

	// Summary
	var passed, flaked, flakedRace, flakedSlow int
	for _, t := range tests {
		switch t.Status {
		case "pass":
			passed++
		case "flake":
			flaked++
		case "flake-race":
			flakedRace++
		case "flake-slow":
			flakedSlow++
		}
	}

	fmt.Printf("\n=== Summary ===\n")
	fmt.Printf("Total tests: %d\n", len(tests))
	fmt.Printf("Passed:      %d\n", passed)
	fmt.Printf("Flaky:       %d\n", flaked)
	fmt.Printf("Flaky-race:  %d\n", flakedRace)
	fmt.Printf("Flaky-slow:  %d\n", flakedSlow)
	fmt.Printf("Results written to %s\n", *outputFile)
	if flaked+flakedRace+flakedSlow > 0 {
		fmt.Printf("Flake details in %s\n", *flakeLogFile)
	}
}

func runBaseline(goTool, packages string) ([]*TestInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, goTool, "test", "-v", "-p", "1", "-json", packages)
	cmd.Env = append(os.Environ(), "SSH_CLIENT=") // prevent SSH detection flake

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("creating stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting test: %w", err)
	}

	// Parse JSON output
	tests := make(map[string]*TestInfo) // key: "package:test"
	scanner := bufio.NewScanner(stdout)
	// Increase buffer size for long lines
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 10*1024*1024)

	for scanner.Scan() {
		var event TestEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue // skip malformed lines
		}

		// Only track top-level test pass/fail events with timing
		if event.Test == "" || strings.Contains(event.Test, "/") {
			continue // skip package-level events and subtests
		}

		key := event.Package + ":" + event.Test
		if event.Action == "pass" || event.Action == "fail" {
			if _, exists := tests[key]; !exists {
				tests[key] = &TestInfo{
					Package:    event.Package,
					Test:       event.Test,
					BaselineMS: event.Elapsed * 1000, // convert to ms
					Status:     "pending",
				}
			} else {
				// Update timing if we see it again
				tests[key].BaselineMS = event.Elapsed * 1000
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning output: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		// Don't fail on test failures - we still want the timing data
		fmt.Printf("Warning: baseline had failures: %v\n", err)
	}

	// Convert map to slice
	result := make([]*TestInfo, 0, len(tests))
	for _, t := range tests {
		result = append(result, t)
	}

	// Sort by package then test name
	sort.Slice(result, func(i, j int) bool {
		if result[i].Package != result[j].Package {
			return result[i].Package < result[j].Package
		}
		return result[i].Test < result[j].Test
	})

	// Save baseline for future use
	baselineData, _ := json.MarshalIndent(result, "", "  ")
	os.WriteFile("baseline.json", baselineData, 0644)

	return result, nil
}

func loadBaseline(path string) ([]*TestInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var tests []*TestInfo
	if err := json.Unmarshal(data, &tests); err != nil {
		return nil, err
	}

	return tests, nil
}

func loadCSV(path string) ([]*TestInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	records, err := r.ReadAll()
	if err != nil {
		return nil, err
	}

	var tests []*TestInfo
	for i, record := range records {
		if i == 0 {
			continue // skip header
		}
		if len(record) < 5 {
			continue
		}

		baselineS, _ := strconv.ParseFloat(record[2], 64)
		passCount, _ := strconv.Atoi(record[3])

		tests = append(tests, &TestInfo{
			Package:    record[0],
			Test:       record[1],
			BaselineMS: baselineS, // CSV already has ms
			PassCount:  passCount,
			Status:     record[4],
		})
	}

	return tests, nil
}

func runPackageTests(goTool, pkg string, tests []*TestInfo, flakeLog *os.File, mu *sync.Mutex) {
	for _, t := range tests {
		runSingleTest(goTool, t, false, flakeLog, mu) // non-race first
		if t.Status == "pending" && *raceFlag {
			runSingleTest(goTool, t, true, flakeLog, mu) // race if non-race passed
		}
		if t.Status == "pending" {
			t.Status = "pass"
		}
	}
}

// testTimeout calculates the timeout for running a test with the given parameters.
// Returns the expected max duration for the test to complete.
func testTimeout(t *TestInfo, race bool) time.Duration {
	// Calculate timeout: max(5s, N * 1.5 * baseline, 5 * baseline)
	// Most iterations should complete near baseline; allow some slack for outliers.
	baselineSeconds := t.BaselineMS / 1000
	countBaseline := float64(*countFlag) * 1.5 * baselineSeconds
	singleBaseline := 5 * baselineSeconds
	timeout := max(5.0, countBaseline, singleBaseline)
	dur := time.Duration(timeout) * time.Second
	// Race mode needs extra time for compilation
	if race {
		dur += 30 * time.Second
	}
	return dur
}

func runSingleTest(goTool string, t *TestInfo, race bool, flakeLog *os.File, mu *sync.Mutex) {
	timeoutDur := testTimeout(t, race)
	// Add buffer for go test's own overhead; set go test -timeout slightly higher
	// than our context timeout so our context fires first with a cleaner error
	goTestTimeout := timeoutDur + 1*time.Minute
	ctxTimeout := timeoutDur + 30*time.Second

	// Build command
	args := []string{"test", "-v", "-count", strconv.Itoa(*countFlag),
		"-timeout", goTestTimeout.String(),
		"-run", fmt.Sprintf("^%s$", t.Test),
		t.Package}
	if race {
		args = []string{"test", "-v", "-race", "-count", strconv.Itoa(*countFlag),
			"-timeout", goTestTimeout.String(),
			"-run", fmt.Sprintf("^%s$", t.Test),
			t.Package}
	}

	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, goTool, args...)
	cmd.Env = append(os.Environ(), "SSH_CLIENT=")

	output, err := cmd.CombinedOutput()

	// Count passes for the top-level test only (not subtests)
	// Look for "--- PASS: TestName (" pattern (space before paren distinguishes from subtests)
	passPattern := fmt.Sprintf("--- PASS: %s (", t.Test)
	passCount := strings.Count(string(output), passPattern)

	mu.Lock()
	defer mu.Unlock()

	if race {
		t.PassCount += passCount
	} else {
		t.PassCount = passCount
	}

	if err != nil || passCount < *countFlag {
		// Test flaked
		if race {
			t.Status = "flake-race"
		} else {
			t.Status = "flake"
		}

		// Log flake details
		fmt.Fprintf(flakeLog, "\n=== FLAKE: %s:%s (race=%v) ===\n", t.Package, t.Test, race)
		fmt.Fprintf(flakeLog, "Timeout: %v, Passed: %d/%d\n", timeoutDur, passCount, *countFlag)
		fmt.Fprintf(flakeLog, "Output:\n%s\n", string(output))
		flakeLog.Sync()

		fmt.Printf("FLAKE: %s:%s (race=%v) - %d/%d passed\n", t.Package, t.Test, race, passCount, *countFlag)
	}
}

func writeCSV(path string, tests []*TestInfo) error {
	// Write to temp file first, then rename for atomicity
	tmpPath := path + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return err
	}

	w := csv.NewWriter(f)
	w.Write([]string{"package", "test", "baseline_ms", "pass_count", "status"})

	for _, t := range tests {
		w.Write([]string{
			t.Package,
			t.Test,
			fmt.Sprintf("%.2f", t.BaselineMS),
			strconv.Itoa(t.PassCount),
			t.Status,
		})
	}

	w.Flush()
	if err := w.Error(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return err
	}

	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}

	return os.Rename(tmpPath, path)
}

// cleanupOldTestDirs removes old Go test temp directories from /tmp.
// These directories are created by t.TempDir() and start with "Test".
// Over time, especially when tests timeout or crash, these can accumulate
// and exhaust /tmp space.
func cleanupOldTestDirs() {
	tmpDir := os.TempDir()
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		return // silently ignore if we can't read /tmp
	}

	var cleaned int64
	var count int
	cutoff := time.Now().Add(-1 * time.Hour) // remove dirs older than 1 hour

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Go test temp dirs start with "Test" followed by test name
		if !strings.HasPrefix(name, "Test") {
			continue
		}

		path := filepath.Join(tmpDir, name)
		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Only remove old directories
		if info.ModTime().After(cutoff) {
			continue
		}

		// Get size before removing
		size := getDirSize(path)

		if err := os.RemoveAll(path); err == nil {
			cleaned += size
			count++
		}
	}

	if count > 0 {
		fmt.Printf("Cleaned up %d old test directories (%.1f MB freed)\n", count, float64(cleaned)/(1024*1024))
	}
}

// getDirSize returns the total size of a directory in bytes
func getDirSize(path string) int64 {
	var size int64
	filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size
}

func init() {
	// Ensure we're in the right directory
	if _, err := os.Stat("go.mod"); os.IsNotExist(err) {
		// Try to find repo root
		dir, _ := os.Getwd()
		for {
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				os.Chdir(dir)
				break
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
}
