// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package sizetest_test measures how much an additional eventbus flow
// (one event type with a publisher and a subscriber) contributes to
// compiled binary size.
//
// Background: in Go, every distinct event type T passed through
// eventbus.Publish[T] / Subscribe[T] / SubscribeFunc[T] causes the
// compiler to emit fresh GC-shape stencils of the generic method
// bodies (Publisher[T].Publish, Subscriber[T].dispatch,
// SubscriberFunc[T].dispatch, ...) plus per-T reflection metadata
// from reflect.TypeFor[T](). For typical event structs with distinct
// shapes this is a few KB per flow. See util/eventbus/doc.go and the
// surrounding implementation.
//
// Methodology: we build two programs, a small "baseline" with just
// enough flows to amortize one-time setup costs (bus init, reflect
// pull-in, etc.) and a larger "treatment" with many additional
// distinct flows. The size delta divided by the added flow count
// gives a stable per-flow byte cost.
//
// We deliberately use a large flow delta (see addedFlows) so the
// total byte difference is well above the linker's page-quantization
// floor on any platform. That way even small per-flow improvements
// (a few hundred bytes) produce a clearly measurable change in the
// total delta.
//
// We measure on two architectures: the host arch (whatever Go reports
// as runtime.GOARCH) and linux/arm64 via cross-compilation. arm64 is
// the architecture where binary-size constraint actually bites for
// this codebase (iOS, Android, Apple Silicon), so reporting it
// alongside the host arch makes regressions on the constrained
// platform visible during normal CI.
//
// Uses:
//
//  1. As an artifact: print the per-flow numbers, do an optimization,
//     re-run, and quote the improvement.
//  2. As a regression gate: set EVENTBUS_SIZETEST_MAX_BYTES_PER_FLOW
//     in CI to fail when per-flow cost exceeds a known-good threshold
//     on the host arch. (Cross-arch gating could be added later if
//     needed; for now the host-arch gate prevents most regressions.)
//
// Note that absolute byte counts are NOT portable across Go versions,
// GOOS, or GOARCH. Any threshold needs to be paired with a known
// build matrix; we deliberately do not bake one in.
package sizetest_test

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"tailscale.com/util/sizetest"
	"tailscale.com/util/sizetest/symcost"
)

const (
	// baselineFlows is the number of flows in the baseline program.
	// It needs to be >0 so one-time costs (the eventbus package's
	// non-generic code, reflect, runtime support for generics, etc.)
	// are present in both variants and cancel out in the delta.
	// A handful is plenty.
	baselineFlows = 4

	// addedFlows is the number of additional distinct flows the
	// treatment has. We use a large value so the total byte delta
	// is well above the linker's page-quantization floor (~4 KB on
	// most platforms) and so even small per-flow improvements
	// produce a clearly visible swing in the total delta. The
	// per-flow average is then rock-stable (~2% spread vs. much
	// smaller N).
	//
	// 500 was chosen as the best signal-to-cost point after
	// sweeping 30..5000:
	//
	//   addedFlows  per-flow   wall    RSS
	//          100   3154 B   1.0s   176 MB
	//          500   3097 B   2.3s   310 MB
	//         1000   3101 B   3.1s   550 MB
	//         5000   3114 B  13.0s  2560 MB
	//
	// The per-flow number is already stable by ~100 flows; going
	// higher mostly buys memory and wall-time pain without
	// improving sensitivity.
	addedFlows = 500
)

// archMeasurement is the per-flow cost result for one (GOOS, GOARCH)
// pair, with optional per-receiver attribution from symcost.
type archMeasurement struct {
	goos, goarch string
	baseline     int64
	treatment    int64
	delta        int64
	perFlow      float64

	// symcostFor maps a receiver name (e.g.
	// "tailscale.com/util/eventbus.Publisher") to the bytes
	// attributed to it on the treatment binary. Populated by
	// runSymcost when symbol-table-bearing builds are available;
	// nil otherwise.
	symcostFor map[string]int64
}

func TestPerFlowBinaryCost(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: invokes `go build` multiple times")
	}

	// Always measure on the host arch (this is what the gate
	// applies to and what existing CI users expect).
	host := measureOnArch(t, "", "")
	logArchMeasurement(t, host)

	// Also measure on linux/arm64 via cross-compilation. We don't
	// run the binaries; we only stat them and (for symcost-mode)
	// parse their ELF. Cross-compilation is fast and works on any
	// host; if it ever fails we report a t.Logf and continue
	// rather than failing the test, since the host-arch number
	// is the gating signal.
	if runtime.GOOS != "linux" || runtime.GOARCH != "arm64" {
		arm := measureOnArchOrSkip(t, "linux", "arm64")
		if arm != nil {
			logArchMeasurement(t, *arm)
		}
	}

	if host.delta <= 0 {
		// A non-positive delta means either the linker
		// dead-stripped our flows (the program isn't exercising
		// them enough) or something pathological happened. Fail
		// loudly so we don't silently report a meaningless number.
		t.Fatalf("expected positive delta with %d added flows; got %d. The variants "+
			"likely aren't keeping the generic instantiations alive end-to-end.",
			addedFlows, host.delta)
	}

	if maxStr := os.Getenv("EVENTBUS_SIZETEST_MAX_BYTES_PER_FLOW"); maxStr != "" {
		max, err := strconv.ParseInt(maxStr, 10, 64)
		if err != nil {
			t.Fatalf("EVENTBUS_SIZETEST_MAX_BYTES_PER_FLOW=%q: %v", maxStr, err)
		}
		// Compare against the integer per-flow cost (rounded up) so a
		// gate like "fail if any flow costs more than 4096 bytes" is
		// expressed naturally. The gate applies to the host arch
		// only; cross-arch numbers are reported but not gated.
		perFlowInt := (host.delta + int64(addedFlows) - 1) / int64(addedFlows)
		if perFlowInt > max {
			t.Errorf("host-arch per-flow cost %d bytes exceeds gate of %d bytes "+
				"(EVENTBUS_SIZETEST_MAX_BYTES_PER_FLOW)", perFlowInt, max)
		}
	}
}

// measureOnArch builds the baseline and treatment programs for the
// given (GOOS, GOARCH) — empty strings mean the host's defaults —
// and returns the resulting per-flow numbers. It also builds an
// unstripped treatment binary (symbols preserved) and runs symcost
// against it to get per-receiver attribution; the symcost step is
// best-effort and silently skipped on architectures we can't analyze.
func measureOnArch(t *testing.T, goos, goarch string) archMeasurement {
	t.Helper()

	stripped := sizetest.BuildOptions{
		LDFlags:  "-s -w",
		Trimpath: ptr(true),
		GOOS:     goos,
		GOARCH:   goarch,
	}
	unstripped := sizetest.BuildOptions{
		LDFlags:  " ", // explicit non-empty to override default of "-s -w"
		Trimpath: ptr(true),
		GOOS:     goos,
		GOARCH:   goarch,
	}

	baseline := sizetest.Variant{
		Name:   fmt.Sprintf("flows-%d-%s", baselineFlows, archTag(goos, goarch)),
		Source: programWithFlows(baselineFlows),
	}
	treatment := sizetest.Variant{
		Name:   fmt.Sprintf("flows-%d-%s", baselineFlows+addedFlows, archTag(goos, goarch)),
		Source: programWithFlows(baselineFlows + addedFlows),
	}

	// Stripped builds give the headline size delta with minimal
	// noise.
	baseRes, treatRes, totalDelta := sizetest.DiffWithOptions(t, baseline, treatment, stripped)

	m := archMeasurement{
		goos:      effective(goos, runtime.GOOS),
		goarch:    effective(goarch, runtime.GOARCH),
		baseline:  baseRes.Bytes,
		treatment: treatRes.Bytes,
		delta:     totalDelta,
		perFlow:   float64(totalDelta) / float64(addedFlows),
	}

	// Unstripped treatment build for symcost attribution.
	treatmentUnstripped := sizetest.Variant{
		Name:   treatment.Name + "-symbols",
		Source: treatment.Source,
	}
	unstrippedRes := sizetest.BuildWithOptions(t, treatmentUnstripped, unstripped)
	m.symcostFor = runSymcost(t, unstrippedRes.BinaryPath)

	return m
}

// measureOnArchOrSkip is like measureOnArch but converts cross-build
// failures to a t.Logf + nil result rather than failing the test. We
// don't want a flaky cross-arch toolchain to fail the CI run; the
// host-arch number is the gate.
func measureOnArchOrSkip(t *testing.T, goos, goarch string) *archMeasurement {
	t.Helper()
	// We can't easily catch a t.Fatal from sizetest, so we
	// pre-flight by trying a no-op cross-build. If that succeeds,
	// run the real measurement.
	if !canCrossBuild(t, goos, goarch) {
		t.Logf("skipping %s/%s measurement: cross-compile not available", goos, goarch)
		return nil
	}
	m := measureOnArch(t, goos, goarch)
	return &m
}

// canCrossBuild reports whether `go build` can target (goos, goarch)
// in this environment. We probe by running a trivial cross-compile;
// if the toolchain doesn't support the target, the probe fails fast.
//
// We probe with a direct `go build` rather than going through
// sizetest because sizetest is t.Fatal-on-failure and we want to
// silently fall back when cross-compilation isn't available.
func canCrossBuild(t *testing.T, goos, goarch string) bool {
	t.Helper()
	dir := t.TempDir()
	const src = "package main\nfunc main() {}\n"
	if err := os.WriteFile(dir+"/main.go", []byte(src), 0o644); err != nil {
		return false
	}
	if err := os.WriteFile(dir+"/go.mod", []byte("module probe\n\ngo 1.21\n"), 0o644); err != nil {
		return false
	}
	cmd := exec.Command("go", "build", "-o", dir+"/out", ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch)
	return cmd.Run() == nil
}

// runSymcost opens binPath with symcost and returns the per-receiver
// attribution for the eventbus types we care about. Returns nil if
// the binary can't be opened (e.g. unsupported architecture for
// symcost.Open's parser).
func runSymcost(t *testing.T, binPath string) map[string]int64 {
	t.Helper()
	b, err := symcost.Open(binPath)
	if err != nil {
		t.Logf("symcost.Open(%s): %v", binPath, err)
		return nil
	}
	defer b.Close()
	out := map[string]int64{}
	for _, recv := range []string{
		"tailscale.com/util/eventbus.Publisher",
		"tailscale.com/util/eventbus.SubscriberFunc",
	} {
		c := b.CostByReceiver(recv)
		out[recv] = c.Total
	}
	return out
}

// logArchMeasurement prints a human-readable per-arch summary block.
func logArchMeasurement(t *testing.T, m archMeasurement) {
	t.Helper()
	t.Logf("eventbus per-flow binary cost on %s/%s:", m.goos, m.goarch)
	t.Logf("  baseline:  %d flows -> %d bytes", baselineFlows, m.baseline)
	t.Logf("  treatment: %d flows -> %d bytes", baselineFlows+addedFlows, m.treatment)
	t.Logf("  total delta over %d added flows: %+d bytes", addedFlows, m.delta)
	t.Logf("  average per-flow cost: %.1f bytes", m.perFlow)
	if len(m.symcostFor) > 0 {
		t.Logf("  symcost attribution on treatment binary:")
		// Sort by total descending for stable, easy-to-read output.
		names := make([]string, 0, len(m.symcostFor))
		for k := range m.symcostFor {
			names = append(names, k)
		}
		sortByMapValueDesc(names, m.symcostFor)
		for _, name := range names {
			v := m.symcostFor[name]
			perFlow := float64(v) / float64(baselineFlows+addedFlows)
			t.Logf("    %-50s %8d bytes  (%5.1f B/flow)", name, v, perFlow)
		}
	}
}

// programWithFlows returns the source of a package main program that
// creates n distinct event types and wires each one through a
// publisher and a SubscribeFunc subscriber. It also actually publishes
// events on each, to defeat any dead-code elimination the linker
// might attempt.
//
// The event types are made structurally distinct (different field
// counts and types) so the Go compiler treats them as distinct GC
// shapes and emits separate stencils per flow, which is the realistic
// scenario we want to measure.
func programWithFlows(n int) string {
	var b strings.Builder
	b.WriteString(`// Code generated by util/eventbus/sizetest; DO NOT EDIT.
package main

import (
	"tailscale.com/util/eventbus"
)

`)

	// Distinct event types.
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "type Event%d struct {\n", i)
		// Vary the field shape so each type has a distinct GC shape.
		// We mix pointer and non-pointer fields and vary count.
		fields := (i % 4) + 1
		for f := 0; f < fields; f++ {
			switch (i + f) % 4 {
			case 0:
				fmt.Fprintf(&b, "\tF%d int64\n", f)
			case 1:
				fmt.Fprintf(&b, "\tF%d string\n", f)
			case 2:
				fmt.Fprintf(&b, "\tF%d *int\n", f)
			case 3:
				fmt.Fprintf(&b, "\tF%d []byte\n", f)
			}
		}
		b.WriteString("}\n\n")
	}

	b.WriteString(`func main() {
	bus := eventbus.New()
	defer bus.Close()
	pcli := bus.Client("pub")
	scli := bus.Client("sub")

`)

	// Per-flow wiring.
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "\tp%d := eventbus.Publish[Event%d](pcli)\n", i, i)
		fmt.Fprintf(&b, "\teventbus.SubscribeFunc(scli, func(Event%d) {})\n", i)
		fmt.Fprintf(&b, "\tp%d.Publish(Event%d{})\n", i, i)
	}

	b.WriteString("}\n")
	return b.String()
}

// archTag returns a filesystem-safe identifier for the (goos, goarch)
// pair. Empty strings (host defaults) become "host".
func archTag(goos, goarch string) string {
	if goos == "" && goarch == "" {
		return "host"
	}
	return effective(goos, "") + "-" + effective(goarch, "")
}

func effective(override, fallback string) string {
	if override != "" {
		return override
	}
	return fallback
}

func ptr[T any](v T) *T { return &v }

// sortByMapValueDesc sorts keys in place by descending value in m.
// Stable for ties; insertion sort, fine for the few-element case.
func sortByMapValueDesc(keys []string, m map[string]int64) {
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && m[keys[j-1]] < m[keys[j]]; j-- {
			keys[j-1], keys[j] = keys[j], keys[j-1]
		}
	}
}
