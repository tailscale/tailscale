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
// Uses:
//
//  1. As an artifact: print the per-flow number, do an optimization,
//     re-run, and quote the improvement.
//  2. As a regression gate: set EVENTBUS_SIZETEST_MAX_BYTES_PER_FLOW
//     in CI to fail when per-flow cost exceeds a known-good threshold.
//
// Note that absolute byte counts are NOT portable across Go versions,
// GOOS, or GOARCH. Any threshold needs to be paired with a known
// build matrix; we deliberately do not bake one in.
package sizetest_test

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"tailscale.com/util/sizetest"
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

func TestPerFlowBinaryCost(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: invokes `go build` twice")
	}

	baseline := sizetest.Variant{
		Name:   fmt.Sprintf("flows-%d", baselineFlows),
		Source: programWithFlows(baselineFlows),
	}
	treatment := sizetest.Variant{
		Name:   fmt.Sprintf("flows-%d", baselineFlows+addedFlows),
		Source: programWithFlows(baselineFlows + addedFlows),
	}

	baseRes, treatRes, totalDelta := sizetest.Diff(t, baseline, treatment)

	perFlow := float64(totalDelta) / float64(addedFlows)

	t.Logf("eventbus per-flow binary cost measurement:")
	t.Logf("  baseline:  %d flows -> %d bytes", baselineFlows, baseRes.Bytes)
	t.Logf("  treatment: %d flows -> %d bytes", baselineFlows+addedFlows, treatRes.Bytes)
	t.Logf("  total delta over %d added flows: %+d bytes", addedFlows, totalDelta)
	t.Logf("  average per-flow cost: %.1f bytes", perFlow)

	if totalDelta <= 0 {
		// A non-positive delta means either the linker dead-stripped
		// our flows (the program isn't exercising them enough) or
		// something pathological happened. Fail loudly so we don't
		// silently report a meaningless number.
		t.Fatalf("expected positive delta with %d added flows; got %d. The variants "+
			"likely aren't keeping the generic instantiations alive end-to-end.",
			addedFlows, totalDelta)
	}

	if maxStr := os.Getenv("EVENTBUS_SIZETEST_MAX_BYTES_PER_FLOW"); maxStr != "" {
		max, err := strconv.ParseInt(maxStr, 10, 64)
		if err != nil {
			t.Fatalf("EVENTBUS_SIZETEST_MAX_BYTES_PER_FLOW=%q: %v", maxStr, err)
		}
		// Compare against the integer per-flow cost (rounded up) so a
		// gate like "fail if any flow costs more than 4096 bytes" is
		// expressed naturally.
		perFlowInt := (totalDelta + int64(addedFlows) - 1) / int64(addedFlows)
		if perFlowInt > max {
			t.Errorf("average per-flow cost %d bytes exceeds gate of %d bytes "+
				"(EVENTBUS_SIZETEST_MAX_BYTES_PER_FLOW)", perFlowInt, max)
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
