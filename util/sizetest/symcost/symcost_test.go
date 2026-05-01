// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package symcost

import (
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", ""},
		{"plain.symbol", "plain.symbol"},
		{
			"tailscale.com/util/eventbus.(*Publisher[main.Event0]).Close",
			"tailscale.com/util/eventbus.(*Publisher[…]).Close",
		},
		{
			"tailscale.com/util/eventbus.(*Publisher[go.shape.struct { F0 int64 }]).Publish",
			"tailscale.com/util/eventbus.(*Publisher[…]).Publish",
		},
		{
			"go:itab.*tailscale.com/util/eventbus.Publisher[main.Event0],tailscale.com/util/eventbus.publisher",
			"go:itab.*tailscale.com/util/eventbus.Publisher[…],tailscale.com/util/eventbus.publisher",
		},
		{
			// Nested brackets inside the type arg should not unbalance
			// the depth counter.
			"pkg.Foo[go.shape.[]int].Bar",
			"pkg.Foo[…].Bar",
		},
		{
			// Multiple top-level type-arg lists (e.g. on chained
			// methods) should each collapse independently.
			"pkg.Foo[A].Bar[B]",
			"pkg.Foo[…].Bar[…]",
		},
	}
	for _, tt := range tests {
		got := normalize(tt.in)
		if got != tt.want {
			t.Errorf("normalize(%q):\n got: %q\nwant: %q", tt.in, got, tt.want)
		}
	}
}

func TestPackageOf(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"runtime.gcWork", "runtime"},
		{"tailscale.com/util/eventbus.(*Publisher[…]).Close", "tailscale.com/util/eventbus"},
		{"tailscale.com/util/eventbus.(*Publisher[…]).Publish", "tailscale.com/util/eventbus"},
		{
			"go:itab.*tailscale.com/util/eventbus.Publisher[…],tailscale.com/util/eventbus.publisher",
			"tailscale.com/util/eventbus",
		},
		// Linker-internal pools like "$f32.<hex>" don't have a real
		// package; we report the leading prefix verbatim, which is
		// fine for grouping purposes.
		{"$f32.358637bd", "$f32"},
	}
	for _, tt := range tests {
		got := packageOf(tt.in)
		if got != tt.want {
			t.Errorf("packageOf(%q): got %q, want %q", tt.in, got, tt.want)
		}
	}
}

const sampleNM = `  6360e0        357 T tailscale.com/util/eventbus.(*Publisher[go.shape.struct { F0 int64 }]).Publish
  636260         92 T tailscale.com/util/eventbus.(*Publisher[go.shape.struct { F0 int64 }]).Close
  6385e0         50 T tailscale.com/util/eventbus.(*Publisher[main.Event0]).Close
  6385f0         50 T tailscale.com/util/eventbus.(*Publisher[main.Event1]).Close
  6385f4         50 T tailscale.com/util/eventbus.(*Publisher[main.Event2]).Close
  614cc0        369 T tailscale.com/util/eventbus.(*Bus).Close
`

func TestAnalyzeNMOutput(t *testing.T) {
	groups, err := AnalyzeNMOutput(strings.NewReader(sampleNM))
	if err != nil {
		t.Fatal(err)
	}

	byTpl := make(map[string]Group)
	for _, g := range groups {
		byTpl[g.Template] = g
	}

	// (*Publisher[…]).Close should aggregate 4 members (1 stencil + 3 wrappers).
	closeGrp, ok := byTpl["tailscale.com/util/eventbus.(*Publisher[…]).Close"]
	if !ok {
		t.Fatalf("missing Publisher[…].Close group; got templates: %v", templateNames(groups))
	}
	if got, want := closeGrp.Count(), 4; got != want {
		t.Errorf("Publisher[…].Close count: got %d, want %d", got, want)
	}
	if got, want := closeGrp.Total, int64(92+50+50+50); got != want {
		t.Errorf("Publisher[…].Close total: got %d, want %d", got, want)
	}
	if got, want := closeGrp.Max, int64(92); got != want {
		t.Errorf("Publisher[…].Close max: got %d, want %d", got, want)
	}
	if got, want := closeGrp.Min, int64(50); got != want {
		t.Errorf("Publisher[…].Close min: got %d, want %d", got, want)
	}
	if !closeGrp.IsGeneric() {
		t.Error("Publisher[…].Close should be flagged as generic")
	}
	if got, want := closeGrp.Package, "tailscale.com/util/eventbus"; got != want {
		t.Errorf("Publisher[…].Close package: got %q, want %q", got, want)
	}

	// (*Bus).Close is a single non-generic symbol.
	busGrp, ok := byTpl["tailscale.com/util/eventbus.(*Bus).Close"]
	if !ok {
		t.Fatal("missing Bus.Close group")
	}
	if busGrp.Count() != 1 {
		t.Errorf("Bus.Close count: got %d, want 1", busGrp.Count())
	}
	if busGrp.IsGeneric() {
		t.Error("Bus.Close should not be flagged as generic")
	}

	// Sort order: total descending. Publisher[…].Publish (357) is
	// alone in its template, vs Publisher[…].Close (242 across 4)
	// and Bus.Close (369).
	if groups[0].Total < groups[1].Total {
		t.Errorf("groups not sorted by Total descending: %d < %d",
			groups[0].Total, groups[1].Total)
	}
}

func TestFilter(t *testing.T) {
	groups, err := AnalyzeNMOutput(strings.NewReader(sampleNM))
	if err != nil {
		t.Fatal(err)
	}
	gen := Filter{GenericOnly: true}.Apply(groups)
	for _, g := range gen {
		if !g.IsGeneric() {
			t.Errorf("GenericOnly retained non-generic %q", g.Template)
		}
	}
	pkg := Filter{PackageSubstr: "eventbus"}.Apply(groups)
	for _, g := range pkg {
		if !strings.Contains(g.Package, "eventbus") {
			t.Errorf("PackageSubstr retained %q (pkg %q)", g.Template, g.Package)
		}
	}
	min := Filter{MinCount: 2}.Apply(groups)
	for _, g := range min {
		if g.Count() < 2 {
			t.Errorf("MinCount=2 retained %q (count %d)", g.Template, g.Count())
		}
	}
}

func templateNames(gs []Group) []string {
	out := make([]string, len(gs))
	for i, g := range gs {
		out[i] = g.Template
	}
	return out
}
