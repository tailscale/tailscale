// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"net/netip"
	"strings"
	"testing"

	"tailscale.com/tailcfg"
)

func TestRenderBlueprintConfig_NilCfg(t *testing.T) {
	var sb strings.Builder
	renderBlueprintConfig(&sb, "github-connector", nil)
	got := sb.String()
	want := "Blueprint:  bp:github-connector\n  (projection not yet received)\n"
	if got != want {
		t.Errorf("got:\n%q\nwant:\n%q", got, want)
	}
}

func TestRenderBlueprintConfig_AllBuckets(t *testing.T) {
	cfg := &tailcfg.BlueprintConfig{
		Tags:          []string{"tag:bp//github-connector", "tag:prod"},
		Routes:        []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("10.0.1.0/24")},
		ServeApps:     []string{"app:github"},
		ServeServices: []string{"svc:webhook"},
		ServeIPSets:   []string{"ipset:corp-internal"},
		Attrs:         []string{"nodeAttr:funnel"},
		Prefs:         []string{"pref:ssh", "pref:accept-routes"},
	}
	var sb strings.Builder
	renderBlueprintConfig(&sb, "github-connector", cfg)
	got := sb.String()
	want := "Blueprint:  bp:github-connector\n" +
		"  Tags:      tag:bp//github-connector, tag:prod\n" +
		"  Routes:    10.0.0.0/24, 10.0.1.0/24\n" +
		"  Apps:      app:github\n" +
		"  Services:  svc:webhook\n" +
		"  IPSets:    ipset:corp-internal\n" +
		"  Attrs:     nodeAttr:funnel\n" +
		"  Prefs:     pref:ssh, pref:accept-routes\n"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRenderBlueprintConfig_EmptyBucketsOmitted(t *testing.T) {
	cfg := &tailcfg.BlueprintConfig{
		Tags: []string{"tag:bp//foo"},
	}
	var sb strings.Builder
	renderBlueprintConfig(&sb, "foo", cfg)
	got := sb.String()
	want := "Blueprint:  bp:foo\n  Tags:      tag:bp//foo\n"
	if got != want {
		t.Errorf("got:\n%q\nwant:\n%q", got, want)
	}
}

func TestRenderBlueprintConfig_AllEmptyBuckets(t *testing.T) {
	cfg := &tailcfg.BlueprintConfig{}
	var sb strings.Builder
	renderBlueprintConfig(&sb, "foo", cfg)
	got := sb.String()
	want := "Blueprint:  bp:foo\n"
	if got != want {
		t.Errorf("got:\n%q\nwant:\n%q", got, want)
	}
}
