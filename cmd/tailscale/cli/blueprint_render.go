// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"fmt"
	"io"
	"net/netip"
	"strings"

	"tailscale.com/tailcfg"
)

// renderBlueprintConfig writes a human-readable description of cfg to
// w. The output is shared by `tailscale join`, `tailscale leave`, and
// `tailscale join status`; the shape is intentionally identical across
// the three so operators learn one layout. Empty buckets are omitted
// entirely (no "Apps: (none)" lines).
//
// cfg may be nil. A nil cfg indicates the local node is blueprint-bound
// (the caller has a known id) but the projection has not yet arrived
// via map poll; the renderer prints a single explanatory line in that
// case.
func renderBlueprintConfig(w io.Writer, id string, cfg *tailcfg.BlueprintConfig) {
	fmt.Fprintf(w, "Blueprint:  bp:%s\n", id)
	if cfg == nil {
		fmt.Fprintln(w, "  (projection not yet received)")
		return
	}
	writeBucket(w, "Tags", cfg.Tags)
	writeBucketPrefixes(w, "Routes", cfg.Routes)
	writeBucket(w, "Apps", cfg.ServeApps)
	writeBucket(w, "Services", cfg.ServeServices)
	writeBucket(w, "IPSets", cfg.ServeIPSets)
	writeBucket(w, "Attrs", cfg.Attrs)
	writeBucket(w, "Prefs", cfg.Prefs)
}

// blueprintLabelWidth is the field-width passed to %-*s when writing a
// bucket line; the value column starts at column 11 (2 spaces + a
// label of up to 9 chars including its trailing colon + at least 1
// trailing space). "Services:" at 9 chars is the widest label, so this
// width keeps every value column aligned. Changing it shifts every
// value column.
const blueprintLabelWidth = 11

func writeBucket(w io.Writer, label string, values []string) {
	if len(values) == 0 {
		return
	}
	fmt.Fprintf(w, "  %-*s%s\n", blueprintLabelWidth, label+":", strings.Join(values, ", "))
}

func writeBucketPrefixes(w io.Writer, label string, values []netip.Prefix) {
	if len(values) == 0 {
		return
	}
	ss := make([]string, len(values))
	for i, v := range values {
		ss[i] = v.String()
	}
	fmt.Fprintf(w, "  %-*s%s\n", blueprintLabelWidth, label+":", strings.Join(ss, ", "))
}
