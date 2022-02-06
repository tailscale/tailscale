// Package ctxt provides routines to reduce the amount of context in an edit script.
package ctxt

import (
	"github.com/pkg/diff/edit"
)

// Size returns an edit script preserving only n common elements of context for changes.
// The returned edit script may alias the input.
// If n is negative, Size panics.
func Size(e edit.Script, n int) edit.Script {
	if n < 0 {
		panic("ctxt.Size called with negative n")
	}

	// Handle small scripts.
	switch len(e.Ranges) {
	case 0:
		return edit.Script{}
	case 1:
		if e.Ranges[0].IsEqual() {
			// Entirely identical contents.
			// Unclear what to do here. For now, just bail.
			// TODO: something else? what does command line diff do?
			return edit.Script{}
		}
		return edit.NewScript(e.Ranges[0])
	}

	out := make([]edit.Range, 0, len(e.Ranges))
	for i, seg := range e.Ranges {
		if !seg.IsEqual() {
			out = append(out, seg)
			continue
		}
		if i == 0 {
			// Leading Range. Keep only the final n entries.
			if seg.Len() > n {
				seg = rangeLastN(seg, n)
			}
			out = append(out, seg)
			continue
		}
		if i == len(e.Ranges)-1 {
			// Trailing Range. Keep only the first n entries.
			if seg.Len() > n {
				seg = rangeFirstN(seg, n)
			}
			out = append(out, seg)
			continue
		}
		if seg.Len() <= n*2 {
			// Small middle Range. Keep unchanged.
			out = append(out, seg)
			continue
		}
		// Large middle Range. Break into two disjoint parts.
		out = append(out, rangeFirstN(seg, n), rangeLastN(seg, n))
	}

	// TODO: Stock macOS diff also trims common blank lines
	// from the beginning/end of eq IndexRangess.
	// Perhaps we should do that here too.
	// Or perhaps that should be a separate, composable function?
	return edit.Script{Ranges: out}
}

func rangeFirstN(seg edit.Range, n int) edit.Range {
	if !seg.IsEqual() {
		panic("rangeFirstN bad op")
	}
	if seg.Len() < n {
		panic("rangeFirstN bad Len")
	}
	return edit.Range{
		LowA: seg.LowA, HighA: seg.LowA + n,
		LowB: seg.LowB, HighB: seg.LowB + n,
	}
}

func rangeLastN(seg edit.Range, n int) edit.Range {
	if !seg.IsEqual() {
		panic("rangeLastN bad op")
	}
	if seg.Len() < n {
		panic("rangeLastN bad Len")
	}
	return edit.Range{
		LowA: seg.HighA - n, HighA: seg.HighA,
		LowB: seg.HighB - n, HighB: seg.HighB,
	}
}
