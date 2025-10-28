// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package safediff computes the difference between two lists.
//
// It is guaranteed to run in O(n), but may not produce an optimal diff.
// Most diffing algorithms produce optimal diffs but run in O(n²).
// It is safe to pass in untrusted input.
package safediff

import (
	"bytes"
	"fmt"
	"math"
	"strings"
	"unicode"

	"github.com/google/go-cmp/cmp"
)

var diffTest = false

// Lines constructs a humanly readable line-by-line diff from x to y.
// The output (if multiple lines) is guaranteed to be no larger than maxSize,
// by truncating the output if necessary. A negative maxSize enforces no limit.
//
// Example diff:
//
//	… 440 identical lines
//	  	"ssh": [
//	… 35 identical lines
//	  		{
//	- 			"src":    ["maisem@tailscale.com"],
//	- 			"dst":    ["tag:maisem-test"],
//	- 			"users":  ["maisem", "root"],
//	- 			"action": "check",
//	- 			// "recorder": ["100.12.34.56:80"],
//	+ 			"src":      ["maisem@tailscale.com"],
//	+ 			"dst":      ["tag:maisem-test"],
//	+ 			"users":    ["maisem", "root"],
//	+ 			"action":   "check",
//	+ 			"recorder": ["node:recorder-2"],
//	  		},
//	… 77 identical lines
//	  	],
//	… 345 identical lines
//
// Meaning of each line prefix:
//
//   - '…' precedes a summary statement
//   - ' ' precedes an identical line printed for context
//   - '-' precedes a line removed from x
//   - '+' precedes a line inserted from y
//
// The diffing algorithm runs in O(n) and is safe to use with untrusted inputs.
func Lines(x, y string, maxSize int) (out string, truncated bool) {
	// Convert x and y into a slice of lines and compute the edit-script.
	xs := strings.Split(x, "\n")
	ys := strings.Split(y, "\n")
	es := diffStrings(xs, ys)

	// Modify the edit-script to support printing identical lines of context.
	const identicalContext edit = '*' // special edit code to indicate printed line
	var xi, yi int                    // index into xs or ys
	isIdentical := func(e edit) bool { return e == identical || e == identicalContext }
	indentOf := func(s string) string { return s[:len(s)-len(strings.TrimLeftFunc(s, unicode.IsSpace))] }
	for i, e := range es {
		if isIdentical(e) {
			// Print current line if adjacent symbols are non-identical.
			switch {
			case i-1 >= 0 && !isIdentical(es[i-1]):
				es[i] = identicalContext
			case i+1 < len(es) && !isIdentical(es[i+1]):
				es[i] = identicalContext
			}
		} else {
			// Print any preceding or succeeding lines,
			// where the leading indent is a prefix of the current indent.
			// Indentation often indicates a parent-child relationship
			// in structured source code.
			addParents := func(ss []string, si, direction int) {
				childIndent := indentOf(ss[si])
				for j := direction; i+j >= 0 && i+j < len(es) && isIdentical(es[i+j]); j += direction {
					parentIndent := indentOf(ss[si+j])
					if strings.HasPrefix(childIndent, parentIndent) && len(parentIndent) < len(childIndent) && parentIndent != "" {
						es[i+j] = identicalContext
						childIndent = parentIndent
					}
				}
			}
			switch e {
			case removed, modified: // arbitrarily use the x value for modified values
				addParents(xs, xi, -1)
				addParents(xs, xi, +1)
			case inserted:
				addParents(ys, yi, -1)
				addParents(ys, yi, +1)
			}
		}
		if e != inserted {
			xi++
		}
		if e != removed {
			yi++
		}
	}

	// Show the line for a single hidden identical line,
	// since it occupies the same vertical height.
	for i, e := range es {
		if e == identical {
			prevNotIdentical := i-1 < 0 || es[i-1] != identical
			nextNotIdentical := i+1 >= len(es) || es[i+1] != identical
			if prevNotIdentical && nextNotIdentical {
				es[i] = identicalContext
			}
		}
	}

	// Adjust the maxSize, reserving space for the final summary.
	if maxSize < 0 {
		maxSize = math.MaxInt
	}
	maxSize -= len(stats{len(xs) + len(ys), len(xs), len(ys)}.appendText(nil))

	// mayAppendLine appends a line if it does not exceed maxSize.
	// Otherwise, it just updates prevStats.
	var buf []byte
	var prevStats stats
	mayAppendLine := func(edit edit, line string) {
		// Append the stats (if non-zero) and the line text.
		// The stats reports the number of preceding identical lines.
		if !truncated {
			bufLen := len(buf) // original length (in case we exceed maxSize)
			if !prevStats.isZero() {
				buf = prevStats.appendText(buf)
				prevStats = stats{} // just printed, so clear the stats
			}
			buf = fmt.Appendf(buf, "%c %s\n", edit, line)
			truncated = len(buf) > maxSize
			if !truncated {
				return
			}
			buf = buf[:bufLen] // restore original buffer contents
		}

		// Output is truncated, so just update the statistics.
		switch edit {
		case identical:
			prevStats.numIdentical++
		case removed:
			prevStats.numRemoved++
		case inserted:
			prevStats.numInserted++
		}
	}

	// Process the entire edit script.
	for len(es) > 0 {
		num := len(es) - len(bytes.TrimLeft(es, string(es[:1])))
		switch es[0] {
		case identical:
			prevStats.numIdentical += num
			xs, ys = xs[num:], ys[num:]
		case identicalContext:
			for n := len(xs) - num; len(xs) > n; xs, ys = xs[1:], ys[1:] {
				mayAppendLine(identical, xs[0]) // implies xs[0] == ys[0]
			}
		case modified:
			for n := len(xs) - num; len(xs) > n; xs = xs[1:] {
				mayAppendLine(removed, xs[0])
			}
			for n := len(ys) - num; len(ys) > n; ys = ys[1:] {
				mayAppendLine(inserted, ys[0])
			}
		case removed:
			for n := len(xs) - num; len(xs) > n; xs = xs[1:] {
				mayAppendLine(removed, xs[0])
			}
		case inserted:
			for n := len(ys) - num; len(ys) > n; ys = ys[1:] {
				mayAppendLine(inserted, ys[0])
			}
		}
		es = es[num:]
	}
	if len(xs)+len(ys)+len(es) > 0 {
		panic("BUG: slices not fully consumed")
	}

	if !prevStats.isZero() {
		buf = prevStats.appendText(buf) // may exceed maxSize
	}
	return string(buf), truncated
}

type stats struct{ numIdentical, numRemoved, numInserted int }

func (s stats) isZero() bool { return s.numIdentical+s.numRemoved+s.numInserted == 0 }

func (s stats) appendText(b []byte) []byte {
	switch {
	case s.numIdentical > 0 && s.numRemoved > 0 && s.numInserted > 0:
		return fmt.Appendf(b, "… %d identical, %d removed, and %d inserted lines\n", s.numIdentical, s.numRemoved, s.numInserted)
	case s.numIdentical > 0 && s.numRemoved > 0:
		return fmt.Appendf(b, "… %d identical and %d removed lines\n", s.numIdentical, s.numRemoved)
	case s.numIdentical > 0 && s.numInserted > 0:
		return fmt.Appendf(b, "… %d identical and %d inserted lines\n", s.numIdentical, s.numInserted)
	case s.numRemoved > 0 && s.numInserted > 0:
		return fmt.Appendf(b, "… %d removed and %d inserted lines\n", s.numRemoved, s.numInserted)
	case s.numIdentical > 0:
		return fmt.Appendf(b, "… %d identical lines\n", s.numIdentical)
	case s.numRemoved > 0:
		return fmt.Appendf(b, "… %d removed lines\n", s.numRemoved)
	case s.numInserted > 0:
		return fmt.Appendf(b, "… %d inserted lines\n", s.numInserted)
	default:
		return fmt.Appendf(b, "…\n")
	}
}

// diffStrings computes an edit-script of two slices of strings.
//
// This calls cmp.Equal to access the "github.com/go-cmp/cmp/internal/diff"
// implementation, which has an O(N) diffing algorithm. It is not guaranteed
// to produce an optimal edit-script, but protects our runtime against
// adversarial inputs that would wreck the optimal O(N²) algorithm used by
// most diffing packages available in open-source.
//
// TODO(https://go.dev/issue/58893): Use "golang.org/x/tools/diff" instead?
func diffStrings(xs, ys []string) []edit {
	d := new(diffRecorder)
	cmp.Equal(xs, ys, cmp.Reporter(d))
	if diffTest {
		numRemoved := bytes.Count(d.script, []byte{removed})
		numInserted := bytes.Count(d.script, []byte{inserted})
		if len(xs) != len(d.script)-numInserted || len(ys) != len(d.script)-numRemoved {
			panic("BUG: edit-script is inconsistent")
		}
	}
	return d.script
}

type edit = byte

const (
	identical edit = ' ' // equal symbol in both x and y
	modified  edit = '~' // modified symbol in both x and y
	removed   edit = '-' // removed symbol from x
	inserted  edit = '+' // inserted symbol from y
)

// diffRecorder reproduces an edit-script, essentially recording
// the edit-script from "github.com/google/go-cmp/cmp/internal/diff".
// This implements the cmp.Reporter interface.
type diffRecorder struct {
	last   cmp.PathStep
	script []edit
}

func (d *diffRecorder) PushStep(ps cmp.PathStep) { d.last = ps }

func (d *diffRecorder) Report(rs cmp.Result) {
	if si, ok := d.last.(cmp.SliceIndex); ok {
		if rs.Equal() {
			d.script = append(d.script, identical)
		} else {
			switch xi, yi := si.SplitKeys(); {
			case xi >= 0 && yi >= 0:
				d.script = append(d.script, modified)
			case xi >= 0:
				d.script = append(d.script, removed)
			case yi >= 0:
				d.script = append(d.script, inserted)
			}
		}
	}
}

func (d *diffRecorder) PopStep() { d.last = nil }
