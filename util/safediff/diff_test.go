// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package safediff

import (
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func init() { diffTest = true }

func TestLines(t *testing.T) {
	// The diffs shown below technically depend on the stability of cmp,
	// but that should be fine for sufficiently simple diffs like these.
	// If the output does change, that would suggest a significant regression
	// in the optimality of cmp's diffing algorithm.

	x := `{
	"firstName": "John",
	"lastName": "Smith",
	"isAlive": true,
	"age": 27,
	"address": {
		"streetAddress": "21 2nd Street",
		"city": "New York",
		"state": "NY",
		"postalCode": "10021-3100"
	},
	"phoneNumbers": [{
		"type": "home",
		"number": "212 555-1234"
	}, {
		"type": "office",
		"number": "646 555-4567"
	}],
	"children": [
		"Catherine",
		"Thomas",
		"Trevor"
	],
	"spouse": null
}`
	y := x
	y = strings.ReplaceAll(y, `"New York"`, `"Los Angeles"`)
	y = strings.ReplaceAll(y, `"NY"`, `"CA"`)
	y = strings.ReplaceAll(y, `"646 555-4567"`, `"315 252-8888"`)

	wantDiff := `
… 5 identical lines
  	"address": {
  		"streetAddress": "21 2nd Street",
- 		"city": "New York",
- 		"state": "NY",
+ 		"city": "Los Angeles",
+ 		"state": "CA",
  		"postalCode": "10021-3100"
  	},
… 3 identical lines
  	}, {
  		"type": "office",
- 		"number": "646 555-4567"
+ 		"number": "315 252-8888"
  	}],
… 7 identical lines
`[1:]
	gotDiff, gotTrunc := Lines(x, y, -1)
	if d := cmp.Diff(gotDiff, wantDiff); d != "" {
		t.Errorf("Lines mismatch (-got +want):\n%s\ngot:\n%s\nwant:\n%s", d, gotDiff, wantDiff)
	} else if gotTrunc == true {
		t.Errorf("Lines: output unexpectedly truncated")
	}

	wantDiff = `
… 5 identical lines
  	"address": {
  		"streetAddress": "21 2nd Street",
- 		"city": "New York",
- 		"state": "NY",
+ 		"city": "Los Angeles",
… 15 identical, 1 removed, and 2 inserted lines
`[1:]
	gotDiff, gotTrunc = Lines(x, y, 200)
	if d := cmp.Diff(gotDiff, wantDiff); d != "" {
		t.Errorf("Lines mismatch (-got +want):\n%s\ngot:\n%s\nwant:\n%s", d, gotDiff, wantDiff)
	} else if gotTrunc == false {
		t.Errorf("Lines: output unexpectedly not truncated")
	}

	wantDiff = "… 22 identical, 3 removed, and 3 inserted lines\n"
	gotDiff, gotTrunc = Lines(x, y, 0)
	if d := cmp.Diff(gotDiff, wantDiff); d != "" {
		t.Errorf("Lines mismatch (-got +want):\n%s\ngot:\n%s\nwant:\n%s", d, gotDiff, wantDiff)
	} else if gotTrunc == false {
		t.Errorf("Lines: output unexpectedly not truncated")
	}

	x = `{
	"unrelated": [
		"unrelated",
	],
	"related": {
		"unrelated": [
			"unrelated",
		],
		"related": {
			"unrelated": [
				"unrelated",
			],
			"related": {
				"related": "changed",
			},
			"unrelated": [
				"unrelated",
			],
		},
		"unrelated": [
			"unrelated",
		],
	},
	"unrelated": [
		"unrelated",
	],
}`
	y = strings.ReplaceAll(x, "changed", "CHANGED")

	wantDiff = `
… 4 identical lines
  	"related": {
… 3 identical lines
  		"related": {
… 3 identical lines
  			"related": {
- 				"related": "changed",
+ 				"related": "CHANGED",
  			},
… 3 identical lines
  		},
… 3 identical lines
  	},
… 4 identical lines
`[1:]
	gotDiff, gotTrunc = Lines(x, y, -1)
	if d := cmp.Diff(gotDiff, wantDiff); d != "" {
		t.Errorf("Lines mismatch (-got +want):\n%s\ngot:\n%s\nwant:\n%s", d, gotDiff, wantDiff)
	} else if gotTrunc == true {
		t.Errorf("Lines: output unexpectedly truncated")
	}

	x = `{
	"ACLs": [
		{
			"Action": "accept",
			"Users":  ["group:all"],
			"Ports":  ["tag:tmemes:80"],
		},
	],
}`
	y = strings.ReplaceAll(x, "tag:tmemes:80", "tag:tmemes:80,8383")
	wantDiff = `
  {
  	"ACLs": [
  		{
  			"Action": "accept",
  			"Users":  ["group:all"],
- 			"Ports":  ["tag:tmemes:80"],
+ 			"Ports":  ["tag:tmemes:80,8383"],
  		},
  	],
  }
`[1:]
	gotDiff, gotTrunc = Lines(x, y, -1)
	if d := cmp.Diff(gotDiff, wantDiff); d != "" {
		t.Errorf("Lines mismatch (-got +want):\n%s\ngot:\n%s\nwant:\n%s", d, gotDiff, wantDiff)
	} else if gotTrunc == true {
		t.Errorf("Lines: output unexpectedly truncated")
	}
}

// TestLinesAccounting verifies that every input line is accounted for in the
// output, whether printed individually or tallied in a "…" summary, at every
// maxSize. Truncation must only ever hide lines, never lose track of them.
func TestLinesAccounting(t *testing.T) {
	x := strings.Repeat("identical\n", 50) + "before\n" + strings.Repeat("identical\n", 50)
	y := strings.Repeat("identical\n", 50) + "after\n" + strings.Repeat("identical\n", 50)

	// Tally the expected counts straight from the edit-script.
	var want stats
	for _, e := range diffStrings(strings.Split(x, "\n"), strings.Split(y, "\n")) {
		switch e {
		case identical:
			want.numIdentical++
		case modified:
			want.numRemoved++
			want.numInserted++
		case removed:
			want.numRemoved++
		case inserted:
			want.numInserted++
		}
	}

	for _, maxSize := range append([]int{-1}, rangeInts(0, 400)...) {
		out, _ := Lines(x, y, maxSize)
		if got := tallyDiff(t, out); got != want {
			t.Errorf("Lines(maxSize=%d) accounts for %+v lines, want %+v; output:\n%s", maxSize, got, want, out)
		}
	}
}

func rangeInts(lo, hi int) []int {
	out := make([]int, 0, hi-lo)
	for i := lo; i < hi; i++ {
		out = append(out, i)
	}
	return out
}

var summaryRx = regexp.MustCompile(`(\d+) (identical|removed|inserted)`)

// tallyDiff counts how many lines of each kind a [Lines] output accounts for,
// summing both individually printed lines and "…" summary statements.
func tallyDiff(t *testing.T, out string) (s stats) {
	t.Helper()
	for line := range strings.Lines(out) {
		switch {
		case strings.HasPrefix(line, "  "):
			s.numIdentical++
		case strings.HasPrefix(line, "- "):
			s.numRemoved++
		case strings.HasPrefix(line, "+ "):
			s.numInserted++
		case strings.HasPrefix(line, "… "):
			for _, m := range summaryRx.FindAllStringSubmatch(line, -1) {
				n, err := strconv.Atoi(m[1])
				if err != nil {
					t.Fatalf("bad summary line %q: %v", line, err)
				}
				switch m[2] {
				case "identical":
					s.numIdentical += n
				case "removed":
					s.numRemoved += n
				case "inserted":
					s.numInserted += n
				}
			}
		default:
			t.Fatalf("unexpected output line %q", line)
		}
	}
	return s
}
