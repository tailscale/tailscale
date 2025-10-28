// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package safediff

import (
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

	wantDiff = "… 17 identical, 3 removed, and 3 inserted lines\n"
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

func FuzzDiff(f *testing.F) {
	f.Fuzz(func(t *testing.T, x, y string, maxSize int) {
		const maxInput = 1e3
		if len(x) > maxInput {
			x = x[:maxInput]
		}
		if len(y) > maxInput {
			y = y[:maxInput]
		}
		diff, _ := Lines(x, y, maxSize) // make sure this does not panic
		if strings.Count(diff, "\n") > 1 && maxSize >= 0 && len(diff) > maxSize {
			t.Fatal("maxSize exceeded")
		}
	})
}
