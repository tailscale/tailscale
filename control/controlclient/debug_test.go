// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlclient

import (
	"strings"
	"testing"
)

const stack string = `
    debug_test.go:15: goroutine 18 [running]:
        command-line-arguments.TestScrubbedGoroutineDump(0xc000082600)
                /Documents/Code/tailscale/tailscale/control/controlclient/debug_test.go:14 +0x6f
        testing.tRunner(0xc000082600, 0x54dec8)
                /usr/local/go/src/testing/testing.go:1194 +0xef
        created by testing.(*T).Run
                /usr/local/go/src/testing/testing.go:1239 +0x2b3

        goroutine 1 [chan receive]:
        testing.(*T).Run(0xc000082600, 0x548603, 0x19, 0x54dec8, 0x47f166)
                /usr/local/go/src/testing/testing.go:1240 +0x2da
        testing.runTests.func1(0xc000082480)
                /usr/local/go/src/testing/testing.go:1512 +0x78
        testing.tRunner(0xc000082480, 0xc000093de0)
                /usr/local/go/src/testing/testing.go:1194 +0xef
        testing.runTests(0xc0000bc018, 0x613c80, 0x1, 0x1, 0xc036831ecba340db, 0x8bb2ce015b, 0x61c060, 0x545c1a)
                /usr/local/go/src/testing/testing.go:1510 +0x2fe
        testing.(*M).Run(0xFFFFFFFFFF, 0x0)
                /usr/local/go/src/testing/testing.go:1418 +0x1eb
        main.main()
                _testmain.go:43 +0x138
`

func TestScrubGoroutineDump(t *testing.T) {
	got := string(scrubGoroutineDump([]byte(stack)))
	if strings.Contains(got, "0xc000082600") {
		t.Errorf("Want=not Contains(0xc000082600); got=%q", got)
	}
	if strings.Contains(got, "0xFFFFFFFFFF") {
		t.Errorf("Want=not Contains(0xFFFFFFFFFF); got=%q", got)
	}
	if !strings.Contains(got, "0x0") {
		t.Errorf("Want=Contains(0x0); got=%q", got)
	}
	if !strings.Contains(got, "/usr/local/go/src/testing/testing.go") {
		t.Errorf("Want=Contains(/usr/local/go/src/testing/testing.go); got=%q", got)
	}
	if strings.Contains(got, "MISSING") {
		t.Errorf("Want=not Contains(MISSING); got=%q", got)
	}
}

func TestScrubbedGoroutineDump(t *testing.T) {
	t.Logf("Got:\n%s\n", scrubbedGoroutineDump())
}
