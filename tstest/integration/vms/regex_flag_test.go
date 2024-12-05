// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package vms

import (
	"flag"
	"testing"
)

func TestRegexFlag(t *testing.T) {
	var v regexValue
	fs := flag.NewFlagSet(t.Name(), flag.PanicOnError)
	fs.Var(&v, "regex", "regex to parse")

	const want = `.*`
	fs.Parse([]string{"-regex", want})
	if v.Unwrap().String() != want {
		t.Fatalf("got wrong regex: %q, wanted: %q", v.Unwrap().String(), want)
	}
}
