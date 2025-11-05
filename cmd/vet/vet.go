// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package vet is a tool to statically check Go source code.
package main

import (
	_ "embed"

	"golang.org/x/tools/go/analysis/unitchecker"
	"tailscale.com/cmd/vet/jsontags"
)

//go:embed jsontags_allowlist
var jsontagsAllowlistSource string

func init() {
	jsontags.RegisterAllowlist(jsontags.ParseAllowlist(jsontagsAllowlistSource))
	jsontags.RegisterPureIsZeroMethods(jsontags.PureIsZeroMethodsInTailscaleModule)
}

func main() {
	unitchecker.Main(jsontags.Analyzer)
}
