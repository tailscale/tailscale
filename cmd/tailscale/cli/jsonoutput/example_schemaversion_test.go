// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package jsonoutput_test

import (
	"flag"
	"fmt"

	"tailscale.com/cmd/tailscale/cli/jsonoutput"
)

var args struct {
	json jsonoutput.SchemaVersion
}

func ExampleSchemaVersion() {
	fs := flag.NewFlagSet("ExampleSchemaVersion", flag.ExitOnError)
	fs.Var(&args.json, "json", "output in JSON format")

	fs.Parse([]string{"-json=2"})
	fmt.Printf(`{set: %t, version: %d}`, args.json.IsSet, args.json.Version)
	// Output:
	// {set: true, version: 2}
}
