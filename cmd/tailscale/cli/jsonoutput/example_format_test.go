// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package jsonoutput_test

import (
	"flag"
	"fmt"

	"tailscale.com/cmd/tailscale/cli/jsonoutput"
)

func ExampleFormat_JSONBool() {
	var args struct {
		format jsonoutput.Format
	}

	fs := flag.NewFlagSet("ExampleFormat", flag.ExitOnError)
	fs.Var(&args.format, "format", `output format; empty (for human-readable), "json" or "json-line"`)
	fs.Var(args.format.JSONBool(), "json", "output in JSON format")

	fs.Parse([]string{"-json"})
	fmt.Printf(`{format: %q, set: %t, version: %d}`, args.format, args.format.IsSet, args.format.Version)
	// Output:
	// {format: "json", set: true, version: 1}
}

func ExampleFormat_JSONSchemaVersion() {
	var args struct {
		format jsonoutput.Format
	}

	fs := flag.NewFlagSet("ExampleFormat", flag.ExitOnError)
	fs.Var(&args.format, "format", `output format; empty (for human-readable), "json" or "json-line"`)
	fs.Var(args.format.JSONSchemaVersion(), "json", "output in JSON format")

	fs.Parse([]string{"-json=2", "-format=json-line"})
	fmt.Printf(`{format: %q, set: %t, version: %d}`, args.format, args.format.IsSet, args.format.Version)
	// Output:
	// {format: "json-line", set: true, version: 2}
}
