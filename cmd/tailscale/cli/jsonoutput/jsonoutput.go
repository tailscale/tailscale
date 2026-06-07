// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package jsonoutput provides stable and versioned JSON serialization for CLI output.
// This allows us to provide stable output to scripts and clients,
// but also allows us to make useful and breaking changes to the output
// by incrementing the version number.
//
// Historically we only used a boolean -json flag, so changing the output
// could break scripts that rely on the existing format.
//
// # Unmarshaling JSON output in other programs
//
// The Tailscale client can format the output of many commands in JSON,
// which makes it easier to write programs that read and process this output.
// Commands that support JSON output will provide a -json flag:
//
// For example, performing a DNS query produces this human-readable output:
//
//	$ tailscale dns query hello.ts.net
//	DNS query for "hello.ts.net" (A) using internal resolver:
//
//	Forwarding to resolver: 199.247.155.53
//
//	Response code: RCodeSuccess
//
//	Name           TTL  Class      Type   Body
//	----           ---  -----      ----   ----
//	hello.ts.net.  600  ClassINET  TypeA  100.101.102.103
//
// that corresponds with this JSON output:
//
//	$ tailscale dns query --json hello.ts.net
//	{
//	  "Name": "hello.ts.net",
//	  "QueryType": "A",
//	  "Resolvers": [
//	    {
//	      "Addr": "199.247.155.53"
//	    }
//	  ],
//	  "ResponseCode": "RCodeSuccess",
//	  "Answers": [
//	    {
//	      "Name": "hello.ts.net.",
//	      "TTL": 600,
//	      "Class": "ClassINET",
//	      "Type": "TypeA",
//	      "Body": "100.101.102.103"
//	    }
//	  ]
//	}
//
// To unmarshal this response, use [tailscale.com/cmd/tailscale/cli/jsonoutput.DNSStatusResult].
// For other responses, you can find the corresponding struct
// in this package or within one of its subpackages.
//
// # Defining a stable, versioned JSON format
//
// This package provides the [ResponseEnvelope] struct
// which provides the set of fields common to all versioned JSON output.
// This struct must be embedded in every JSON response from the CLI.
// For example, a hypothetical "tailscale hello" command:
//
//	$ tailscale hello --json=1
//	{
//	  "SchemaVersion": "1",
//	  "Greeting": "Hello, 世界"
//	}
//
// would provide a hellocmdjsonv1 package under the
// [tailscale.com/cmd/tailscale/cli/jsonoutput] package,
// that exports of a HelloResponse struct for third-party programs to use:
//
//	package hellocmdjsonv1
//
//	type HelloResponse struct {
//		jsonoutput.ResponseEnvelope
//		Greeting string
//	}
//
// For an actual example for the "tailscale lock" subcommand,
// see [tailscale.com/cmd/tailscale/cli/jsonoutput/tslockjsonv1].
//
// When we make a backwards incompatible change to the JSON output,
// e.g. if we remove a field or change a field’s type or format,
// we must add a new package with an incremented [ResponseEnvelope.SchemaVersion] number.
// For example, if we were forced to break the format by changing a field’s type:
//
//	$ tailscale hello --json=2
//	{
//	  "SchemaVersion": "2",
//	  "Greeting": {
//	    "en": "Hello, world",
//	    "zh": "你好世界"
//	  }
//	}
//
// We must create a new hellocmdjsonv2 package that exports an updated
// HelloResponse that can be used to unmarshal the version 2 output:
//
//	package hellocmdjsonv2
//
//	type HelloResponse struct {
//		jsonoutput.ResponseEnvelope
//		Greeting map[string]string
//	}
//
// We should also add a [ResponseEnvelope.ResponseWarning] to older versions
// that advise clients of the a newer version of this response:
//
//	$ tailscale hello --json=1
//	{
//	  "_WARNING": "a newer schema version is available",
//	  "SchemaVersion": "1",
//	  "Greeting": "Hello, 世界"
//	}
//
// # Marshaling to JSON in the cmd/tailscale client
//
// This package provides a [SchemaVersion] flag type that allows callers
// to pass either a boolean -json flag or a version-numbered -json=2 flag
// in order to get consistent output.
//
// Passing just the boolean flag will always imply -json=1
// to preserve compatibility with scripts written before we versioned our output.
package jsonoutput

import (
	"errors"
	"flag"
	"io"
	"strconv"
	"strings"
)

var _ flag.Value = &SchemaVersion{}

// SchemaVersion implements the [flag.Value] interface,
// tracking whether the flag has been set or cleared, and its value when set.
type SchemaVersion struct {
	// IsSet tracks if the flag was set or cleared.
	// This flag is true when set by -name or -name=true or -name=INT,
	// otherwise it is false when cleared by -name=false.
	IsSet bool

	// Version tracks the desired schema version, as set by the -name=INT flag.
	// The version defaults to 1 when implicitly set by -name or -name=true.
	Version int
}

// String returns the default value which is printed in the CLI help text.
func (v *SchemaVersion) String() string {
	if v.IsSet {
		return strconv.Itoa(v.Version)
	}
	return strconv.FormatBool(false)
}

// Set is called when the user passes the flag as a command-line argument.
func (v *SchemaVersion) Set(s string) error {
	// Delegate to a FlagSet to parse this as both a BoolVar and an IntVar.
	// This is less efficient than copying the implementation from the standard library
	// but this design makes it likelier that Set will inherit any upstream fixes.
	fs := flag.NewFlagSet("", flag.ContinueOnError)
	fs.BoolVar(&v.IsSet, "bool", false, "")
	fs.IntVar(&v.Version, "int", 0, "")
	fs.SetOutput(io.Discard) // silence

	// First, try to parse as an IntVar to handle -flag=INT.
	// This order is important because -bool=0 will parse as false.
	if err := fs.Parse([]string{"-int=" + s}); err == nil {
		v.IsSet = true
		return nil
	}
	// If that fails, parse as a BoolVar to handle -flag and -flag=false.
	// This is checked last for compatibility with the boolean -json flag.
	if err := fs.Parse([]string{"-bool=" + s}); err != nil {
		// Unwrap the header added by FlagSet.failf:
		// `invalid boolean value "invalid" for -bool: `
		bits := strings.SplitN(err.Error(), ": ", 2)
		return errors.New(bits[len(bits)-1])
	}
	// If the user doesn't supply a schema version, default to 1.
	// This ensures that any existing scripts will continue to get their
	// current output.
	if v.IsSet {
		v.Version = 1
	} else {
		v.Version = 0 // if unset, zero out the Version
	}
	return nil
}

// IsBoolFlag reports that this [flag.Value] can be set without an argument.
// This is the magic interface that makes -name equivalent to -name=true
// rather than using the next command-line argument.
func (v *SchemaVersion) IsBoolFlag() bool {
	return true
}

// ResponseEnvelope is a set of fields common to all versioned JSON output.
type ResponseEnvelope struct {
	// SchemaVersion is the version of the JSON output, e.g. "1", "2", "3"
	SchemaVersion string

	// ResponseWarning tells a user if a newer version of the JSON output
	// is available.
	ResponseWarning string `json:"_WARNING,omitzero"`
}
