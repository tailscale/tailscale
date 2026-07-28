// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package jsonoutput provides stable and versioned JSON serialisation for CLI output.
// This allows us to provide stable output to scripts/clients, but also make
// breaking changes to the output when it's useful.
//
// Historically we only used a boolean -json flag, so changing the output
// could break scripts that rely on the existing format.
//
// This package provides a [SchemaVersion] flag type that allows callers
// to pass either a boolean or a version number and get a consistent output.
// We'll bump the version when we make a breaking change
// that's likely to break scripts that rely on the existing output,
// e.g. if we remove a field or change the type/format.
// Passing just the boolean flag will always return 1, to preserve
// compatibility with scripts written before we versioned our output.
//
// This package provides a [Format] flag type that allows callers to specify
// which output format the command should print.
// This flag provides [Format.JSONBool] and [Format.JSONSchemaVersion] methods
// to support combining both -format=json and -format=json-line options
// with either boolean or versioned -json flags.
//
// This package also provides [ResponseEnvelope] which is used to provide the
// set of fields common to all versioned JSON output.
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
func (v SchemaVersion) String() string {
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
