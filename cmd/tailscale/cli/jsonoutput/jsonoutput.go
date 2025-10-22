// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package jsonoutput provides stable and versioned JSON serialisation for CLI output.
// This allows us to provide stable output to scripts/clients, but also make
// breaking changes to the output when it's useful.
//
// Historically we only used `--json` as a boolean flag, so changing the output
// could break scripts that rely on the existing format.
//
// This package allows callers to pass a version number to `--json` and get
// a consistent output. We'll bump the version when we make a breaking change
// that's likely to break scripts that rely on the existing output, e.g. if
// we remove a field or change the type/format.
//
// Passing just the boolean flag `--json` will always return v1, to preserve
// compatibility with scripts written before we versioned our output.
package jsonoutput

import (
	"errors"
	"fmt"
	"strconv"
)

// JSONSchemaVersion implements flag.Value, and tracks whether the CLI has
// been called with `--json`, and if so, with what value.
type JSONSchemaVersion struct {
	// IsSet tracks if the flag was provided at all.
	IsSet bool

	// Value tracks the desired schema version, which defaults to 1 if
	// the user passes `--json` without an argument.
	Value int
}

// String returns the default value which is printed in the CLI help text.
func (v *JSONSchemaVersion) String() string {
	if v.IsSet {
		return strconv.Itoa(v.Value)
	} else {
		return "(not set)"
	}
}

// Set is called when the user passes the flag as a command-line argument.
func (v *JSONSchemaVersion) Set(s string) error {
	if v.IsSet {
		return errors.New("received multiple instances of --json; only pass it once")
	}

	v.IsSet = true

	// If the user doesn't supply a schema version, default to 1.
	// This ensures that any existing scripts will continue to get their
	// current output.
	if s == "true" {
		v.Value = 1
		return nil
	}

	version, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("invalid integer value passed to --json: %q", s)
	}
	v.Value = version
	return nil
}

// IsBoolFlag tells the flag package that JSONSchemaVersion can be set
// without an argument.
func (v *JSONSchemaVersion) IsBoolFlag() bool {
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
