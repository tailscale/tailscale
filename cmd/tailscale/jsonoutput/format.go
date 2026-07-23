// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package jsonoutput

import (
	"errors"
	"flag"
	"strconv"
)

var _ flag.Value = new(Format)

// Format implements the [flag.Value] interface,
// supporting a combination of both -format and -json flags.
//
// For some commands, like tailscale netcheck or tailscale routecheck,
// the user can specify the output format using the -format flag:
//
//	tailscale routecheck -format=json-line.
//
// Setting this flag to "json" or "json-line" implies that the -json flag is set.
type Format struct {
	s string
	SchemaVersion
}

// String returns the default value which is printed in the CLI help text.
func (f Format) String() string {
	return string(f.s)
}

// Set is called when the user passes the flag as a command-line argument.
func (f *Format) Set(s string) error {
	f.s = s
	isJSON := f.isJSON()
	f.IsSet = isJSON
	if !isJSON {
		f.Version = 0
	}
	return nil
}

// IsBoolFlag reports that this [flag.Value] can be set without an argument.
// This is the magic interface that makes -name equivalent to -name=true
// rather than using the next command-line argument.
func (f *Format) IsBoolFlag() bool {
	return false // requires argument, overrides [SchemaVersion.IsBoolFlag]
}

// isJSON reports whether f represents a format based on JSON.
func (f *Format) isJSON() bool {
	return f.s == "json" || f.s == "json-line"
}

// setJSON either sets or clears the format value if it doesn’t match x.
func (f *Format) setJSON(x bool) {
	switch x {
	case f.isJSON():
		return // no change
	case true:
		f.s = "json"
	case false:
		f.s = "" // clear
		f.Version = 0
	}
}

// JSONBool returns a [flag.Value] for a boolean -json flag
// which is aware of the underlying format.
func (f *Format) JSONBool() flag.Value {
	return &formatBool{f}
}

type formatBool struct {
	*Format
}

// String returns the default value which is printed in the CLI help text.
func (f formatBool) String() string {
	return strconv.FormatBool(f.isJSON())
}

// Set is called when the user passes the flag as a command-line argument.
func (f *formatBool) Set(s string) error {
	if _, err := strconv.ParseBool(s); err != nil {
		return errors.New("parse error")
	}
	f.SchemaVersion.Set(s)
	f.setJSON(f.IsSet)
	return nil
}

// IsBoolFlag reports that this [flag.Value] can be set without an argument.
// This is the magic interface that makes -name equivalent to -name=true
// rather than using the next command-line argument.
func (f *formatBool) IsBoolFlag() bool {
	return true
}

// JSONSchemaVersion returns a [flag.Value] for a [SchemaVersion] -json flag
// which is aware of the underlying format.
func (f *Format) JSONSchemaVersion() flag.Value {
	return &formatSchemaVersion{f}
}

type formatSchemaVersion struct {
	*Format
}

// String returns the default value which is printed in the CLI help text.
func (f formatSchemaVersion) String() string {
	return f.SchemaVersion.String()
}

// Set is called when the user passes the flag as a command-line argument.
func (f *formatSchemaVersion) Set(s string) error {
	if err := f.SchemaVersion.Set(s); err != nil {
		return err
	}
	f.setJSON(f.IsSet)
	return nil
}

// IsBoolFlag reports that this [flag.Value] can be set without an argument.
// This is the magic interface that makes -name equivalent to -name=true
// rather than using the next command-line argument.
func (f *formatSchemaVersion) IsBoolFlag() bool {
	return f.SchemaVersion.IsBoolFlag()
}
