// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package jsonoutput

import (
	"errors"
	"flag"
	"io"
	"strconv"
	"strings"
)

var _ flag.Value = new(Format)

type Format string

func (f *Format) String() string {
	if f == nil {
		return ""
	}
	return string(*f)
}

func (f *Format) Set(s string) error {
	*f = Format(s)
	return nil
}

func (f *Format) isJSON() bool {
	return *f == "json" || *f == "json-line"
}

func (f *Format) Bool() flag.Value {
	return &formatBool{f}
}

type formatBool struct {
	*Format
}

func (f *formatBool) String() string {
	return strconv.FormatBool(f.isJSON())
}

func (f *formatBool) Set(s string) error {
	// Delegate to a FlagSet to parse this as a BoolVar.
	var b bool
	fs := flag.NewFlagSet("", flag.ContinueOnError)
	fs.BoolVar(&b, "bool", false, "")
	fs.SetOutput(io.Discard) // silence
	if err := fs.Parse([]string{"-bool=" + s}); err != nil {
		// Unwrap the header added by FlagSet.failf:
		// `invalid boolean value "invalid" for -bool: `
		bits := strings.SplitN(err.Error(), ": ", 2)
		return errors.New(bits[len(bits)-1])
	}

	if isJSON := f.isJSON(); b == isJSON {
		return nil // no change
	}

	if !b {
		*f.Format = ""
	} else {
		*f.Format = "json"
	}
	return nil
}

func (f *formatBool) IsBoolFlag() bool {
	return true
}
