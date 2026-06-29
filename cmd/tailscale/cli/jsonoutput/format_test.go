// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package jsonoutput_test

import (
	"errors"
	"flag"
	"io"
	"strings"
	"testing"

	"tailscale.com/cmd/tailscale/cli/jsonoutput"
)

func TestFormat(t *testing.T) {
	for _, tc := range []struct {
		name        string
		flags       []string
		wantString  string
		wantIsSet   bool
		wantVersion int
		wantErr     string
	}{
		{
			name:        "no-flags",
			flags:       []string{},
			wantString:  "",
			wantIsSet:   false,
			wantVersion: 0,
		},
		{
			name:        "format-json",
			flags:       []string{"-format=json"},
			wantString:  "json",
			wantIsSet:   true,
			wantVersion: 0,
		},
		{
			name:        "format-json-line",
			flags:       []string{"-format=json-line"},
			wantString:  "json-line",
			wantIsSet:   true,
			wantVersion: 0,
		},
		{
			name:        "format-not-json",
			flags:       []string{"-format=xml"},
			wantString:  "xml",
			wantIsSet:   false,
			wantVersion: 0,
		},
		{
			name:        "bool-bare",
			flags:       []string{"-bool"},
			wantString:  "json",
			wantIsSet:   true,
			wantVersion: 1,
		},
		{
			name:        "bool-true",
			flags:       []string{"-bool=true"},
			wantString:  "json",
			wantIsSet:   true,
			wantVersion: 1,
		},
		{
			name:        "bool-false",
			flags:       []string{"-bool=false"},
			wantString:  "",
			wantIsSet:   false,
			wantVersion: 0,
		},
		{
			name:    "bool-invalid",
			flags:   []string{"-bool=2"},
			wantErr: "parse error",
		},
		{
			name:        "version-bare",
			flags:       []string{"-version"},
			wantString:  "json",
			wantIsSet:   true,
			wantVersion: 1,
		},
		{
			name:        "version-true",
			flags:       []string{"-version=true"},
			wantString:  "json",
			wantIsSet:   true,
			wantVersion: 1,
		},
		{
			name:        "version-false",
			flags:       []string{"-version=false"},
			wantString:  "",
			wantIsSet:   false,
			wantVersion: 0,
		},
		{
			name:        "version-number",
			flags:       []string{"-version=2"},
			wantString:  "json",
			wantIsSet:   true,
			wantVersion: 2,
		},
		{
			name:        "version-zero",
			flags:       []string{"-version=0"},
			wantString:  "json",
			wantIsSet:   true,
			wantVersion: 0,
		},
		{
			name:    "version-invalid",
			flags:   []string{"-version=1.0"},
			wantErr: "parse error",
		},
		{
			name:        "format-xml-then-bool-true",
			flags:       []string{"-format=xml", "-bool"},
			wantString:  "json",
			wantIsSet:   true,
			wantVersion: 1,
		},
		{
			name:        "format-json-then-bool-true",
			flags:       []string{"-format=json", "-bool"},
			wantString:  "json",
			wantIsSet:   true,
			wantVersion: 1,
		},
		{
			name:        "format-json-line-then-bool-true",
			flags:       []string{"-format=json-line", "-bool"},
			wantString:  "json-line",
			wantIsSet:   true,
			wantVersion: 1,
		},
		{
			name:        "format-xml-then-bool-false",
			flags:       []string{"-format=xml", "-bool=false"},
			wantString:  "xml",
			wantIsSet:   false,
			wantVersion: 0,
		},
		{
			name:        "format-json-then-bool-false",
			flags:       []string{"-format=json", "-bool=false"},
			wantString:  "",
			wantIsSet:   false,
			wantVersion: 0,
		},
		{
			name:        "format-json-line-then-bool-false",
			flags:       []string{"-format=json-line", "-bool=false"},
			wantString:  "",
			wantIsSet:   false,
			wantVersion: 0,
		},
		{
			name:        "bool-true-then-format-xml",
			flags:       []string{"-bool", "-format=xml"},
			wantString:  "xml",
			wantIsSet:   false,
			wantVersion: 0,
		},
		{
			name:        "bool-true-then-format-json",
			flags:       []string{"-bool", "--format=json"},
			wantString:  "json",
			wantIsSet:   true,
			wantVersion: 1,
		},
		{
			name:        "bool-true-then-format-json-line",
			flags:       []string{"-bool", "--format=json-line"},
			wantString:  "json-line",
			wantIsSet:   true,
			wantVersion: 1,
		},
		{
			name:        "bool-false-then-format-xml",
			flags:       []string{"-bool=false", "--format=xml"},
			wantString:  "xml",
			wantIsSet:   false,
			wantVersion: 0,
		},
		{
			name:        "bool-false-then-format-json",
			flags:       []string{"-bool=false", "--format=json"},
			wantString:  "json",
			wantIsSet:   true,
			wantVersion: 0,
		},
		{
			name:        "bool-false-then-format-json-line",
			flags:       []string{"-bool=false", "--format=json-line"},
			wantString:  "json-line",
			wantIsSet:   true,
			wantVersion: 0,
		},
		{
			name:        "format-xml-then-version-true",
			flags:       []string{"-format=xml", "-version"},
			wantString:  "json",
			wantIsSet:   true,
			wantVersion: 1,
		},
		{
			name:        "format-json-then-version-true",
			flags:       []string{"-format=json", "-version"},
			wantString:  "json",
			wantIsSet:   true,
			wantVersion: 1,
		},
		{
			name:        "format-json-line-then-version-true",
			flags:       []string{"-format=json-line", "-version"},
			wantString:  "json-line",
			wantIsSet:   true,
			wantVersion: 1,
		},
		{
			name:        "format-xml-then-version-number",
			flags:       []string{"-format=xml", "-version=2"},
			wantString:  "json",
			wantIsSet:   true,
			wantVersion: 2,
		},
		{
			name:        "format-json-then-version-number",
			flags:       []string{"-format=json", "-version=2"},
			wantString:  "json",
			wantIsSet:   true,
			wantVersion: 2,
		},
		{
			name:        "format-json-line-then-version-number",
			flags:       []string{"-format=json-line", "-version=2"},
			wantString:  "json-line",
			wantIsSet:   true,
			wantVersion: 2,
		},
		{
			name:        "format-xml-then-version-zero",
			flags:       []string{"-format=xml", "-version=0"},
			wantString:  "json",
			wantIsSet:   true,
			wantVersion: 0,
		},
		{
			name:        "format-json-then-version-zero",
			flags:       []string{"-format=json", "-version=0"},
			wantString:  "json",
			wantIsSet:   true,
			wantVersion: 0,
		},
		{
			name:        "format-json-line-then-version-zero",
			flags:       []string{"-format=json-line", "-version=0"},
			wantString:  "json-line",
			wantIsSet:   true,
			wantVersion: 0,
		},
		{
			name:        "format-xml-then-version-false",
			flags:       []string{"-format=xml", "-version=false"},
			wantString:  "xml",
			wantIsSet:   false,
			wantVersion: 0,
		},
		{
			name:        "format-json-then-version-false",
			flags:       []string{"-format=json", "-version=false"},
			wantString:  "",
			wantIsSet:   false,
			wantVersion: 0,
		},
		{
			name:        "format-json-line-then-version-false",
			flags:       []string{"-format=json-line", "-version=false"},
			wantString:  "",
			wantIsSet:   false,
			wantVersion: 0,
		},
		{
			name:        "version-true-then-format-xml",
			flags:       []string{"-version", "-format=xml"},
			wantString:  "xml",
			wantIsSet:   false,
			wantVersion: 0,
		},
		{
			name:        "version-true-then-format-json",
			flags:       []string{"-version", "--format=json"},
			wantString:  "json",
			wantIsSet:   true,
			wantVersion: 1,
		},
		{
			name:        "version-true-then-format-json-line",
			flags:       []string{"-version", "--format=json-line"},
			wantString:  "json-line",
			wantIsSet:   true,
			wantVersion: 1,
		},
		{
			name:        "version-false-then-format-xml",
			flags:       []string{"-version=false", "--format=xml"},
			wantString:  "xml",
			wantIsSet:   false,
			wantVersion: 0,
		},
		{
			name:        "version-false-then-format-json",
			flags:       []string{"-version=false", "--format=json"},
			wantString:  "json",
			wantIsSet:   true,
			wantVersion: 0,
		},
		{
			name:        "version-false-then-format-json-line",
			flags:       []string{"-version=false", "--format=json-line"},
			wantString:  "json-line",
			wantIsSet:   true,
			wantVersion: 0,
		},
		{
			name:        "version-number-then-format-xml",
			flags:       []string{"-version=2", "--format=xml"},
			wantString:  "xml",
			wantIsSet:   false,
			wantVersion: 0,
		},
		{
			name:        "version-number-then-format-json",
			flags:       []string{"-version=2", "--format=json"},
			wantString:  "json",
			wantIsSet:   true,
			wantVersion: 2,
		},
		{
			name:        "version-number-then-format-json-line",
			flags:       []string{"-version=2", "--format=json-line"},
			wantString:  "json-line",
			wantIsSet:   true,
			wantVersion: 2,
		},
		{
			name:        "version-zero-then-format-xml",
			flags:       []string{"-version=0", "--format=xml"},
			wantString:  "xml",
			wantIsSet:   false,
			wantVersion: 0,
		},
		{
			name:        "version-zero-then-format-json",
			flags:       []string{"-version=0", "--format=json"},
			wantString:  "json",
			wantIsSet:   true,
			wantVersion: 0,
		},
		{
			name:        "version-zero-then-format-json-line",
			flags:       []string{"-version=0", "--format=json-line"},
			wantString:  "json-line",
			wantIsSet:   true,
			wantVersion: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var f jsonoutput.Format
			fs := flag.NewFlagSet("", flag.ContinueOnError)
			fs.Var(&f, "format", "")
			fs.Var(f.JSONBool(), "bool", "")
			fs.Var(f.JSONSchemaVersion(), "version", "")
			fs.SetOutput(io.Discard) // silence

			t.Logf("flags: %q", tc.flags)
			if err := fs.Parse(tc.flags); err != nil {
				// Unwrap the header added by FlagSet.failf:
				// `invalid boolean value "invalid" for -json: `
				bits := strings.SplitN(err.Error(), ": ", 2)
				err := errors.New(bits[len(bits)-1])
				if tc.wantErr == "" && err != nil {
					t.Fatalf("err %s, want <nil>", err)
				} else if tc.wantErr != "" && (err == nil || err.Error() != tc.wantErr) {
					t.Fatalf("err %v, want %s", err, tc.wantErr)
				}
			}

			if got := f.String(); got != tc.wantString {
				t.Errorf("Format.String %q, want %q", got, tc.wantString)
			}
			if got := f.IsSet; got != tc.wantIsSet {
				t.Errorf("Format.IsSet %t, want %t", got, tc.wantIsSet)
			}
			if got := f.Version; got != tc.wantVersion {
				t.Errorf("Format.Version %d, want %d", got, tc.wantVersion)
			}
		})
	}
}
