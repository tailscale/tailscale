// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package jsonoutput_test

import (
	"flag"
	"math"
	"testing"

	gcmp "github.com/google/go-cmp/cmp"
	"github.com/kballard/go-shellquote"

	"tailscale.com/cmd/tailscale/cli/jsonoutput"
)

func TestSchemaVersion(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    string
		want    jsonoutput.SchemaVersion
		wantErr string
		wantStr string
	}{
		{
			name:    "none",
			want:    jsonoutput.SchemaVersion{IsSet: false, Version: 0},
			wantStr: "false",
		},
		{
			name:    "default",
			args:    "-got",
			want:    jsonoutput.SchemaVersion{IsSet: true, Version: 1},
			wantStr: "1",
		},
		{
			name:    "true",
			args:    "-got=true",
			want:    jsonoutput.SchemaVersion{IsSet: true, Version: 1},
			wantStr: "1",
		},
		{
			name:    "false",
			args:    "-got=false",
			want:    jsonoutput.SchemaVersion{IsSet: false, Version: 0},
			wantStr: "false",
		},
		{
			// Test that -got=0 isn’t interpreted as -bool=0, i.e. false.
			name:    "zero_not_false",
			args:    "-got=0",
			want:    jsonoutput.SchemaVersion{IsSet: true, Version: 0},
			wantStr: "0",
		},
		{
			name:    "one",
			args:    "-got=1",
			want:    jsonoutput.SchemaVersion{IsSet: true, Version: 1},
			wantStr: "1",
		},
		{
			name:    "two",
			args:    "-got=2",
			want:    jsonoutput.SchemaVersion{IsSet: true, Version: 2},
			wantStr: "2",
		},
		{
			name:    "max",
			args:    "-got=2147483647",
			want:    jsonoutput.SchemaVersion{IsSet: true, Version: math.MaxInt32},
			wantStr: "2147483647",
		},
		{
			name:    "min",
			args:    "-got=-2147483648",
			want:    jsonoutput.SchemaVersion{IsSet: true, Version: math.MinInt32},
			wantStr: "-2147483648",
		},
		{
			name:    "invalid",
			args:    "-got=invalid",
			wantErr: `invalid boolean value "invalid" for -got: parse error`,
		},
		{
			name:    "float",
			args:    "-got=1.3",
			wantErr: `invalid boolean value "1.3" for -got: parse error`,
		},
		{
			name:    "space",
			args:    "-got=' '",
			wantErr: `invalid boolean value " " for -got: parse error`,
		},
		{
			name:    "trailing_space",
			args:    "-got='1 '",
			wantErr: `invalid boolean value "1 " for -got: parse error`,
		},
	} {
		args, err := shellquote.Split(tc.args)
		if err != nil {
			t.Fatalf("broken args %q: %v", tc.args, err)
		}

		// Test both Set and String methods.
		t.Run(tc.name, func(t *testing.T) {
			var got jsonoutput.SchemaVersion
			fs := flag.NewFlagSet("name", flag.ContinueOnError)
			fs.Var(&got, "got", "usage")

			err = fs.Parse(args)
			if err != nil && tc.wantErr == "" {
				t.Errorf("parse error: %v", err)
			} else if err != nil && err.Error() != tc.wantErr {
				t.Errorf("parse error mismatch: %q, want %q", err, tc.wantErr)
			} else if err == nil && tc.wantErr != "" {
				t.Errorf("parse error: %v, want %q", err, tc.wantErr)
			}

			if len(fs.Args()) != 0 {
				t.Errorf("unexpected positional arguments: %q", fs.Args())
			}

			if diff := gcmp.Diff(tc.want, got); diff != "" {
				t.Errorf("parse mismatch: -want +got\n%s", diff)
			}

			if s := got.String(); s != tc.wantStr && tc.wantStr != "" {
				t.Errorf("string %q, want %q", s, tc.wantStr)
			}
		})

		if tc.args == "" {
			continue // nothing to clobber
		}
		if tc.wantErr != "" {
			continue // clobbering will just trigger another error
		}

		// The last -got flag will clobber all previous -got flags.
		t.Run(tc.name+"/clobber", func(t *testing.T) {
			var got jsonoutput.SchemaVersion
			fs := flag.NewFlagSet("name", flag.ContinueOnError)
			fs.Var(&got, "got", "usage")

			sentinel := []string{"-got=-1"}
			if err := fs.Parse(append(sentinel, args...)); err != nil {
				t.Errorf("parse error: %v", err)
			}

			if got.Version == -1 {
				t.Errorf("sentinel detected: flag didn’t clobber")
			}

			if len(fs.Args()) != 0 {
				t.Errorf("unexpected positional arguments: %q", fs.Args())
			}

			if diff := gcmp.Diff(tc.want, got); diff != "" {
				t.Errorf("parse mismatch: -want +got\n%s", diff)
			}
		})
	}
}
