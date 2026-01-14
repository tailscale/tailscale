// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_aws

package awsparamstore

import (
	"testing"
)

func TestParseARN(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		wantOk        bool
		wantRegion    string
		wantParamName string
	}{
		{
			name:   "non-arn-passthrough",
			input:  "tskey-abcd1234",
			wantOk: false,
		},
		{
			name:   "file-prefix-passthrough",
			input:  "file:/path/to/key",
			wantOk: false,
		},
		{
			name:   "empty-passthrough",
			input:  "",
			wantOk: false,
		},
		{
			name:   "non-ssm-arn-passthrough",
			input:  "arn:aws:s3:::my-bucket",
			wantOk: false,
		},
		{
			name:   "invalid-arn-passthrough",
			input:  "arn:invalid",
			wantOk: false,
		},
		{
			name:   "arn-invalid-resource-passthrough",
			input:  "arn:aws:ssm:us-east-1:123456789012:document/myDoc",
			wantOk: false,
		},
		{
			name:          "valid-arn",
			input:         "arn:aws:ssm:us-west-2:123456789012:parameter/my-secret",
			wantOk:        true,
			wantRegion:    "us-west-2",
			wantParamName: "/my-secret",
		},
		{
			name:          "valid-arn-with-path",
			input:         "arn:aws:ssm:eu-central-1:123456789012:parameter/path/to/secret",
			wantOk:        true,
			wantRegion:    "eu-central-1",
			wantParamName: "/path/to/secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRegion, gotParamName, gotOk := parseARN(tt.input)
			if gotOk != tt.wantOk {
				t.Errorf("parseARN(%q) got ok=%v, want %v", tt.input, gotOk, tt.wantOk)
			}
			if !tt.wantOk {
				return
			}
			if gotRegion != tt.wantRegion {
				t.Errorf("parseARN(%q) got region=%q, want %q", tt.input, gotRegion, tt.wantRegion)
			}
			if gotParamName != tt.wantParamName {
				t.Errorf("parseARN(%q) got paramName=%q, want %q", tt.input, gotParamName, tt.wantParamName)
			}
		})
	}
}
