// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows
// +build windows

package dns

import (
	"reflect"
	"testing"
)

func TestParseIni(t *testing.T) {
	var tests = []struct {
		src  string
		want map[string]map[string]string
	}{
		{
			src: `# appended wsl.conf file
[automount]
	enabled = true
	root=/mnt/
# added by tailscale
[network] # trailing comment
generateResolvConf = false  # trailing comment`,
			want: map[string]map[string]string{
				"automount": {"enabled": "true", "root": "/mnt/"},
				"network":   {"generateResolvConf": "false"},
			},
		},
	}
	for _, test := range tests {
		got := parseIni(test.src)
		if !reflect.DeepEqual(got, test.want) {
			t.Errorf("for:\n%s\ngot:  %v\nwant: %v", test.src, got, test.want)
		}
	}
}
