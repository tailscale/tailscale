// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package osrouter

import (
	"slices"
	"testing"
)

func TestPFTablesReferenced(t *testing.T) {
	tests := []struct {
		name  string
		rules string
		want  []string
	}{
		{"empty", "", nil},
		{
			// What a bare FreeBSD box looks like: only our anchor refs.
			"anchors only",
			"nat-anchor \"tailscale\"\nanchor \"tailscale\"\n",
			nil,
		},
		{
			"no tables",
			"scrub in all fragment reassemble\npass in all flags S/SA keep state\n",
			nil,
		},
		{
			// pfctl emits automatic tables like this for interface groups; a
			// reload without table preservation would empty them too.
			"automatic table",
			"block drop in log inet from <__automatic_591ee83a_0> to any\n",
			[]string{"__automatic_591ee83a_0"},
		},
		{
			"named table",
			"pass out log on em0 proto tcp from <zabbix_proxies> to any port = ssh\n",
			[]string{"zabbix_proxies"},
		},
		{
			"deduplicated and sorted",
			"pass in log from <trusted> to any\n" +
				"pass in log from <admins> to any\n" +
				"pass out log from any to <trusted>\n",
			[]string{"admins", "trusted"},
		},
		{
			"names with punctuation",
			"pass in log from <fw-cluster.v4> to any\npass in log from <mon_hosts> to any\n",
			[]string{"fw-cluster.v4", "mon_hosts"},
		},
		{
			// A bare "<" with no closing ">" is not a table reference.
			"unclosed angle bracket",
			"pass in all # < not a table\n",
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pfTablesReferenced(tt.rules); !slices.Equal(got, tt.want) {
				t.Errorf("pfTablesReferenced() = %v, want %v", got, tt.want)
			}
		})
	}
}
