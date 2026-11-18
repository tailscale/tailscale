// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"strings"
	"testing"
)

// TestServeConfigMixed runs sequences that mix tailscale serve commands and
// config files, and checks each lands on the state the commands in want
// build, in state and in every read-out. A step is one of:
//
//	"<args>"                        tailscale serve <args>
//	"set-config <flag> <json>"      set-config <flag> of that file
//	"set-config <flag> $FROM"       set-config <flag> of what get-config <flag> writes on the from node
//	"set-config --all $FROM_STATUS" set-config --all of what serve status --json writes on the from node
func TestServeConfigMixed(t *testing.T) {
	tests := []struct {
		name  string
		from  []string // tailscale serve commands that build the from node
		steps []string
		want  []string // tailscale serve commands that build the same state
	}{
		// One node's export applied over another's state. See
		// TestServeConfigRoundTrip for --all.
		{
			name: "export_of_advertised_service_without_config",
			from: []string{"advertise svc:foo"},
			steps: []string{
				"--service=svc:foo --tcp=5432 tcp://localhost:5432",
				"set-config --service=svc:foo $FROM",
			},
			want: []string{"advertise svc:foo"},
		},

		// set-config reads serve status --json as the legacy format. It
		// carries what the config file format cannot, but has no advertised
		// state: every service it names comes back advertised.
		{
			name: "status_json_loses_drain",
			from: []string{
				"--service=svc:foo --tcp=5432 tcp://localhost:5432",
				"drain svc:foo",
			},
			steps: []string{"set-config --all $FROM_STATUS"},
			want:  []string{"--service=svc:foo --tcp=5432 tcp://localhost:5432"},
		},
		{
			name: "status_json_loses_advertised_without_config",
			from: []string{
				"--service=svc:foo --tcp=5432 tcp://localhost:5432",
				"advertise svc:bar",
			},
			steps: []string{"set-config --all $FROM_STATUS"},
			want:  []string{"--service=svc:foo --tcp=5432 tcp://localhost:5432"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			from := buildState(t, dir, tt.from)
			got := newServiceHostClient()
			for _, step := range tt.steps {
				verb, rest, _ := strings.Cut(step, " ")
				if verb != "set-config" {
					runServeCmd(t, got, cmd(step)...)
					continue
				}
				flag, file, _ := strings.Cut(rest, " ")
				switch file {
				case "$FROM":
					file = runServeCmd(t, from, "get-config", flag)
				case "$FROM_STATUS":
					// set-config warns that serve status --json is deprecated
					// as input; the warning is pinned in TestRunServeSetConfig.
					if _, stderr, err := serveRun(got, "set-config", flag, writeTmpServeConfig(t, runServeCmd(t, from, "status", "--json"))); err != nil {
						t.Fatalf("step %q: %v\n%s", step, err, stderr)
					}
					continue
				}
				setConfig(t, got, flag, file)
			}
			assertSameState(t, buildState(t, dir, tt.want), got)
		})
	}
}
