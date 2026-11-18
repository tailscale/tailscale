// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"cmp"
	"testing"
)

// fileRow is a config file that set-config accepts. The file means the state
// the tailscale serve commands in means build, and get-config writes export
// back for that state.
type fileRow struct {
	name   string
	flag   string   // for set-config and get-config; --all if empty
	file   string   // applied with set-config
	means  []string // tailscale serve commands that build the same state
	export string   // what get-config then writes; file if empty
}

// TestServeConfigExistingFiles pins what every 0.0.1 spelling set-config has
// accepted means, so existing files keep applying to the state they always
// did, without warnings. A row whose export is set is one get-config writes
// differently.
func TestServeConfigExistingFiles(t *testing.T) {
	testFileRows(t, []fileRow{
		// Hosts.
		{
			name:   "ipv6_unbracketed",
			file:   `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:5432": "tcp://::1:5432"}}}}`,
			means:  []string{"--service=svc:foo --tcp=5432 tcp://[::1]:5432"},
			export: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:5432": "tcp://[::1]:5432"}}}}`,
		},
		{
			name:   "ipv6_unbracketed_web",
			file:   `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:80": "http://::1:3000"}}}}`,
			means:  []string{"--service=svc:foo --http=80 http://[::1]:3000"},
			export: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:80": "http://[::1]:3000"}}}}`,
		},
		{
			name:  "ipv6_bracketed",
			file:  `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:5432": "tcp://[::1]:5432"}}}}`,
			means: []string{"--service=svc:foo --tcp=5432 tcp://[::1]:5432"},
		},
		{
			name:  "ipv6_bracketed_web",
			file:  `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:80": "http://[::1]:3000"}}}}`,
			means: []string{"--service=svc:foo --http=80 http://[::1]:3000"},
		},
		{
			name:  "host_case_kept",
			file:  `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:5432": "tcp://DB.Example.com:5432"}}}}`,
			means: []string{"--service=svc:foo --tcp=5432 tcp://DB.Example.com:5432"},
		},
	})
}

// testFileRows applies each row's file with set-config, checks it builds the
// state its commands build, without warnings, and that get-config writes its
// export, which set-config reads back as the same state.
func testFileRows(t *testing.T, rows []fileRow) {
	t.Helper()
	for _, tt := range rows {
		t.Run(tt.name, func(t *testing.T) {
			skipOnWindows(t, tt.file)
			dir := serveTestDir(t)
			flag := cmp.Or(tt.flag, "--all")
			want := buildState(t, dir, tt.means)

			got := newServiceHostClient()
			setConfig(t, got, flag, expandDir(tt.file, dir))
			assertSameState(t, want, got)

			export := expandDir(cmp.Or(tt.export, tt.file), dir)
			checkJSON(t, "get-config "+flag, export, runServeCmd(t, got, "get-config", flag))
			again := newServiceHostClient()
			setConfig(t, again, flag, export)
			assertSameState(t, want, again)
		})
	}
}
