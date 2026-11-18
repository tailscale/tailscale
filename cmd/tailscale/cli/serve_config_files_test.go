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

		// Advertisement.
		{
			name: "advertised_false",
			file: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:5432": "tcp://localhost:5432"}, "advertised": false}}}`,
			means: []string{
				"--service=svc:foo --tcp=5432 tcp://localhost:5432",
				"drain svc:foo",
			},
		},
		{
			name:   "advertised_true_is_default",
			file:   `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:5432": "tcp://localhost:5432"}, "advertised": true}}}`,
			means:  []string{"--service=svc:foo --tcp=5432 tcp://localhost:5432"},
			export: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:5432": "tcp://localhost:5432"}}}}`,
		},
		{
			name:  "no_endpoints",
			file:  `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {}}}}`,
			means: []string{"advertise svc:foo"},
		},
		{
			name:   "no_endpoints_not_advertised",
			file:   `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {}, "advertised": false}}}`,
			export: `{"version": "0.0.1"}`,
		},
		{
			name:   "no_services",
			file:   `{"version": "0.0.1", "services": {}}`,
			export: `{"version": "0.0.1"}`,
		},
		{
			name: "version_only",
			file: `{"version": "0.0.1"}`,
		},

		// One Service.
		{
			name:  "service",
			flag:  "--service=svc:foo",
			file:  `{"version": "0.0.1", "endpoints": {"tcp:443": "https://localhost:8443"}}`,
			means: []string{"--service=svc:foo --https=443 https://localhost:8443"},
		},
		{
			name:  "service_no_endpoints",
			flag:  "--service=svc:foo",
			file:  `{"version": "0.0.1", "endpoints": {}}`,
			means: []string{"advertise svc:foo"},
		},
		{
			name: "service_no_endpoints_not_advertised",
			flag: "--service=svc:foo",
			file: `{"version": "0.0.1", "endpoints": {}, "advertised": false}`,
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

// TestServeConfigNotRepresentable pins what the config file format cannot
// say. The CLI builds each state, get-config refuses it with an error naming
// the service, the port and what is lost, rather than writing a file without
// it, and serve status --json still carries it.
func TestServeConfigNotRepresentable(t *testing.T) {
	tests := []struct {
		name    string
		cli     []string // builds the state
		legacy  string   // or a serve status --json document that does
		refused string   // get-config's error, with --service=svc:foo and with --all
	}{
		{
			name:    "text",
			cli:     []string{"--service=svc:foo --http=80 text:hello"},
			refused: `service "svc:foo": port 80: the config file format cannot represent a text handler`,
		},
		{
			name: "mount_point",
			cli: []string{
				"--service=svc:foo --http=80 http://localhost:3000",
				"--service=svc:foo --http=80 --set-path=/api http://localhost:4000",
			},
			refused: `service "svc:foo": port 80: the config file format cannot represent mount point "/api"`,
		},
		{
			name:    "mount_point_without_root",
			cli:     []string{"--service=svc:foo --http=80 --set-path=/api http://localhost:4000"},
			refused: `service "svc:foo": port 80: the config file format cannot represent mount point "/api"`,
		},
		{
			name:    "accept_app_caps",
			cli:     []string{"--service=svc:foo --http=80 --accept-app-caps=example.com/cap/foo http://localhost:3000"},
			refused: `service "svc:foo": port 80: the config file format cannot represent --accept-app-caps`,
		},
		{
			name:    "proxy_protocol",
			cli:     []string{"--service=svc:foo --tcp=5432 --proxy-protocol=1 tcp://localhost:5432"},
			refused: `service "svc:foo": port 5432: the config file format cannot represent --proxy-protocol`,
		},
		{
			name:    "proxy_with_path",
			cli:     []string{"--service=svc:foo --http=80 http://localhost:3000/api"},
			refused: `service "svc:foo": port 80: the config file format cannot represent proxy "http://localhost:3000/api", only <scheme>://<host>:<port>`,
		},
		{
			name:    "proxy_with_trailing_slash",
			cli:     []string{"--service=svc:foo --http=80 http://localhost:3000/"},
			refused: `service "svc:foo": port 80: the config file format cannot represent proxy "http://localhost:3000/", only <scheme>://<host>:<port>`,
		},
		{
			name:    "proxy_with_query",
			cli:     []string{"--service=svc:foo --http=80 http://localhost:3000?x=1"},
			refused: `service "svc:foo": port 80: the config file format cannot represent proxy "http://localhost:3000?x=1", only <scheme>://<host>:<port>`,
		},
		{
			name:    "proxy_without_port",
			cli:     []string{"--service=svc:foo --http=80 http://example.com"},
			refused: `service "svc:foo": port 80: the config file format cannot represent proxy "http://example.com", only <scheme>://<host>:<port>`,
		},
		{
			// Not a CLI feature, but reachable through serve status --json.
			name:    "redirect",
			legacy:  `{"Services": {"svc:foo": {"TCP": {"80": {"HTTP": true}}, "Web": {"foo.test.ts.net:80": {"Handlers": {"/": {"Redirect": "https://example.com"}}}}}}}`,
			refused: `service "svc:foo": port 80: the config file format cannot represent a handler that is neither a path nor a proxy`,
		},

		// With more than one, the error is the same every time: the lowest
		// port of the first service by name.
		{
			name: "ports_in_order",
			cli: []string{
				"--service=svc:foo --tcp=5432 --proxy-protocol=1 tcp://localhost:5432",
				"--service=svc:foo --http=80 text:hello",
				"--service=svc:foo --http=8080 --set-path=/api http://localhost:4000",
			},
			refused: `service "svc:foo": port 80: the config file format cannot represent a text handler`,
		},
		{
			name: "services_in_order",
			cli: []string{
				"--service=svc:qux --tcp=5432 --proxy-protocol=1 tcp://localhost:5432",
				"--service=svc:foo --http=80 text:hello",
				"--service=svc:bar --tcp=22 tcp://localhost:22",
			},
			refused: `service "svc:foo": port 80: the config file format cannot represent a text handler`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lc := buildState(t, t.TempDir(), tt.cli)
			if tt.legacy != "" {
				if _, _, err := serveRun(lc, "set-config", "--all", writeTmpServeConfig(t, tt.legacy)); err != nil {
					t.Fatal(err)
				}
			}

			checkRefused(t, lc, "--service=svc:foo", tt.refused)
			checkRefused(t, lc, "--all", tt.refused)

			legacy := newServiceHostClient()
			if _, _, err := serveRun(legacy, "set-config", "--all", writeTmpServeConfig(t, runServeCmd(t, lc, "status", "--json"))); err != nil {
				t.Fatalf("set-config --all of serve status --json: %v", err)
			}
			assertSameState(t, lc, legacy)
		})
	}
}
