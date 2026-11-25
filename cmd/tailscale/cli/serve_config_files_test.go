// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"cmp"
	"fmt"
	"strings"
	"testing"

	"tailscale.com/feature/buildfeatures"
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
	hujson bool     // file is HuJSON, which needs support built in
}

// TestServeConfigExistingFiles pins what every 0.0.1 spelling set-config has
// accepted means, so existing files keep applying to the state they always
// did, without warnings. A row whose export is set is one get-config writes
// differently.
func TestServeConfigExistingFiles(t *testing.T) {
	testFileRows(t, []fileRow{
		// A string endpoint's scheme names both the listener and the back-end.
		{
			// The file from #18381: plaintext HTTP on port 443.
			name:  "http_on_443",
			file:  `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": "http://127.0.0.1:30123"}}}}`,
			means: []string{"--service=svc:foo --http=443 http://127.0.0.1:30123"},
		},
		{
			name:  "http",
			file:  `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:80": "http://localhost:3000"}}}}`,
			means: []string{"--service=svc:foo --http=80 http://localhost:3000"},
		},
		{
			name:  "https",
			file:  `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": "https://localhost:8443"}}}}`,
			means: []string{"--service=svc:foo --https=443 https://localhost:8443"},
		},
		{
			name:  "https_on_80",
			file:  `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:80": "https://localhost:8443"}}}}`,
			means: []string{"--service=svc:foo --https=80 https://localhost:8443"},
		},
		{
			name:  "tcp",
			file:  `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:5432": "tcp://localhost:5432"}}}}`,
			means: []string{"--service=svc:foo --tcp=5432 tcp://localhost:5432"},
		},
		{
			name:  "tls_terminated_tcp",
			file:  `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": "tls-terminated-tcp://localhost:9481"}}}}`,
			means: []string{"--service=svc:foo --tls-terminated-tcp=443 tcp://localhost:9481"},
		},
		{
			name:  "tun",
			file:  `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"*": "TUN"}}}}`,
			means: []string{"--service=svc:foo --tun"},
		},

		// https+insecure and file are served over HTTPS, on any port.
		{
			name:  "https_insecure",
			file:  `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:80": "https+insecure://localhost:8443"}}}}`,
			means: []string{"--service=svc:foo --https=80 https+insecure://localhost:8443"},
		},
		{
			name:  "file",
			file:  `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:80": "file://$DIR/index.html"}}}}`,
			means: []string{"--service=svc:foo --https=80 $DIR/index.html"},
		},
		{
			name:  "file_directory",
			file:  `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": "file://$DIR"}}}}`,
			means: []string{"--service=svc:foo --https=443 $DIR"},
		},
		{
			name:   "file_path_cleaned",
			file:   `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": "file://$DIR/./index.html"}}}}`,
			means:  []string{"--service=svc:foo --https=443 $DIR/index.html"},
			export: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": "file://$DIR/index.html"}}}}`,
		},
		{
			// Not a path, so served as a proxy to the port. The export names the
			// HTTPS listener, which a string to that proxy cannot.
			name:   "file_not_a_path",
			file:   `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": "file://3000"}}}}`,
			means:  []string{"--service=svc:foo --https=443 3000"},
			export: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": {"front": "https", "backend": "http://127.0.0.1:3000"}}}}}`,
		},

		// Unix sockets: tailscaled speaks plain HTTP or TCP to the socket.
		{
			name:  "http_unix",
			file:  `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:80": "http://unix:/run/app.sock"}}}}`,
			means: []string{"--service=svc:foo --http=80 unix:/run/app.sock"},
		},
		{
			name:  "http_unix_relative",
			file:  `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:80": "http://unix:relative.sock"}}}}`,
			means: []string{"--service=svc:foo --http=80 unix:relative.sock"},
		},
		{
			name:  "https_unix",
			file:  `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": "https://unix:/run/app.sock"}}}}`,
			means: []string{"--service=svc:foo --https=443 unix:/run/app.sock"},
		},
		{
			name:   "https_insecure_unix",
			file:   `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": "https+insecure://unix:/run/app.sock"}}}}`,
			means:  []string{"--service=svc:foo --https=443 unix:/run/app.sock"},
			export: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": "https://unix:/run/app.sock"}}}}`,
		},
		{
			name:  "tcp_unix",
			file:  `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:22": "tcp://unix:/run/ssh.sock"}}}}`,
			means: []string{"--service=svc:foo --tcp=22 unix:/run/ssh.sock"},
		},
		{
			name:  "tcp_unix_relative",
			file:  `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:22": "tcp://unix:relative.sock"}}}}`,
			means: []string{"--service=svc:foo --tcp=22 unix:relative.sock"},
		},
		{
			name:  "tls_terminated_tcp_unix",
			file:  `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": "tls-terminated-tcp://unix:/run/app.sock"}}}}`,
			means: []string{"--service=svc:foo --tls-terminated-tcp=443 unix:/run/app.sock"},
		},

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

		// Ports.
		{
			name: "port_range",
			file: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:8000-8002": "http://localhost:9000-9002"}}}}`,
			means: []string{
				"--service=svc:foo --http=8000 http://localhost:9000",
				"--service=svc:foo --http=8001 http://localhost:9001",
				"--service=svc:foo --http=8002 http://localhost:9002",
			},
			export: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {
				"tcp:8000": "http://localhost:9000",
				"tcp:8001": "http://localhost:9001",
				"tcp:8002": "http://localhost:9002"
			}}}}`,
		},
		{
			// A Unix socket has no ports, so every source port goes to it.
			name: "port_range_to_unix",
			file: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:8000-8001": "tcp://unix:/run/app.sock"}}}}`,
			means: []string{
				"--service=svc:foo --tcp=8000 unix:/run/app.sock",
				"--service=svc:foo --tcp=8001 unix:/run/app.sock",
			},
			export: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {
				"tcp:8000": "tcp://unix:/run/app.sock",
				"tcp:8001": "tcp://unix:/run/app.sock"
			}}}}`,
		},
		{
			name:  "max_port",
			file:  `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:65535": "http://localhost:8080"}}}}`,
			means: []string{"--service=svc:foo --http=65535 http://localhost:8080"},
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

		// Several at once, and the HuJSON a hand-written file may use.
		{
			name: "several_services",
			file: `{"version": "0.0.1", "services": {
				"svc:foo": {"endpoints": {
					"tcp:80": "http://localhost:3000",
					"tcp:443": "https+insecure://localhost:8443",
					"tcp:5432": "tcp://localhost:5432",
					"tcp:9481": "tls-terminated-tcp://localhost:9481"
				}},
				"svc:bar": {"endpoints": {"*": "TUN"}, "advertised": false}
			}}`,
			means: []string{
				"--service=svc:foo --http=80 http://localhost:3000",
				"--service=svc:foo --https=443 https+insecure://localhost:8443",
				"--service=svc:foo --tcp=5432 tcp://localhost:5432",
				"--service=svc:foo --tls-terminated-tcp=9481 tcp://localhost:9481",
				"--service=svc:bar --tun",
				"drain svc:bar",
			},
		},
		{
			name: "comments_and_trailing_commas",
			file: `{
				// A hand-written file.
				"version": "0.0.1",
				"services": {"svc:foo": {"endpoints": {"tcp:5432": "tcp://localhost:5432",},},},
			}`,
			means:  []string{"--service=svc:foo --tcp=5432 tcp://localhost:5432"},
			export: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:5432": "tcp://localhost:5432"}}}}`,
			hujson: true,
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

// TestServeConfigObjectFiles pins the object form of an endpoint, which names
// the listener as front and writes the back-end in the string form. get-config
// writes it only where the string would name a different listener.
func TestServeConfigObjectFiles(t *testing.T) {
	testFileRows(t, []fileRow{
		{
			name:  "https_to_http",
			file:  `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": {"front": "https", "backend": "http://localhost:3000"}}}}}`,
			means: []string{"--service=svc:foo --https=443 http://localhost:3000"},
		},
		{
			name:  "https_on_80_to_http",
			file:  `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:80": {"front": "https", "backend": "http://localhost:3000"}}}}}`,
			means: []string{"--service=svc:foo --https=80 http://localhost:3000"},
		},
		{
			name:  "http_to_https",
			file:  `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:80": {"front": "http", "backend": "https://localhost:8443"}}}}}`,
			means: []string{"--service=svc:foo --http=80 https://localhost:8443"},
		},
		{
			name:  "http_to_https_insecure",
			file:  `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:80": {"front": "http", "backend": "https+insecure://localhost:8443"}}}}}`,
			means: []string{"--service=svc:foo --http=80 https+insecure://localhost:8443"},
		},
		{
			name:  "http_to_file",
			file:  `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:80": {"front": "http", "backend": "file://$DIR/index.html"}}}}}`,
			means: []string{"--service=svc:foo --http=80 $DIR/index.html"},
		},
		{
			name: "port_range",
			file: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:8000-8001": {"front": "https", "backend": "http://localhost:9000-9001"}}}}}`,
			means: []string{
				"--service=svc:foo --https=8000 http://localhost:9000",
				"--service=svc:foo --https=8001 http://localhost:9001",
			},
			export: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {
				"tcp:8000": {"front": "https", "backend": "http://localhost:9000"},
				"tcp:8001": {"front": "https", "backend": "http://localhost:9001"}
			}}}}`,
		},
		{
			name: "beside_strings",
			file: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {
				"tcp:443": {"front": "https", "backend": "http://localhost:3000"},
				"tcp:80": "http://localhost:3000"
			}, "advertised": false}}}`,
			means: []string{
				"--service=svc:foo --https=443 http://localhost:3000",
				"--service=svc:foo --http=80 http://localhost:3000",
				"drain svc:foo",
			},
		},
		{
			name:  "service",
			flag:  "--service=svc:foo",
			file:  `{"version": "0.0.1", "endpoints": {"tcp:443": {"front": "https", "backend": "http://localhost:3000"}}}`,
			means: []string{"--service=svc:foo --https=443 http://localhost:3000"},
		},

		// An object where a string would have done is written back as the
		// string.
		{
			name:   "https_to_https",
			file:   `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": {"front": "https", "backend": "https://localhost:8443"}}}}}`,
			means:  []string{"--service=svc:foo --https=443 https://localhost:8443"},
			export: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": "https://localhost:8443"}}}}`,
		},
		{
			name:   "https_to_https_insecure",
			file:   `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": {"front": "https", "backend": "https+insecure://localhost:8443"}}}}}`,
			means:  []string{"--service=svc:foo --https=443 https+insecure://localhost:8443"},
			export: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": "https+insecure://localhost:8443"}}}}`,
		},
		{
			name:   "https_to_file",
			file:   `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": {"front": "https", "backend": "file://$DIR/index.html"}}}}}`,
			means:  []string{"--service=svc:foo --https=443 $DIR/index.html"},
			export: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": "file://$DIR/index.html"}}}}`,
		},
		{
			name:   "http_to_http",
			file:   `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:80": {"front": "http", "backend": "http://localhost:3000"}}}}}`,
			means:  []string{"--service=svc:foo --http=80 http://localhost:3000"},
			export: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:80": "http://localhost:3000"}}}}`,
		},
		{
			name:   "https_to_unix",
			file:   `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": {"front": "https", "backend": "http://unix:/run/app.sock"}}}}}`,
			means:  []string{"--service=svc:foo --https=443 unix:/run/app.sock"},
			export: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": "https://unix:/run/app.sock"}}}}`,
		},
		{
			name:   "tcp",
			file:   `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:5432": {"front": "tcp", "backend": "tcp://localhost:5432"}}}}}`,
			means:  []string{"--service=svc:foo --tcp=5432 tcp://localhost:5432"},
			export: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:5432": "tcp://localhost:5432"}}}}`,
		},
		{
			name:   "tls_terminated_tcp",
			file:   `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": {"front": "tls-terminated-tcp", "backend": "tcp://localhost:9481"}}}}}`,
			means:  []string{"--service=svc:foo --tls-terminated-tcp=443 tcp://localhost:9481"},
			export: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": "tls-terminated-tcp://localhost:9481"}}}}`,
		},
		{
			name:   "tls_terminated_tcp_to_unix",
			file:   `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": {"front": "tls-terminated-tcp", "backend": "tcp://unix:/run/app.sock"}}}}}`,
			means:  []string{"--service=svc:foo --tls-terminated-tcp=443 unix:/run/app.sock"},
			export: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": "tls-terminated-tcp://unix:/run/app.sock"}}}}`,
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
			if tt.hujson && !buildfeatures.HasHuJSONConf {
				t.Skip("built without HuJSON support")
			}
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

// TestServeConfigRejectedFiles pins files set-config refuses, by the end of
// its error, and checks the node is left as it was.
func TestServeConfigRejectedFiles(t *testing.T) {
	tests := []struct {
		name string
		flag string // --all if empty
		file string
		// The end of set-config's error. The JSON decoder words what comes
		// before it differently from run to run.
		err string
	}{
		{
			name: "missing_version",
			file: `{"services": {"svc:foo": {"endpoints": {"tcp:80": "http://localhost:3000"}}}}`,
			err:  `config file looks like a Services configuration file but is missing the required "version" field`,
		},
		{
			name: "unknown_version",
			file: `{"version": "0.0.2", "services": {"svc:foo": {"endpoints": {"tcp:80": "http://localhost:3000"}}}}`,
			err:  `unsupported config file version "0.0.2"`,
		},
		{
			name: "not_an_endpoint",
			file: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:80": 80}}}}`,
			err:  `unmarshal JSON number into Go string within "/services/svc:foo/endpoints/tcp:80"`,
		},

		// Object form: front must be a listener.
		{
			name: "front_missing",
			file: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": {"backend": "http://localhost:3000"}}}}}`,
			err:  `invalid front protocol ""`,
		},
		{
			name: "front_https_insecure",
			file: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": {"front": "https+insecure", "backend": "https://localhost:8443"}}}}}`,
			err:  `invalid front protocol "https+insecure"`,
		},
		{
			name: "front_file",
			file: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": {"front": "file", "backend": "file:///srv"}}}}}`,
			err:  `invalid front protocol "file"`,
		},
		{
			name: "front_tun",
			file: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"*": {"front": "TUN", "backend": "TUN"}}}}}`,
			err:  `invalid front protocol "TUN"`,
		},

		// Object form: the back-end must be one the listener can reach.
		{
			name: "backend_missing",
			file: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": {"front": "https"}}}}}`,
			err:  `handler not of form <proto>://<destination>`,
		},
		{
			name: "web_front_tcp_backend",
			file: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": {"front": "https", "backend": "tcp://localhost:22"}}}}}`,
			err:  `front protocol "https" cannot proxy to a "tcp" back-end`,
		},
		{
			name: "web_front_tls_terminated_tcp_backend",
			file: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": {"front": "http", "backend": "tls-terminated-tcp://localhost:22"}}}}}`,
			err:  `front protocol "http" cannot proxy to a "tls-terminated-tcp" back-end`,
		},
		{
			name: "web_front_tun_backend",
			file: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": {"front": "https", "backend": "TUN"}}}}}`,
			err:  `front protocol "https" cannot proxy to a "TUN" back-end`,
		},
		{
			name: "tcp_front_web_backend",
			file: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:5432": {"front": "tcp", "backend": "http://localhost:5432"}}}}}`,
			err:  `front protocol "tcp" cannot proxy to a "http" back-end`,
		},
		{
			name: "tcp_front_file_backend",
			file: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:5432": {"front": "tcp", "backend": "file:///srv"}}}}}`,
			err:  `front protocol "tcp" cannot proxy to a "file" back-end`,
		},
		{
			// TLS is terminated at the listener; the back-end is plain TCP.
			name: "tls_terminated_tcp_front_tls_terminated_tcp_backend",
			file: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": {"front": "tls-terminated-tcp", "backend": "tls-terminated-tcp://localhost:9481"}}}}}`,
			err:  `front protocol "tls-terminated-tcp" cannot proxy to a "tls-terminated-tcp" back-end`,
		},
		{
			// tailscaled speaks plain HTTP to a Unix socket.
			name: "unix_backend_over_https",
			file: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": {"front": "https", "backend": "https://unix:/run/app.sock"}}}}}`,
			err:  `unix socket "unix:/run/app.sock" must use the "http" back-end protocol`,
		},
		{
			name: "unix_backend_over_https_insecure",
			file: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": {"front": "https", "backend": "https+insecure://unix:/run/app.sock"}}}}}`,
			err:  `unix socket "unix:/run/app.sock" must use the "http" back-end protocol`,
		},
		{
			// A string's non-path file:// target is served as a proxy or
			// text; the object form refuses it.
			name: "file_backend_not_a_path",
			file: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:80": {"front": "http", "backend": "file://3000"}}}}}`,
			err:  `file path "3000" is not absolute`,
		},
		{
			name: "file_backend_text",
			file: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": {"front": "https", "backend": "file://text:hello"}}}}}`,
			err:  `file path "text:hello" is not absolute`,
		},
		{
			// A newer client may add members; this one must not drop them.
			name: "unknown_member",
			file: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:5432": {"front": "tcp", "backend": "tcp://localhost:5432", "proxyProtocol": 1}}}}}`,
			err:  `unknown object member name "proxyProtocol" within "/services/svc:foo/endpoints/tcp:5432"`,
		},
		{
			name: "single_service_object_incoherent",
			flag: "--service=svc:foo",
			file: `{"version": "0.0.1", "endpoints": {"tcp:443": {"front": "https", "backend": "tcp://localhost:22"}}}`,
			err:  `front protocol "https" cannot proxy to a "tcp" back-end`,
		},

		// What the CLI serves but the format has no way to say, in either
		// form. See TestServeConfigNotRepresentable for get-config's side.
		{
			name: "text",
			file: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:80": "text:hello"}}}}`,
			err:  `handler not of form <proto>://<destination>`,
		},
		{
			name: "text_backend",
			file: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:80": {"front": "http", "backend": "text:hello"}}}}}`,
			err:  `handler not of form <proto>://<destination>`,
		},
		{
			name: "proxy_with_path",
			file: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:80": "http://localhost:3000/api"}}}}`,
			err:  `port range "3000/api": invalid first integer`,
		},
		{
			name: "backend_with_path",
			file: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": {"front": "https", "backend": "http://localhost:3000/api"}}}}}`,
			err:  `port range "3000/api": invalid first integer`,
		},
		{
			name: "proxy_without_port",
			file: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:80": "http://example.com"}}}}`,
			err:  `hostport must contain a colon (":")`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := serveTestDir(t)
			flag := cmp.Or(tt.flag, "--all")
			path := writeTmpServeConfig(t, tt.file)
			node := buildState(t, dir, otherState)
			_, _, err := serveRun(node, "set-config", flag, path)
			prefix := fmt.Sprintf("could not read config from file %q: ", path)
			if err == nil || !strings.HasPrefix(err.Error(), prefix) || !strings.HasSuffix(err.Error(), tt.err) {
				t.Fatalf("set-config err = %v\nwant: %s...%s", err, prefix, tt.err)
			}
			assertSameState(t, buildState(t, dir, otherState), node)
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
			// A path, not a port.
			name:    "proxy_with_path_ending_in_port",
			cli:     []string{"--service=svc:foo --http=80 http://example.com/api:8080"},
			refused: `service "svc:foo": port 80: the config file format cannot represent proxy "http://example.com/api:8080", only <scheme>://<host>:<port>`,
		},
		{
			name:    "proxy_with_query_ending_in_port",
			cli:     []string{"--service=svc:foo --http=80 http://example.com?x=:8080"},
			refused: `service "svc:foo": port 80: the config file format cannot represent proxy "http://example.com?x=:8080", only <scheme>://<host>:<port>`,
		},
		{
			name:    "proxy_with_user",
			cli:     []string{"--service=svc:foo --http=80 http://user@localhost:3000"},
			refused: `service "svc:foo": port 80: the config file format cannot represent proxy "http://user@localhost:3000", only <scheme>://<host>:<port>`,
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

// TestServeConfigUncleanPaths pins get-config on a path the CLI would have
// cleaned, as serve status --json or set-raw can leave it: written as it is,
// and read back cleaned.
func TestServeConfigUncleanPaths(t *testing.T) {
	tests := []struct {
		name   string
		legacy string   // a serve status --json document that builds the state
		export string   // what get-config --all writes
		means  []string // tailscale serve commands that build what export applies
	}{
		{
			name:   "trailing_slash",
			legacy: `{"Services": {"svc:foo": {"TCP": {"443": {"HTTPS": true}}, "Web": {"foo.test.ts.net:443": {"Handlers": {"/": {"Path": "$DIR/"}}}}}}}`,
			export: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:443": "file://$DIR/"}}}}`,
			means:  []string{"--service=svc:foo --https=443 $DIR"},
		},
		{
			name:   "dot_object",
			legacy: `{"Services": {"svc:foo": {"TCP": {"80": {"HTTP": true}}, "Web": {"foo.test.ts.net:80": {"Handlers": {"/": {"Path": "$DIR/./index.html"}}}}}}}`,
			export: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:80": {"front": "http", "backend": "file://$DIR/./index.html"}}}}}`,
			means:  []string{"--service=svc:foo --http=80 $DIR/index.html"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			skipOnWindows(t, tt.legacy)
			dir := serveTestDir(t)
			lc := newServiceHostClient()
			if _, _, err := serveRun(lc, "set-config", "--all", writeTmpServeConfig(t, expandDir(tt.legacy, dir))); err != nil {
				t.Fatal(err)
			}
			export := expandDir(tt.export, dir)
			checkJSON(t, "get-config --all", export, runServeCmd(t, lc, "get-config", "--all"))
			got := newServiceHostClient()
			setConfig(t, got, "--all", export)
			assertSameState(t, buildState(t, dir, tt.means), got)
		})
	}
}
