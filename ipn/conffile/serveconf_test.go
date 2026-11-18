// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_serve

package conffile

import (
	"cmp"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tailscale.com/tailcfg"
)

func TestTargetUnixSocketRoundtrip(t *testing.T) {
	tests := []struct {
		name       string
		serialized string
		want       Target
	}{
		{
			name:       "tcp_unix_socket",
			serialized: "tcp://unix:/var/run/app.sock",
			want: Target{
				Front:       ProtoTCP,
				Protocol:    ProtoTCP,
				Destination: "unix:/var/run/app.sock",
			},
		},
		{
			name:       "tls_terminated_tcp_unix_socket",
			serialized: "tls-terminated-tcp://unix:/var/run/app.sock",
			want: Target{
				Front:       ProtoTLSTerminatedTCP,
				Protocol:    ProtoTLSTerminatedTCP,
				Destination: "unix:/var/run/app.sock",
			},
		},
		{
			name:       "tcp_unix_socket_relative",
			serialized: "tcp://unix:relative.sock",
			want: Target{
				Front:       ProtoTCP,
				Protocol:    ProtoTCP,
				Destination: "unix:relative.sock",
			},
		},
		{
			name:       "http_unix_socket",
			serialized: "http://unix:/var/run/app.sock",
			want: Target{
				Front:       ProtoHTTP,
				Protocol:    ProtoHTTP,
				Destination: "unix:/var/run/app.sock",
			},
		},
		{
			name:       "https_unix_socket",
			serialized: "https://unix:/var/run/app.sock",
			want: Target{
				Front:       ProtoHTTPS,
				Protocol:    ProtoHTTPS,
				Destination: "unix:/var/run/app.sock",
			},
		},
		{
			name:       "https_insecure_unix_socket",
			serialized: "https+insecure://unix:/var/run/app.sock",
			want: Target{
				Front:       ProtoHTTPS,
				Protocol:    ProtoHTTPSInsecure,
				Destination: "unix:/var/run/app.sock",
			},
		},
		{
			name:       "http_unix_socket_relative",
			serialized: "http://unix:relative.sock",
			want: Target{
				Front:       ProtoHTTP,
				Protocol:    ProtoHTTP,
				Destination: "unix:relative.sock",
			},
		},
		{
			name:       "tcp_host_port",
			serialized: "tcp://localhost:5432",
			want: Target{
				Front:            ProtoTCP,
				Protocol:         ProtoTCP,
				Destination:      "localhost",
				DestinationPorts: tailcfg.PortRange{First: 5432, Last: 5432},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test unmarshal
			var got Target
			if err := got.UnmarshalJSON([]byte(`"` + tt.serialized + `"`)); err != nil {
				t.Fatalf("UnmarshalJSON(%q) failed: %v", tt.serialized, err)
			}
			if got != tt.want {
				t.Errorf("UnmarshalJSON(%q) = %+v, want %+v", tt.serialized, got, tt.want)
			}

			// Test marshal roundtrip
			marshaled, err := tt.want.MarshalText()
			if err != nil {
				t.Fatalf("MarshalText() failed: %v", err)
			}
			if string(marshaled) != tt.serialized {
				t.Errorf("MarshalText() = %q, want %q", marshaled, tt.serialized)
			}
		})
	}
}

func port(p uint16) tailcfg.PortRange { return tailcfg.PortRange{First: p, Last: p} }

// TestTargetJSON pins how an endpoint reads into a Target and is written back.
// A string names the listener by its scheme; an object names it as front, with
// the back-end in the string form. A Target is written as the string the
// loader reads back as it, or failing that as the object.
func TestTargetJSON(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want Target
		out  string // what MarshalJSON writes for want; in if empty
	}{
		// Strings. https+insecure and file are served over HTTPS.
		{
			name: "http",
			in:   `"http://127.0.0.1:3000"`,
			want: Target{Front: ProtoHTTP, Protocol: ProtoHTTP, Destination: "127.0.0.1", DestinationPorts: port(3000)},
		},
		{
			name: "https",
			in:   `"https://127.0.0.1:8443"`,
			want: Target{Front: ProtoHTTPS, Protocol: ProtoHTTPS, Destination: "127.0.0.1", DestinationPorts: port(8443)},
		},
		{
			name: "https_insecure",
			in:   `"https+insecure://127.0.0.1:8443"`,
			want: Target{Front: ProtoHTTPS, Protocol: ProtoHTTPSInsecure, Destination: "127.0.0.1", DestinationPorts: port(8443)},
		},
		{
			name: "file",
			in:   `"file:///var/www"`,
			want: Target{Front: ProtoHTTPS, Protocol: ProtoFile, Destination: "/var/www"},
		},
		{
			name: "tcp",
			in:   `"tcp://127.0.0.1:22"`,
			want: Target{Front: ProtoTCP, Protocol: ProtoTCP, Destination: "127.0.0.1", DestinationPorts: port(22)},
		},
		{
			name: "tls_terminated_tcp",
			in:   `"tls-terminated-tcp://127.0.0.1:22"`,
			want: Target{Front: ProtoTLSTerminatedTCP, Protocol: ProtoTLSTerminatedTCP, Destination: "127.0.0.1", DestinationPorts: port(22)},
		},
		{
			name: "tun",
			in:   `"TUN"`,
			want: Target{Front: ProtoTUN, Protocol: ProtoTUN, DestinationPorts: tailcfg.PortRangeAny},
		},
		{
			name: "port_range",
			in:   `"http://localhost:9000-9002"`,
			want: Target{Front: ProtoHTTP, Protocol: ProtoHTTP, Destination: "localhost", DestinationPorts: tailcfg.PortRange{First: 9000, Last: 9002}},
		},

		// Hosts are kept as written, and IPv6 hosts are unbracketed in memory
		// as net.JoinHostPort expects.
		{
			name: "ipv6",
			in:   `"tcp://[::1]:5432"`,
			want: Target{Front: ProtoTCP, Protocol: ProtoTCP, Destination: "::1", DestinationPorts: port(5432)},
		},
		{
			name: "ipv6_unbracketed",
			in:   `"tcp://::1:5432"`,
			want: Target{Front: ProtoTCP, Protocol: ProtoTCP, Destination: "::1", DestinationPorts: port(5432)},
			out:  `"tcp://[::1]:5432"`,
		},
		{
			name: "ipv6_zone",
			in:   `"tcp://[fe80::1%eth0]:5432"`,
			want: Target{Front: ProtoTCP, Protocol: ProtoTCP, Destination: "fe80::1%eth0", DestinationPorts: port(5432)},
		},
		{
			name: "host_case",
			in:   `"http://App.Example.com:3000"`,
			want: Target{Front: ProtoHTTP, Protocol: ProtoHTTP, Destination: "App.Example.com", DestinationPorts: port(3000)},
		},

		// Objects.
		{
			name: "object_https_to_http",
			in:   `{"front":"https","backend":"http://127.0.0.1:3000"}`,
			want: Target{Front: ProtoHTTPS, Protocol: ProtoHTTP, Destination: "127.0.0.1", DestinationPorts: port(3000)},
		},
		{
			name: "object_http_to_https",
			in:   `{"front":"http","backend":"https://127.0.0.1:8443"}`,
			want: Target{Front: ProtoHTTP, Protocol: ProtoHTTPS, Destination: "127.0.0.1", DestinationPorts: port(8443)},
		},
		{
			name: "object_http_to_https_insecure",
			in:   `{"front":"http","backend":"https+insecure://127.0.0.1:8443"}`,
			want: Target{Front: ProtoHTTP, Protocol: ProtoHTTPSInsecure, Destination: "127.0.0.1", DestinationPorts: port(8443)},
		},
		{
			name: "object_http_to_file",
			in:   `{"front":"http","backend":"file:///var/www"}`,
			want: Target{Front: ProtoHTTP, Protocol: ProtoFile, Destination: "/var/www"},
		},
		{
			name: "object_ipv6",
			in:   `{"front":"https","backend":"http://[::1]:3000"}`,
			want: Target{Front: ProtoHTTPS, Protocol: ProtoHTTP, Destination: "::1", DestinationPorts: port(3000)},
		},
		{
			name: "object_https_to_unix",
			in:   `{"front":"https","backend":"http://unix:/run/app.sock"}`,
			want: Target{Front: ProtoHTTPS, Protocol: ProtoHTTP, Destination: "unix:/run/app.sock"},
		},
		{
			name: "object_tls_terminated_tcp",
			in:   `{"front":"tls-terminated-tcp","backend":"tcp://127.0.0.1:22"}`,
			want: Target{Front: ProtoTLSTerminatedTCP, Protocol: ProtoTCP, Destination: "127.0.0.1", DestinationPorts: port(22)},
		},
		{
			// The same Target as its string, so written as the string.
			name: "object_https_to_https",
			in:   `{"front":"https","backend":"https://127.0.0.1:8443"}`,
			want: Target{Front: ProtoHTTPS, Protocol: ProtoHTTPS, Destination: "127.0.0.1", DestinationPorts: port(8443)},
			out:  `"https://127.0.0.1:8443"`,
		},
		{
			name: "object_tcp",
			in:   `{"front":"tcp","backend":"tcp://127.0.0.1:22"}`,
			want: Target{Front: ProtoTCP, Protocol: ProtoTCP, Destination: "127.0.0.1", DestinationPorts: port(22)},
			out:  `"tcp://127.0.0.1:22"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Target
			if err := got.UnmarshalJSON([]byte(tt.in)); err != nil {
				t.Fatalf("Unmarshal(%s): %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("Unmarshal(%s) = %+v; want %+v", tt.in, got, tt.want)
			}
			// get-config writes with the standard library.
			b, err := json.Marshal(&tt.want)
			if err != nil {
				t.Fatalf("Marshal(%+v): %v", tt.want, err)
			}
			if want := cmp.Or(tt.out, tt.in); string(b) != want {
				t.Errorf("Marshal(%+v) = %s; want %s", tt.want, b, want)
			}
		})
	}
}

// TestTargetJSONErrors pins endpoints the loader refuses, by the end of the
// error.
func TestTargetJSONErrors(t *testing.T) {
	tests := []struct {
		in  string
		err string
	}{
		{`"bogus"`, `handler not of form <proto>://<destination>`},
		{`"gopher://127.0.0.1:70"`, `unsupported protocol`},
		{`"tcp://unix:"`, `unix socket path cannot be empty`},
		{`"http://127.0.0.1:3000/api"`, `port range "3000/api": invalid first integer`},

		// front must be a listener.
		{`{"backend":"http://127.0.0.1:3000"}`, `invalid front protocol ""`},
		{`{"front":"https+insecure","backend":"https://127.0.0.1:8443"}`, `invalid front protocol "https+insecure"`},
		{`{"front":"file","backend":"file:///var/www"}`, `invalid front protocol "file"`},
		{`{"front":"TUN","backend":"TUN"}`, `invalid front protocol "TUN"`},

		// backend must be one the listener can reach.
		{`{"front":"https"}`, `handler not of form <proto>://<destination>`},
		{`{"front":"https","backend":"tcp://127.0.0.1:22"}`, `front protocol "https" cannot proxy to a "tcp" back-end`},
		{`{"front":"http","backend":"tls-terminated-tcp://127.0.0.1:22"}`, `front protocol "http" cannot proxy to a "tls-terminated-tcp" back-end`},
		{`{"front":"https","backend":"TUN"}`, `front protocol "https" cannot proxy to a "TUN" back-end`},
		{`{"front":"tcp","backend":"http://127.0.0.1:80"}`, `front protocol "tcp" cannot proxy to a "http" back-end`},
		{`{"front":"tcp","backend":"file:///var/www"}`, `front protocol "tcp" cannot proxy to a "file" back-end`},
		{`{"front":"tls-terminated-tcp","backend":"tls-terminated-tcp://127.0.0.1:22"}`, `front protocol "tls-terminated-tcp" cannot proxy to a "tls-terminated-tcp" back-end`},
		{`{"front":"https","backend":"https://unix:/run/app.sock"}`, `unix socket "unix:/run/app.sock" must use the "http" back-end protocol`},
		{`{"front":"https","backend":"https+insecure://unix:/run/app.sock"}`, `unix socket "unix:/run/app.sock" must use the "http" back-end protocol`},
		{`{"front":"tcp","backend":"tcp://127.0.0.1:22","proxyProtocol":1}`, `unknown object member name "proxyProtocol"`},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			var got Target
			err := got.UnmarshalJSON([]byte(tt.in))
			if err == nil || !strings.HasSuffix(err.Error(), tt.err) {
				t.Errorf("Unmarshal(%s) err = %v; want ...%s", tt.in, err, tt.err)
			}
		})
	}
}

// TestTargetMarshalErrors pins Targets that neither form can say, which
// MarshalJSON refuses rather than write a file the loader reads differently.
func TestTargetMarshalErrors(t *testing.T) {
	tests := []struct {
		name   string
		target Target
		err    string
	}{
		{
			name:   "no_front",
			target: Target{Protocol: ProtoHTTP, Destination: "127.0.0.1", DestinationPorts: port(3000)},
			err:    `invalid front protocol ""`,
		},
		{
			name:   "web_front_tcp_backend",
			target: Target{Front: ProtoHTTPS, Protocol: ProtoTCP, Destination: "127.0.0.1", DestinationPorts: port(22)},
			err:    `front protocol "https" cannot proxy to a "tcp" back-end`,
		},
		{
			name:   "unix_over_https",
			target: Target{Front: ProtoHTTP, Protocol: ProtoHTTPS, Destination: "unix:/run/app.sock"},
			err:    `unix socket "unix:/run/app.sock" must use the "http" back-end protocol`,
		},
		{
			// Bracketed in memory, so bracketed twice in the file.
			name:   "bracketed_host",
			target: Target{Front: ProtoHTTPS, Protocol: ProtoHTTP, Destination: "[::1]", DestinationPorts: port(3000)},
			err:    `endpoint "http://[[::1]]:3000" does not read back as written`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := json.Marshal(&tt.target)
			if err == nil || !strings.HasSuffix(err.Error(), tt.err) {
				t.Errorf("Marshal(%+v) = %s, %v; want error ...%s", tt.target, b, err, tt.err)
			}
		})
	}
}

func TestLoadServicesConfigNull(t *testing.T) {
	tests := []struct {
		name       string
		forService string
		config     string
		wantErr    string
	}{
		{
			name:    "null_service",
			config:  `{"version":"0.0.1","services":{"svc:a":null}}`,
			wantErr: `service "svc:a": must not be null`,
		},
		{
			name:    "null_endpoint",
			config:  `{"version":"0.0.1","services":{"svc:a":{"endpoints":{"tcp:443":null}}}}`,
			wantErr: `service "svc:a": endpoint "tcp:443": must not be null`,
		},
		{
			name:       "null_endpoint_for_service",
			forService: "svc:a",
			config:     `{"version":"0.0.1","endpoints":{"tcp:443":null}}`,
			wantErr:    `service "svc:a": endpoint "tcp:443": must not be null`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(tt.config), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadServicesConfig(path, tt.forService)
			if err == nil {
				t.Fatalf("LoadServicesConfig succeeded; want error %q", tt.wantErr)
			}
			if err.Error() != tt.wantErr {
				t.Errorf("LoadServicesConfig error = %q; want %q", err, tt.wantErr)
			}
		})
	}
}
