// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_serve

package conffile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	jsonv2 "github.com/go-json-experiment/json"
	"tailscale.com/tailcfg"
)

func port(p uint16) tailcfg.PortRange { return tailcfg.PortRange{First: p, Last: p} }

// TestTargetMarshal verifies that a Target marshals to the shorthand string
// form when the back-end is the front-end's implied default, and to the object
// form otherwise so the back-end protocol is preserved.
func TestTargetMarshal(t *testing.T) {
	tests := []struct {
		name   string
		target Target
		want   string
	}{
		{
			name:   "https-front-http-backend",
			target: Target{Front: ProtoHTTPS, Backend: ProtoHTTP, Destination: "127.0.0.1", DestinationPorts: port(30123)},
			want:   `"https://127.0.0.1:30123"`,
		},
		{
			name:   "http-front-http-backend",
			target: Target{Front: ProtoHTTP, Backend: ProtoHTTP, Destination: "127.0.0.1", DestinationPorts: port(3000)},
			want:   `"http://127.0.0.1:3000"`,
		},
		{
			name:   "https-front-https-backend",
			target: Target{Front: ProtoHTTPS, Backend: ProtoHTTPS, Destination: "127.0.0.1", DestinationPorts: port(8443)},
			want:   `{"front":"https","backend":"https://127.0.0.1:8443"}`,
		},
		{
			name:   "https-front-https-insecure-backend",
			target: Target{Front: ProtoHTTPS, Backend: ProtoHTTPSInsecure, Destination: "127.0.0.1", DestinationPorts: port(8443)},
			want:   `"https+insecure://127.0.0.1:8443"`,
		},
		{
			name:   "http-front-https-backend",
			target: Target{Front: ProtoHTTP, Backend: ProtoHTTPS, Destination: "127.0.0.1", DestinationPorts: port(8443)},
			want:   `{"front":"http","backend":"https://127.0.0.1:8443"}`,
		},
		{
			name:   "https-front-file-backend",
			target: Target{Front: ProtoHTTPS, Backend: ProtoFile, Destination: "/var/www"},
			want:   `"file:///var/www"`,
		},
		{
			name:   "http-front-file-backend",
			target: Target{Front: ProtoHTTP, Backend: ProtoFile, Destination: "/var/www"},
			want:   `{"front":"http","backend":"file:///var/www"}`,
		},
		{
			name:   "tcp",
			target: Target{Front: ProtoTCP, Backend: ProtoTCP, Destination: "127.0.0.1", DestinationPorts: port(22)},
			want:   `"tcp://127.0.0.1:22"`,
		},
		{
			name:   "tls-terminated-tcp",
			target: Target{Front: ProtoTLSTerminatedTCP, Backend: ProtoTCP, Destination: "127.0.0.1", DestinationPorts: port(22)},
			want:   `"tls-terminated-tcp://127.0.0.1:22"`,
		},
		{
			name:   "tun",
			target: Target{Front: ProtoTUN, DestinationPorts: tailcfg.PortRangeAny},
			want:   `"TUN"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// serve get-config marshals with the standard library.
			got, err := json.Marshal(&tt.target)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("Marshal = %s; want %s", got, tt.want)
			}
		})
	}
}

// TestTargetUnmarshal verifies parsing of both the shorthand string form
// (including the back-end-only schemes) and the object form.
func TestTargetUnmarshal(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want Target
	}{
		{
			name: "https-shorthand-defaults-to-http-backend",
			in:   `"https://127.0.0.1:30123"`,
			want: Target{Front: ProtoHTTPS, Backend: ProtoHTTP, Destination: "127.0.0.1", DestinationPorts: port(30123)},
		},
		{
			name: "http-shorthand",
			in:   `"http://127.0.0.1:3000"`,
			want: Target{Front: ProtoHTTP, Backend: ProtoHTTP, Destination: "127.0.0.1", DestinationPorts: port(3000)},
		},
		{
			name: "https-insecure-shorthand-implies-https-front",
			in:   `"https+insecure://127.0.0.1:8443"`,
			want: Target{Front: ProtoHTTPS, Backend: ProtoHTTPSInsecure, Destination: "127.0.0.1", DestinationPorts: port(8443)},
		},
		{
			name: "file-shorthand-implies-https-front",
			in:   `"file:///var/www"`,
			want: Target{Front: ProtoHTTPS, Backend: ProtoFile, Destination: "/var/www"},
		},
		{
			name: "tcp-shorthand",
			in:   `"tcp://127.0.0.1:22"`,
			want: Target{Front: ProtoTCP, Backend: ProtoTCP, Destination: "127.0.0.1", DestinationPorts: port(22)},
		},
		{
			name: "tls-terminated-tcp-shorthand",
			in:   `"tls-terminated-tcp://127.0.0.1:22"`,
			want: Target{Front: ProtoTLSTerminatedTCP, Backend: ProtoTCP, Destination: "127.0.0.1", DestinationPorts: port(22)},
		},
		{
			name: "tun",
			in:   `"TUN"`,
			want: Target{Front: ProtoTUN, DestinationPorts: tailcfg.PortRangeAny},
		},
		{
			name: "object-https-backend",
			in:   `{"front":"https","backend":"https://127.0.0.1:8443"}`,
			want: Target{Front: ProtoHTTPS, Backend: ProtoHTTPS, Destination: "127.0.0.1", DestinationPorts: port(8443)},
		},
		{
			name: "object-http-front-file-backend",
			in:   `{"front":"http","backend":"file:///var/www"}`,
			want: Target{Front: ProtoHTTP, Backend: ProtoFile, Destination: "/var/www"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Target
			if err := jsonv2.Unmarshal([]byte(tt.in), &got); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if got != tt.want {
				t.Errorf("Unmarshal(%s) = %+v; want %+v", tt.in, got, tt.want)
			}
		})
	}
}

func TestTargetUnmarshalErrors(t *testing.T) {
	for _, in := range []string{
		`"bogus"`,                 // no <proto>://
		`"gopher://127.0.0.1:70"`, // unsupported protocol
		`{"front":"file","backend":"http://127.0.0.1:1"}`, // file is not a valid front
		`{"front":"TUN","backend":"http://127.0.0.1:1"}`,  // TUN has no object form
		`42`, // not a string or object
		// Incoherent front/back-end combinations: these parse field-by-field
		// but would fail at apply time, so they're rejected up front (#19724).
		`{"front":"tcp","backend":"http://127.0.0.1:80"}`,                // TCP front needs a tcp back-end
		`{"front":"tcp","backend":"file:///var/www"}`,                    // TCP front can't serve a file
		`{"front":"https","backend":"tcp://127.0.0.1:22"}`,               // web front can't proxy raw tcp
		`{"front":"tls-terminated-tcp","backend":"https://127.0.0.1:1"}`, // TCP front needs a tcp back-end
	} {
		var got Target
		if err := jsonv2.Unmarshal([]byte(in), &got); err == nil {
			t.Errorf("Unmarshal(%s) = nil error; want error", in)
		}
	}
}

// TestLoadServicesConfigMigration pins how the loader reads the one shorthand
// whose meaning changed between 0.0.1 and 0.0.2: a bare "https://" endpoint. It
// is read with the fixed meaning in both (an HTTPS front with a plain-HTTP
// back-end), but a 0.0.1 file gets a warning because that is the version where
// the meaning changed (it formerly named a TLS back-end).
func TestLoadServicesConfigMigration(t *testing.T) {
	load := func(t *testing.T, body string) (*ServicesConfigFile, []string) {
		t.Helper()
		f := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(f, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		cfg, warnings, err := LoadServicesConfig(f, "")
		if err != nil {
			t.Fatalf("LoadServicesConfig: %v", err)
		}
		return cfg, warnings
	}
	backend := func(t *testing.T, cfg *ServicesConfigFile) ServiceProtocol {
		t.Helper()
		for _, sdf := range cfg.Services {
			for _, tgt := range sdf.Endpoints {
				return tgt.Backend
			}
		}
		t.Fatal("no endpoint found")
		return ""
	}

	// A pre-change 0.0.1 file: "https://" named a TLS back-end.
	const httpsBody = `{"version":%q,"services":{"svc:web":{"endpoints":{"tcp:443":"https://127.0.0.1:8443"}}}}`

	t.Run("v1-uses-fixed-http-backend-and-warns", func(t *testing.T) {
		cfg, warnings := load(t, fmt.Sprintf(httpsBody, "0.0.1"))
		if got := backend(t, cfg); got != ProtoHTTP {
			t.Errorf("backend = %q; want %q (0.0.1 https:// read with the fixed front-naming meaning)", got, ProtoHTTP)
		}
		if len(warnings) != 1 {
			t.Fatalf("warnings = %v; want exactly one migration warning", warnings)
		}
		if !strings.Contains(warnings[0], "svc:web") || !strings.Contains(warnings[0], "https://") {
			t.Errorf("warning = %q; want it to name the service and the https:// shorthand", warnings[0])
		}
	})

	t.Run("v2-uses-http-backend-no-warning", func(t *testing.T) {
		cfg, warnings := load(t, fmt.Sprintf(httpsBody, "0.0.2"))
		if got := backend(t, cfg); got != ProtoHTTP {
			t.Errorf("backend = %q; want %q (new meaning)", got, ProtoHTTP)
		}
		if len(warnings) != 0 {
			t.Errorf("warnings = %v; want none for a 0.0.2 file", warnings)
		}
	})

	t.Run("v1-http-shorthand-unchanged-no-warning", func(t *testing.T) {
		cfg, warnings := load(t, `{"version":"0.0.1","services":{"svc:web":{"endpoints":{"tcp:80":"http://127.0.0.1:3000"}}}}`)
		if got := backend(t, cfg); got != ProtoHTTP {
			t.Errorf("backend = %q; want %q", got, ProtoHTTP)
		}
		if len(warnings) != 0 {
			t.Errorf("warnings = %v; want none for an http:// shorthand", warnings)
		}
	})
}

// TestLoadServicesConfigVersion verifies that the loader accepts both 0.0.1 and
// 0.0.2 (parsing the object form under either, leniently) and rejects a missing
// or unknown version.
func TestLoadServicesConfigVersion(t *testing.T) {
	for _, tt := range []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"v1-shorthand", `{"version":"0.0.1","services":{"svc:web":{"endpoints":{"tcp:443":"https://127.0.0.1:3000"}}}}`, false},
		{"v2-object", `{"version":"0.0.2","services":{"svc:web":{"endpoints":{"tcp:443":{"front":"https","backend":"https://127.0.0.1:8443"}}}}}`, false},
		{"v2-shorthand", `{"version":"0.0.2","services":{"svc:web":{"endpoints":{"tcp:443":"https://127.0.0.1:3000"}}}}`, false},
		{"v1-with-object-is-lenient", `{"version":"0.0.1","services":{"svc:web":{"endpoints":{"tcp:443":{"front":"https","backend":"https://127.0.0.1:8443"}}}}}`, false},
		{"missing-version", `{"services":{"svc:web":{"endpoints":{"tcp:443":"https://127.0.0.1:3000"}}}}`, true},
		{"unknown-version", `{"version":"9.9.9","services":{"svc:web":{"endpoints":{"tcp:443":"https://127.0.0.1:3000"}}}}`, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(f, []byte(tt.body), 0600); err != nil {
				t.Fatal(err)
			}
			_, _, err := LoadServicesConfig(f, "")
			if (err != nil) != tt.wantErr {
				t.Fatalf("LoadServicesConfig err = %v; wantErr = %v", err, tt.wantErr)
			}
		})
	}
}
