// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_serve

package conffile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/peercap"
)

const testMDS = "example.ts.net"

// testAbsPath is a path that is absolute on the OS that runs the tests.
var testAbsPath = func() string {
	if runtime.GOOS == "windows" {
		return `C:\var\www`
	}
	return "/var/www"
}()

// withTestAbsPath returns the JSON document config with every "/var/www"
// replaced by [testAbsPath].
func withTestAbsPath(t *testing.T, config string) string {
	t.Helper()
	j, err := json.Marshal(testAbsPath)
	if err != nil {
		t.Fatal(err)
	}
	// Drop the quotes, because the path can be part of a longer string.
	return strings.ReplaceAll(config, "/var/www", string(j[1:len(j)-1]))
}

// skipIfNoUnixSocketProxy skips the test on an OS where a web route cannot
// proxy to a Unix socket.
func skipIfNoUnixSocketProxy(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("a Unix socket proxy target is not supported on Windows")
	}
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// applyAll applies every Service in sf to a new serve config.
func applyAll(t *testing.T, sf *ServicesFile) *ipn.ServeConfig {
	t.Helper()
	sc := new(ipn.ServeConfig)
	for name, svc := range sf.Services {
		if err := svc.ApplyTo(sc, name, testMDS); err != nil {
			t.Fatalf("ApplyTo(%q): %v", name, err)
		}
	}
	return sc
}

func TestLoadServicesFileV1(t *testing.T) {
	const config = `{
		"version": "0.1.0",
		"services": {
			"svc:web": {
				"advertised": false,
				"listeners": {
					"443": {
						"protocol": "https",
						"routes": {
							"/":     {"proxy": {"url": "http://127.0.0.1:8080", "http": "h2c"}, "acceptAppCaps": ["example.com/cap/x"]},
							"/tls":  {"proxy": {"url": "https://10.0.0.1:8443", "insecureSkipVerify": true}},
							"/doc/": {"path": "/var/www"},
							"/hi":   {"text": "hello"},
							"/old":  {"redirect": "301:https://example.com"}
						}
					},
					"80":   {"protocol": "http", "routes": {"/": {"proxy": {"url": "http://127.0.0.1:8080"}}}},
					"5432": {"protocol": "tls-terminated-tcp", "forward": {"addr": "127.0.0.1:5432", "proxyProtocol": 2}},
					"22":   {"protocol": "tcp", "forward": {"addr": "unix:/run/ssh.sock"}}
				}
			},
			"svc:l3": {"tun": true}
		}
	}`
	sf, err := LoadServicesFile(writeConfig(t, withTestAbsPath(t, config)), "")
	if err != nil {
		t.Fatal(err)
	}
	if sf.Version != ConfigVersionV1 {
		t.Errorf("Version = %q, want %q", sf.Version, ConfigVersionV1)
	}
	if v, ok := sf.Services["svc:web"].Advertised.Get(); !ok || v {
		t.Errorf("svc:web Advertised = %v, %v; want false, true", v, ok)
	}

	const host = "web." + testMDS
	want := &ipn.ServeConfig{Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
		"svc:web": {
			TCP: map[uint16]*ipn.TCPPortHandler{
				443:  {HTTPS: true},
				80:   {HTTP: true},
				5432: {TCPForward: "127.0.0.1:5432", TerminateTLS: host, ProxyProtocol: 2},
				22:   {TCPForward: "unix:/run/ssh.sock"},
			},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				host + ":443": {Handlers: map[string]*ipn.HTTPHandler{
					"/":     {Proxy: "http://127.0.0.1:8080", BackendHTTP: "h2c", AcceptAppCaps: []peercap.Cap{"example.com/cap/x"}},
					"/tls":  {Proxy: "https+insecure://10.0.0.1:8443"},
					"/doc/": {Path: testAbsPath},
					"/hi":   {Text: "hello"},
					"/old":  {Redirect: "301:https://example.com"},
				}},
				host + ":80": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "http://127.0.0.1:8080"},
				}},
			},
		},
		"svc:l3": {Tun: true},
	}}
	if diff := cmp.Diff(want, applyAll(t, sf)); diff != "" {
		t.Errorf("applied serve config (-want +got):\n%s", diff)
	}
}

func TestLoadServicesFileUnixSocketProxy(t *testing.T) {
	skipIfNoUnixSocketProxy(t)
	const host = "web." + testMDS
	want := &ipn.ServeConfig{Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
		"svc:web": {
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				host + ":443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "unix:/run/app.sock"},
				}},
			},
		},
	}}
	tests := []struct {
		name   string
		config string
	}{
		{"v1", `{"version":"0.1.0","services":{"svc:web":{"listeners":{"443":{"protocol":"https","routes":{"/":{"proxy":{"url":"unix:/run/app.sock"}}}}}}}}`},
		{"v0", `{"version":"0.0.1","services":{"svc:web":{"endpoints":{"tcp:443":"https://unix:/run/app.sock"}}}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sf, err := LoadServicesFile(writeConfig(t, tt.config), "")
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(want, applyAll(t, sf)); diff != "" {
				t.Errorf("applied serve config (-want +got):\n%s", diff)
			}
		})
	}
}

func TestLoadServicesFileV1ForService(t *testing.T) {
	const config = `{"version": "0.1.0", "listeners": {"443": {"protocol": "https", "routes": {"/": {"text": "hi"}}}}}`
	sf, err := LoadServicesFile(writeConfig(t, config), "svc:one")
	if err != nil {
		t.Fatal(err)
	}
	if len(sf.Services) != 1 || sf.Services["svc:one"] == nil {
		t.Fatalf("Services = %v, want only svc:one", sf.Services)
	}
}

func TestLoadServicesFileV1Errors(t *testing.T) {
	// listener wraps one listener on port 443 of svc:a in a whole file.
	listener := func(body string) string {
		return `{"version":"0.1.0","services":{"svc:a":{"listeners":{"443":` + body + `}}}}`
	}
	route := func(r string) string {
		return listener(`{"protocol":"https","routes":{"/":` + r + `}}`)
	}
	tests := []struct {
		name    string
		config  string
		wantErr string
	}{
		{"unknown_version", `{"version":"9.9.9"}`, `unsupported config file version "9.9.9"`},
		{"missing_version", `{"services":{}}`, `missing the required "version" field`},
		{"missing_version_single", `{"listeners":{}}`, `missing the required "version" field`},
		{"unknown_field", `{"version":"0.1.0","services":{"svc:a":{"funnel":true}}}`, `unknown`},
		{"v0_field_in_v1", `{"version":"0.1.0","services":{"svc:a":{"endpoints":{}}}}`, `unknown`},
		{"bad_service_name", `{"version":"0.1.0","services":{"web":{}}}`, `svc:`},
		{"null_service", `{"version":"0.1.0","services":{"svc:a":null}}`, `service "svc:a": must not be null`},
		{"nested_version", `{"version":"0.1.0","services":{"svc:a":{"version":"0.1.0"}}}`, `cannot be versioned separately`},
		{"tun_and_listeners", `{"version":"0.1.0","services":{"svc:a":{"tun":true,"listeners":{"443":{"protocol":"https","routes":{"/":{"text":"x"}}}}}}}`, `cannot mix TUN mode with listeners`},
		{"port_zero", `{"version":"0.1.0","services":{"svc:a":{"listeners":{"0":{"protocol":"tcp","forward":{"addr":"127.0.0.1:1"}}}}}}`, `port must not be 0`},
		{"port_range_key", `{"version":"0.1.0","services":{"svc:a":{"listeners":{"80-90":{"protocol":"tcp","forward":{"addr":"127.0.0.1:1"}}}}}}`, `80-90`},
		{"null_listener", listener(`null`), `listener 443: must not be null`},
		{"missing_protocol", listener(`{"routes":{"/":{"text":"x"}}}`), `missing "protocol"`},
		{"backend_scheme_as_protocol", listener(`{"protocol":"https+insecure","routes":{"/":{"text":"x"}}}`), `unsupported protocol "https+insecure"`},
		{"https_with_forward", listener(`{"protocol":"https","forward":{"addr":"127.0.0.1:1"}}`), `does not take "forward"`},
		{"https_without_routes", listener(`{"protocol":"https"}`), `requires "routes"`},
		{"tcp_with_routes", listener(`{"protocol":"tcp","routes":{"/":{"text":"x"}}}`), `does not take "routes"`},
		{"tcp_without_forward", listener(`{"protocol":"tcp"}`), `requires "forward"`},
		{"forward_no_port", listener(`{"protocol":"tcp","forward":{"addr":"localhost"}}`), `addr "localhost"`},
		{"forward_port_zero", listener(`{"protocol":"tcp","forward":{"addr":"localhost:0"}}`), `invalid port`},
		{"forward_unix_proxy_protocol", listener(`{"protocol":"tcp","forward":{"addr":"unix:/s","proxyProtocol":1}}`), `not supported with unix socket`},
		{"forward_proxy_protocol_3", listener(`{"protocol":"tcp","forward":{"addr":"localhost:1","proxyProtocol":3}}`), `unsupported PROXY protocol version 3`},
		{"mount_without_slash", listener(`{"protocol":"https","routes":{"api":{"text":"x"}}}`), `must start with "/"`},
		{"duplicate_mount", listener(`{"protocol":"https","routes":{"/a":{"text":"x"},"/a/":{"text":"y"}}}`), `routes "/a" and "/a/" are the same mount point`},
		{"null_route", route(`null`), `route "/": must not be null`},
		{"empty_route", route(`{}`), `exactly one of`},
		{"two_handlers", route(`{"text":"x","redirect":"https://example.com"}`), `exactly one of`},
		{"caps_without_proxy", route(`{"text":"x","acceptAppCaps":["example.com/cap/x"]}`), `"acceptAppCaps" requires "proxy"`},
		{"relative_path", route(`{"path":"www"}`), `must be absolute`},
		{"proxy_no_scheme", route(`{"proxy":{"url":"127.0.0.1:8080"}}`), `must start with`},
		{"proxy_insecure_scheme", route(`{"proxy":{"url":"https+insecure://127.0.0.1:8080"}}`), `must start with`},
		{"proxy_insecure_http", route(`{"proxy":{"url":"http://127.0.0.1:8080","insecureSkipVerify":true}}`), `requires an "https://" url`},
		{"proxy_h2c_https", route(`{"proxy":{"url":"https://127.0.0.1:8443","http":"h2c"}}`), `requires a plaintext url`},
		{"proxy_bad_http", route(`{"proxy":{"url":"http://127.0.0.1:8080","http":"h3"}}`), `unsupported "http" value "h3"`},
		{"proxy_localhost_no_port", route(`{"proxy":{"url":"http://localhost"}}`), `port required`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadServicesFile(writeConfig(t, tt.config), "")
			if err == nil {
				t.Fatalf("LoadServicesFile succeeded; want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("LoadServicesFile error = %q; want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// TestServiceFileRoundTrip tests that exporting a Service, writing the file,
// loading it, and applying it reproduces the Service exactly.
func TestServiceFileRoundTrip(t *testing.T) {
	const name = tailcfg.ServiceName("svc:web")
	const host = "web." + testMDS
	web := func(tcp *ipn.TCPPortHandler, handlers map[string]*ipn.HTTPHandler) *ipn.ServiceConfig {
		return &ipn.ServiceConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: tcp},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{host + ":443": {Handlers: handlers}},
		}
	}
	root := func(h *ipn.HTTPHandler) map[string]*ipn.HTTPHandler {
		return map[string]*ipn.HTTPHandler{"/": h}
	}
	tests := []struct {
		name string
		cfg  *ipn.ServiceConfig
	}{
		{"empty", &ipn.ServiceConfig{}},
		{"tun", &ipn.ServiceConfig{Tun: true}},
		// The tailscale/tailscale#18381 case.
		{"https_listener_http_backend", web(&ipn.TCPPortHandler{HTTPS: true}, root(&ipn.HTTPHandler{Proxy: "http://127.0.0.1:30123"}))},
		{"http_listener_http_backend", web(&ipn.TCPPortHandler{HTTP: true}, root(&ipn.HTTPHandler{Proxy: "http://127.0.0.1:30123"}))},
		{"http_listener_https_backend", web(&ipn.TCPPortHandler{HTTP: true}, root(&ipn.HTTPHandler{Proxy: "https://10.0.0.1:8443"}))},
		{"https_insecure_backend", web(&ipn.TCPPortHandler{HTTPS: true}, root(&ipn.HTTPHandler{Proxy: "https+insecure://10.0.0.1:8443"}))},
		{"backend_with_path", web(&ipn.TCPPortHandler{HTTPS: true}, root(&ipn.HTTPHandler{Proxy: "http://127.0.0.1:8080/base"}))},
		{"unix_backend", web(&ipn.TCPPortHandler{HTTPS: true}, root(&ipn.HTTPHandler{Proxy: "unix:/run/app.sock"}))},
		{"h2c_backend", web(&ipn.TCPPortHandler{HTTPS: true}, root(&ipn.HTTPHandler{Proxy: "http://127.0.0.1:8080", BackendHTTP: ipn.BackendHTTPH2C}))},
		{"h2c_unix_backend", web(&ipn.TCPPortHandler{HTTPS: true}, root(&ipn.HTTPHandler{Proxy: "unix:/run/app.sock", BackendHTTP: ipn.BackendHTTPH2C}))},
		{"app_caps", web(&ipn.TCPPortHandler{HTTPS: true}, root(&ipn.HTTPHandler{Proxy: "http://127.0.0.1:8080", AcceptAppCaps: []peercap.Cap{"example.com/cap/a", "example.com/cap/b"}}))},
		{"path", web(&ipn.TCPPortHandler{HTTPS: true}, root(&ipn.HTTPHandler{Path: testAbsPath}))},
		{"text", web(&ipn.TCPPortHandler{HTTPS: true}, root(&ipn.HTTPHandler{Text: "hello"}))},
		{"redirect", web(&ipn.TCPPortHandler{HTTPS: true}, root(&ipn.HTTPHandler{Redirect: "301:https://${HOST}${REQUEST_URI}"}))},
		{"mount_points", web(&ipn.TCPPortHandler{HTTPS: true}, map[string]*ipn.HTTPHandler{
			"/":      {Proxy: "http://127.0.0.1:8080"},
			"/api":   {Proxy: "http://127.0.0.1:9090", BackendHTTP: ipn.BackendHTTPH2C},
			"/doc/":  {Path: testAbsPath},
			"/hello": {Text: "hello"},
		})},
		{"no_root_mount", web(&ipn.TCPPortHandler{HTTPS: true}, map[string]*ipn.HTTPHandler{"/api": {Text: "x"}})},
		{"tcp", &ipn.ServiceConfig{TCP: map[uint16]*ipn.TCPPortHandler{22: {TCPForward: "127.0.0.1:22"}}}},
		{"tcp_unix", &ipn.ServiceConfig{TCP: map[uint16]*ipn.TCPPortHandler{22: {TCPForward: "unix:/run/ssh.sock"}}}},
		{"tcp_proxy_protocol", &ipn.ServiceConfig{TCP: map[uint16]*ipn.TCPPortHandler{22: {TCPForward: "127.0.0.1:22", ProxyProtocol: 1}}}},
		{"tls_terminated_tcp", &ipn.ServiceConfig{TCP: map[uint16]*ipn.TCPPortHandler{5432: {TCPForward: "[::1]:5432", TerminateTLS: host, ProxyProtocol: 2}}}},
		{"many_ports", &ipn.ServiceConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{
				80:    {HTTP: true},
				443:   {HTTPS: true},
				5432:  {TCPForward: "127.0.0.1:5432", TerminateTLS: host},
				65535: {TCPForward: "127.0.0.1:65535"},
			},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				host + ":80":  {Handlers: root(&ipn.HTTPHandler{Redirect: "https://" + host})},
				host + ":443": {Handlers: root(&ipn.HTTPHandler{Proxy: "http://127.0.0.1:8080"})},
			},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, web := range tt.cfg.Web {
				for _, h := range web.Handlers {
					if strings.HasPrefix(h.Proxy, "unix:") {
						skipIfNoUnixSocketProxy(t)
					}
				}
			}
			svc, err := ServiceFromServeConfig(name, tt.cfg, testMDS)
			if err != nil {
				t.Fatalf("ServiceFromServeConfig: %v", err)
			}
			file := &ServicesFile{Version: ConfigVersionV1, Services: map[tailcfg.ServiceName]*ServiceFile{name: svc}}
			// The CLI writes the file with encoding/json.
			j, err := json.MarshalIndent(file, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := LoadServicesFile(writeConfig(t, string(j)), "")
			if err != nil {
				t.Fatalf("LoadServicesFile: %v\n%s", err, j)
			}
			want := &ipn.ServeConfig{Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{name: tt.cfg}}
			if diff := cmp.Diff(want, applyAll(t, loaded)); diff != "" {
				t.Errorf("serve config after round trip (-want +got):\n%s\nfile:\n%s", diff, j)
			}
		})
	}
}

func TestServiceFromServeConfigBarePortProxy(t *testing.T) {
	const host = "web." + testMDS
	for proxy, wantURL := range map[string]string{
		"3030":           "http://127.0.0.1:3030",
		"localhost:3030": "http://localhost:3030",
	} {
		cfg := &ipn.ServiceConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{host + ":443": {Handlers: map[string]*ipn.HTTPHandler{"/": {Proxy: proxy}}}},
		}
		svc, err := ServiceFromServeConfig("svc:web", cfg, testMDS)
		if err != nil {
			t.Fatalf("proxy %q: %v", proxy, err)
		}
		if got := svc.Listeners[443].Routes["/"].Proxy.URL; got != wantURL {
			t.Errorf("proxy %q exported as %q, want %q", proxy, got, wantURL)
		}
	}
}

// TestServiceFromServeConfigUnrepresentable tests that an export fails, and
// does not drop anything, when the Service holds state the file cannot
// describe.
func TestServiceFromServeConfigUnrepresentable(t *testing.T) {
	const host = "web." + testMDS
	tests := []struct {
		name    string
		cfg     *ipn.ServiceConfig
		wantErr string
	}{
		{
			name:    "nil_config",
			cfg:     nil,
			wantErr: "has no configuration",
		},
		{
			name:    "tun_with_tcp",
			cfg:     &ipn.ServiceConfig{Tun: true, TCP: map[uint16]*ipn.TCPPortHandler{22: {TCPForward: "127.0.0.1:22"}}},
			wantErr: "TUN mode is set along with",
		},
		{
			name:    "web_without_handlers",
			cfg:     &ipn.ServiceConfig{TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}}},
			wantErr: "no handlers",
		},
		{
			name: "web_for_other_name",
			cfg: &ipn.ServiceConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
				Web: map[ipn.HostPort]*ipn.WebServerConfig{
					host + ":443":           {Handlers: map[string]*ipn.HTTPHandler{"/": {Text: "x"}}},
					"other.example.com:443": {Handlers: map[string]*ipn.HTTPHandler{"/": {Text: "y"}}},
				},
			},
			wantErr: "does not listen on",
		},
		{
			name:    "terminate_tls_other_name",
			cfg:     &ipn.ServiceConfig{TCP: map[uint16]*ipn.TCPPortHandler{443: {TCPForward: "127.0.0.1:1", TerminateTLS: "other.example.com"}}},
			wantErr: "terminates TLS for",
		},
		{
			name:    "empty_port_handler",
			cfg:     &ipn.ServiceConfig{TCP: map[uint16]*ipn.TCPPortHandler{443: {}}},
			wantErr: "neither a TCP forward nor a web server",
		},
		{
			name: "handler_with_two_kinds",
			cfg: &ipn.ServiceConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
				Web: map[ipn.HostPort]*ipn.WebServerConfig{host + ":443": {Handlers: map[string]*ipn.HTTPHandler{"/": {Text: "x", Path: "/var/www"}}}},
			},
			wantErr: "exactly one of",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, err := ServiceFromServeConfig("svc:web", tt.cfg, testMDS)
			if err == nil {
				t.Fatalf("ServiceFromServeConfig = %+v; want error containing %q", svc, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q; want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// TestLoadServicesFileV0 tests that a 0.0.1 file keeps the meaning it had
// before the 0.1.0 format existed.
func TestLoadServicesFileV0(t *testing.T) {
	const config = `{
		"version": "0.0.1",
		"services": {
			"svc:web": {
				"endpoints": {
					"tcp:80":        "http://127.0.0.1:8080",
					"tcp:443":       "https://127.0.0.1:8443",
					"tcp:444":       "https+insecure://127.0.0.1:8443",
					"tcp:445":       "file:///var/www",
					"tcp:5432":      "tls-terminated-tcp://127.0.0.1:5432",
					"tcp:6000-6001": "tcp://127.0.0.1:7000-7001",
					"tcp:6100":      "tcp://unix:/run/raw.sock"
				},
				"advertised": false
			},
			"svc:l3": {"endpoints": {"*": "TUN"}}
		}
	}`
	sf, err := LoadServicesFile(writeConfig(t, withTestAbsPath(t, config)), "")
	if err != nil {
		t.Fatal(err)
	}
	if sf.Version != ConfigVersionV0 {
		t.Errorf("Version = %q, want %q", sf.Version, ConfigVersionV0)
	}
	if v, ok := sf.Services["svc:web"].Advertised.Get(); !ok || v {
		t.Errorf("svc:web Advertised = %v, %v; want false, true", v, ok)
	}

	const host = "web." + testMDS
	root := func(h ipn.HTTPHandler) *ipn.WebServerConfig {
		return &ipn.WebServerConfig{Handlers: map[string]*ipn.HTTPHandler{"/": &h}}
	}
	want := &ipn.ServeConfig{Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
		"svc:web": {
			TCP: map[uint16]*ipn.TCPPortHandler{
				80:   {HTTP: true},
				443:  {HTTPS: true},
				444:  {HTTPS: true},
				445:  {HTTPS: true},
				5432: {TCPForward: "127.0.0.1:5432", TerminateTLS: host},
				6000: {TCPForward: "127.0.0.1:7000"},
				6001: {TCPForward: "127.0.0.1:7001"},
				6100: {TCPForward: "unix:/run/raw.sock"},
			},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				host + ":80":  root(ipn.HTTPHandler{Proxy: "http://127.0.0.1:8080"}),
				host + ":443": root(ipn.HTTPHandler{Proxy: "https://127.0.0.1:8443"}),
				host + ":444": root(ipn.HTTPHandler{Proxy: "https+insecure://127.0.0.1:8443"}),
				host + ":445": root(ipn.HTTPHandler{Path: testAbsPath}),
			},
		},
		"svc:l3": {Tun: true},
	}}
	if diff := cmp.Diff(want, applyAll(t, sf)); diff != "" {
		t.Errorf("applied serve config (-want +got):\n%s", diff)
	}
}

func TestLoadServicesFileV0NonTCPSource(t *testing.T) {
	const config = `{"version":"0.0.1","services":{"svc:dns":{"endpoints":{"udp:53":"tcp://127.0.0.1:53"}}}}`
	_, err := LoadServicesFile(writeConfig(t, config), "")
	if err == nil || !strings.Contains(err.Error(), "source ports must be TCP") {
		t.Fatalf("err = %v, want a 'source ports must be TCP' error", err)
	}
}

func TestLoadServicesFileV0MaxPort(t *testing.T) {
	const config = `{"version":"0.0.1","services":{"svc:a":{"endpoints":{"tcp:65534-65535":"tcp://127.0.0.1:65534-65535"}}}}`
	sf, err := LoadServicesFile(writeConfig(t, config), "")
	if err != nil {
		t.Fatal(err)
	}
	if got := len(sf.Services["svc:a"].Listeners); got != 2 {
		t.Errorf("got %d listeners, want 2", got)
	}
}

func TestLoadServicesFileLegacy(t *testing.T) {
	const config = `{"Services":{"svc:a":{"TCP":{"443":{"HTTPS":true}}}}}`
	sf, err := LoadServicesFile(writeConfig(t, config), "")
	if err != nil {
		t.Fatal(err)
	}
	if sf.Version != LegacyVersion || sf.Legacy == nil || sf.Services != nil {
		t.Errorf("got Version %q, Legacy %v, Services %v; want legacy config only", sf.Version, sf.Legacy, sf.Services)
	}
	if sf.Legacy.Services["svc:a"] == nil {
		t.Errorf("Legacy.Services = %v, want svc:a", sf.Legacy.Services)
	}
}
