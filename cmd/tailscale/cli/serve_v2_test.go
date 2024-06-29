// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
)

func TestServeDevConfigMutations(t *testing.T) {
	// step is a stateful mutation within a group
	type step struct {
		command []string                       // serve args; nil means no command to run (only reset)
		want    *ipn.ServeConfig               // non-nil means we want a save of this value
		wantErr func(error) (badErrMsg string) // nil means no error is wanted
	}

	// group is a group of steps that share the same
	// config mutation, but always starts from an empty config
	type group struct {
		name  string
		steps []step
	}

	// creaet a temporary directory for path-based destinations
	td := t.TempDir()
	writeFile := func(suffix, contents string) {
		if err := os.WriteFile(filepath.Join(td, suffix), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeFile("foo", "this is foo")
	err := os.MkdirAll(filepath.Join(td, "subdir"), 0700)
	if err != nil {
		t.Fatal(err)
	}
	writeFile("subdir/file-a", "this is subdir")

	groups := [...]group{
		{
			name: "using_port_number",
			steps: []step{{
				command: cmd("funnel --bg 3000"),
				want: &ipn.ServeConfig{
					TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
					Web: map[ipn.HostPort]*ipn.WebServerConfig{
						"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
							"/": {Proxy: "http://127.0.0.1:3000"},
						}},
					},
					AllowFunnel: map[ipn.HostPort]bool{"foo.test.ts.net:443": true},
				},
			}},
		},
		{
			name: "funnel_background",
			steps: []step{{
				command: cmd("funnel --bg localhost:3000"),
				want: &ipn.ServeConfig{
					TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
					Web: map[ipn.HostPort]*ipn.WebServerConfig{
						"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
							"/": {Proxy: "http://localhost:3000"},
						}},
					},
					AllowFunnel: map[ipn.HostPort]bool{"foo.test.ts.net:443": true},
				},
			}},
		},
		{
			name: "serve_background",
			steps: []step{{
				command: cmd("serve --bg localhost:3000"),
				want: &ipn.ServeConfig{
					TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
					Web: map[ipn.HostPort]*ipn.WebServerConfig{
						"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
							"/": {Proxy: "http://localhost:3000"},
						}},
					},
				},
			}},
		},
		{
			name: "set_path_bg",
			steps: []step{{
				command: cmd("serve --set-path=/ --bg localhost:3000"),
				want: &ipn.ServeConfig{
					TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
					Web: map[ipn.HostPort]*ipn.WebServerConfig{
						"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
							"/": {Proxy: "http://localhost:3000"},
						}},
					},
				},
			}},
		},
		{
			name: "http_listener",
			steps: []step{{
				command: cmd("serve --bg --http=80 localhost:3000"),
				want: &ipn.ServeConfig{
					TCP: map[uint16]*ipn.TCPPortHandler{80: {HTTP: true}},
					Web: map[ipn.HostPort]*ipn.WebServerConfig{
						"foo.test.ts.net:80": {Handlers: map[string]*ipn.HTTPHandler{
							"/": {Proxy: "http://localhost:3000"},
						}},
					},
				},
			}},
		},
		{
			name: "https_listener_valid_port",
			steps: []step{{
				command: cmd("serve --bg --https=8443 localhost:3000"),
				want: &ipn.ServeConfig{
					TCP: map[uint16]*ipn.TCPPortHandler{8443: {HTTPS: true}},
					Web: map[ipn.HostPort]*ipn.WebServerConfig{
						"foo.test.ts.net:8443": {Handlers: map[string]*ipn.HTTPHandler{
							"/": {Proxy: "http://localhost:3000"},
						}},
					},
				},
			}},
		},
		{
			name: "multiple_http_with_off",
			steps: []step{
				{
					command: cmd("serve --http=80 --bg http://localhost:3000"),
					want: &ipn.ServeConfig{
						TCP: map[uint16]*ipn.TCPPortHandler{80: {HTTP: true}},
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"foo.test.ts.net:80": {Handlers: map[string]*ipn.HTTPHandler{
								"/": {Proxy: "http://localhost:3000"},
							}},
						},
					},
				},
				{ // support non Funnel port
					command: cmd("serve --bg --http=9999 --set-path=/abc http://localhost:3001"),
					want: &ipn.ServeConfig{
						TCP: map[uint16]*ipn.TCPPortHandler{80: {HTTP: true}, 9999: {HTTP: true}},
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"foo.test.ts.net:80": {Handlers: map[string]*ipn.HTTPHandler{
								"/": {Proxy: "http://localhost:3000"},
							}},
							"foo.test.ts.net:9999": {Handlers: map[string]*ipn.HTTPHandler{
								"/abc": {Proxy: "http://localhost:3001"},
							}},
						},
					},
				},
				{ // turn off one handler
					command: cmd("serve --bg --http=9999 --set-path=/abc off"),
					want: &ipn.ServeConfig{
						TCP: map[uint16]*ipn.TCPPortHandler{80: {HTTP: true}},
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"foo.test.ts.net:80": {Handlers: map[string]*ipn.HTTPHandler{
								"/": {Proxy: "http://localhost:3000"},
							}},
						},
					},
				},
				{ // add another handler
					command: cmd("serve --bg --http=8080 --set-path=/abc http://127.0.0.1:3001"),
					want: &ipn.ServeConfig{
						TCP: map[uint16]*ipn.TCPPortHandler{80: {HTTP: true}, 8080: {HTTP: true}},
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"foo.test.ts.net:80": {Handlers: map[string]*ipn.HTTPHandler{
								"/": {Proxy: "http://localhost:3000"},
							}},
							"foo.test.ts.net:8080": {Handlers: map[string]*ipn.HTTPHandler{
								"/abc": {Proxy: "http://127.0.0.1:3001"},
							}},
						},
					},
				},
			},
		},
		{
			name: "invalid_port_too_low",
			steps: []step{{
				command: cmd("serve --https=443 --bg http://localhost:0"), // invalid port, too low
				wantErr: anyErr(),
			}},
		},
		{
			name: "invalid_port_too_high",
			steps: []step{{
				command: cmd("serve --https=443 --bg http://localhost:65536"), // invalid port, too high
				wantErr: anyErr(),
			}},
		},
		{
			name: "invalid_mount_port_too_high",
			steps: []step{{
				command: cmd("serve --https=65536 --bg http://localhost:3000"), // invalid port, too high
				wantErr: anyErr(),
			}},
		},
		{
			name: "invalid_host",
			steps: []step{{
				command: cmd("serve --https=443 --bg http://somehost:3000"), // invalid host
				wantErr: anyErr(),
			}},
		},
		{
			name: "invalid_scheme",
			steps: []step{{
				command: cmd("serve --https=443 --bg httpz://127.0.0.1"), // invalid scheme
				wantErr: anyErr(),
			}},
		},
		{
			name: "turn_off_https",
			steps: []step{
				{
					command: cmd("serve --bg --https=443 http://localhost:3000"),
					want: &ipn.ServeConfig{
						TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
								"/": {Proxy: "http://localhost:3000"},
							}},
						},
					},
				},
				{
					command: cmd("serve --bg --https=9999 --set-path=/abc http://localhost:3001"),
					want: &ipn.ServeConfig{
						TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}, 9999: {HTTPS: true}},
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
								"/": {Proxy: "http://localhost:3000"},
							}},
							"foo.test.ts.net:9999": {Handlers: map[string]*ipn.HTTPHandler{
								"/abc": {Proxy: "http://localhost:3001"},
							}},
						},
					},
				},
				{
					command: cmd("serve --bg --https=9999 --set-path=/abc off"),
					want: &ipn.ServeConfig{
						TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
								"/": {Proxy: "http://localhost:3000"},
							}},
						},
					},
				},
				{
					command: cmd("serve --bg --https=8443 --set-path=/abc http://127.0.0.1:3001"),
					want: &ipn.ServeConfig{
						TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}, 8443: {HTTPS: true}},
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
								"/": {Proxy: "http://localhost:3000"},
							}},
							"foo.test.ts.net:8443": {Handlers: map[string]*ipn.HTTPHandler{
								"/abc": {Proxy: "http://127.0.0.1:3001"},
							}},
						},
					},
				},
			},
		},
		{
			name: "https_text_bg",
			steps: []step{{
				command: cmd("serve --bg --https=10000 text:hi"),
				want: &ipn.ServeConfig{
					TCP: map[uint16]*ipn.TCPPortHandler{10000: {HTTPS: true}},
					Web: map[ipn.HostPort]*ipn.WebServerConfig{
						"foo.test.ts.net:10000": {Handlers: map[string]*ipn.HTTPHandler{
							"/": {Text: "hi"},
						}},
					},
				},
			}},
		},
		{
			name: "handler_not_found",
			steps: []step{{
				command: cmd("serve --https=443 --set-path=/foo off"),
				want:    nil, // nothing to save
				wantErr: anyErr(),
			}},
		},
		{
			name: "clean_mount", // "bar" becomes "/bar"
			steps: []step{{
				command: cmd("serve --bg --https=443 --set-path=bar https://127.0.0.1:8443"),
				want: &ipn.ServeConfig{
					TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
					Web: map[ipn.HostPort]*ipn.WebServerConfig{
						"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
							"/bar": {Proxy: "https://127.0.0.1:8443"},
						}},
					},
				},
			}},
		},
		{
			name: "serve_reset",
			steps: []step{
				{
					command: cmd("serve --bg --https=443 --set-path=bar https://127.0.0.1:8443"),
					want: &ipn.ServeConfig{
						TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
								"/bar": {Proxy: "https://127.0.0.1:8443"},
							}},
						},
					},
				},
				{
					command: cmd("serve reset"),
					want:    &ipn.ServeConfig{},
				},
			},
		},
		{
			name: "https_insecure",
			steps: []step{{
				command: cmd("serve --bg --https=443 https+insecure://127.0.0.1:3001"),
				want: &ipn.ServeConfig{
					TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
					Web: map[ipn.HostPort]*ipn.WebServerConfig{
						"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
							"/": {Proxy: "https+insecure://127.0.0.1:3001"},
						}},
					},
				},
			}},
		},
		{
			name: "two_ports_same_dest",
			steps: []step{
				{
					command: cmd("serve --bg --https=443 --set-path=/foo localhost:3000"),
					want: &ipn.ServeConfig{
						TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
								"/foo": {Proxy: "http://localhost:3000"},
							}},
						},
					},
				},
				{
					command: cmd("serve --bg --https=8443 --set-path=/foo localhost:3000"),
					want: &ipn.ServeConfig{
						TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}, 8443: {HTTPS: true}},
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
								"/foo": {Proxy: "http://localhost:3000"},
							}},
							"foo.test.ts.net:8443": {Handlers: map[string]*ipn.HTTPHandler{
								"/foo": {Proxy: "http://localhost:3000"},
							}},
						},
					},
				},
			},
		},
		{
			name: "path_in_dest",
			steps: []step{{
				command: cmd("serve --bg --https=443 http://127.0.0.1:3000/foo/bar"),
				want: &ipn.ServeConfig{
					TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
					Web: map[ipn.HostPort]*ipn.WebServerConfig{
						"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
							"/": {Proxy: "http://127.0.0.1:3000/foo/bar"},
						}},
					},
				},
			}},
		},
		{
			name: "unknown_host_tcp",
			steps: []step{{
				command: cmd("serve --tls-terminated-tcp=443 --bg tcp://somehost:5432"),
				wantErr: exactErrMsg(errHelp),
			}},
		},
		{
			name: "tcp_port_too_low",
			steps: []step{{
				command: cmd("serve --tls-terminated-tcp=443 --bg tcp://somehost:0"),
				wantErr: exactErrMsg(errHelp),
			}},
		},
		{
			name: "tcp_port_too_high",
			steps: []step{{
				command: cmd("serve --tls-terminated-tcp=443 --bg tcp://somehost:65536"),
				wantErr: exactErrMsg(errHelp),
			}},
		},
		{
			name: "tcp_shorthand",
			steps: []step{{
				command: cmd("serve --tls-terminated-tcp=443 --bg 5432"),
				want: &ipn.ServeConfig{
					TCP: map[uint16]*ipn.TCPPortHandler{
						443: {
							TCPForward:   "127.0.0.1:5432",
							TerminateTLS: "foo.test.ts.net",
						},
					},
				},
			}},
		},
		{
			name: "tls_terminated_tcp",
			steps: []step{
				{
					command: cmd("serve --tls-terminated-tcp=443 --bg tcp://localhost:5432"),
					want: &ipn.ServeConfig{
						TCP: map[uint16]*ipn.TCPPortHandler{
							443: {
								TCPForward:   "localhost:5432",
								TerminateTLS: "foo.test.ts.net",
							},
						},
					},
				},
				{
					command: cmd("serve --tls-terminated-tcp=443 --bg tcp://127.0.0.1:8443"),
					want: &ipn.ServeConfig{
						TCP: map[uint16]*ipn.TCPPortHandler{
							443: {
								TCPForward:   "127.0.0.1:8443",
								TerminateTLS: "foo.test.ts.net",
							},
						},
					},
				},
			},
		},
		{
			name: "tcp_off",
			steps: []step{
				{
					command: cmd("serve --tls-terminated-tcp=443 --bg tcp://localhost:123"),
					want: &ipn.ServeConfig{
						TCP: map[uint16]*ipn.TCPPortHandler{
							443: {
								TCPForward:   "localhost:123",
								TerminateTLS: "foo.test.ts.net",
							},
						},
					},
				},
				{ // handler doesn't exist
					command: cmd("serve --tls-terminated-tcp=8443 off"),
					wantErr: anyErr(),
				},
				{
					command: cmd("serve --tls-terminated-tcp=443 off"),
					want:    &ipn.ServeConfig{},
				},
			},
		},
		{
			name: "text",
			steps: []step{{
				command: cmd("serve --https=443 --bg text:hello"),
				want: &ipn.ServeConfig{
					TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
					Web: map[ipn.HostPort]*ipn.WebServerConfig{
						"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
							"/": {Text: "hello"},
						}},
					},
				},
			}},
		},
		{
			name: "path",
			steps: []step{
				{
					command: cmd("serve --https=443 --bg " + filepath.Join(td, "foo")),
					want: &ipn.ServeConfig{
						TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
								"/": {Path: filepath.Join(td, "foo")},
							}},
						},
					},
				},
				{
					command: cmd("serve --bg --https=443 --set-path=/some/where " + filepath.Join(td, "subdir/file-a")),
					want: &ipn.ServeConfig{
						TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
								"/":           {Path: filepath.Join(td, "foo")},
								"/some/where": {Path: filepath.Join(td, "subdir/file-a")},
							}},
						},
					},
				},
			},
		},
		{
			name: "bad_path",
			steps: []step{{
				command: cmd("serve --bg --https=443 bad/path"),
				wantErr: exactErrMsg(errHelp),
			}},
		},
		{
			name: "path_off",
			steps: []step{
				{
					command: cmd("serve --bg --https=443 " + filepath.Join(td, "subdir")),
					want: &ipn.ServeConfig{
						TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
								"/": {Path: filepath.Join(td, "subdir/")},
							}},
						},
					},
				},
				{
					command: cmd("serve --bg --https=443 off"),
					want:    &ipn.ServeConfig{},
				},
			},
		},
		{
			name: "combos",
			steps: []step{
				{
					command: cmd("serve --bg localhost:3000"),
					want: &ipn.ServeConfig{
						TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
								"/": {Proxy: "http://localhost:3000"},
							}},
						},
					},
				},
				{ // enable funnel for primary port
					command: cmd("funnel --bg localhost:3000"),
					want: &ipn.ServeConfig{
						AllowFunnel: map[ipn.HostPort]bool{"foo.test.ts.net:443": true},
						TCP:         map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
								"/": {Proxy: "http://localhost:3000"},
							}},
						},
					},
				},
				{ // serving on secondary port doesn't change funnel on primary port
					command: cmd("serve --bg --https=8443 --set-path=/bar localhost:3001"),
					want: &ipn.ServeConfig{
						AllowFunnel: map[ipn.HostPort]bool{"foo.test.ts.net:443": true},
						TCP:         map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}, 8443: {HTTPS: true}},
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
								"/": {Proxy: "http://localhost:3000"},
							}},
							"foo.test.ts.net:8443": {Handlers: map[string]*ipn.HTTPHandler{
								"/bar": {Proxy: "http://localhost:3001"},
							}},
						},
					},
				},
				{ // turn funnel on for secondary port
					command: cmd("funnel --bg --https=8443 --set-path=/bar localhost:3001"),
					want: &ipn.ServeConfig{
						AllowFunnel: map[ipn.HostPort]bool{"foo.test.ts.net:443": true, "foo.test.ts.net:8443": true},
						TCP:         map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}, 8443: {HTTPS: true}},
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
								"/": {Proxy: "http://localhost:3000"},
							}},
							"foo.test.ts.net:8443": {Handlers: map[string]*ipn.HTTPHandler{
								"/bar": {Proxy: "http://localhost:3001"},
							}},
						},
					},
				},
				{ // turn funnel off for primary port 443
					command: cmd("serve --bg localhost:3000"),
					want: &ipn.ServeConfig{
						AllowFunnel: map[ipn.HostPort]bool{"foo.test.ts.net:8443": true},
						TCP:         map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}, 8443: {HTTPS: true}},
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
								"/": {Proxy: "http://localhost:3000"},
							}},
							"foo.test.ts.net:8443": {Handlers: map[string]*ipn.HTTPHandler{
								"/bar": {Proxy: "http://localhost:3001"},
							}},
						},
					},
				},
				{ // remove secondary port
					command: cmd("serve --bg --https=8443 --set-path=/bar off"),
					want: &ipn.ServeConfig{
						TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
								"/": {Proxy: "http://localhost:3000"},
							}},
						},
					},
				},
				{ // start a tcp forwarder on 8443
					command: cmd("serve --bg --tcp=8443 tcp://localhost:5432"),
					want: &ipn.ServeConfig{
						TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}, 8443: {TCPForward: "localhost:5432"}},
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
								"/": {Proxy: "http://localhost:3000"},
							}},
						},
					},
				},
				{ // remove primary port http handler
					command: cmd("serve off"),
					want: &ipn.ServeConfig{
						TCP: map[uint16]*ipn.TCPPortHandler{8443: {TCPForward: "localhost:5432"}},
					},
				},
				{ // remove tcp forwarder
					command: cmd("serve --tls-terminated-tcp=8443 off"),
					want:    &ipn.ServeConfig{},
				},
			},
		},
		{
			name: "tricky_steps",
			steps: []step{
				{ // a directory with a trailing slash mount point
					command: cmd("serve --bg --https=443 --set-path=/dir " + filepath.Join(td, "subdir")),
					want: &ipn.ServeConfig{
						TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
								"/dir/": {Path: filepath.Join(td, "subdir/")},
							}},
						},
					},
				},
				{ // this should overwrite the previous one
					command: cmd("serve --bg --https=443 --set-path=/dir " + filepath.Join(td, "foo")),
					want: &ipn.ServeConfig{
						TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
								"/dir": {Path: filepath.Join(td, "foo")},
							}},
						},
					},
				},
				{ // reset and do opposite
					command: cmd("serve reset"),
					want:    &ipn.ServeConfig{},
				},
				{ // a file without a trailing slash mount point
					command: cmd("serve --bg --https=443 --set-path=/dir " + filepath.Join(td, "foo")),
					want: &ipn.ServeConfig{
						TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
								"/dir": {Path: filepath.Join(td, "foo")},
							}},
						},
					},
				},
				{ // this should overwrite the previous one
					command: cmd("serve --bg --https=443 --set-path=/dir " + filepath.Join(td, "subdir")),
					want: &ipn.ServeConfig{
						TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
								"/dir/": {Path: filepath.Join(td, "subdir/")},
							}},
						},
					},
				},
			},
		},
		{
			name: "cannot_override_tcp_with_http",
			steps: []step{
				{ // tcp forward 5432 on serve port 443
					command: cmd("serve --tls-terminated-tcp=443 --bg tcp://localhost:5432"),
					want: &ipn.ServeConfig{
						TCP: map[uint16]*ipn.TCPPortHandler{
							443: {
								TCPForward:   "localhost:5432",
								TerminateTLS: "foo.test.ts.net",
							},
						},
					},
				},
				{
					command: cmd("serve --https=443 --bg localhost:3000"),
					wantErr: anyErr(),
				},
			},
		},
		{
			name: "cannot_override_http_with_tcp",
			steps: []step{
				{
					command: cmd("serve --https=443 --bg localhost:3000"),
					want: &ipn.ServeConfig{
						TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
								"/": {Proxy: "http://localhost:3000"},
							}},
						},
					},
				},
				{ // try to start a tcp forwarder on the same serve port
					command: cmd("serve --tls-terminated-tcp=443 --bg tcp://localhost:5432"),
					wantErr: anyErr(),
				},
			},
		},
		{
			name: "turn_off_multiple_handlers",
			steps: []step{
				{
					command: cmd("serve --https=4545 --set-path=/foo --bg localhost:3000"),
					want: &ipn.ServeConfig{
						TCP: map[uint16]*ipn.TCPPortHandler{4545: {HTTPS: true}},
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"foo.test.ts.net:4545": {Handlers: map[string]*ipn.HTTPHandler{
								"/foo": {Proxy: "http://localhost:3000"},
							}},
						},
					},
				},
				{
					command: cmd("serve --https=4545 --set-path=/bar --bg localhost:3000"),
					want: &ipn.ServeConfig{
						TCP: map[uint16]*ipn.TCPPortHandler{4545: {HTTPS: true}},
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"foo.test.ts.net:4545": {Handlers: map[string]*ipn.HTTPHandler{
								"/foo": {Proxy: "http://localhost:3000"},
								"/bar": {Proxy: "http://localhost:3000"},
							}},
						},
					},
				},
				{
					command: cmd("serve --https=4545 --bg --yes localhost:3000 off"),
					want:    &ipn.ServeConfig{},
				},
			},
		},
		{
			name: "no_http_with_funnel",
			steps: []step{
				{
					command: cmd("funnel --http=80 3000"),
					// error parsing commandline arguments: flag provided but not defined: -http
					wantErr: anyErr(),
				},
			},
		},
		{
			name: "forground_with_bg_conflict",
			steps: []step{
				{
					command: cmd("serve --bg --http=3000  localhost:3000"),
					want: &ipn.ServeConfig{
						TCP: map[uint16]*ipn.TCPPortHandler{3000: {HTTP: true}},
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"foo.test.ts.net:3000": {Handlers: map[string]*ipn.HTTPHandler{
								"/": {Proxy: "http://localhost:3000"},
							}},
						},
					},
				},
				{
					command: cmd("serve --http=3000 localhost:3000"),
					wantErr: exactErrMsg(fmt.Errorf(backgroundExistsMsg, "serve", "http", 3000)),
				},
			},
		},
	}

	for _, group := range groups {
		t.Run(group.name, func(t *testing.T) {
			lc := &fakeLocalServeClient{}
			for i, st := range group.steps {
				var stderr bytes.Buffer
				var stdout bytes.Buffer
				var flagOut bytes.Buffer
				e := &serveEnv{
					lc:          lc,
					testFlagOut: &flagOut,
					testStdout:  &stdout,
					testStderr:  &stderr,
				}
				lastCount := lc.setCount
				var cmd *ffcli.Command
				var args []string

				mode := serve
				if st.command[0] == "funnel" {
					mode = funnel
				}
				cmd = newServeV2Command(e, mode)
				args = st.command[1:]

				err := cmd.ParseAndRun(context.Background(), args)
				if flagOut.Len() > 0 {
					t.Logf("flag package output: %q", flagOut.Bytes())
				}
				if err != nil {
					if st.wantErr == nil {
						t.Fatalf("step #%d: unexpected error: %v", i, err)
					}
					if bad := st.wantErr(err); bad != "" {
						t.Fatalf("step #%d: unexpected error: %v", i, bad)
					}
					continue
				}
				if st.wantErr != nil {
					t.Fatalf("step #%d: got success (saved=%v), but wanted an error", i, lc.config != nil)
				}
				var got *ipn.ServeConfig = nil
				if lc.setCount > lastCount {
					got = lc.config
				}
				if !reflect.DeepEqual(got, st.want) {
					gotbts, _ := json.MarshalIndent(got, "", "\t")
					wantbts, _ := json.MarshalIndent(st.want, "", "\t")
					t.Fatalf("step: %d, cmd: %v, diff:\n%s", i, st.command, cmp.Diff(string(gotbts), string(wantbts)))

				}
			}
		})

	}
}

func TestValidateConfig(t *testing.T) {
	tests := [...]struct {
		name      string
		desc      string
		cfg       *ipn.ServeConfig
		servePort uint16
		serveType serveType
		bg        bool
		wantErr   bool
	}{
		{
			name:      "nil_config",
			desc:      "when config is nil, all requests valid",
			cfg:       nil,
			servePort: 3000,
			serveType: serveTypeHTTPS,
		},
		{
			name: "new_bg_tcp",
			desc: "no error when config exists but we're adding a new bg tcp port",
			cfg: &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{
					443: {HTTPS: true},
				},
			},
			bg:        true,
			servePort: 10000,
			serveType: serveTypeHTTPS,
		},
		{
			name: "override_bg_tcp",
			desc: "no error when overwriting previous port under the same serve type",
			cfg: &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{
					443: {TCPForward: "http://localhost:4545"},
				},
			},
			bg:        true,
			servePort: 443,
			serveType: serveTypeTCP,
		},
		{
			name: "override_bg_tcp",
			desc: "error when overwriting previous port under a different serve type",
			cfg: &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{
					443: {HTTPS: true},
				},
			},
			bg:        true,
			servePort: 443,
			serveType: serveTypeHTTP,
			wantErr:   true,
		},
		{
			name: "new_fg_port",
			desc: "no error when serving a new foreground port",
			cfg: &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{
					443: {HTTPS: true},
				},
				Foreground: map[string]*ipn.ServeConfig{
					"abc123": {
						TCP: map[uint16]*ipn.TCPPortHandler{
							3000: {HTTPS: true},
						},
					},
				},
			},
			servePort: 4040,
			serveType: serveTypeTCP,
		},
		{
			name: "same_fg_port",
			desc: "error when overwriting a previous fg port",
			cfg: &ipn.ServeConfig{
				Foreground: map[string]*ipn.ServeConfig{
					"abc123": {
						TCP: map[uint16]*ipn.TCPPortHandler{
							3000: {HTTPS: true},
						},
					},
				},
			},
			servePort: 3000,
			serveType: serveTypeTCP,
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			se := serveEnv{bg: tc.bg}
			err := se.validateConfig(tc.cfg, tc.servePort, tc.serveType)
			if err == nil && tc.wantErr {
				t.Fatal("expected an error but got nil")
			}
			if err != nil && !tc.wantErr {
				t.Fatalf("expected no error but got: %v", err)
			}
		})
	}

}

func TestSrcTypeFromFlags(t *testing.T) {
	tests := []struct {
		name         string
		env          *serveEnv
		expectedType serveType
		expectedPort uint16
		expectedErr  bool
	}{
		{
			name:         "only http set",
			env:          &serveEnv{http: 80},
			expectedType: serveTypeHTTP,
			expectedPort: 80,
			expectedErr:  false,
		},
		{
			name:         "only https set",
			env:          &serveEnv{https: 10000},
			expectedType: serveTypeHTTPS,
			expectedPort: 10000,
			expectedErr:  false,
		},
		{
			name:         "only tcp set",
			env:          &serveEnv{tcp: 8000},
			expectedType: serveTypeTCP,
			expectedPort: 8000,
			expectedErr:  false,
		},
		{
			name:         "only tls-terminated-tcp set",
			env:          &serveEnv{tlsTerminatedTCP: 8080},
			expectedType: serveTypeTLSTerminatedTCP,
			expectedPort: 8080,
			expectedErr:  false,
		},
		{
			name:         "defaults to https, port 443",
			env:          &serveEnv{},
			expectedType: serveTypeHTTPS,
			expectedPort: 443,
			expectedErr:  false,
		},
		{
			name:         "multiple types set",
			env:          &serveEnv{http: 80, https: 443},
			expectedPort: 0,
			expectedErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srcType, srcPort, err := srvTypeAndPortFromFlags(tt.env)
			if (err != nil) != tt.expectedErr {
				t.Errorf("Expected error: %v, got: %v", tt.expectedErr, err)
			}
			if srcType != tt.expectedType {
				t.Errorf("Expected srcType: %s, got: %s", tt.expectedType.String(), srcType)
			}
			if srcPort != tt.expectedPort {
				t.Errorf("Expected srcPort: %d, got: %d", tt.expectedPort, srcPort)
			}
		})
	}
}

func TestCleanURLPath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		wantErr  bool
	}{
		{input: "", expected: "/"},
		{input: "/", expected: "/"},
		{input: "/foo", expected: "/foo"},
		{input: "/foo/", expected: "/foo/"},
		{input: "/../bar", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			actual, err := cleanURLPath(tt.input)

			if tt.wantErr == true && err == nil {
				t.Errorf("Expected an error but got none")
				return
			}

			if tt.wantErr == false && err != nil {
				t.Errorf("Got an error, but didn't expect one: %v", err)
				return
			}

			if actual != tt.expected {
				t.Errorf("Got: %q; expected: %q", actual, tt.expected)
			}
		})
	}
}

func TestMessageForPort(t *testing.T) {
	tests := []struct {
		name        string
		subcmd      serveMode
		serveConfig *ipn.ServeConfig
		status      *ipnstate.Status
		dnsName     string
		srvType     serveType
		srvPort     uint16
		expected    string
	}{
		{
			name:   "funnel-https",
			subcmd: funnel,
			serveConfig: &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{
					443: {HTTPS: true},
				},
				Web: map[ipn.HostPort]*ipn.WebServerConfig{
					"foo.test.ts.net:443": {
						Handlers: map[string]*ipn.HTTPHandler{
							"/": {Proxy: "http://127.0.0.1:3000"},
						},
					},
				},
				AllowFunnel: map[ipn.HostPort]bool{
					"foo.test.ts.net:443": true,
				},
			},
			status:  &ipnstate.Status{},
			dnsName: "foo.test.ts.net",
			srvType: serveTypeHTTPS,
			srvPort: 443,
			expected: strings.Join([]string{
				msgFunnelAvailable,
				"",
				"https://foo.test.ts.net/",
				"|-- proxy http://127.0.0.1:3000",
				"",
				fmt.Sprintf(msgRunningInBackground, "Funnel"),
				fmt.Sprintf(msgDisableProxy, "funnel", "https", 443),
			}, "\n"),
		},
		{
			name:   "serve-http",
			subcmd: serve,
			serveConfig: &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{
					443: {HTTP: true},
				},
				Web: map[ipn.HostPort]*ipn.WebServerConfig{
					"foo.test.ts.net:80": {
						Handlers: map[string]*ipn.HTTPHandler{
							"/": {Proxy: "http://127.0.0.1:3000"},
						},
					},
				},
			},
			status:  &ipnstate.Status{},
			dnsName: "foo.test.ts.net",
			srvType: serveTypeHTTP,
			srvPort: 80,
			expected: strings.Join([]string{
				msgServeAvailable,
				"",
				"https://foo.test.ts.net:80/",
				"|-- proxy http://127.0.0.1:3000",
				"",
				fmt.Sprintf(msgRunningInBackground, "Serve"),
				fmt.Sprintf(msgDisableProxy, "serve", "http", 80),
			}, "\n"),
		},
	}

	for _, tt := range tests {
		e := &serveEnv{bg: true, subcmd: tt.subcmd}

		t.Run(tt.name, func(t *testing.T) {
			actual := e.messageForPort(tt.serveConfig, tt.status, tt.dnsName, tt.srvType, tt.srvPort)

			if actual == "" {
				t.Errorf("Got empty message")
			}

			if actual != tt.expected {
				t.Errorf("\nGot:      %q\nExpected: %q", actual, tt.expected)
			}
		})
	}
}

func TestIsLegacyInvocation(t *testing.T) {
	tests := []struct {
		subcmd      serveMode
		args        []string
		expected    bool
		translation string
	}{
		{
			subcmd:      serve,
			args:        []string{"https", "/", "localhost:3000"},
			expected:    true,
			translation: "tailscale serve --bg localhost:3000",
		},
		{
			subcmd:      serve,
			args:        []string{"https", "/", "localhost:3000", "off"},
			expected:    true,
			translation: "tailscale serve --bg localhost:3000 off",
		},
		{
			subcmd:      serve,
			args:        []string{"https", "/", "off"},
			expected:    true,
			translation: "tailscale serve --bg off",
		},
		{
			subcmd:      serve,
			args:        []string{"https:4545", "/foo", "off"},
			expected:    true,
			translation: "tailscale serve --bg --https 4545 --set-path /foo off",
		},
		{
			subcmd:      serve,
			args:        []string{"https:4545", "/foo", "localhost:9090", "off"},
			expected:    true,
			translation: "tailscale serve --bg --https 4545 --set-path /foo localhost:9090 off",
		},
		{
			subcmd:      serve,
			args:        []string{"https:8443", "/", "localhost:3000"},
			expected:    true,
			translation: "tailscale serve --bg --https 8443 localhost:3000",
		},
		{
			subcmd:      serve,
			args:        []string{"http", "/", "localhost:3000"},
			expected:    true,
			translation: "tailscale serve --bg --http 80 localhost:3000",
		},
		{
			subcmd:      serve,
			args:        []string{"http:80", "/", "localhost:3000"},
			expected:    true,
			translation: "tailscale serve --bg --http 80 localhost:3000",
		},
		{
			subcmd:      serve,
			args:        []string{"https:10000", "/motd.txt", `text:Hello, world!`},
			expected:    true,
			translation: `tailscale serve --bg --https 10000 --set-path /motd.txt "text:Hello, world!"`,
		},
		{
			subcmd:      serve,
			args:        []string{"tcp:2222", "tcp://localhost:22"},
			expected:    true,
			translation: "tailscale serve --bg --tcp 2222 tcp://localhost:22",
		},
		{
			subcmd:      serve,
			args:        []string{"tls-terminated-tcp:443", "tcp://localhost:80"},
			expected:    true,
			translation: "tailscale serve --bg --tls-terminated-tcp 443 tcp://localhost:80",
		},
		{
			subcmd:   funnel,
			args:     []string{"443", "on"},
			expected: true,
		},
		{
			subcmd:   funnel,
			args:     []string{"443", "off"},
			expected: true,
		},

		{
			subcmd:   serve,
			args:     []string{"3000"},
			expected: false,
		},
		{
			subcmd:   serve,
			args:     []string{"localhost:3000"},
			expected: false,
		},
	}

	for idx, tt := range tests {
		t.Run(strconv.Itoa(idx), func(t *testing.T) {
			gotTranslation, actual := isLegacyInvocation(tt.subcmd, tt.args)

			if actual != tt.expected {
				t.Fatalf("got: %v; expected: %v", actual, tt.expected)
			}

			if gotTranslation != tt.translation {
				t.Fatalf("expected translaction to be %q but got %q", tt.translation, gotTranslation)
			}
		})
	}
}

// exactErrMsg returns an error checker that wants exactly the provided want error.
// If optName is non-empty, it's used in the error message.
func exactErrMsg(want error) func(error) string {
	return func(got error) string {
		if got.Error() == want.Error() {
			return ""
		}
		return fmt.Sprintf("\ngot:  %v\nwant: %v\n", got, want)
	}
}
