// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/logger"
)

func TestCleanMountPoint(t *testing.T) {
	tests := []struct {
		mount   string
		want    string
		wantErr bool
	}{
		{"foo", "/foo", false},              // missing prefix
		{"/foo/", "/foo/", false},           // keep trailing slash
		{"////foo", "", true},               // too many slashes
		{"/foo//", "", true},                // too many slashes
		{"", "", true},                      // empty
		{"https://tailscale.com", "", true}, // not a path
	}
	for _, tt := range tests {
		mp, err := cleanMountPoint(tt.mount)
		if err != nil && tt.wantErr {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}

		if mp != tt.want {
			t.Fatalf("got %q, want %q", mp, tt.want)
		}
	}
}

func TestServeConfigMutations(t *testing.T) {
	tstest.Replace(t, &Stderr, io.Discard)
	tstest.Replace(t, &Stdout, io.Discard)

	// Stateful mutations, starting from an empty config.
	type step struct {
		command []string                       // serve args; nil means no command to run (only reset)
		reset   bool                           // if true, reset all ServeConfig state
		want    *ipn.ServeConfig               // non-nil means we want a save of this value
		wantErr func(error) (badErrMsg string) // nil means no error is wanted
		line    int                            // line number of addStep call, for error messages

		debugBreak func()
	}
	var steps []step
	add := func(s step) {
		_, _, s.line, _ = runtime.Caller(1)
		steps = append(steps, s)
	}

	// funnel
	add(step{reset: true})
	add(step{
		command: cmd("funnel 443 on"),
		want:    &ipn.ServeConfig{AllowFunnel: map[ipn.HostPort]bool{"foo.test.ts.net:443": true}},
	})
	add(step{
		command: cmd("funnel 443 on"),
		want:    nil, // nothing to save
	})
	add(step{
		command: cmd("funnel 443 off"),
		want:    &ipn.ServeConfig{},
	})
	add(step{
		command: cmd("funnel 443 off"),
		want:    nil, // nothing to save
	})
	add(step{
		command: cmd("funnel"),
		wantErr: exactErr(flag.ErrHelp, "flag.ErrHelp"),
	})

	// https
	add(step{reset: true})
	add(step{ // allow omitting port (default to 80)
		command: cmd("http / http://localhost:3000"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{80: {HTTP: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:80": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "http://127.0.0.1:3000"},
				}},
			},
		},
	})
	add(step{ // support non Funnel port
		command: cmd("http:9999 /abc http://localhost:3001"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{80: {HTTP: true}, 9999: {HTTP: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:80": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "http://127.0.0.1:3000"},
				}},
				"foo.test.ts.net:9999": {Handlers: map[string]*ipn.HTTPHandler{
					"/abc": {Proxy: "http://127.0.0.1:3001"},
				}},
			},
		},
	})
	add(step{
		command: cmd("http:9999 /abc off"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{80: {HTTP: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:80": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "http://127.0.0.1:3000"},
				}},
			},
		},
	})
	add(step{
		command: cmd("http:8080 /abc http://127.0.0.1:3001"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{80: {HTTP: true}, 8080: {HTTP: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:80": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "http://127.0.0.1:3000"},
				}},
				"foo.test.ts.net:8080": {Handlers: map[string]*ipn.HTTPHandler{
					"/abc": {Proxy: "http://127.0.0.1:3001"},
				}},
			},
		},
	})

	// https
	add(step{reset: true})
	add(step{
		command: cmd("https:443 / http://localhost:0"), // invalid port, too low
		wantErr: anyErr(),
	})
	add(step{
		command: cmd("https:443 / http://localhost:65536"), // invalid port, too high
		wantErr: anyErr(),
	})
	add(step{
		command: cmd("https:443 / http://somehost:3000"), // invalid host
		wantErr: anyErr(),
	})
	add(step{
		command: cmd("https:443 / httpz://127.0.0.1"), // invalid scheme
		wantErr: anyErr(),
	})
	add(step{ // allow omitting port (default to 443)
		command: cmd("https / http://localhost:3000"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "http://127.0.0.1:3000"},
				}},
			},
		},
	})
	add(step{ // support non Funnel port
		command: cmd("https:9999 /abc http://localhost:3001"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}, 9999: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "http://127.0.0.1:3000"},
				}},
				"foo.test.ts.net:9999": {Handlers: map[string]*ipn.HTTPHandler{
					"/abc": {Proxy: "http://127.0.0.1:3001"},
				}},
			},
		},
	})
	add(step{
		command: cmd("https:9999 /abc off"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "http://127.0.0.1:3000"},
				}},
			},
		},
	})
	add(step{
		command: cmd("https:8443 /abc http://127.0.0.1:3001"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}, 8443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "http://127.0.0.1:3000"},
				}},
				"foo.test.ts.net:8443": {Handlers: map[string]*ipn.HTTPHandler{
					"/abc": {Proxy: "http://127.0.0.1:3001"},
				}},
			},
		},
	})
	add(step{
		command: cmd("https:10000 / text:hi"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{
				443: {HTTPS: true}, 8443: {HTTPS: true}, 10000: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "http://127.0.0.1:3000"},
				}},
				"foo.test.ts.net:8443": {Handlers: map[string]*ipn.HTTPHandler{
					"/abc": {Proxy: "http://127.0.0.1:3001"},
				}},
				"foo.test.ts.net:10000": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Text: "hi"},
				}},
			},
		},
	})
	add(step{
		command: cmd("https:443 /foo off"),
		want:    nil, // nothing to save
		wantErr: anyErr(),
	}) // handler doesn't exist, so we get an error
	add(step{
		command: cmd("https:10000 / off"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}, 8443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "http://127.0.0.1:3000"},
				}},
				"foo.test.ts.net:8443": {Handlers: map[string]*ipn.HTTPHandler{
					"/abc": {Proxy: "http://127.0.0.1:3001"},
				}},
			},
		},
	})
	add(step{
		command: cmd("https:443 / off"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{8443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:8443": {Handlers: map[string]*ipn.HTTPHandler{
					"/abc": {Proxy: "http://127.0.0.1:3001"},
				}},
			},
		},
	})
	add(step{
		command: cmd("https:8443 /abc off"),
		want:    &ipn.ServeConfig{},
	})
	add(step{ // clean mount: "bar" becomes "/bar"
		command: cmd("https:443 bar https://127.0.0.1:8443"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/bar": {Proxy: "https://127.0.0.1:8443"},
				}},
			},
		},
	})
	add(step{
		command: cmd("https:443 bar https://127.0.0.1:8443"),
		want:    nil, // nothing to save
	})
	add(step{ // try resetting using reset command
		command: cmd("reset"),
		want:    &ipn.ServeConfig{},
	})
	add(step{
		command: cmd("https:443 / https+insecure://127.0.0.1:3001"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "https+insecure://127.0.0.1:3001"},
				}},
			},
		},
	})
	add(step{reset: true})
	add(step{
		command: cmd("https:443 /foo localhost:3000"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/foo": {Proxy: "http://127.0.0.1:3000"},
				}},
			},
		},
	})
	add(step{ // test a second handler on the same port
		command: cmd("https:8443 /foo localhost:3000"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}, 8443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/foo": {Proxy: "http://127.0.0.1:3000"},
				}},
				"foo.test.ts.net:8443": {Handlers: map[string]*ipn.HTTPHandler{
					"/foo": {Proxy: "http://127.0.0.1:3000"},
				}},
			},
		},
	})
	add(step{reset: true})
	add(step{ // support path in proxy
		command: cmd("https / http://127.0.0.1:3000/foo/bar"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "http://127.0.0.1:3000/foo/bar"},
				}},
			},
		},
	})

	// tcp
	add(step{reset: true})
	add(step{ // must include scheme for tcp
		command: cmd("tls-terminated-tcp:443 localhost:5432"),
		wantErr: exactErr(errHelp, "errHelp"),
	})
	add(step{ // !somehost, must be localhost or 127.0.0.1
		command: cmd("tls-terminated-tcp:443 tcp://somehost:5432"),
		wantErr: exactErr(errHelp, "errHelp"),
	})
	add(step{ // bad target port, too low
		command: cmd("tls-terminated-tcp:443 tcp://somehost:0"),
		wantErr: exactErr(errHelp, "errHelp"),
	})
	add(step{ // bad target port, too high
		command: cmd("tls-terminated-tcp:443 tcp://somehost:65536"),
		wantErr: exactErr(errHelp, "errHelp"),
	})
	add(step{
		command: cmd("tls-terminated-tcp:443 tcp://localhost:5432"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{
				443: {
					TCPForward:   "127.0.0.1:5432",
					TerminateTLS: "foo.test.ts.net",
				},
			},
		},
	})
	add(step{
		command: cmd("tls-terminated-tcp:443 tcp://127.0.0.1:8443"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{
				443: {
					TCPForward:   "127.0.0.1:8443",
					TerminateTLS: "foo.test.ts.net",
				},
			},
		},
	})
	add(step{
		command: cmd("tls-terminated-tcp:443 tcp://127.0.0.1:8443"),
		want:    nil, // nothing to save
	})
	add(step{
		command: cmd("tls-terminated-tcp:443 tcp://localhost:8444"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{
				443: {
					TCPForward:   "127.0.0.1:8444",
					TerminateTLS: "foo.test.ts.net",
				},
			},
		},
	})
	add(step{
		command: cmd("tls-terminated-tcp:443 tcp://127.0.0.1:8445"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{
				443: {
					TCPForward:   "127.0.0.1:8445",
					TerminateTLS: "foo.test.ts.net",
				},
			},
		},
	})
	add(step{reset: true})
	add(step{
		command: cmd("tls-terminated-tcp:443 tcp://localhost:123"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{
				443: {
					TCPForward:   "127.0.0.1:123",
					TerminateTLS: "foo.test.ts.net",
				},
			},
		},
	})
	add(step{ // handler doesn't exist, so we get an error
		command: cmd("tls-terminated-tcp:8443 off"),
		wantErr: anyErr(),
	})
	add(step{
		command: cmd("tls-terminated-tcp:443 off"),
		want:    &ipn.ServeConfig{},
	})

	// text
	add(step{reset: true})
	add(step{
		command: cmd("https:443 / text:hello"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Text: "hello"},
				}},
			},
		},
	})

	// path
	td := t.TempDir()
	writeFile := func(suffix, contents string) {
		if err := os.WriteFile(filepath.Join(td, suffix), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	add(step{reset: true})
	writeFile("foo", "this is foo")
	add(step{
		command: cmd("https:443 / " + filepath.Join(td, "foo")),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Path: filepath.Join(td, "foo")},
				}},
			},
		},
	})
	os.MkdirAll(filepath.Join(td, "subdir"), 0700)
	writeFile("subdir/file-a", "this is A")
	add(step{
		command: cmd("https:443 /some/where " + filepath.Join(td, "subdir/file-a")),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/":           {Path: filepath.Join(td, "foo")},
					"/some/where": {Path: filepath.Join(td, "subdir/file-a")},
				}},
			},
		},
	})
	add(step{ // bad path
		command: cmd("https:443 / bad/path"),
		wantErr: exactErr(errHelp, "errHelp"),
	})
	add(step{reset: true})
	add(step{
		command: cmd("https:443 / " + filepath.Join(td, "subdir")),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Path: filepath.Join(td, "subdir/")},
				}},
			},
		},
	})
	add(step{
		command: cmd("https:443 / off"),
		want:    &ipn.ServeConfig{},
	})

	// combos
	add(step{reset: true})
	add(step{
		command: cmd("https:443 / localhost:3000"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "http://127.0.0.1:3000"},
				}},
			},
		},
	})
	add(step{
		command: cmd("funnel 443 on"),
		want: &ipn.ServeConfig{
			AllowFunnel: map[ipn.HostPort]bool{"foo.test.ts.net:443": true},
			TCP:         map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "http://127.0.0.1:3000"},
				}},
			},
		},
	})
	add(step{ // serving on secondary port doesn't change funnel
		command: cmd("https:8443 /bar localhost:3001"),
		want: &ipn.ServeConfig{
			AllowFunnel: map[ipn.HostPort]bool{"foo.test.ts.net:443": true},
			TCP:         map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}, 8443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "http://127.0.0.1:3000"},
				}},
				"foo.test.ts.net:8443": {Handlers: map[string]*ipn.HTTPHandler{
					"/bar": {Proxy: "http://127.0.0.1:3001"},
				}},
			},
		},
	})
	add(step{ // turn funnel on for secondary port
		command: cmd("funnel 8443 on"),
		want: &ipn.ServeConfig{
			AllowFunnel: map[ipn.HostPort]bool{"foo.test.ts.net:443": true, "foo.test.ts.net:8443": true},
			TCP:         map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}, 8443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "http://127.0.0.1:3000"},
				}},
				"foo.test.ts.net:8443": {Handlers: map[string]*ipn.HTTPHandler{
					"/bar": {Proxy: "http://127.0.0.1:3001"},
				}},
			},
		},
	})
	add(step{ // turn funnel off for primary port 443
		command: cmd("funnel 443 off"),
		want: &ipn.ServeConfig{
			AllowFunnel: map[ipn.HostPort]bool{"foo.test.ts.net:8443": true},
			TCP:         map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}, 8443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "http://127.0.0.1:3000"},
				}},
				"foo.test.ts.net:8443": {Handlers: map[string]*ipn.HTTPHandler{
					"/bar": {Proxy: "http://127.0.0.1:3001"},
				}},
			},
		},
	})
	add(step{ // remove secondary port
		command: cmd("https:8443 /bar off"),
		want: &ipn.ServeConfig{
			AllowFunnel: map[ipn.HostPort]bool{"foo.test.ts.net:8443": true},
			TCP:         map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "http://127.0.0.1:3000"},
				}},
			},
		},
	})
	add(step{ // start a tcp forwarder on 8443
		command: cmd("tcp:8443 tcp://localhost:5432"),
		want: &ipn.ServeConfig{
			AllowFunnel: map[ipn.HostPort]bool{"foo.test.ts.net:8443": true},
			TCP:         map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}, 8443: {TCPForward: "127.0.0.1:5432"}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "http://127.0.0.1:3000"},
				}},
			},
		},
	})
	add(step{ // remove primary port http handler
		command: cmd("https:443 / off"),
		want: &ipn.ServeConfig{
			AllowFunnel: map[ipn.HostPort]bool{"foo.test.ts.net:8443": true},
			TCP:         map[uint16]*ipn.TCPPortHandler{8443: {TCPForward: "127.0.0.1:5432"}},
		},
	})
	add(step{ // remove tcp forwarder
		command: cmd("tls-terminated-tcp:8443 off"),
		want: &ipn.ServeConfig{
			AllowFunnel: map[ipn.HostPort]bool{"foo.test.ts.net:8443": true},
		},
	})
	add(step{ // turn off funnel
		command: cmd("funnel 8443 off"),
		want:    &ipn.ServeConfig{},
	})

	// tricky steps
	add(step{reset: true})
	add(step{ // a directory with a trailing slash mount point
		command: cmd("https:443 /dir " + filepath.Join(td, "subdir")),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/dir/": {Path: filepath.Join(td, "subdir/")},
				}},
			},
		},
	})
	add(step{ // this should overwrite the previous one
		command: cmd("https:443 /dir " + filepath.Join(td, "foo")),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/dir": {Path: filepath.Join(td, "foo")},
				}},
			},
		},
	})
	add(step{reset: true}) // reset and do the opposite
	add(step{              // a file without a trailing slash mount point
		command: cmd("https:443 /dir " + filepath.Join(td, "foo")),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/dir": {Path: filepath.Join(td, "foo")},
				}},
			},
		},
	})
	add(step{ // this should overwrite the previous one
		command: cmd("https:443 /dir " + filepath.Join(td, "subdir")),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/dir/": {Path: filepath.Join(td, "subdir/")},
				}},
			},
		},
	})

	// error states
	add(step{reset: true})
	add(step{ // tcp forward 5432 on serve port 443
		command: cmd("tls-terminated-tcp:443 tcp://localhost:5432"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{
				443: {
					TCPForward:   "127.0.0.1:5432",
					TerminateTLS: "foo.test.ts.net",
				},
			},
		},
	})
	add(step{ // try to start a web handler on the same port
		command: cmd("https:443 / localhost:3000"),
		wantErr: exactErr(errHelp, "errHelp"),
	})
	add(step{reset: true})
	add(step{ // start a web handler on port 443
		command: cmd("https:443 / localhost:3000"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "http://127.0.0.1:3000"},
				}},
			},
		},
	})
	add(step{ // try to start a tcp forwarder on the same serve port
		command: cmd("tls-terminated-tcp:443 tcp://localhost:5432"),
		wantErr: anyErr(),
	})

	lc := &fakeLocalServeClient{}
	// And now run the steps above.
	for i, st := range steps {
		if st.debugBreak != nil {
			st.debugBreak()
		}
		if st.reset {
			t.Logf("Executing step #%d, line %v: [reset]", i, st.line)
			lc.config = nil
		}
		if st.command == nil {
			continue
		}
		t.Logf("Executing step #%d, line %v: %q ... ", i, st.line, st.command)

		var stdout bytes.Buffer
		var flagOut bytes.Buffer
		e := &serveEnv{
			lc:          lc,
			testFlagOut: &flagOut,
			testStdout:  &stdout,
			testStderr:  io.Discard,
		}
		lastCount := lc.setCount
		var cmd *ffcli.Command
		var args []string
		if st.command[0] == "funnel" {
			cmd = newFunnelCommand(e)
			args = st.command[1:]
		} else {
			cmd = newServeLegacyCommand(e)
			args = st.command
		}
		if cmd.FlagSet == nil {
			cmd.FlagSet = flag.NewFlagSet(cmd.Name, flag.ContinueOnError)
			cmd.FlagSet.SetOutput(Stdout)
		}
		err := cmd.ParseAndRun(context.Background(), args)
		if flagOut.Len() > 0 {
			t.Logf("flag package output: %q", flagOut.Bytes())
		}
		if err != nil {
			if st.wantErr == nil {
				t.Fatalf("step #%d, line %v: unexpected error: %v", i, st.line, err)
			}
			if bad := st.wantErr(err); bad != "" {
				t.Fatalf("step #%d, line %v: unexpected error: %v", i, st.line, bad)
			}
			continue
		}
		if st.wantErr != nil {
			t.Fatalf("step #%d, line %v: got success (saved=%v), but wanted an error", i, st.line, lc.config != nil)
		}
		var got *ipn.ServeConfig = nil
		if lc.setCount > lastCount {
			got = lc.config
		}
		if !reflect.DeepEqual(got, st.want) {
			t.Fatalf("[%d] %v: bad state. got:\n%v\n\nwant:\n%v\n",
				i, st.command, logger.AsJSON(got), logger.AsJSON(st.want))
			// NOTE: asJSON will omit empty fields, which might make
			// result in bad state got/want diffs being the same, even
			// though the actual state is different. Use below to debug:
			// t.Fatalf("[%d] %v: bad state. got:\n%+v\n\nwant:\n%+v\n",
			// 	i, st.command, got, st.want)
		}
	}
}

func TestVerifyFunnelEnabled(t *testing.T) {
	tstest.Replace(t, &Stderr, io.Discard)
	tstest.Replace(t, &Stdout, io.Discard)

	lc := &fakeLocalServeClient{}
	var stdout bytes.Buffer
	var flagOut bytes.Buffer
	e := &serveEnv{
		lc:          lc,
		testFlagOut: &flagOut,
		testStdout:  &stdout,
		testStderr:  io.Discard,
	}

	tests := []struct {
		name string
		// queryFeatureResponse is the mock response desired from the
		// call made to lc.QueryFeature by verifyFunnelEnabled.
		queryFeatureResponse mockQueryFeatureResponse
		caps                 []tailcfg.NodeCapability // optionally set at fakeStatus.Capabilities
		wantErr              string
		wantPanic            string
	}{
		{
			name:                 "enabled",
			queryFeatureResponse: mockQueryFeatureResponse{resp: &tailcfg.QueryFeatureResponse{Complete: true}, err: nil},
			wantErr:              "", // no error, success
		},
		{
			name:                 "fallback-to-non-interactive-flow",
			queryFeatureResponse: mockQueryFeatureResponse{resp: nil, err: errors.New("not-allowed")},
			wantErr:              "Funnel not available; HTTPS must be enabled. See https://tailscale.com/s/https.",
		},
		{
			name:                 "fallback-flow-missing-acl-rule",
			queryFeatureResponse: mockQueryFeatureResponse{resp: nil, err: errors.New("not-allowed")},
			caps:                 []tailcfg.NodeCapability{tailcfg.CapabilityHTTPS},
			wantErr:              `Funnel not available; "funnel" node attribute not set. See https://tailscale.com/s/no-funnel.`,
		},
		{
			name:                 "fallback-flow-enabled",
			queryFeatureResponse: mockQueryFeatureResponse{resp: nil, err: errors.New("not-allowed")},
			caps:                 []tailcfg.NodeCapability{tailcfg.CapabilityHTTPS, tailcfg.NodeAttrFunnel, "https://tailscale.com/cap/funnel-ports?ports=80,443,8080-8090"},
			wantErr:              "", // no error, success
		},
		{
			name: "not-allowed-to-enable",
			queryFeatureResponse: mockQueryFeatureResponse{resp: &tailcfg.QueryFeatureResponse{
				Complete:   false,
				Text:       "You don't have permission to enable this feature.",
				ShouldWait: false,
			}, err: nil},
			wantErr:   "",
			wantPanic: "unexpected call to os.Exit(0) during test", // os.Exit(0) should be called to end process
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			lc.setQueryFeatureResponse(tt.queryFeatureResponse)

			if tt.caps != nil {
				cm := make(tailcfg.NodeCapMap)
				for _, c := range tt.caps {
					cm[c] = nil
				}
				tstest.Replace(t, &fakeStatus.Self.CapMap, cm)
			}

			defer func() {
				r := recover()
				var gotPanic string
				if r != nil {
					gotPanic = fmt.Sprint(r)
				}
				if gotPanic != tt.wantPanic {
					t.Errorf("wrong panic; got=%s, want=%s", gotPanic, tt.wantPanic)
				}
			}()
			gotErr := e.verifyFunnelEnabled(ctx, 443)
			var got string
			if gotErr != nil {
				got = gotErr.Error()
			}
			if got != tt.wantErr {
				t.Errorf("wrong error; got=%s, want=%s", gotErr, tt.wantErr)
			}
		})
	}
}

// fakeLocalServeClient is a fake local.Client for tests.
// It's not a full implementation, just enough to test the serve command.
//
// The fake client is stateful, and is used to test manipulating
// ServeConfig state. This implementation cannot be used concurrently.
type fakeLocalServeClient struct {
	config               *ipn.ServeConfig
	setCount             int                       // counts calls to SetServeConfig
	queryFeatureResponse *mockQueryFeatureResponse // mock response to QueryFeature calls
	prefs                *ipn.Prefs                // fake preferences, used to test GetPrefs and SetPrefs
	statusWithoutPeers   *ipnstate.Status          // nil for fakeStatus
}

// fakeStatus is a fake ipnstate.Status value for tests.
// It's not a full implementation, just enough to test the serve command.
//
// It returns a state that's running, with a fake DNSName and the Funnel
// node attribute capability.
var fakeStatus = &ipnstate.Status{
	BackendState: ipn.Running.String(),
	Self: &ipnstate.PeerStatus{
		DNSName: "foo.test.ts.net",
		CapMap: tailcfg.NodeCapMap{
			tailcfg.NodeAttrFunnel:                            nil,
			tailcfg.CapabilityFunnelPorts + "?ports=443,8443": nil,
		},
	},
	CurrentTailnet: &ipnstate.TailnetStatus{MagicDNSSuffix: "test.ts.net"},
}

func (lc *fakeLocalServeClient) StatusWithoutPeers(ctx context.Context) (*ipnstate.Status, error) {
	if lc.statusWithoutPeers == nil {
		return fakeStatus, nil
	}
	return lc.statusWithoutPeers, nil
}

func (lc *fakeLocalServeClient) GetServeConfig(ctx context.Context) (*ipn.ServeConfig, error) {
	return lc.config.Clone(), nil
}

func (lc *fakeLocalServeClient) SetServeConfig(ctx context.Context, config *ipn.ServeConfig) error {
	lc.setCount += 1
	lc.config = config.Clone()
	return nil
}

func (lc *fakeLocalServeClient) GetPrefs(ctx context.Context) (*ipn.Prefs, error) {
	if lc.prefs == nil {
		lc.prefs = ipn.NewPrefs()
	}
	return lc.prefs, nil
}

func (lc *fakeLocalServeClient) EditPrefs(ctx context.Context, prefs *ipn.MaskedPrefs) (*ipn.Prefs, error) {
	if lc.prefs == nil {
		lc.prefs = ipn.NewPrefs()
	}
	lc.prefs.ApplyEdits(prefs)
	return lc.prefs, nil
}

type mockQueryFeatureResponse struct {
	resp *tailcfg.QueryFeatureResponse
	err  error
}

func (lc *fakeLocalServeClient) setQueryFeatureResponse(resp mockQueryFeatureResponse) {
	lc.queryFeatureResponse = &resp
}

func (lc *fakeLocalServeClient) QueryFeature(ctx context.Context, feature string) (*tailcfg.QueryFeatureResponse, error) {
	if resp := lc.queryFeatureResponse; resp != nil {
		// If we're testing QueryFeature, use the response value set for the test.
		return resp.resp, resp.err
	}
	return &tailcfg.QueryFeatureResponse{Complete: true}, nil // fallback to already enabled
}

func (lc *fakeLocalServeClient) WatchIPNBus(ctx context.Context, mask ipn.NotifyWatchOpt) (*local.IPNBusWatcher, error) {
	return nil, nil // unused in tests
}

func (lc *fakeLocalServeClient) IncrementCounter(ctx context.Context, name string, delta int) error {
	return nil // unused in tests
}

// exactError returns an error checker that wants exactly the provided want error.
// If optName is non-empty, it's used in the error message.
func exactErr(want error, optName ...string) func(error) string {
	return func(got error) string {
		if got == want {
			return ""
		}
		if len(optName) > 0 {
			return fmt.Sprintf("got error %v, want %v", got, optName[0])
		}
		return fmt.Sprintf("got error %v, want %v", got, want)
	}
}

// anyErr returns an error checker that wants any error.
func anyErr() func(error) string {
	return func(got error) string {
		return ""
	}
}

func cmd(s string) []string {
	return strings.Fields(s)
}
