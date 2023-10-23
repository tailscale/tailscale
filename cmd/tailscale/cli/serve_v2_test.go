// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/logger"
)

func TestServeDevConfigMutations(t *testing.T) {
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

	// using port number
	add(step{reset: true})
	add(step{
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
	})

	// funnel background
	add(step{reset: true})
	add(step{
		command: cmd("funnel --bg localhost:3000"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "http://127.0.0.1:3000"},
				}},
			},
			AllowFunnel: map[ipn.HostPort]bool{"foo.test.ts.net:443": true},
		},
	})

	// serve background
	add(step{reset: true})
	add(step{
		command: cmd("serve --bg localhost:3000"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "http://127.0.0.1:3000"},
				}},
			},
		},
	})

	// --set-path runs in background
	add(step{reset: true})
	add(step{
		command: cmd("serve --set-path=/ localhost:3000"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "http://127.0.0.1:3000"},
				}},
			},
		},
	})

	// using http listener
	add(step{reset: true})
	add(step{
		command: cmd("serve --bg --http=80 localhost:3000"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{80: {HTTP: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:80": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "http://127.0.0.1:3000"},
				}},
			},
		},
	})

	// using https listener with a valid port
	add(step{reset: true})
	add(step{
		command: cmd("serve --bg --https=8443 localhost:3000"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{8443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:8443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "http://127.0.0.1:3000"},
				}},
			},
		},
	})

	// https
	add(step{reset: true})
	add(step{ // allow omitting port (default to 80)
		command: cmd("serve --http=80 --bg http://localhost:3000"),
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
		command: cmd("serve --http=9999 --set-path=/abc http://localhost:3001"),
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
		command: cmd("serve --http=9999 --set-path=/abc off"),
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
		command: cmd("serve --http=8080 --set-path=/abc http://127.0.0.1:3001"),
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

	// // https
	add(step{reset: true})
	add(step{
		command: cmd("serve --https=443 --bg http://localhost:0"), // invalid port, too low
		wantErr: anyErr(),
	})
	add(step{
		command: cmd("serve --https=443 --bg http://localhost:65536"), // invalid port, too high
		wantErr: anyErr(),
	})
	add(step{
		command: cmd("serve --https=443 --bg http://somehost:3000"), // invalid host
		wantErr: anyErr(),
	})
	add(step{
		command: cmd("serve --https=443 --bg httpz://127.0.0.1"), // invalid scheme
		wantErr: anyErr(),
	})
	add(step{ // allow omitting port (default to 443)
		command: cmd("serve --https=443 --bg http://localhost:3000"),
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
		command: cmd("serve --https=9999 --set-path=/abc http://localhost:3001"),
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
		command: cmd("serve --https=9999 --set-path=/abc off"),
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
		command: cmd("serve --https=8443 --set-path=/abc http://127.0.0.1:3001"),
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
		command: cmd("serve --https=10000 --bg text:hi"),
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
		command: cmd("serve --https=443 --set-path=/foo off"),
		want:    nil, // nothing to save
		wantErr: anyErr(),
	}) // handler doesn't exist, so we get an error
	add(step{
		command: cmd("serve --https=10000 off"),
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
		command: cmd("serve --https=443 off"),
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
		command: cmd("serve --https=8443 --set-path=/abc off"),
		want:    &ipn.ServeConfig{},
	})
	add(step{ // clean mount: "bar" becomes "/bar"
		command: cmd("serve --https=443 --set-path=bar https://127.0.0.1:8443"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/bar": {Proxy: "https://127.0.0.1:8443"},
				}},
			},
		},
	})
	// add(step{
	// 	command:   cmd("serve --https=443 --set-path=bar https://127.0.0.1:8443"),
	// 	want:      nil, // nothing to save
	// })
	add(step{ // try resetting using reset command
		command: cmd("serve reset"),
		want:    &ipn.ServeConfig{},
	})
	add(step{
		command: cmd("serve --https=443 --bg https+insecure://127.0.0.1:3001"),
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
		command: cmd("serve --https=443 --set-path=/foo localhost:3000"),
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
		command: cmd("serve --https=8443 --set-path=/foo localhost:3000"),
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
		command: cmd("serve --https=443 --bg http://127.0.0.1:3000/foo/bar"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "http://127.0.0.1:3000/foo/bar"},
				}},
			},
		},
	})

	// // tcp
	add(step{reset: true})
	add(step{ // !somehost, must be localhost or 127.0.0.1
		command: cmd("serve --tls-terminated-tcp=443 --bg tcp://somehost:5432"),
		wantErr: exactErr(errHelp, "errHelp"),
	})
	add(step{ // bad target port, too low
		command: cmd("serve --tls-terminated-tcp=443 --bg tcp://somehost:0"),
		wantErr: exactErr(errHelp, "errHelp"),
	})
	add(step{ // bad target port, too high
		command: cmd("serve --tls-terminated-tcp=443 --bg tcp://somehost:65536"),
		wantErr: exactErr(errHelp, "errHelp"),
	})
	add(step{ // support shorthand
		command: cmd("serve --tls-terminated-tcp=443 --bg 5432"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{
				443: {
					TCPForward:   "127.0.0.1:5432",
					TerminateTLS: "foo.test.ts.net",
				},
			},
		},
	})
	add(step{reset: true})
	add(step{
		command: cmd("serve --tls-terminated-tcp=443 --bg tcp://localhost:5432"),
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
		command: cmd("serve --tls-terminated-tcp=443 --bg tcp://127.0.0.1:8443"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{
				443: {
					TCPForward:   "127.0.0.1:8443",
					TerminateTLS: "foo.test.ts.net",
				},
			},
		},
	})
	// add(step{
	// 	command:   cmd("serve --tls-terminated-tcp=443 --bg tcp://127.0.0.1:8443"),
	// 	want:      nil, // nothing to save
	// })
	add(step{
		command: cmd("serve --tls-terminated-tcp=443 --bg tcp://localhost:8444"),
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
		command: cmd("serve --tls-terminated-tcp=443 --bg tcp://127.0.0.1:8445"),
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
		command: cmd("serve --tls-terminated-tcp=443 --bg tcp://localhost:123"),
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
		command: cmd("serve --tls-terminated-tcp=8443 off"),
		wantErr: anyErr(),
	})
	add(step{
		command: cmd("serve --tls-terminated-tcp=443 off"),
		want:    &ipn.ServeConfig{},
	})

	// // text
	add(step{reset: true})
	add(step{
		command: cmd("serve --https=443 --bg text:hello"),
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
		command: cmd("serve --https=443 --bg " + filepath.Join(td, "foo")),
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
		command: cmd("serve --https=443 --set-path=/some/where " + filepath.Join(td, "subdir/file-a")),
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
		command: cmd("serve --https=443 --bg bad/path"),
		wantErr: exactErr(errHelp, "errHelp"),
	})
	add(step{reset: true})
	add(step{
		command: cmd("serve --https=443 --bg " + filepath.Join(td, "subdir")),
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
		command: cmd("serve --https=443 off"),
		want:    &ipn.ServeConfig{},
	})

	// // combos
	add(step{reset: true})
	add(step{
		command: cmd("serve --bg localhost:3000"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "http://127.0.0.1:3000"},
				}},
			},
		},
	})
	add(step{ // enable funnel for primary port
		command: cmd("funnel --bg localhost:3000"),
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
	add(step{ // serving on secondary port doesn't change funnel on primary port
		command: cmd("serve --https=8443 --set-path=/bar localhost:3001"),
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
		command: cmd("funnel --https=8443 --set-path=/bar localhost:3001"),
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
		command: cmd("serve --bg localhost:3000"),
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
		command: cmd("serve --https=8443 --set-path=/bar off"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "http://127.0.0.1:3000"},
				}},
			},
		},
	})
	add(step{ // start a tcp forwarder on 8443
		command: cmd("serve --bg --tcp=8443 tcp://localhost:5432"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}, 8443: {TCPForward: "127.0.0.1:5432"}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "http://127.0.0.1:3000"},
				}},
			},
		},
	})
	add(step{ // remove primary port http handler
		command: cmd("serve off"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{8443: {TCPForward: "127.0.0.1:5432"}},
		},
	})
	add(step{ // remove tcp forwarder
		command: cmd("serve --tls-terminated-tcp=8443 off"),
		want:    &ipn.ServeConfig{},
	})

	// tricky steps
	add(step{reset: true})
	add(step{ // a directory with a trailing slash mount point
		command: cmd("serve --https=443 --set-path=/dir " + filepath.Join(td, "subdir")),
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
		command: cmd("serve --https=443 --set-path=/dir " + filepath.Join(td, "foo")),
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
		command: cmd("serve --https=443 --set-path=/dir " + filepath.Join(td, "foo")),
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
		command: cmd("serve --https=443 --set-path=/dir " + filepath.Join(td, "subdir")),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/dir/": {Path: filepath.Join(td, "subdir/")},
				}},
			},
		},
	})

	// // error states
	add(step{reset: true})
	add(step{ // tcp forward 5432 on serve port 443
		command: cmd("serve --tls-terminated-tcp=443 --bg tcp://localhost:5432"),
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
		command: cmd("serve --https=443 --bg localhost:3000"),
		wantErr: anyErr(),
	})
	add(step{reset: true})
	add(step{ // start a web handler on port 443
		command: cmd("serve --https=443 --bg localhost:3000"),
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
		command: cmd("serve --tls-terminated-tcp=443 --bg tcp://localhost:5432"),
		wantErr: anyErr(),
	})

	add(step{
		command: cmd("serve reset"),
		want:    &ipn.ServeConfig{},
	})

	// start two handlers and turn them off in one command
	add(step{
		command: cmd("serve --https=4545 --set-path=/foo --bg localhost:3000"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{4545: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:4545": {Handlers: map[string]*ipn.HTTPHandler{
					"/foo": {Proxy: "http://127.0.0.1:3000"},
				}},
			},
		},
	})
	add(step{
		command: cmd("serve --https=4545 --set-path=/bar --bg localhost:3000"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{4545: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:4545": {Handlers: map[string]*ipn.HTTPHandler{
					"/foo": {Proxy: "http://127.0.0.1:3000"},
					"/bar": {Proxy: "http://127.0.0.1:3000"},
				}},
			},
		},
	})
	add(step{
		command: cmd("serve --https=4545 --bg --yes localhost:3000 off"),
		want:    &ipn.ServeConfig{},
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
			env:          &serveEnv{http: "80"},
			expectedType: serveTypeHTTP,
			expectedPort: 80,
			expectedErr:  false,
		},
		{
			name:         "only https set",
			env:          &serveEnv{https: "10000"},
			expectedType: serveTypeHTTPS,
			expectedPort: 10000,
			expectedErr:  false,
		},
		{
			name:         "only tcp set",
			env:          &serveEnv{tcp: "8000"},
			expectedType: serveTypeTCP,
			expectedPort: 8000,
			expectedErr:  false,
		},
		{
			name:         "only tls-terminated-tcp set",
			env:          &serveEnv{tlsTerminatedTCP: "8080"},
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
			env:          &serveEnv{http: "80", https: "443"},
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

func TestExpandProxyTargetDev(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		defaultScheme    string
		supportedSchemes []string
		expected         string
		wantErr          bool
	}{
		{name: "port-only", input: "8080", expected: "http://127.0.0.1:8080"},
		{name: "hostname+port", input: "localhost:8080", expected: "http://127.0.0.1:8080"},
		{name: "convert-localhost", input: "http://localhost:8080", expected: "http://127.0.0.1:8080"},
		{name: "no-change", input: "http://127.0.0.1:8080", expected: "http://127.0.0.1:8080"},
		{name: "include-path", input: "http://127.0.0.1:8080/foo", expected: "http://127.0.0.1:8080/foo"},
		{name: "https-scheme", input: "https://localhost:8080", expected: "https://127.0.0.1:8080"},
		{name: "https+insecure-scheme", input: "https+insecure://localhost:8080", expected: "https+insecure://127.0.0.1:8080"},
		{name: "change-default-scheme", input: "localhost:8080", defaultScheme: "https", expected: "https://127.0.0.1:8080"},
		{name: "change-supported-schemes", input: "localhost:8080", defaultScheme: "tcp", supportedSchemes: []string{"tcp"}, expected: "tcp://127.0.0.1:8080"},

		// errors
		{name: "invalid-port", input: "localhost:9999999", wantErr: true},
		{name: "unsupported-scheme", input: "ftp://localhost:8080", expected: "", wantErr: true},
		{name: "not-localhost", input: "https://tailscale.com:8080", expected: "", wantErr: true},
		{name: "empty-input", input: "", expected: "", wantErr: true},
	}

	for _, tt := range tests {
		defaultScheme := "http"
		supportedSchemes := []string{"http", "https", "https+insecure"}

		if tt.supportedSchemes != nil {
			supportedSchemes = tt.supportedSchemes
		}
		if tt.defaultScheme != "" {
			defaultScheme = tt.defaultScheme
		}

		t.Run(tt.name, func(t *testing.T) {
			actual, err := expandProxyTargetDev(tt.input, supportedSchemes, defaultScheme)

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

func unindent(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSpace(line)
	}
	return strings.Join(lines, "\n")
}

func TestIsLegacyInvocation(t *testing.T) {
	tests := []struct {
		subcmd   serveMode
		args     []string
		expected bool
	}{
		{subcmd: serve, args: []string{"https", "localhost:3000"}, expected: true},
		{subcmd: serve, args: []string{"https:8443", "localhost:3000"}, expected: true},
		{subcmd: serve, args: []string{"http", "localhost:3000"}, expected: true},
		{subcmd: serve, args: []string{"http:80", "localhost:3000"}, expected: true},
		{subcmd: serve, args: []string{"tcp:2222", "tcp://localhost:22"}, expected: true},
		{subcmd: serve, args: []string{"tls-terminated-tcp:443", "tcp://localhost:80"}, expected: true},

		// false
		{subcmd: serve, args: []string{"3000"}, expected: false},
		{subcmd: serve, args: []string{"localhost:3000"}, expected: false},
	}

	for _, tt := range tests {
		args := strings.Join(tt.args, " ")
		t.Run(fmt.Sprintf("%v %s", infoMap[tt.subcmd].Name, args), func(t *testing.T) {
			actual := isLegacyInvocation(tt.subcmd, tt.args)

			if actual != tt.expected {
				t.Errorf("Got: %v; expected: %v", actual, tt.expected)
			}
		})
	}
}
