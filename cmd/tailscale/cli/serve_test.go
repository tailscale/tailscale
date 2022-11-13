// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
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
	// Stateful mutations, starting from an empty config.
	type step struct {
		command []string                       // serve args; nil means no command to run (only reset)
		reset   bool                           // if true, reset all ServeConfig state
		want    *ipn.ServeConfig               // non-nil means we want a save of this value
		wantErr func(error) (badErrMsg string) // nil means no error is wanted
		line    int                            // line number of addStep call, for error messages
	}
	var steps []step
	add := func(s step) {
		_, _, s.line, _ = runtime.Caller(1)
		steps = append(steps, s)
	}

	// funnel
	add(step{reset: true})
	add(step{
		command: cmd("funnel on"),
		want:    &ipn.ServeConfig{AllowFunnel: map[ipn.HostPort]bool{"foo.test.ts.net:443": true}},
	})
	add(step{
		command: cmd("funnel on"),
		want:    nil, // nothing to save
	})
	add(step{
		command: cmd("funnel off"),
		want:    &ipn.ServeConfig{},
	})
	add(step{
		command: cmd("funnel off"),
		want:    nil, // nothing to save
	})
	add(step{
		command: cmd("funnel"),
		wantErr: exactErr(flag.ErrHelp, "flag.ErrHelp"),
	})

	// https
	add(step{reset: true})
	add(step{
		command: cmd("/ proxy 0"), // invalid port, too low
		wantErr: anyErr(),
	})
	add(step{
		command: cmd("/ proxy 65536"), // invalid port, too high
		wantErr: anyErr(),
	})
	add(step{
		command: cmd("/ proxy somehost"), // invalid host
		wantErr: anyErr(),
	})
	add(step{
		command: cmd("/ proxy http://otherhost"), // invalid host
		wantErr: anyErr(),
	})
	add(step{
		command: cmd("/ proxy httpz://127.0.0.1"), // invalid scheme
		wantErr: anyErr(),
	})
	add(step{
		command: cmd("/ proxy 3000"),
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
		command: cmd("--serve-port=9999 /abc proxy 3001"),
		wantErr: anyErr(),
	}) // invalid port
	add(step{
		command: cmd("--serve-port=8443 /abc proxy 3001"),
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
		command: cmd("--serve-port=10000 / text hi"),
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
		command: cmd("--remove /foo"),
		want:    nil, // nothing to save
		wantErr: anyErr(),
	}) // handler doesn't exist, so we get an error
	add(step{
		command: cmd("--remove --serve-port=10000 /"),
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
		command: cmd("--remove /"),
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
		command: cmd("--remove --serve-port=8443 /abc"),
		want:    &ipn.ServeConfig{},
	})
	add(step{
		command: cmd("bar proxy https://127.0.0.1:8443"),
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
		command: cmd("bar proxy https://127.0.0.1:8443"),
		want:    nil, // nothing to save
	})
	add(step{reset: true})
	add(step{
		command: cmd("/ proxy https+insecure://127.0.0.1:3001"),
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
		command: cmd("/foo proxy localhost:3000"),
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
		command: cmd("--serve-port=8443 /foo proxy localhost:3000"),
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

	// tcp
	add(step{reset: true})
	add(step{
		command: cmd("tcp 5432"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{
				443: {TCPForward: "127.0.0.1:5432"},
			},
		},
	})
	add(step{
		command: cmd("tcp -terminate-tls 8443"),
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
		command: cmd("tcp -terminate-tls 8443"),
		want:    nil, // nothing to save
	})
	add(step{
		command: cmd("tcp --terminate-tls 8444"),
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
		command: cmd("tcp -terminate-tls=false 8445"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{
				443: {TCPForward: "127.0.0.1:8445"},
			},
		},
	})
	add(step{reset: true})
	add(step{
		command: cmd("tcp 123"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{
				443: {TCPForward: "127.0.0.1:123"},
			},
		},
	})
	add(step{
		command: cmd("--remove tcp 321"),
		wantErr: anyErr(),
	}) // handler doesn't exist, so we get an error
	add(step{
		command: cmd("--remove tcp 123"),
		want:    &ipn.ServeConfig{},
	})

	// text
	add(step{reset: true})
	add(step{
		command: cmd("/ text hello"),
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
		command: cmd("/ path " + filepath.Join(td, "foo")),
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
		command: cmd("/some/where path " + filepath.Join(td, "subdir/file-a")),
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
	add(step{
		command: cmd("/ path missing"),
		wantErr: exactErr(flag.ErrHelp, "flag.ErrHelp"),
	})
	add(step{reset: true})
	add(step{
		command: cmd("/ path " + filepath.Join(td, "subdir")),
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
		command: cmd("--remove /"),
		want:    &ipn.ServeConfig{},
	})

	// combos
	add(step{reset: true})
	add(step{
		command: cmd("/ proxy 3000"),
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
		command: cmd("funnel on"),
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
		command: cmd("--serve-port=8443 /bar proxy 3001"),
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
		command: cmd("--serve-port=8443 funnel on"),
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
		command: cmd("funnel off"),
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
		command: cmd("--serve-port=8443 --remove /bar"),
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
		command: cmd("--serve-port=8443 tcp 5432"),
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
		command: cmd("--remove /"),
		want: &ipn.ServeConfig{
			AllowFunnel: map[ipn.HostPort]bool{"foo.test.ts.net:8443": true},
			TCP:         map[uint16]*ipn.TCPPortHandler{8443: {TCPForward: "127.0.0.1:5432"}},
		},
	})
	add(step{ // remove tcp forwarder
		command: cmd("--serve-port=8443 --remove tcp 5432"),
		want: &ipn.ServeConfig{
			AllowFunnel: map[ipn.HostPort]bool{"foo.test.ts.net:8443": true},
		},
	})
	add(step{ // turn off funnel
		command: cmd("--serve-port=8443 funnel off"),
		want:    &ipn.ServeConfig{},
	})

	// tricky steps
	add(step{reset: true})
	add(step{ // a directory with a trailing slash mount point
		command: cmd("/dir path " + filepath.Join(td, "subdir")),
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
		command: cmd("/dir path " + filepath.Join(td, "foo")),
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
		command: cmd("/dir path " + filepath.Join(td, "foo")),
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
		command: cmd("/dir path " + filepath.Join(td, "subdir")),
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
	add(step{ // make sure we can't add "tcp" as if it was a mount
		command: cmd("tcp text foo"),
		wantErr: exactErr(flag.ErrHelp, "flag.ErrHelp"),
	})
	add(step{ // "/tcp" is fine though as a mount
		command: cmd("/tcp text foo"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/tcp": {Text: "foo"},
				}},
			},
		},
	})
	add(step{reset: true})
	add(step{ // tcp forward 5432 on serve port 443
		command: cmd("tcp 5432"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{
				443: {TCPForward: "127.0.0.1:5432"},
			},
		},
	})
	add(step{ // try to start a web handler on the same port
		command: cmd("/ proxy 3000"),
		wantErr: exactErr(flag.ErrHelp, "flag.ErrHelp"),
	})
	add(step{reset: true})
	add(step{ // start a web handler on port 443
		command: cmd("/ proxy 3000"),
		want: &ipn.ServeConfig{
			TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "http://127.0.0.1:3000"},
				}},
			},
		},
	})
	add(step{ // try to start a tcp forwarder on the same port
		command: cmd("tcp 5432"),
		wantErr: exactErr(flag.ErrHelp, "flag.ErrHelp"),
	})

	// And now run the steps above.
	var current *ipn.ServeConfig
	for i, st := range steps {
		if st.reset {
			t.Logf("Executing step #%d, line %v: [reset]", i, st.line)
			current = nil
		}
		if st.command == nil {
			continue
		}
		t.Logf("Executing step #%d, line %v: %q ... ", i, st.line, st.command)

		var stdout bytes.Buffer
		var flagOut bytes.Buffer
		var newState *ipn.ServeConfig
		e := &serveEnv{
			testFlagOut: &flagOut,
			testStdout:  &stdout,
			testGetLocalClientStatus: func(context.Context) (*ipnstate.Status, error) {
				return &ipnstate.Status{
					Self: &ipnstate.PeerStatus{
						DNSName:      "foo.test.ts.net",
						Capabilities: []string{tailcfg.NodeAttrFunnel},
					},
				}, nil
			},
			testGetServeConfig: func(context.Context) (*ipn.ServeConfig, error) {
				return current, nil
			},
			testSetServeConfig: func(_ context.Context, c *ipn.ServeConfig) error {
				newState = c
				return nil
			},
		}
		cmd := newServeCommand(e)
		err := cmd.ParseAndRun(context.Background(), st.command)
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
			t.Fatalf("step #%d, line %v: got success (saved=%v), but wanted an error", i, st.line, newState != nil)
		}
		if !reflect.DeepEqual(newState, st.want) {
			t.Fatalf("[%d] %v: bad state. got:\n%s\n\nwant:\n%s\n",
				i, st.command, asJSON(newState), asJSON(st.want))
			// NOTE: asJSON will omit empty fields, which might make
			// result in bad state got/want diffs being the same, even
			// though the actual state is different. Use below to debug:
			// t.Fatalf("[%d] %v: bad state. got:\n%+v\n\nwant:\n%+v\n",
			// i, st.command, newState, st.want)
		}
		if newState != nil {
			current = newState
		}
	}
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
	cmds := strings.Fields(s)
	fmt.Printf("cmd: %v", cmds)
	return cmds
}
