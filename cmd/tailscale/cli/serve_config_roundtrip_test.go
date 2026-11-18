// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

// TestServeConfigRoundTrip checks, for each row, that the commands build the
// state; that the file builds it with set-config, on a fresh node and over one
// serving something else; that get-config writes the file back whichever way
// the state was built, with --all and per service with --service; and that
// serve status --json reads out the same, and carries the state back through
// set-config except for what that format cannot hold.
func TestServeConfigRoundTrip(t *testing.T) {
	type services = map[tailcfg.ServiceName]*ipn.ServiceConfig
	type tcp = map[uint16]*ipn.TCPPortHandler
	type web = map[ipn.HostPort]*ipn.WebServerConfig
	type handlers = map[string]*ipn.HTTPHandler

	tests := []struct {
		name string
		cli  []string // tailscale serve commands
		file string   // what get-config --all writes
		// The state both build.
		services   services
		advertised []string
	}{
		// Host spelling: IPv6 hosts are bracketed, and case is kept.
		{
			name:       "tcp_ipv6",
			cli:        []string{"--service=svc:foo --tcp=5432 tcp://[::1]:5432"},
			file:       `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:5432": "tcp://[::1]:5432"}}}}`,
			services:   services{"svc:foo": {TCP: tcp{5432: {TCPForward: "[::1]:5432"}}}},
			advertised: []string{"svc:foo"},
		},
		{
			name: "web_ipv6",
			cli:  []string{"--service=svc:foo --http=80 http://[::1]:3000"},
			file: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:80": "http://[::1]:3000"}}}}`,
			services: services{"svc:foo": {
				TCP: tcp{80: {HTTP: true}},
				Web: web{"foo.test.ts.net:80": {Handlers: handlers{"/": {Proxy: "http://[::1]:3000"}}}},
			}},
			advertised: []string{"svc:foo"},
		},
		{
			name: "mixed_case_host",
			cli:  []string{"--service=svc:foo --http=80 http://App.example.com:3000"},
			file: `{"version": "0.0.1", "services": {"svc:foo": {"endpoints": {"tcp:80": "http://App.example.com:3000"}}}}`,
			services: services{"svc:foo": {
				TCP: tcp{80: {HTTP: true}},
				Web: web{"foo.test.ts.net:80": {Handlers: handlers{"/": {Proxy: "http://App.example.com:3000"}}}},
			}},
			advertised: []string{"svc:foo"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			skipOnWindows(t, tt.file)
			dir := serveTestDir(t)
			file := expandDir(tt.file, dir)
			want := expandDirInServices(tt.services, dir)

			// commands -> state
			cliNode := buildState(t, dir, tt.cli)
			checkState(t, "tailscale serve", cliNode, want, tt.advertised)

			// file -> state
			fileNode := newServiceHostClient()
			setConfig(t, fileNode, "--all", file)
			checkState(t, "set-config --all", fileNode, want, tt.advertised)

			replaced := buildState(t, dir, otherState)
			setConfig(t, replaced, "--all", file)
			checkState(t, "set-config --all over another state", replaced, want, tt.advertised)

			// state -> file
			nodes := []struct {
				name string
				lc   *fakeLocalServeClient
			}{{"CLI-built", cliNode}, {"file-built", fileNode}}
			for _, n := range nodes {
				checkJSON(t, "get-config --all on the "+n.name+" node", file, runServeCmd(t, n.lc, "get-config", "--all"))
			}

			// state -> file -> state, per service
			perService := newServiceHostClient()
			for svc, svcFile := range perServiceFiles(t, file) {
				for _, n := range nodes {
					checkJSON(t, "get-config --service="+svc+" on the "+n.name+" node", svcFile, runServeCmd(t, n.lc, "get-config", "--service="+svc))
				}
				setConfig(t, perService, "--service="+svc, svcFile)
			}
			checkState(t, "set-config --service for each service", perService, want, tt.advertised)

			// state -> serve status --json -> state
			status := runServeCmd(t, cliNode, "status", "--json")
			if got := runServeCmd(t, fileNode, "status", "--json"); got != status {
				t.Errorf("serve status --json differs between the CLI-built and file-built nodes (-cli +file):\n%s", cmp.Diff(status, got))
			}
			// set-config reads serve status --json as the legacy format, which
			// has no advertised state: every service it names comes back
			// advertised, and an advertised service without config is lost.
			legacy := newServiceHostClient()
			if _, _, err := serveRun(legacy, "set-config", "--all", writeTmpServeConfig(t, status)); err != nil {
				t.Fatalf("set-config --all of serve status --json: %v", err)
			}
			var legacyAdvertised []string
			for svc := range want {
				legacyAdvertised = append(legacyAdvertised, svc.String())
			}
			slices.Sort(legacyAdvertised)
			checkState(t, "set-config --all of serve status --json", legacy, want, legacyAdvertised)
		})
	}
}

// otherState is a node already serving other things, so applying a file over
// it shows the file replaces that state rather than adding to it.
var otherState = []string{
	"--service=svc:foo --http=8080 text:stale",
	"drain svc:foo",
	"--service=svc:stale --tcp=22 tcp://localhost:22",
	"advertise svc:other",
}

// serviceHostStatus is a tagged node, since only tagged nodes may host Services.
var serviceHostStatus = &ipnstate.Status{
	BackendState:   ipn.Running.String(),
	Self:           &ipnstate.PeerStatus{DNSName: "foo.test.ts.net", Tags: ptrToReadOnlySlice([]string{"tag:server"})},
	CurrentTailnet: &ipnstate.TailnetStatus{MagicDNSSuffix: "test.ts.net"},
}

func newServiceHostClient() *fakeLocalServeClient {
	return &fakeLocalServeClient{
		config:             new(ipn.ServeConfig),
		statusWithoutPeers: serviceHostStatus,
		SOMarkInUse:        true, // permits remote proxy destinations on Linux
	}
}

// serveRun runs "tailscale serve <args>" against lc.
func serveRun(lc *fakeLocalServeClient, args ...string) (stdout, stderr string, err error) {
	var out, errOut, flagOut bytes.Buffer
	e := &serveEnv{lc: lc, testStdout: &out, testStderr: &errOut, testFlagOut: &flagOut}
	err = newServeV2Command(e, serve).ParseAndRun(context.Background(), args)
	return out.String(), errOut.String() + flagOut.String(), err
}

// runServeCmd runs "tailscale serve <args>" against lc and returns its stdout.
// It fails the test on an error or on any output to stderr, where the CLI
// writes warnings.
func runServeCmd(t *testing.T, lc *fakeLocalServeClient, args ...string) string {
	t.Helper()
	stdout, stderr, err := serveRun(lc, args...)
	if err != nil || stderr != "" {
		t.Fatalf("tailscale serve %s: err = %v\nstderr:\n%s", strings.Join(args, " "), err, stderr)
	}
	return stdout
}

// setConfig applies the config file body to lc with set-config.
func setConfig(t *testing.T, lc *fakeLocalServeClient, flag, body string) {
	t.Helper()
	runServeCmd(t, lc, "set-config", flag, writeTmpServeConfig(t, body))
}

// buildState runs tailscale serve commands against a fresh service host.
func buildState(t *testing.T, dir string, cmds []string) *fakeLocalServeClient {
	t.Helper()
	lc := newServiceHostClient()
	for _, c := range cmds {
		runServeCmd(t, lc, cmd(expandDir(c, dir))...)
	}
	return lc
}

// checkState compares lc's Services and advertised Services with want.
func checkState(t *testing.T, how string, lc *fakeLocalServeClient, want map[tailcfg.ServiceName]*ipn.ServiceConfig, wantAdvertised []string) {
	t.Helper()
	if diff := cmp.Diff(want, lc.config.Services, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("%s: Services (-want +got):\n%s", how, diff)
	}
	if diff := cmp.Diff(wantAdvertised, advertisedServices(lc), cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("%s: advertised (-want +got):\n%s", how, diff)
	}
}

// assertSameState compares got with want in state and in every read-out:
// serve status --json and get-config --all, including its error.
func assertSameState(t *testing.T, want, got *fakeLocalServeClient) {
	t.Helper()
	checkState(t, "state", got, want.config.Services, advertisedServices(want))
	for _, args := range [][]string{{"status", "--json"}, {"get-config", "--all"}} {
		wantOut, _, wantErr := serveRun(want, args...)
		gotOut, _, gotErr := serveRun(got, args...)
		if diff := cmp.Diff(wantOut, gotOut); diff != "" {
			t.Errorf("serve %s (-want +got):\n%s", strings.Join(args, " "), diff)
		}
		if fmt.Sprint(wantErr) != fmt.Sprint(gotErr) {
			t.Errorf("serve %s err = %v; want %v", strings.Join(args, " "), gotErr, wantErr)
		}
	}
}

func advertisedServices(lc *fakeLocalServeClient) []string {
	prefs, _ := lc.GetPrefs(context.Background())
	return slices.Sorted(slices.Values(prefs.AdvertiseServices))
}

// checkJSON compares two JSON documents as values, so whitespace and key
// order do not matter. It diffs them laid out alike, so the diff reads as
// JSON.
func checkJSON(t *testing.T, how, want, got string) {
	t.Helper()
	w, err := indentJSON(want)
	if err != nil {
		t.Fatalf("invalid JSON in test: %v\n%s", err, want)
	}
	g, err := indentJSON(got)
	if err != nil {
		t.Fatalf("%s wrote invalid JSON: %v\n%s", how, err, got)
	}
	if diff := cmp.Diff(w, g); diff != "" {
		t.Errorf("%s (-want +got):\n%s", how, diff)
	}
}

// indentJSON lays out a JSON document with sorted keys.
func indentJSON(s string) (string, error) {
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	return string(b), err
}

// perServiceFiles splits a get-config --all file into the get-config
// --service file of each service: its entry, plus the version.
func perServiceFiles(t *testing.T, file string) map[string]string {
	t.Helper()
	var all struct {
		Version  string                    `json:"version"`
		Services map[string]map[string]any `json:"services"`
	}
	if err := json.Unmarshal([]byte(file), &all); err != nil {
		t.Fatalf("invalid JSON in test: %v\n%s", err, file)
	}
	files := make(map[string]string)
	for svc, entry := range all.Services {
		entry["version"] = all.Version
		b, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		files[svc] = string(b)
	}
	return files
}

// serveTestDir returns a directory holding index.html, for rows that serve a
// file as $DIR/index.html.
func serveTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("hi"), 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func expandDir(s, dir string) string { return strings.ReplaceAll(s, "$DIR", dir) }

// expandDirInServices returns a copy of svcs with $DIR expanded in the paths
// it serves.
func expandDirInServices(svcs map[tailcfg.ServiceName]*ipn.ServiceConfig, dir string) map[tailcfg.ServiceName]*ipn.ServiceConfig {
	out := make(map[tailcfg.ServiceName]*ipn.ServiceConfig)
	for name, svc := range svcs {
		svc = svc.Clone()
		for _, web := range svc.Web {
			for _, h := range web.Handlers {
				h.Path = expandDir(h.Path, dir)
			}
		}
		out[name] = svc
	}
	return out
}

// skipOnWindows skips a row that serves a Unix socket or a path on Windows.
// The CLI rejects Unix socket targets there. A Windows path would need JSON
// escaping in the row's file and comes back from the CLI with its separators
// respelled by filepath.Clean, so "$DIR/index.html" would not compare equal.
func skipOnWindows(t *testing.T, row ...string) {
	t.Helper()
	if runtime.GOOS != "windows" {
		return
	}
	for _, s := range row {
		if strings.Contains(s, "unix:") {
			t.Skip("the CLI does not serve Unix sockets on Windows")
		}
		if strings.Contains(s, "$DIR") {
			t.Skip("row spells a path with forward slashes")
		}
	}
}
