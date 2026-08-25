// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || freebsd || openbsd

package dns

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"tailscale.com/util/must"
)

// fakeResolvconf is the canned behavior of the two read-only resolvconf
// subcommands openresolvManager uses: "-i" to list the names of the registered
// config snippets, and "-l" to dump their contents.
type fakeResolvconf struct {
	listOut  string // stdout of "resolvconf -i"
	listCode int    // exit status of "resolvconf -i"
	dumpOut  string // stdout of "resolvconf -l ..."
	dumpCode int    // exit status of "resolvconf -l ..."
}

// install puts f at the front of $PATH as "resolvconf", so that the exec.Command
// calls in openresolv.go find it, and returns the path of the file it appends
// its arguments to, one invocation per line.
//
// The canned stdout reaches the script through files rather than being
// substituted into it, so that no test data has to survive shell quoting.
func (f fakeResolvconf) install(t *testing.T) (argvLog string) {
	t.Helper()

	dir := t.TempDir()
	writeFile := func(name, content string) string {
		path := filepath.Join(dir, name)
		must.Do(os.WriteFile(path, []byte(content), 0644))
		return path
	}
	argvLog = filepath.Join(dir, "argv")
	listOut := writeFile("list-out", f.listOut)
	dumpOut := writeFile("dump-out", f.dumpOut)

	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' "$*" >>%s
case "$1" in
-i)	cat %s
	# Diagnostics on stderr must never be parsed as snippet names.
	echo 'No resolv.conf for key bogus' >&2
	exit %d ;;
-l)	cat %s
	exit %d ;;
esac
echo "fake resolvconf: unexpected args: $*" >&2
exit 99
`, argvLog, listOut, f.listCode, dumpOut, f.dumpCode)
	must.Do(os.WriteFile(filepath.Join(dir, "resolvconf"), []byte(script), 0755))

	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return argvLog
}

func TestOpenresolvGetBaseConfig(t *testing.T) {
	// The dump openresolv prints for a single snippet belonging to eth0.
	const eth0Dump = "# resolv.conf from eth0\nnameserver 192.168.1.1\nsearch lan\n"

	tests := []struct {
		name       string
		resolvconf fakeResolvconf

		wantNameservers []string
		wantSearch      []string
		wantErr         bool
		// wantArgv is every resolvconf invocation we expect, in order.
		wantArgv []string
	}{
		{
			// The bug in tailscale/tailscale#20825: openresolv exits 2
			// when its key directory exists but is empty. That means
			// "no snippets", so we must report an empty base config
			// rather than failing the whole DNS reconfiguration.
			name:       "no_snippets_at_all",
			resolvconf: fakeResolvconf{listCode: 2},
			wantArgv:   []string{"-i"},
		},
		{
			// The other half of #20825: we're the only registered
			// snippet, so "resolvconf -l" must not be run at all, lest
			// openresolv hand our own config back as our upstream.
			name:       "only_tailscale_registered",
			resolvconf: fakeResolvconf{listOut: "tailscale\n"},
			wantArgv:   []string{"-i"},
		},
		{
			// openresolv exits 0 with no output when it has no key
			// directory yet. Same conclusion, different exit status.
			name:     "empty_listing_exit_zero",
			wantArgv: []string{"-i"},
		},
		{
			name: "tailscale_among_others",
			resolvconf: fakeResolvconf{
				listOut: "eth0 tailscale wlan0\n",
				dumpOut: eth0Dump,
			},
			wantNameservers: []string{"192.168.1.1"},
			wantSearch:      []string{"lan."},
			// Priority order must be preserved, and our own snippet dropped.
			wantArgv: []string{"-i", "-l eth0 wlan0"},
		},
		{
			name: "no_tailscale_snippet_yet",
			resolvconf: fakeResolvconf{
				listOut: "eth0\n",
				dumpOut: eth0Dump,
			},
			wantNameservers: []string{"192.168.1.1"},
			wantSearch:      []string{"lan."},
			wantArgv:        []string{"-i", "-l eth0"},
		},
		{
			// Any status other than 2 is a real failure and must be
			// reported, so the caller can flag DNS as unhealthy.
			name:       "listing_fails",
			resolvconf: fakeResolvconf{listCode: 1},
			wantErr:    true,
			wantArgv:   []string{"-i"},
		},
		{
			// A snippet can be deregistered between the two calls. The
			// dump then prints nothing and exits 2; that's an empty base
			// config, not a reason to abandon the reconfiguration.
			name: "snippet_vanished_before_dump",
			resolvconf: fakeResolvconf{
				listOut:  "eth0\n",
				dumpCode: 2,
			},
			wantArgv: []string{"-i", "-l eth0"},
		},
		{
			// Defense in depth for tailscale/tailscale#7816: quad-100
			// must never become our own upstream, even if some other
			// snippet names it.
			name: "quad-100_in_another_snippet",
			resolvconf: fakeResolvconf{
				listOut: "eth0\n",
				dumpOut: "nameserver 100.100.100.100\nnameserver 192.168.1.1\nnameserver fd7a:115c:a1e0::53\nsearch lan\n",
			},
			wantNameservers: []string{"192.168.1.1"},
			wantSearch:      []string{"lan."},
			wantArgv:        []string{"-i", "-l eth0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			argvLog := tt.resolvconf.install(t)
			m := openresolvManager{t.Logf}

			cfg, err := m.GetBaseConfig()
			if gotErr := err != nil; gotErr != tt.wantErr {
				t.Fatalf("GetBaseConfig() error = %v, want error = %v", err, tt.wantErr)
			}

			var gotNameservers []string
			for _, ns := range cfg.Nameservers {
				gotNameservers = append(gotNameservers, ns.String())
			}
			if !slices.Equal(gotNameservers, tt.wantNameservers) {
				t.Errorf("nameservers = %q, want %q", gotNameservers, tt.wantNameservers)
			}

			var gotSearch []string
			for _, d := range cfg.SearchDomains {
				gotSearch = append(gotSearch, d.WithTrailingDot())
			}
			if !slices.Equal(gotSearch, tt.wantSearch) {
				t.Errorf("search domains = %q, want %q", gotSearch, tt.wantSearch)
			}

			var gotArgv []string
			if b, err := os.ReadFile(argvLog); err == nil {
				gotArgv = strings.Split(strings.TrimRight(string(b), "\n"), "\n")
			}
			if !slices.Equal(gotArgv, tt.wantArgv) {
				t.Errorf("resolvconf invocations = %q, want %q", gotArgv, tt.wantArgv)
			}
		})
	}
}
