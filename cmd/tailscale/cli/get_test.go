// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bytes"
	"context"
	"flag"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"runtime"
	"testing"

	"tailscale.com/client/local"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/ipnserver"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tsd"
	"tailscale.com/tstest"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/wgengine"
)

func TestGetSettingsArePairedWithPrefFlags(t *testing.T) {
	// Every get setting should have a corresponding prefsOfFlag.
	// Some prefsOfFlag might not be in getSettings because it is either
	// a prefless flag or it doesn't apply to this operating system.
	for name := range getSettings {
		if _, ok := prefsOfFlag[name]; !ok {
			t.Errorf("mismatched getter: %s", name)
		}
	}
}

func TestGetSettingsArePairedWithSetFlags(t *testing.T) {
	// Every set flag should have a corresponding get setting,
	// except for prefless flags, which don't have get settings.
	setFlagSet.VisitAll(func(f *flag.Flag) {
		if preflessFlag(f.Name) {
			return
		}
		if _, ok := getSettings[f.Name]; !ok {
			t.Errorf("missing set flag: %s", f.Name)
		}
	})
}

func TestGetSettingsArePairedWithUpFlags(t *testing.T) {
	// Every up flag should have a corresponding get setting,
	// except for prefless flags, which don't have get settings.
	upFlagSet.VisitAll(func(f *flag.Flag) {
		if preflessFlag(f.Name) {
			return
		}
		if _, ok := getSettings[f.Name]; !ok {
			t.Errorf("missing up flag: %s", f.Name)
		}
	})
}

func TestGetSettingsWillRoundtrip(t *testing.T) {
	for _, tt := range []struct{ flag, value string }{
		// --nickname is at the top-level in .ProfileName
		{"nickname", "home"},
		{"nickname", "work"},
		// --update-check is nested in .AutoUpdate.Check
		{"update-check", "false"},
		{"update-check", "true"},
	} {
		name := tt.flag + "=" + tt.value
		t.Run(name, func(t *testing.T) {
			// Capture outln calls
			var stdout bytes.Buffer
			tstest.Replace[io.Writer](t, &Stdout, &stdout)

			// Use a fake localClient that processes settings updates
			lc := newLocalClient(t)
			tstest.Replace(t, &localClient, lc)

			// setCmd.FlagSet must be reset to parse arguments
			cmd := *setCmd
			cmd.FlagSet = newSetFlagSet(effectiveGOOS(), &setArgs)
			tstest.Replace(t, &setCmd, &cmd)
			tstest.Replace(t, &setFlagSet, cmd.FlagSet)

			// Capture errors from setCmd
			cmd.FlagSet.Init(cmd.FlagSet.Name(), flag.PanicOnError)
			defer func() {
				if r := recover(); r != nil {
					t.Fatal(r)
				}
			}()

			// Capture errors from getCmd
			tstest.Replace(t, &Fatalf, t.Fatalf)

			arg := "--" + tt.flag + "=" + tt.value
			t.Logf("tailscale set %s", arg)
			if err := setCmd.ParseAndRun(t.Context(), []string{arg}); err != nil {
				t.Fatal(err)
			}

			stdout.Reset()
			arg = tt.flag
			t.Logf("tailscale get %s", arg)
			if err := runGet(t.Context(), []string{arg}); err != nil {
				t.Fatal(err)
			}

			got := stdout.String()
			want := tt.value + "\n"
			if got != want {
				t.Errorf("got %q, want %q", got, want)
			}
		})
	}
}

func TestGetDefaultSettings(t *testing.T) {
	// Fetch the default settings from all of the flags
	for _, fs := range []*flag.FlagSet{setFlagSet, upFlagSet} {
		fs.VisitAll(func(f *flag.Flag) {
			if preflessFlag(f.Name) {
				return
			}

			t.Run(f.Name, func(t *testing.T) {
				// Capture outln calls
				var stdout bytes.Buffer
				tstest.Replace[io.Writer](t, &Stdout, &stdout)

				// Use a fake localClient that processes settings updates
				lc := newLocalClient(t)
				tstest.Replace(t, &localClient, lc)

				if err := runGet(t.Context(), []string{f.Name}); err != nil {
					t.Fatal(err)
				}

				want := f.DefValue
				switch f.Name {
				case "auto-update":
					// Unset by tailscale up.
					want = "unset"
				case "login-server":
					// The default settings is empty,
					// but tailscale up sets it on start.
					want = ""
				}
				want += "\n"

				got := stdout.String()
				if got != want {
					t.Errorf("tailscale get %s: got %q, want %q", f.Name, got, want)
				}
			})
		})
	}
	setFlagSet.VisitAll(func(f *flag.Flag) {
		if preflessFlag(f.Name) {
			return
		}
		if _, ok := getSettings[f.Name]; !ok {
			t.Errorf("missing set flag: %s", f.Name)
		}
	})
}

// TODO(sfllaw): Replace the following test IPN server and client once
// https://github.com/tailscale/tailscale/issues/15575 is complete.

func newLocalListener(t testing.TB) net.Listener {
	sock := filepath.Join(t.TempDir(), "sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func newLocalBackend(t testing.TB, logID logid.PublicID) *ipnlocal.LocalBackend {
	var logf logger.Logf = func(_ string, _ ...any) {}
	if testing.Verbose() {
		logf = tstest.WhileTestRunningLogger(t)
	}

	sys := new(tsd.System)
	if _, ok := sys.StateStore.GetOK(); !ok {
		sys.Set(new(mem.Store))
	}
	if _, ok := sys.Engine.GetOK(); !ok {
		eng, err := wgengine.NewFakeUserspaceEngine(logf, sys.Set, sys.HealthTracker(), sys.UserMetricsRegistry())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(eng.Close)

		sys.Set(eng)
	}

	lb, err := ipnlocal.NewLocalBackend(logf, logID, sys, 0)
	if err != nil {
		t.Fatal(err)
	}
	return lb
}

func newLocalClient(t testing.TB) *local.Client {
	if runtime.GOOS == "windows" {
		// Connect over a Unix domain socket for admin access,
		// which keeps ipnauth_notwindows happy, but ipnauth_windows
		// wants a different guarantee on Windows.
		t.Skip("newLocalClient doesn't know to authorize with safesocket.WindowsClientConn")
	}

	var logf logger.Logf = func(_ string, _ ...any) {}
	if testing.Verbose() {
		logf = tstest.WhileTestRunningLogger(t)
	}

	logID := logid.PublicID{}

	lb := newLocalBackend(t, logID)
	t.Cleanup(lb.Shutdown)

	// Connect over Unix domain socket for admin access.
	l := newLocalListener(t)
	t.Cleanup(func() { l.Close() })

	srv := ipnserver.New(logf, logID, lb.NetMon())
	srv.SetLocalBackend(lb)

	go srv.Run(t.Context(), l)

	return &local.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				var std net.Dialer
				return std.DialContext(ctx, "unix", l.Addr().String())
			},
		},
	}
}
