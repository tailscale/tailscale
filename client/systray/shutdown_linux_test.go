// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package systray

import (
	"bytes"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	dbus "github.com/godbus/dbus/v5"
	"tailscale.com/client/local"
)

func TestShutdownProcess(t *testing.T) {
	if socket := os.Getenv("TS_SYSTRAY_SHUTDOWN_SOCKET"); socket != "" {
		new(Menu).Run(&local.Client{Socket: socket, UseSocketOnly: true})
	}
}

// TestShutdownSignals exercises the real tray loop and signal handlers in a
// subprocess, isolated from the desktop and the test runner's signal handlers.
func TestShutdownSignals(t *testing.T) {
	if _, err := exec.LookPath("dbus-daemon"); err != nil {
		t.Skip("dbus-daemon not available")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		sig  os.Signal
	}{
		{"interrupt", syscall.SIGINT},
		{"terminated", syscall.SIGTERM},
		{"menu_quit", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := startSessionBus(t)
			registered := startFakeWatcher(t, addr)
			socket := startFakeLocalAPI(t)
			cmd := exec.Command(executable, "-test.run=^TestShutdownProcess$")
			cmd.Env = append(os.Environ(),
				"DBUS_SESSION_BUS_ADDRESS="+addr,
				"TS_SYSTRAY_SHUTDOWN_SOCKET="+socket,
				"GORACE=atexit_sleep_ms=0",
			)
			var output bytes.Buffer
			cmd.Stdout, cmd.Stderr = &output, &output
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			var waitErr error
			go func() {
				waitErr = cmd.Wait()
				close(done)
			}()
			t.Cleanup(func() {
				cmd.Process.Kill()
				<-done
			})
			select {
			case <-registered:
			case <-done:
				t.Fatalf("tray exited before registering: %v\n%s", waitErr, &output)
			case <-time.After(10 * time.Second):
				t.Fatal("tray did not register")
			}
			obj, layoutCall := waitForMenuLayout(t, addr, cmd.Process.Pid, "Quit")
			if tc.sig != nil {
				if err := cmd.Process.Signal(tc.sig); err != nil {
					t.Fatal(err)
				}
			} else {
				var revision uint32
				var layout struct {
					ID         int32
					Properties map[string]dbus.Variant
					Children   []dbus.Variant
				}
				if err := layoutCall.Store(&revision, &layout); err != nil {
					t.Fatal(err)
				}
				quitID := int32(-1)
				for _, child := range layout.Children {
					item := layout
					if err := dbus.Store([]any{child.Value()}, &item); err == nil && item.Properties["label"].Value() == "Quit" {
						quitID = item.ID
						break
					}
				}
				if quitID < 0 {
					t.Fatal("Quit item not found")
				}
				if err := obj.Call("com.canonical.dbusmenu.Event", 0, quitID, "clicked", dbus.MakeVariant(int32(0)), uint32(0)).Err; err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-done:
				if waitErr != nil {
					t.Fatalf("tray did not exit cleanly after %s: %v\n%s", tc.name, waitErr, &output)
				}
			case <-time.After(5 * time.Second):
				cmd.Process.Kill()
				<-done
				t.Fatalf("tray remained running after %s\n%s", tc.name, &output)
			}
		})
	}
}
