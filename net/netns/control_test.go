// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"syscall"
	"testing"

	"tailscale.com/net/netmon"
)

func TestSetNamespaceControl(t *testing.T) {
	for _, callerHook := range []bool{false, true} {
		for _, failure := range []string{"none", "namespace", "caller"} {
			t.Run(fmt.Sprintf("caller=%v/%s", callerHook, failure), func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				raw := &struct{ syscall.RawConn }{}
				const network, address = "tcp4", "192.0.2.1:443"
				var calls []string
				namespaceErr := errors.New("namespace failed")
				callerErr := errors.New("caller failed")
				check := func(name, n, a string, c syscall.RawConn) {
					t.Helper()
					calls = append(calls, name)
					if n != network || a != address || c != raw {
						t.Errorf("%s arguments = (%q, %q, %v); want (%q, %q, %v)", name, n, a, c, network, address, raw)
					}
				}
				var d net.Dialer
				if callerHook {
					d.ControlContext = func(gotCtx context.Context, n, a string, c syscall.RawConn) error {
						check("caller", n, a, c)
						if gotCtx != ctx {
							t.Error("ControlContext context was replaced")
						}
						if failure == "caller" {
							return callerErr
						}
						return nil
					}
				}
				setNamespaceControl(&d, func(n, a string, c syscall.RawConn) error {
					check("namespace", n, a, c)
					if failure == "namespace" {
						return namespaceErr
					}
					return nil
				})
				if d.Control != nil {
					t.Fatal("namespace setup installed Control instead of ControlContext")
				}
				err := d.ControlContext(ctx, network, address, raw)
				wantCalls := []string{"namespace"}
				var wantErr error
				if failure == "namespace" {
					wantErr = namespaceErr
				} else if callerHook {
					wantCalls = append(wantCalls, "caller")
					if failure == "caller" {
						wantErr = callerErr
					}
				}
				if err != wantErr {
					t.Errorf("error = %v; want %v", err, wantErr)
				}
				if !slices.Equal(calls, wantCalls) {
					t.Errorf("calls = %v; want %v", calls, wantCalls)
				}
			})
		}
	}
}

func TestFromDialerControlContext(t *testing.T) {
	// These globals also control proxy wrapping on platforms without SOCKS.
	// Do not run this test in parallel.
	wasDisabled, origWrap := disabled.Load(), wrapDialer
	t.Cleanup(func() {
		disabled.Store(wasDisabled)
		wrapDialer = origWrap
	})
	for _, disable := range []bool{false, true} {
		for _, proxy := range []bool{false, true} {
			for _, callerHook := range []bool{false, true} {
				t.Run(fmt.Sprintf("disabled=%v/proxy=%v/caller=%v", disable, proxy, callerHook), func(t *testing.T) {
					disabled.Store(disable)
					wrapDialer = nil // do not depend on the process proxy environment
					wrapped := false
					if proxy {
						wrapDialer = func(d Dialer) Dialer {
							wrapped = true
							return &controlTestProxy{d}
						}
					}
					callerErr := errors.New("caller stopped dial")
					called := false
					d := &net.Dialer{KeepAlive: -1}
					if callerHook {
						d.ControlContext = func(context.Context, string, string, syscall.RawConn) error {
							called = true
							return callerErr
						}
					}
					got := FromDialer(t.Logf, netmon.NewStatic(), d)
					if want := proxy && !disable; wrapped != want {
						t.Errorf("proxy wrapped = %v; want %v", wrapped, want)
					}
					if disable && got != d {
						t.Error("disabled FromDialer did not return the original dialer")
					}
					if d.Control != nil {
						t.Error("FromDialer installed a legacy Control hook")
					}
					if want := !disable || callerHook; (d.ControlContext != nil) != want {
						t.Fatalf("ControlContext installed = %v; want %v", d.ControlContext != nil, want)
					}
					if d.KeepAlive != -1 {
						t.Error("FromDialer changed keepalive policy")
					}
					if !callerHook {
						return
					}
					// Loopback namespace setup requires no external network or
					// privileges. The caller hook aborts before connect.
					c, err := got.DialContext(t.Context(), "tcp4", "127.0.0.1:1")
					if c != nil {
						c.Close()
						t.Error("dial returned a connection despite hook error")
					}
					if !called || !errors.Is(err, callerErr) {
						t.Errorf("called = %v, dial error = %v; want caller error", called, err)
					}
				})
			}
		}
	}
}

func TestFromDialerRejectsControl(t *testing.T) {
	wasDisabled := disabled.Load()
	t.Cleanup(func() { disabled.Store(wasDisabled) })
	for _, disable := range []bool{false, true} {
		for _, contextual := range []bool{false, true} {
			t.Run(fmt.Sprintf("disabled=%v/context=%v", disable, contextual), func(t *testing.T) {
				disabled.Store(disable)
				d := &net.Dialer{Control: func(string, string, syscall.RawConn) error {
					t.Fatal("Control must not be called")
					return nil
				}}
				if contextual {
					d.ControlContext = func(context.Context, string, string, syscall.RawConn) error {
						t.Fatal("ControlContext must not be called")
						return nil
					}
				}
				defer func() {
					if got := recover(); got != "netns.FromDialer: use ControlContext instead of Control" {
						t.Errorf("panic = %v; want rejection of Control", got)
					}
				}()
				FromDialer(t.Logf, netmon.NewStatic(), d)
			})
		}
	}
}

// controlTestProxy verifies that a wrapper uses the configured underlying dialer.
// It does not implement the SOCKS protocol.
type controlTestProxy struct{ Dialer }
