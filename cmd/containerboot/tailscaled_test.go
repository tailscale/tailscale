// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/client/local"
)

func TestWatchTailscaledConfigChanges_BaselineBeforeStart(t *testing.T) {
	tests := []struct {
		name     string
		initial  func(current []byte) []byte
		wantLoad bool
	}{
		{
			name:     "update_after_tailscaled_read",
			initial:  func([]byte) []byte { return []byte(`{"Version":"alpha0"}`) },
			wantLoad: true,
		},
		{
			name:     "unchanged",
			initial:  func(current []byte) []byte { return current },
			wantLoad: false,
		},
		{
			name:     "initial_read_failed",
			initial:  func([]byte) []byte { return nil },
			wantLoad: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "cap-106.hujson")
			// The file as it is when the watcher starts, i.e. after the
			// operator has updated it.
			current := []byte(`{"Version":"alpha0","AdvertiseServices":["svc:a"]}`)
			if err := os.WriteFile(path, current, 0o600); err != nil {
				t.Fatal(err)
			}

			var reloads atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/localapi/v0/reload-config" {
					reloads.Add(1)
				}
				w.Write([]byte(`{"reloaded":true}`))
			}))
			defer srv.Close()
			lc := &local.Client{Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", srv.Listener.Addr().String())
			}}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			errCh := make(chan error, 1)
			go watchTailscaledConfigChanges(ctx, path, lc, tt.initial(current), errCh)

			deadline := time.After(2 * time.Second)
			for tt.wantLoad && reloads.Load() == 0 {
				select {
				case err := <-errCh:
					t.Fatal(err)
				case <-deadline:
					t.Fatal("config update made before the watcher started was never reloaded")
				case <-time.After(10 * time.Millisecond):
				}
			}
			if !tt.wantLoad {
				time.Sleep(300 * time.Millisecond)
				if n := reloads.Load(); n != 0 {
					t.Fatalf("unchanged config was reloaded %d times", n)
				}
			}
		})
	}
}
