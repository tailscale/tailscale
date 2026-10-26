// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js && !ts_omit_acme

package local

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"

	"tailscale.com/tstest/nettest"
)

func TestCertStatusUnsupported(t *testing.T) {
	tests := []struct {
		name            string
		status          int
		wantUnsupported bool
	}{
		{name: "not_found", status: http.StatusNotFound, wantUnsupported: true},
		{name: "server_error", status: http.StatusInternalServerError, wantUnsupported: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nw := nettest.GetNetwork(t)
			ts := nettest.NewHTTPServer(nw, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
			}))
			defer ts.Close()

			lc := &Client{
				Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return nw.Dial(ctx, network, ts.Listener.Addr().String())
				},
			}
			_, err := lc.CertStatus(context.Background(), "node.example.ts.net")
			if err == nil {
				t.Fatal("CertStatus: got nil error")
			}
			if got := errors.Is(err, ErrCertStatusUnsupported); got != tt.wantUnsupported {
				t.Errorf("errors.Is(%v, ErrCertStatusUnsupported) = %v, want %v", err, got, tt.wantUnsupported)
			}
			if got := errors.Is(err, errors.ErrUnsupported); got != tt.wantUnsupported {
				t.Errorf("errors.Is(%v, errors.ErrUnsupported) = %v, want %v", err, got, tt.wantUnsupported)
			}
		})
	}
}
