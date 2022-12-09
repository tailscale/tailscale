// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgengine_test

import (
	"testing"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/net/tstun"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/netstack"
	"tailscale.com/wgengine/router"
)

func TestIsNetstack(t *testing.T) {
	e, err := wgengine.NewUserspaceEngine(t.Logf, wgengine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if !wgengine.IsNetstack(e) {
		t.Errorf("IsNetstack = false; want true")
	}
}

func TestIsNetstackRouter(t *testing.T) {
	tests := []struct {
		name string
		conf wgengine.Config
		want bool
	}{
		{
			name: "no_netstack",
			conf: wgengine.Config{
				Tun:    newFakeOSTUN(),
				Router: newFakeOSRouter(),
			},
			want: false,
		},
		{
			name: "netstack",
			conf: wgengine.Config{},
			want: true,
		},
		{
			name: "hybrid_netstack",
			conf: wgengine.Config{
				Tun:    newFakeOSTUN(),
				Router: netstack.NewSubnetRouterWrapper(newFakeOSRouter()),
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := wgengine.NewUserspaceEngine(logger.Discard, tt.conf)
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			if got := wgengine.IsNetstackRouter(e); got != tt.want {
				t.Errorf("IsNetstackRouter = %v; want %v", got, tt.want)
			}

			if got := wgengine.IsNetstackRouter(wgengine.NewWatchdog(e)); got != tt.want {
				t.Errorf("IsNetstackRouter(watchdog-wrapped) = %v; want %v", got, tt.want)
			}
		})
	}
}

func newFakeOSRouter() router.Router {
	return someRandoOSRouter{router.NewFake(logger.Discard)}
}

type someRandoOSRouter struct {
	router.Router
}

func newFakeOSTUN() tun.Device {
	return someRandoOSTUN{tstun.NewFake()}
}

type someRandoOSTUN struct {
	tun.Device
}

// Name returns something that is not FakeTUN.
func (t someRandoOSTUN) Name() (string, error) { return "some_os_tun0", nil }
