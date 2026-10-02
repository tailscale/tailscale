// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsp

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"tailscale.com/health"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/key"
)

// TestLogoutAgainstTestControl verifies that Logout expires the node on the
// coordination server, so a subsequent register reports the key as expired.
func TestLogoutAgainstTestControl(t *testing.T) {
	ctrl := &testcontrol.Server{}
	ctrl.HTTPTestServer = httptest.NewUnstartedServer(ctrl)
	ctrl.HTTPTestServer.Start()
	t.Cleanup(ctrl.HTTPTestServer.Close)
	baseURL := ctrl.HTTPTestServer.URL

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ht := new(health.Tracker)

	serverKey, err := DiscoverServerKey(ctx, baseURL)
	if err != nil {
		t.Fatalf("DiscoverServerKey: %v", err)
	}

	nodeKey := key.NewNode()
	machineKey := key.NewMachine()

	newClient := func() *Client {
		t.Helper()
		c, err := NewClient(ClientOpts{
			ServerURL:     baseURL,
			MachineKey:    machineKey,
			HealthTracker: ht,
		})
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		c.SetControlPublicKey(serverKey)
		return c
	}

	// Register the node.
	c := newClient()
	defer c.Close()
	resp, err := c.Register(ctx, RegisterOpts{
		NodeKey:  nodeKey,
		Hostinfo: &tailcfg.Hostinfo{Hostname: "a"},
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if resp.NodeKeyExpired {
		t.Fatal("node key unexpectedly expired right after register")
	}

	// Log out.
	if err := c.Logout(ctx, nodeKey); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	// A fresh register of the same node key should now report it expired.
	c2 := newClient()
	defer c2.Close()
	resp, err = c2.Register(ctx, RegisterOpts{
		NodeKey:  nodeKey,
		Hostinfo: &tailcfg.Hostinfo{Hostname: "a"},
	})
	if err != nil {
		t.Fatalf("Register after logout: %v", err)
	}
	if !resp.NodeKeyExpired {
		t.Error("node key not reported expired after Logout")
	}
}
