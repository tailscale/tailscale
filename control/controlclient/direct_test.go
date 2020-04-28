// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build depends_on_currently_unreleased

package controlclient

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/tailscale/wireguard-go/wgcfg"
	"tailscale.com/tailcfg"
	"tailscale.io/control" // not yet released
)

// Test that when there are two controlclient connections using the
// same credentials, the later one disconnects the earlier one.
func TestClientsReusingKeys(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "control-test-")
	if err != nil {
		t.Fatal(err)
	}
	var server *control.Server
	httpsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		server.ServeHTTP(w, r)
	}))
	defer func() {
		httpsrv.CloseClientConnections()
		httpsrv.Close()
		os.RemoveAll(tmpdir)
	}()

	httpc := httpsrv.Client()
	httpc.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}

	server, err = control.New(tmpdir, tmpdir, httpsrv.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	server.QuietLogging = true

	hi := NewHostinfo()
	hi.FrontendLogID = "go-test-only"
	hi.BackendLogID = "go-test-only"
	c1, err := NewDirect(Options{
		ServerURL:      httpsrv.URL,
		HTTPTestClient: httpsrv.Client(),
		//TimeNow:   s.control.TimeNow,
		Logf: func(fmt string, args ...interface{}) {
			t.Helper()
			t.Logf("c1: "+fmt, args...)
		},
		Hostinfo: hi,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Use a cancelable context so that goroutines blocking in
	// PollNetMap shut down when the test exits.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Execute c1's login flow: TryLogin to get an auth URL,
	// postAuthURL to execute the (faked) OAuth segment of the flow,
	// and WaitLoginURL to complete the login on the client end.
	const user = "testuser1@tailscale.onmicrosoft.com"
	authURL, err := c1.TryLogin(ctx, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	postAuthURL(t, ctx, httpc, user, authURL)
	newURL, err := c1.WaitLoginURL(ctx, authURL)
	if err != nil {
		t.Fatal(err)
	}
	if newURL != "" {
		t.Fatalf("unexpected newURL: %s", newURL)
	}

	// Start c1's netmap poll in parallel with the rest of the
	// test. We're expecting it to block happily, invoking the no-op
	// update function periodically, then exit once c2 starts its own
	// poll below.
	gotNetmap := make(chan struct{}, 1)
	pollErrCh := make(chan error)
	go func() {
		pollErrCh <- c1.PollNetMap(ctx, -1, func(netMap *NetworkMap) {
			select {
			case gotNetmap <- struct{}{}:
			default:
			}
		})
	}()

	select {
	case <-gotNetmap:
		t.Logf("c1: received initial netmap")
	case err := <-pollErrCh:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("c1 did not receive an initial netmap")
	}

	// Connect c2, reusing c1's credentials. In other words, c2 *is*
	// c1 from the server's perspective.
	c2, err := NewDirect(Options{
		ServerURL:      httpsrv.URL,
		HTTPTestClient: httpsrv.Client(),
		Logf: func(fmt string, args ...interface{}) {
			t.Helper()
			t.Logf("c2: "+fmt, args...)
		},
		Persist:  c1.GetPersist(),
		Hostinfo: hi,
		NewDecompressor: func() (Decompressor, error) {
			return zstd.NewReader(nil)
		},
		KeepAlive: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	authURL, err = c2.TryLogin(ctx, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	// We don't expect to be given an authURL, our credentials from c1
	// should still be good.
	if authURL != "" {
		t.Errorf("unexpected authURL %s", authURL)
	}

	// Request a single netmap, so this function returns promptly
	// instead of blocking like c1's PollNetMap.
	err = c2.PollNetMap(ctx, 1, func(netMap *NetworkMap) {})
	if err != nil {
		t.Fatal(err)
	}

	// Now that c2 connected and got a netmap, we expect c1's poll to
	// have exited.
	select {
	case err := <-pollErrCh:
		t.Logf("c1: netmap poll aborted as expected (%v)", err)
	case <-time.After(5 * time.Second):
		t.Fatal("first client poll failed to close")
	}
}

func TestClientsReusingOldKey(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "control-test-")
	if err != nil {
		t.Fatal(err)
	}
	var server *control.Server
	httpsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		server.ServeHTTP(w, r)
	}))
	httpc := httpsrv.Client()
	httpc.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	server, err = control.New(tmpdir, tmpdir, httpsrv.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	server.QuietLogging = true
	defer func() {
		httpsrv.CloseClientConnections()
		httpsrv.Close()
		os.RemoveAll(tmpdir)
	}()

	hi := NewHostinfo()
	hi.FrontendLogID = "go-test-only"
	hi.BackendLogID = "go-test-only"
	genOpts := func() Options {
		return Options{
			ServerURL:      httpsrv.URL,
			HTTPTestClient: httpc,
			//TimeNow:   s.control.TimeNow,
			Logf: func(fmt string, args ...interface{}) {
				t.Helper()
				t.Logf("c1: "+fmt, args...)
			},
			Hostinfo: hi,
		}
	}

	// Login with a new node key. This requires authorization.
	c1, err := NewDirect(genOpts())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	authURL, err := c1.TryLogin(ctx, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	const user = "testuser1@tailscale.onmicrosoft.com"
	postAuthURL(t, ctx, httpc, user, authURL)
	newURL, err := c1.WaitLoginURL(ctx, authURL)
	if err != nil {
		t.Fatal(err)
	}
	if newURL != "" {
		t.Fatalf("unexpected newURL: %s", newURL)
	}

	if err := c1.PollNetMap(ctx, 1, func(netMap *NetworkMap) {}); err != nil {
		t.Fatal(err)
	}

	newPrivKey := func(t *testing.T) wgcfg.PrivateKey {
		t.Helper()
		k, err := wgcfg.NewPrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		return k
	}

	// Replace the previous key with a new key.
	persist1 := c1.GetPersist()
	persist2 := Persist{
		PrivateMachineKey: persist1.PrivateMachineKey,
		OldPrivateNodeKey: persist1.PrivateNodeKey,
		PrivateNodeKey:    newPrivKey(t),
	}
	opts := genOpts()
	opts.Persist = persist2

	c1, err = NewDirect(opts)
	if err != nil {
		t.Fatal(err)
	}
	if authURL, err := c1.TryLogin(ctx, nil, 0); err != nil {
		t.Fatal(err)
	} else if authURL == "" {
		t.Fatal("expected authURL for reused oldNodeKey, got none")
	} else {
		postAuthURL(t, ctx, httpc, user, authURL)
		if newURL, err := c1.WaitLoginURL(ctx, authURL); err != nil {
			t.Fatal(err)
		} else if newURL != "" {
			t.Fatalf("unexpected newURL: %s", newURL)
		}
	}
	if p := c1.GetPersist(); p.PrivateNodeKey != opts.Persist.PrivateNodeKey {
		t.Error("unexpected node key change")
	} else {
		persist2 = p
	}

	// Here we simulate a client using using old persistent data.
	// We use the key we have already replaced as the old node key.
	// This requires the user to authenticate.
	persist3 := Persist{
		PrivateMachineKey: persist1.PrivateMachineKey,
		OldPrivateNodeKey: persist1.PrivateNodeKey,
		PrivateNodeKey:    newPrivKey(t),
	}
	opts = genOpts()
	opts.Persist = persist3

	c1, err = NewDirect(opts)
	if err != nil {
		t.Fatal(err)
	}
	if authURL, err := c1.TryLogin(ctx, nil, 0); err != nil {
		t.Fatal(err)
	} else if authURL == "" {
		t.Fatal("expected authURL for reused oldNodeKey, got none")
	} else {
		postAuthURL(t, ctx, httpc, user, authURL)
		if newURL, err := c1.WaitLoginURL(ctx, authURL); err != nil {
			t.Fatal(err)
		} else if newURL != "" {
			t.Fatalf("unexpected newURL: %s", newURL)
		}
	}
	if err := c1.PollNetMap(ctx, 1, func(netMap *NetworkMap) {}); err != nil {
		t.Fatal(err)
	}

	// At this point, there should only be one node for the machine key
	// registered as active in the server.
	mkey := tailcfg.MachineKey(persist1.PrivateMachineKey.Public())
	nodeIDs, err := server.DB().MachineNodes(mkey)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodeIDs) != 1 {
		t.Logf("active nodes for machine key %v:", mkey)
		for i, nodeID := range nodeIDs {
			nodeKey := server.DB().NodeKey(nodeID)
			t.Logf("\tnode %d: id=%v, key=%v", i, nodeID, nodeKey)
		}
		t.Fatalf("want 1 active node for the client machine, got %d", len(nodeIDs))
	}

	// Now try the previous node key. It should fail.
	opts = genOpts()
	opts.Persist = persist2
	c1, err = NewDirect(opts)
	if err != nil {
		t.Fatal(err)
	}
	// TODO(crawshaw): make this return an actual error.
	// Have cfgdb track expired keys, and when an expired key is reused
	// produce an error.
	if authURL, err := c1.TryLogin(ctx, nil, 0); err != nil {
		t.Fatal(err)
	} else if authURL == "" {
		t.Fatal("expected authURL for reused nodeKey, got none")
	} else {
		postAuthURL(t, ctx, httpc, user, authURL)
		if newURL, err := c1.WaitLoginURL(ctx, authURL); err != nil {
			t.Fatal(err)
		} else if newURL != "" {
			t.Fatalf("unexpected newURL: %s", newURL)
		}
	}
	if err := c1.PollNetMap(ctx, 1, func(netMap *NetworkMap) {}); err != nil {
		t.Fatal(err)
	}
	if nodeIDs, err := server.DB().MachineNodes(mkey); err != nil {
		t.Fatal(err)
	} else if len(nodeIDs) != 1 {
		t.Fatalf("want 1 active node for the client machine, got %d", len(nodeIDs))
	}
}
