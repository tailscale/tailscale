// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build depends_on_currently_unreleased

package ipn

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun/tuntest"
	"github.com/tailscale/wireguard-go/wgcfg"
	"tailscale.com/control/controlclient"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/tstun"
	"tailscale.io/control" // not yet released
)

func init() {
	// Hacky way to signal to magicsock for now not to bind on the
	// unspecified address. TODO(bradfitz): clean up wgengine's
	// constructors.
	os.Setenv("IN_TS_TEST", "1")
}

func TestIPN(t *testing.T) {
	tstest.PanicOnLog()

	// This gets reassigned inside every test, so that the connections
	// all log using the "current" t.Logf function. Sigh.
	current_t := t
	logf := func(s string, args ...interface{}) {
		current_t.Helper()
		current_t.Logf(s, args...)
	}

	// Turn off STUN for the test to make it hermetic.
	// TODO(crawshaw): add a test that runs against a local STUN server.
	magicsock.DisableSTUNForTesting = true
	defer func() { magicsock.DisableSTUNForTesting = false }()

	// TODO(apenwarr): Make resource checks actually pass.
	// They don't right now, because (at least) wgengine doesn't fully
	// shut down.
	//	rc := tstest.NewResourceCheck()
	//	defer rc.Assert(t)

	var ctl *control.Server

	ctlHandler := func(w http.ResponseWriter, r *http.Request) {
		ctl.ServeHTTP(w, r)
	}
	https := httptest.NewServer(http.HandlerFunc(ctlHandler))
	serverURL := https.URL
	defer https.Close()
	defer https.CloseClientConnections()

	tmpdir, err := ioutil.TempDir("", "ipntest")
	if err != nil {
		t.Fatalf("create tempdir: %v\n", err)
	}
	ctl, err = control.New(tmpdir, tmpdir, tmpdir, serverURL, true, logf)
	if err != nil {
		t.Fatalf("create control server: %v\n", ctl)
	}
	if _, err := ctl.DB().FindOrCreateUser("google", "test1@example.com", "", ""); err != nil {
		t.Fatal(err)
	}

	n1 := newNode(t, logf, "n1", https, false)
	defer n1.Backend.Shutdown()
	n1.Backend.StartLoginInteractive()

	n2 := newNode(t, logf, "n2", https, true)
	defer n2.Backend.Shutdown()
	n2.Backend.StartLoginInteractive()

	t.Run("login", func(t *testing.T) {
		current_t = t

		var s1, s2 State
		for {
			logf("\n\nn1.state=%v n2.state=%v\n\n", s1, s2)

			// TODO(crawshaw): switch from || to &&. To do this we need to
			// transmit some data so that the handshake completes on both
			// sides. (Because handshakes are 1RTT, it is the data
			// transmission that completes the handshake.)
			if s1 == Running || s2 == Running {
				// TODO(apenwarr): ensure state sequence.
				// Right now we'll just exit as soon as
				// state==Running, even if the backend is lying or
				// something. Not a great test.
				break
			}

			select {
			case n := <-n1.NotifyCh:
				logf("n1n: %v\n", n)
				if n.State != nil {
					s1 = *n.State
					if s1 == NeedsMachineAuth {
						authNode(t, ctl, n1.Backend)
					}
				}
			case n := <-n2.NotifyCh:
				logf("n2n: %v\n", n)
				if n.State != nil {
					s2 = *n.State
					if s2 == NeedsMachineAuth {
						authNode(t, ctl, n2.Backend)
					}
				}
			case <-time.After(3 * time.Second):
				t.Fatalf("\n\n\nFATAL: timed out waiting for notifications.\n\n\n")
			}
		}
	})
	current_t = t

	n1addr := n1.Backend.NetMap().Addresses[0].IP
	n2addr := n2.Backend.NetMap().Addresses[0].IP

	t.Run("ping n2", func(t *testing.T) {
		current_t = t
		t.Skip("TODO(crawshaw): skipping ping test, it is flaky")
		msg := tuntest.Ping(n2addr.IP(), n1addr.IP())
		n1.ChannelTUN.Outbound <- msg
		select {
		case msgRecv := <-n2.ChannelTUN.Inbound:
			if !bytes.Equal(msg, msgRecv) {
				t.Error("bad ping")
			}
		case <-time.After(1 * time.Second):
			t.Error("no ping seen")
		}
	})
	current_t = t

	t.Run("ping n1", func(t *testing.T) {
		current_t = t
		t.Skip("TODO(crawshaw): skipping ping test, it is flaky")
		msg := tuntest.Ping(n1addr.IP(), n2addr.IP())
		n2.ChannelTUN.Outbound <- msg
		select {
		case msgRecv := <-n1.ChannelTUN.Inbound:
			if !bytes.Equal(msg, msgRecv) {
				t.Error("bad ping")
			}
		case <-time.After(1 * time.Second):
			t.Error("no ping seen")
		}
	})
	current_t = t

drain:
	for {
		select {
		case <-n1.NotifyCh:
		case <-n2.NotifyCh:
		default:
			break drain
		}
	}

	n1.Backend.Logout()

	t.Run("logout", func(t *testing.T) {
		current_t = t

		var s State
		for {
			select {
			case n := <-n1.NotifyCh:
				if n.State == nil {
					continue
				}
				s = *n.State
				logf("n.State=%v", s)
				if s == NeedsLogin {
					return
				}
			case <-time.After(3 * time.Second):
				t.Fatalf("timeout waiting for logout State=NeedsLogin, got State=%v", s)
			}
		}
	})
	current_t = t
}

type testNode struct {
	Backend    *LocalBackend
	ChannelTUN *tuntest.ChannelTUN
	NotifyCh   <-chan Notify
}

// Create a new IPN node.
func newNode(t *testing.T, logfx logger.Logf, prefix string, https *httptest.Server, weirdPrefs bool) testNode {
	t.Helper()

	logfe := logger.WithPrefix(logfx, prefix+"e: ")
	logf := logger.WithPrefix(logfx, prefix+": ")

	var err error
	httpc := https.Client()
	httpc.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}

	tun := tuntest.NewChannelTUN()
	tundev := tstun.WrapTUN(logfe, tun.TUN())
	e1, err := wgengine.NewUserspaceEngineAdvanced(logfe, tundev, router.NewFake, 0)
	if err != nil {
		t.Fatalf("NewFakeEngine: %v\n", err)
	}
	n, err := NewLocalBackend(logf, prefix, &MemoryStore{}, e1)
	if err != nil {
		t.Fatalf("NewLocalBackend: %v\n", err)
	}
	nch := make(chan Notify, 1000)
	c := controlclient.Persist{
		Provider:  "google",
		LoginName: "test1@example.com",
	}
	prefs := NewPrefs()
	prefs.ControlURL = https.URL
	prefs.Persist = &c

	if weirdPrefs {
		// Let's test some nonempty extra prefs fields to make sure
		// the server can handle them.
		prefs.AdvertiseTags = []string{"tag:abc"}
		cidr, err := wgcfg.ParseCIDR("1.2.3.4/24")
		if err != nil {
			t.Fatalf("ParseCIDR: %v", err)
		}
		prefs.AdvertiseRoutes = []wgcfg.CIDR{cidr}
	}

	n.Start(Options{
		FrontendLogID: prefix + "-f",
		Prefs:         prefs,
		Notify: func(n Notify) {
			// Automatically visit auth URLs
			if n.BrowseToURL != nil {
				logf("BrowseToURL: %v", *n.BrowseToURL)

				authURL := *n.BrowseToURL
				i := strings.Index(authURL, "/a/")
				if i == -1 {
					panic("bad authURL: " + authURL)
				}
				authURL = authURL[:i] + "/login?refresh=true&next_url=" + url.PathEscape(authURL[i:])

				form := url.Values{"user": []string{c.LoginName}}
				req, err := http.NewRequest("POST", authURL, strings.NewReader(form.Encode()))
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

				if _, err := httpc.Do(req); err != nil {
					logf("BrowseToURL: %v\n", err)
				}
			}
			nch <- n
		},
	})

	return testNode{
		Backend:    n,
		ChannelTUN: tun,
		NotifyCh:   nch,
	}
}

// Tell the control server to authorize the given node.
func authNode(t *testing.T, ctl *control.Server, n *LocalBackend) {
	mk := n.prefs.Persist.PrivateMachineKey.Public()
	nk := n.prefs.Persist.PrivateNodeKey.Public()
	ctl.AuthorizeMachine(tailcfg.MachineKey(mk), tailcfg.NodeKey(nk))
}
