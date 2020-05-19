// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build depends_on_currently_unreleased

package controlclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/tailscale/wireguard-go/wgcfg"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/logger"
	"tailscale.io/control" // not yet released
	"tailscale.io/control/cfgdb"
)

func TestTest(t *testing.T) {
	check := tstest.NewResourceCheck()
	defer check.Assert(t)
}

func TestServerStartStop(t *testing.T) {
	s := newServer(t)
	defer s.close()
}

func TestControlBasics(t *testing.T) {
	s := newServer(t)
	defer s.close()

	c := s.newClient(t, "c")
	c.Login(nil, 0)
	status := c.waitStatus(t, stateURLVisitRequired)
	c.postAuthURL(t, "foo@tailscale.com", status.New)
}

// A function with the same semantics as t.Run(), but which doesn't rearrange
// the logs by creating a new sub-t.Logf, and doesn't support parallelism.
// This makes it possible to actually figure out what happened by looking
// at the logs.
func runSub(t *testing.T, name string, fn func(t *testing.T)) {
	t.Helper()
	t.Logf("\n")
	t.Logf("\n\n--- Starting: %v\n\n", name)
	defer func() {
		if t.Failed() {
			t.Logf("\n\n--- FAILED: %v\n\n", name)
		} else {
			t.Logf("\n\n--- PASS: %v\n\n", name)
		}
	}()

	fn(t)
}

func fatal(t *testing.T, args ...interface{}) {
	t.Helper()
	t.Fatal("FAILED: ", fmt.Sprint(args...))
}

func fatalf(t *testing.T, s string, args ...interface{}) {
	t.Helper()
	t.Fatalf("FAILED: "+s, args...)
}

func TestControl(t *testing.T) {
	s := newServer(t)
	defer s.close()

	c1 := s.newClient(t, "c1")

	runSub(t, "authorize first tailscale.com client", func(t *testing.T) {
		const loginName = "testuser1@tailscale.com"
		c1.checkNoStatus(t)
		c1.loginAs(t, loginName)
		c1.waitStatus(t, stateAuthenticated)
		status := c1.waitStatus(t, stateSynchronized)
		if got, want := status.New.NetMap.MachineStatus, tailcfg.MachineUnauthorized; got != want {
			fatalf(t, "MachineStatus=%v, want %v", got, want)
		}
		c1.checkNoStatus(t)
		affectedPeers, err := s.control.AuthorizeMachine(c1.mkey, c1.nkey)
		if err != nil {
			fatal(t, err)
		}
		status = c1.status(t)
		if got := status.New.Persist.LoginName; got != loginName {
			fatalf(t, "LoginName=%q, want %q", got, loginName)
		}
		if got := status.New.Persist.Provider; got != "google" {
			fatalf(t, "Provider=%q, want google", got)
		}
		if len(affectedPeers) != 1 || affectedPeers[0] != c1.id {
			fatalf(t, "authorization should notify the node being authorized (%v), got: %v", c1.id, affectedPeers)
		}
		if peers := status.New.NetMap.Peers; len(peers) != 0 {
			fatalf(t, "peers=%v, want none", peers)
		}
		if userID := status.New.NetMap.User; userID == 0 {
			fatalf(t, "NetMap.User is missing")
		} else {
			profile := status.New.NetMap.UserProfiles[userID]
			if profile.LoginName != loginName {
				fatalf(t, "NetMap user LoginName=%q, want %q", profile.LoginName, loginName)
			}
		}
		c1.checkNoStatus(t)
	})

	c2 := s.newClient(t, "c2")

	runSub(t, "authorize second tailscale.io client", func(t *testing.T) {
		c2.loginAs(t, "testuser2@tailscale.com")
		c2.waitStatus(t, stateAuthenticated)
		c2.waitStatus(t, stateSynchronized)
		c2.checkNoStatus(t)

		// Make sure not to call operations like this on a client in a
		// test until the initial map read is done. Otherwise the
		// initial map read will trigger a map update to peers, and
		// there will sometimes be a spurious map update.
		affectedPeers, err := s.control.AuthorizeMachine(c2.mkey, c2.nkey)
		if err != nil {
			fatal(t, err)
		}
		status := c2.waitStatus(t, stateSynchronized)
		c1Status := c1.waitStatus(t, stateSynchronized)

		if len(affectedPeers) != 2 {
			fatalf(t, "affectedPeers=%v, want two entries", affectedPeers)
		}
		if want := []tailcfg.NodeID{c1.id, c2.id}; !nodeIDsEqual(affectedPeers, want) {
			fatalf(t, "affectedPeers=%v, want %v", affectedPeers, want)
		}

		c1NetMap := c1Status.New.NetMap
		c2NetMap := status.New.NetMap
		if len(c1NetMap.Peers) != 1 || len(c2NetMap.Peers) != 1 {
			t.Error("wrong number of peers")
		} else {
			if c2NetMap.Peers[0].Key != c1.nkey {
				fatalf(t, "c2 has wrong peer key %v, want %v", c2NetMap.Peers[0].Key, c1.nkey)
			}
			if c1NetMap.Peers[0].Key != c2.nkey {
				fatalf(t, "c1 has wrong peer key %v, want %v", c1NetMap.Peers[0].Key, c2.nkey)
			}
		}
		if t.Failed() {
			fatalf(t, "client1 network map:\n%s", c1Status.New.NetMap)
			fatalf(t, "client2 network map:\n%s", status.New.NetMap)
		}

		c1.checkNoStatus(t)
		c2.checkNoStatus(t)
	})

	// c3/c4 are on a different domain to c1/c2.
	// The two domains should never affect one another.
	c3 := s.newClient(t, "c3")

	runSub(t, "authorize first onmicrosoft client", func(t *testing.T) {
		c3.loginAs(t, "testuser1@tailscale.onmicrosoft.com")
		c3.waitStatus(t, stateAuthenticated)
		c3Status := c3.waitStatus(t, stateSynchronized)
		// no machine authorization for tailscale.onmicrosoft.com
		c1.checkNoStatus(t)
		c2.checkNoStatus(t)

		netMap := c3Status.New.NetMap
		if netMap.NodeKey != c3.nkey {
			fatalf(t, "netMap.NodeKey=%v, want %v", netMap.NodeKey, c3.nkey)
		}
		if len(netMap.Peers) != 0 {
			fatalf(t, "netMap.Peers=%v, want none", netMap.Peers)
		}

		c1.checkNoStatus(t)
		c2.checkNoStatus(t)
		c3.checkNoStatus(t)
	})

	c4 := s.newClient(t, "c4")

	runSub(t, "authorize second onmicrosoft client", func(t *testing.T) {
		c4.loginAs(t, "testuser2@tailscale.onmicrosoft.com")
		c4.waitStatus(t, stateAuthenticated)
		c3Status := c3.waitStatus(t, stateSynchronized)
		c4Status := c4.waitStatus(t, stateSynchronized)
		c3NetMap := c3Status.New.NetMap
		c4NetMap := c4Status.New.NetMap

		c1.checkNoStatus(t)
		c2.checkNoStatus(t)

		if len(c3NetMap.Peers) != 1 {
			fatalf(t, "wrong number of c3 peers: %d", len(c3NetMap.Peers))
		} else if len(c4NetMap.Peers) != 1 {
			fatalf(t, "wrong number of c4 peers: %d", len(c4NetMap.Peers))
		} else {
			if c3NetMap.Peers[0].Key != c4.nkey || c4NetMap.Peers[0].Key != c3.nkey {
				t.Error("wrong peer key")
			}
		}
		if t.Failed() {
			fatalf(t, "client3 network map:\n%s", c3NetMap)
			fatalf(t, "client4 network map:\n%s", c4NetMap)
		}
	})

	var c1NetMap *NetworkMap
	runSub(t, "update c1 and c2 endpoints", func(t *testing.T) {
		c1Endpoints := []string{"172.16.1.5:12345", "4.4.4.4:4444"}
		c1.checkNoStatus(t)
		c1.UpdateEndpoints(1234, c1Endpoints)
		c1NetMap = c1.status(t).New.NetMap
		c2NetMap := c2.status(t).New.NetMap
		c1.checkNoStatus(t)
		c2.checkNoStatus(t)

		if c1NetMap.LocalPort != 1234 {
			fatalf(t, "c1 netmap localport=%d, want 1234", c1NetMap.LocalPort)
		}
		if len(c2NetMap.Peers) != 1 {
			fatalf(t, "wrong peer count: %d", len(c2NetMap.Peers))
		}
		if got := c2NetMap.Peers[0].Endpoints; !hasStringsSuffix(got, c1Endpoints) {
			fatalf(t, "c2 peer endpoints=%v, want %v", got, c1Endpoints)
		}
		c3.checkNoStatus(t)
		c4.checkNoStatus(t)

		c2Endpoints := []string{"172.16.1.7:6543", "5.5.5.5.3333"}
		c2.UpdateEndpoints(9876, c2Endpoints)
		c1NetMap = c1.status(t).New.NetMap
		c2NetMap = c2.status(t).New.NetMap

		if c1NetMap.LocalPort != 1234 {
			fatalf(t, "c1 netmap localport=%d, want 1234", c1NetMap.LocalPort)
		}
		if c2NetMap.LocalPort != 9876 {
			fatalf(t, "c2 netmap localport=%d, want 9876", c2NetMap.LocalPort)
		}
		if got := c2NetMap.Peers[0].Endpoints; !hasStringsSuffix(got, c1Endpoints) {
			fatalf(t, "c2 peer endpoints=%v, want suffix %v", got, c1Endpoints)
		}
		if got := c1NetMap.Peers[0].Endpoints; !hasStringsSuffix(got, c2Endpoints) {
			fatalf(t, "c1 peer endpoints=%v, want suffix %v", got, c2Endpoints)
		}

		c1.checkNoStatus(t)
		c2.checkNoStatus(t)
		c3.checkNoStatus(t)
		c4.checkNoStatus(t)
	})

	allZeros, err := wgcfg.ParseCIDR("0.0.0.0/0")
	if err != nil {
		fatal(t, err)
	}

	runSub(t, "route all traffic via client 1", func(t *testing.T) {
		aips := []wgcfg.CIDR{}
		aips = append(aips, c1NetMap.Addresses...)
		aips = append(aips, allZeros)

		affectedPeers, err := s.control.SetAllowedIPs(c1.nkey, aips)
		if err != nil {
			fatal(t, err)
		}
		c2Status := c2.status(t)
		c2NetMap := c2Status.New.NetMap

		if want := []tailcfg.NodeID{c2.id}; !nodeIDsEqual(affectedPeers, want) {
			fatalf(t, "affectedPeers=%v, want %v", affectedPeers, want)
		}

		_ = c2NetMap
		foundAllZeros := false
		for _, cidr := range c2NetMap.Peers[0].AllowedIPs {
			if cidr == allZeros {
				foundAllZeros = true
			}
		}
		if !foundAllZeros {
			fatalf(t, "client2 peer does not contain %s: %v", allZeros, c2NetMap.Peers[0].AllowedIPs)
		}

		c1.checkNoStatus(t)
		c3.checkNoStatus(t)
		c4.checkNoStatus(t)
	})

	runSub(t, "remove route all traffic", func(t *testing.T) {
		affectedPeers, err := s.control.SetAllowedIPs(c1.nkey, c1NetMap.Addresses)
		if err != nil {
			fatal(t, err)
		}
		c2NetMap := c2.status(t).New.NetMap

		if want := []tailcfg.NodeID{c2.id}; !nodeIDsEqual(affectedPeers, want) {
			fatalf(t, "affectedPeers=%v, want %v", affectedPeers, want)
		}

		foundAllZeros := false
		for _, cidr := range c2NetMap.Peers[0].AllowedIPs {
			if cidr == allZeros {
				foundAllZeros = true
			}
		}
		if foundAllZeros {
			fatalf(t, "client2 peer still contains %s: %v", allZeros, c2NetMap.Peers[0].AllowedIPs)
		}

		c1.checkNoStatus(t)
		c3.checkNoStatus(t)
		c4.checkNoStatus(t)
	})

	runSub(t, "refresh client key", func(t *testing.T) {
		oldKey := c1.nkey

		c1.Login(nil, LoginInteractive)
		status := c1.waitStatus(t, stateURLVisitRequired)
		c1.postAuthURL(t, "testuser1@tailscale.com", status.New)
		c1.waitStatus(t, stateAuthenticated)
		status = c1.waitStatus(t, stateSynchronized)
		if status.New.Err != "" {
			fatal(t, status.New.Err)
		}

		c1NetMap := status.New.NetMap
		c1.nkey = c1NetMap.NodeKey
		if c1.nkey == oldKey {
			fatalf(t, "new key is the same as the old key: %s", oldKey)
		}
		c2NetMap := c2.status(t).New.NetMap
		if len(c2NetMap.Peers) != 1 || c2NetMap.Peers[0].Key != c1.nkey {
			fatalf(t, "c2 peer: %v, want new node key %v", c1.nkey, c2NetMap.Peers[0].Key)
		}

		c3.checkNoStatus(t)
		c4.checkNoStatus(t)
	})

	runSub(t, "set hostinfo", func(t *testing.T) {
		c3.Login(nil, LoginDefault)
		c4.Login(nil, LoginDefault)
		c3.waitStatus(t, stateAuthenticated)
		c4.waitStatus(t, stateAuthenticated)
		c3.waitStatus(t, stateSynchronized)
		c4.waitStatus(t, stateSynchronized)

		c3.UpdateEndpoints(9876, []string{"1.2.3.4:3333"})
		c3.waitStatus(t, stateSynchronized)
		c4.waitStatus(t, stateSynchronized)

		c4.UpdateEndpoints(9876, []string{"5.6.7.8:1111"})
		c3.waitStatus(t, stateSynchronized)
		c4.waitStatus(t, stateSynchronized)

		c3.SetHostinfo(&tailcfg.Hostinfo{
			BackendLogID: "set-hostinfo-test",
			OS:           "linux",
		})
		c3.waitStatus(t, stateSynchronized)
		c4NetMap := c4.status(t).New.NetMap
		if len(c4NetMap.Peers) != 1 {
			fatalf(t, "wrong number of peers: %v", c4NetMap.Peers)
		}
		peer := c4NetMap.Peers[0]
		if !peer.KeepAlive {
			fatalf(t, "peer KeepAlive=false, want true")
		}
		if peer.Hostinfo.OS != "linux" {
			fatalf(t, "peer OS is not linux: %v", peer.Hostinfo)
		}

		c4.SetHostinfo(&tailcfg.Hostinfo{
			BackendLogID: "set-hostinfo-test",
			OS:           "iOS",
		})
		c3NetMap := c3.status(t).New.NetMap
		c4NetMap = c4.status(t).New.NetMap
		if len(c3NetMap.Peers) != 1 {
			fatalf(t, "wrong number of peers: %v", c3NetMap.Peers)
		}
		if len(c4NetMap.Peers) != 1 {
			fatalf(t, "wrong number of peers: %v", c4NetMap.Peers)
		}
		peer = c3NetMap.Peers[0]
		if peer.KeepAlive {
			fatalf(t, "peer KeepAlive=true, want false")
		}
		if peer.Hostinfo.OS != "iOS" {
			fatalf(t, "peer OS is not iOS: %v", peer.Hostinfo)
		}
		peer = c4NetMap.Peers[0]
		if peer.KeepAlive {
			fatalf(t, "peer KeepAlive=true, want false")
		}
		if peer.Hostinfo.OS != "linux" {
			fatalf(t, "peer OS is not linux: %v", peer.Hostinfo)
		}

	})
}

func hasStringsSuffix(list, suffix []string) bool {
	if len(list) < len(suffix) {
		return false
	}
	return reflect.DeepEqual(list[len(list)-len(suffix):], suffix)
}

func TestLoginInterrupt(t *testing.T) {
	s := newServer(t)
	defer s.close()

	c := s.newClient(t, "c")

	const loginName = "testuser1@tailscale.com"
	c.checkNoStatus(t)
	c.loginAs(t, loginName)
	c.waitStatus(t, stateAuthenticated)
	c.waitStatus(t, stateSynchronized)
	t.Logf("authorizing: %v %v %v\n", s, c.mkey, c.nkey)
	if _, err := s.control.AuthorizeMachine(c.mkey, c.nkey); err != nil {
		fatal(t, err)
	}
	status := c.waitStatus(t, stateSynchronized)
	if got, want := status.New.NetMap.MachineStatus, tailcfg.MachineAuthorized; got != want {
		fatalf(t, "MachineStatus=%v, want %v", got, want)
	}
	origAddrs := status.New.NetMap.Addresses
	if len(origAddrs) == 0 {
		fatalf(t, "Addresses empty, want something")
	}

	c.Logout()
	c.waitStatus(t, stateNotAuthenticated)
	c.Login(nil, 0)
	status = c.waitStatus(t, stateURLVisitRequired)
	authURL := status.New.URL

	// Interrupt, and do login again.
	c.Login(nil, 0)
	status = c.waitStatus(t, stateURLVisitRequired)
	authURL2 := status.New.URL

	if authURL == authURL2 {
		fatalf(t, "auth URLs match for subsequent logins: %s", authURL)
	}

	// Direct auth URL visit is not enough because our cookie is no longer fresh.
	req, err := http.NewRequest("GET", authURL2, nil)
	if err != nil {
		fatal(t, err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.httpc.Do(req.WithContext(c.ctx))
	if err != nil {
		fatal(t, err)
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fatal(t, err)
	}
	resp.Body.Close()
	if i := bytes.Index(b, []byte("<body")); i != -1 { // strip off noisy <style> header
		b = b[i:]
	}
	if !bytes.Contains(b, []byte("<form")) {
		fatalf(t, "missing login page: %s", b)
	}

	form := url.Values{"user": []string{loginName}}
	req, err = http.NewRequest("POST", authURLForPOST(authURL2), strings.NewReader(form.Encode()))
	if err != nil {
		fatal(t, err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err = c.httpc.Do(req.WithContext(c.ctx))
	if err != nil {
		fatal(t, err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		fatalf(t, "POST %s failed: %q", authURL2, resp.Status)
	}
	cookieURL, err := url.Parse(authURL)
	if err != nil {
		fatal(t, err)
	}
	cookies := c.httpc.Jar.Cookies(cookieURL)
	if len(cookies) == 0 || cookies[0].Name != "tailcontrol" {
		fatalf(t, "POST %s: bad cookie: %v", authURL2, cookies)
	}

	c.waitStatus(t, stateAuthenticated)
	status = c.status(t)
	if got := status.New.NetMap.NodeKey; got != c.nkey {
		fatalf(t, "netmap has wrong node key: %v, want %v", got, c.nkey)
	}
	if got := status.New.NetMap.Addresses; len(got) == 0 {
		fatalf(t, "Addresses empty after re-login, want something")
	} else if len(origAddrs) > 0 && origAddrs[0] != got[0] {
		fatalf(t, "Addresses=%v after re-login, originally was %v, want IP to be unchanged", got, origAddrs)
	}
}

func TestSpinUpdateEndpoints(t *testing.T) {
	s := newServer(t)
	defer s.close()

	c1 := s.newClient(t, "c1")
	c2 := s.newClient(t, "c2")

	const loginName = "testuser1@tailscale.com"
	c1.loginAs(t, loginName)
	c1.waitStatus(t, stateAuthenticated)
	c1.waitStatus(t, stateSynchronized)
	if _, err := s.control.AuthorizeMachine(c1.mkey, c1.nkey); err != nil {
		fatal(t, err)
	}
	c1.waitStatus(t, stateSynchronized)

	c2.loginAs(t, loginName)
	c2.waitStatus(t, stateAuthenticated)
	c2.waitStatus(t, stateSynchronized)
	if _, err := s.control.AuthorizeMachine(c2.mkey, c2.nkey); err != nil {
		fatal(t, err)
	}
	c2.waitStatus(t, stateSynchronized)
	c1.waitStatus(t, stateSynchronized)

	const portBase = 1200
	const portCount = 50
	const portLast = portBase + portCount - 1

	errCh := make(chan error, 1)
	collectPorts := func() error {
		t := time.After(10 * time.Second)
		var port int
		for i := 0; i < portCount; i++ {
			var status statusChange
			select {
			case status = <-c2.statusCh:
			case <-t:
				return fmt.Errorf("c2 status timeout (i=%d)", i)
			}
			peers := status.New.NetMap.Peers
			if len(peers) != 1 {
				return fmt.Errorf("c2 len(peers)=%d, want 1", len(peers))
			}
			eps := peers[0].Endpoints
			for len(eps) > 1 && eps[0] != "127.0.0.1:1234" {
				eps = eps[1:]
			}
			if len(eps) != 2 {
				return fmt.Errorf("c2 peer len(eps)=%d, want 2", len(eps))
			}
			ep := eps[1]
			const prefix = "192.168.1.45:"
			if !strings.HasPrefix(ep, prefix) {
				return fmt.Errorf("c2 peer endpoint=%s, want prefix %s", ep, prefix)
			}
			var err error
			port, err = strconv.Atoi(strings.TrimPrefix(ep, prefix))
			if err != nil {
				return fmt.Errorf("c2 peer endpoint port: %v", err)
			}
			if port == portLast {
				return nil // got it
			}
		}
		return fmt.Errorf("c2 peer endpoint did not see portLast (saw %d)", port)
	}
	go func() {
		errCh <- collectPorts()
	}()

	// Very quickly call UpdateEndpoints several times.
	// Some (most) of these calls will never make it to the server, they
	// will be canceled by subsequent calls.
	// The last call goes through, so we can see portLast.
	eps := []string{"127.0.0.1:1234", ""}
	for i := 0; i < portCount; i++ {
		eps[1] = fmt.Sprintf("192.168.1.45:%d", portBase+i)
		c1.UpdateEndpoints(1234, eps)
	}

	if err := <-errCh; err != nil {
		fatalf(t, "collect ports: %v", err)
	}
}

func TestLogout(t *testing.T) {
	s := newServer(t)
	defer s.close()

	c1 := s.newClient(t, "c1")

	const loginName = "testuser1@tailscale.com"
	c1.loginAs(t, loginName)

	c1.waitStatus(t, stateAuthenticated)
	c1.waitStatus(t, stateSynchronized)
	if _, err := s.control.AuthorizeMachine(c1.mkey, c1.nkey); err != nil {
		fatal(t, err)
	}
	nkey1 := c1.status(t).New.NetMap.NodeKey

	c1.Logout()
	c1.waitStatus(t, stateNotAuthenticated)

	c1.loginAs(t, loginName)
	c1.waitStatus(t, stateAuthenticated)
	status := c1.waitStatus(t, stateSynchronized)
	if got, want := status.New.NetMap.MachineStatus, tailcfg.MachineAuthorized; got != want {
		fatalf(t, "re-login MachineStatus=%v, want %v", got, want)
	}
	nkey2 := status.New.NetMap.NodeKey
	if nkey1 == nkey2 {
		fatalf(t, "key not changed after re-login: %v", nkey1)
	}

	c1.checkNoStatus(t)
}

func TestExpiry(t *testing.T) {
	var nowMu sync.Mutex
	now := time.Now() // Server and Client use this variable as the current time
	timeNow := func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return now
	}
	timeInc := func(d time.Duration) {
		nowMu.Lock()
		defer nowMu.Unlock()
		now = now.Add(d)
	}

	s := newServer(t)
	s.control.TimeNow = timeNow
	defer s.close()

	c1 := s.newClient(t, "c1")

	const loginName = "testuser1@tailscale.com"
	c1.loginAs(t, loginName)

	c1.waitStatus(t, stateAuthenticated)
	c1.waitStatus(t, stateSynchronized)
	if _, err := s.control.AuthorizeMachine(c1.mkey, c1.nkey); err != nil {
		fatal(t, err)
	}
	status := c1.waitStatus(t, stateSynchronized).New
	nkey1 := c1.direct.persist.PrivateNodeKey
	nkey1Expiry := status.NetMap.Expiry
	if wantExpiry := timeNow().Add(180 * 24 * time.Hour); !nkey1Expiry.Equal(wantExpiry) {
		fatalf(t, "node key expiry = %v, want %v", nkey1Expiry, wantExpiry)
	}

	timeInc(1 * time.Hour)          // move the clock forward
	c1.Login(nil, LoginInteractive) // refresh the key
	status = c1.waitStatus(t, stateURLVisitRequired).New
	c1.postAuthURL(t, loginName, status)
	c1.waitStatus(t, stateAuthenticated)
	status = c1.waitStatus(t, stateSynchronized).New
	if newKey := c1.direct.persist.PrivateNodeKey; newKey == nkey1 {
		fatalf(t, "node key unchanged after LoginInteractive: %v", nkey1)
	}
	if want, got := timeNow().Add(180*24*time.Hour), status.NetMap.Expiry; !got.Equal(want) {
		fatalf(t, "node key expiry = %v, want %v", got, want)
	}

	timeInc(2 * time.Hour) // move the clock forward
	c1.Login(nil, 0)
	c1.waitStatus(t, stateAuthenticated)
	c1.waitStatus(t, stateSynchronized)
	c1.checkNoStatus(t) // nothing happens, network map stays the same

	timeInc(180 * 24 * time.Hour) // move the clock past expiry
	c1.loginAs(t, loginName)
	c1.waitStatus(t, stateAuthenticated)
	status = c1.waitStatus(t, stateSynchronized).New
	if got, want := c1.expiry, timeNow(); got.Equal(want) {
		fatalf(t, "node key expiry = %v, want %v", got, want)
	}
	if c1.direct.persist.PrivateNodeKey == nkey1 {
		fatalf(t, "node key after 37 hours is still %v", status.NetMap.NodeKey)
	}
}

func TestRefresh(t *testing.T) {
	var nowMu sync.Mutex
	now := time.Now() // Server and Client use this variable as the current time
	timeNow := func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return now
	}

	s := newServer(t)
	s.control.TimeNow = timeNow
	defer s.close()

	c1 := s.newClient(t, "c1")

	const loginName = "testuser1@versabank.com" // versabank cfgdb has 72 hour key expiry configured
	c1.loginAs(t, loginName)

	c1.waitStatus(t, stateAuthenticated)
	c1.waitStatus(t, stateSynchronized)
	if _, err := s.control.AuthorizeMachine(c1.mkey, c1.nkey); err != nil {
		fatal(t, err)
	}
	status := c1.status(t).New
	nkey1 := status.NetMap.NodeKey
	nkey1Expiry := status.NetMap.Expiry
	if wantExpiry := timeNow().Add(72 * time.Hour); !nkey1Expiry.Equal(wantExpiry) {
		fatalf(t, "node key expiry = %v, want %v", nkey1Expiry, wantExpiry)
	}

	c1.Login(nil, LoginInteractive)
	c1.waitStatus(t, stateURLVisitRequired)
	// Until authorization happens, old netmap is still valid.
	exp := c1.expiry
	if exp == nil {
		fatalf(t, "expiry==nil during refresh\n")
	}
	if got := *exp; !nkey1Expiry.Equal(got) {
		fatalf(t, "node key expiry = %v, want %v", got, nkey1Expiry)
	}
	k := tailcfg.NodeKey(c1.direct.persist.PrivateNodeKey.Public())
	if k != nkey1 {
		fatalf(t, "node key after 2 hours is %v, want %v", k, nkey1)
	}
	c1.Shutdown()
}

func TestAuthKey(t *testing.T) {
	var nowMu sync.Mutex
	now := time.Now() // Server and Client use this variable as the current time
	timeNow := func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return now
	}

	s := newServer(t)
	s.control.TimeNow = timeNow
	defer s.close()

	const loginName = "testuser1@example.com"
	user, err := s.control.DB().FindOrCreateUser("google", loginName, "", "")
	if err != nil {
		fatal(t, err)
	}

	runSub(t, "one-off", func(t *testing.T) {
		oneOffKey, err := s.control.DB().NewAPIKey(user.ID, cfgdb.KeyCapabilities{
			Bits: cfgdb.KeyCapOneOffNodeAuth,
		})
		if err != nil {
			fatal(t, err)
		}

		c1 := s.newClientWithKey(t, "c1", string(oneOffKey))
		c1.Login(nil, 0)
		c1.waitStatus(t, stateAuthenticated)
		c1.waitStatus(t, stateSynchronized)
		c1.Shutdown()

		// Key won't work a second time.
		c2 := s.newClientWithKey(t, "c2", string(oneOffKey))
		c2.Login(nil, 0)
		status := c2.readStatus(t)
		if e, substr := status.New.Err, `revoked`; !strings.Contains(e, substr) {
			fatalf(t, "Err=%q, expect substring %q", e, substr)
		}
		c2.Shutdown()
	})

	runSub(t, "followup", func(t *testing.T) {
		key, err := s.control.DB().NewAPIKey(user.ID, cfgdb.KeyCapabilities{
			Bits: cfgdb.KeyCapNodeAuth,
		})
		if err != nil {
			fatal(t, err)
		}

		c1 := s.newClient(t, "c1")
		c1.Login(nil, 0)
		c1.waitStatus(t, stateURLVisitRequired)

		c1.direct.mu.Lock()
		c1.direct.authKey = string(key)
		c1.direct.mu.Unlock()

		c1.Login(nil, 0)
		c1.waitStatus(t, stateAuthenticated)
		c1.waitStatus(t, stateSynchronized)
		c1.Shutdown()
	})
}

func TestExpectedProvider(t *testing.T) {
	s := newServer(t)
	defer s.close()

	c := s.newClient(t, "c1")

	c.direct.persist.LoginName = "testuser1@tailscale.com"
	c.direct.persist.Provider = "microsoft"
	c.Login(nil, 0)
	status := c.readStatus(t)
	if e, substr := status.New.Err, `provider "microsoft" is not supported`; !strings.Contains(e, substr) {
		fatalf(t, "Err=%q, expect substring %q", e, substr)
	}
}

func TestNewUserWebFlow(t *testing.T) {
	s := newServer(t)
	defer s.close()
	s.control.DB().SetSegmentAPIKey(segmentKey)

	c := s.newClient(t, "c1")
	c.Login(nil, 0)
	status := c.waitStatus(t, stateURLVisitRequired)
	authURL := status.New.URL
	resp, err := c.httpc.Get(authURL)
	if err != nil {
		fatal(t, err)
	}
	if resp.StatusCode != 200 {
		fatalf(t, "statuscode=%d, want 200", resp.StatusCode)
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fatal(t, err)
	}
	got := string(b)
	if !strings.Contains(got, `<input type="email"`) {
		fatalf(t, "page does not mention email field:\n\n%s", got)
	}

	loginWith := "testuser1@tailscale.com"
	authURL = authURLForPOST(authURL)
	resp, err = c.httpc.PostForm(authURL, url.Values{"user": []string{loginWith}})
	if err != nil {
		fatal(t, err)
	}
	if resp.StatusCode != 200 {
		fatalf(t, "statuscode=%d, want 200", resp.StatusCode)
	}
	b, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		fatal(t, err)
	}
	if i := bytes.Index(b, []byte("<body")); i != -1 { // strip off noisy <style> header
		b = b[i:]
	}
	got = string(b)
	if !strings.Contains(got, "This is a new machine") {
		fatalf(t, "no machine authorization message:\n\n%s", got)
	}

	c.waitStatus(t, stateAuthenticated)
	c.waitStatus(t, stateSynchronized)
	if _, err := s.control.AuthorizeMachine(c.mkey, c.nkey); err != nil {
		fatal(t, err)
	}
	netmap := c.status(t).New.NetMap
	loginname := netmap.UserProfiles[netmap.User].LoginName
	if loginname != loginWith {
		fatalf(t, "loginame=%s want %s", loginname, loginWith)
	}

	runSub(t, "segment POST", func(t *testing.T) {
		select {
		case msg := <-s.segmentMsg:
			if got, want := msg["userId"], control.UserIDHash(netmap.User); got != want {
				fatalf(t, "segment hashed user ID = %q, want %q", got, want)
			}
			if got, want := msg["event"], "new node activated"; got != want {
				fatalf(t, "event=%q, want %q", got, want)
			}
			if t.Failed() {
				t.Log(msg)
			}
		case <-time.After(3 * time.Second):
			fatalf(t, "timeout waiting for segment identify req")
		}
	})

	runSub(t, "user expiry", func(t *testing.T) {
		peers, err := s.control.ExpireUserNodes(netmap.User)
		if err != nil {
			fatal(t, err)
		}
		if len(peers) != 1 {
			fatalf(t, "len(peers)=%d, want 1", len(peers))
		}
		var nodeExp time.Time
		if nodes, err := s.control.DB().AllNodes(netmap.User); err != nil {
			fatal(t, err)
		} else if len(nodes) != 1 {
			fatalf(t, "len(nodes)=%d, want 1", len(nodes))
		} else if nodeExp = nodes[0].KeyExpiry; c.timeNow().Sub(nodeExp) > 24*time.Hour {
			fatalf(t, "node[0] expiry=%v, want it to be in less than a day", nodeExp)
		} else if got := c.status(t).New.NetMap.Expiry; !got.Equal(nodeExp) {
			fatalf(t, "expiry=%v, want it to be %v", got, nodeExp)
		}
	})
}

func TestGoogleSigninButton(t *testing.T) {
	s := newServer(t)
	defer s.close()

	c := s.newClient(t, "c1")
	c.Login(nil, 0)
	status := c.waitStatus(t, stateURLVisitRequired)
	authURL := status.New.URL
	resp, err := c.httpc.Get(authURL)
	if err != nil {
		fatal(t, err)
	}
	if resp.StatusCode != 200 {
		fatalf(t, "statuscode=%d, want 200", resp.StatusCode)
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fatal(t, err)
	}
	if i := bytes.Index(b, []byte("<body")); i != -1 { // strip off noisy <style> header
		b = b[i:]
	}
	got := string(b)
	if !strings.Contains(got, `Sign in with Google`) {
		fatalf(t, "page does not mention google signin button:\n\n%s", got)
	}

	authURL = authURLForPOST(authURL)
	resp, err = c.httpc.PostForm(authURL, url.Values{"provider": []string{"google"}})
	if err != nil {
		fatal(t, err)
	}
	if resp.StatusCode != 200 {
		fatalf(t, "statuscode=%d, want 200", resp.StatusCode)
	}
	b, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		fatal(t, err)
	}
	if i := bytes.Index(b, []byte("<body")); i != -1 { // strip off noisy <style> header
		b = b[i:]
	}
	got = string(b)
	if !strings.Contains(got, "Authorization successful") {
		fatalf(t, "no machine authorization message:\n\n%s", got)
	}

	c.waitStatus(t, stateAuthenticated)
	netmap := c.status(t).New.NetMap
	loginname := netmap.UserProfiles[netmap.User].LoginName
	if want := "insecure@example.com"; loginname != want {
		fatalf(t, "loginame=%s want %s", loginname, want)
	}
}

func nodeIDsEqual(n1, n2 []tailcfg.NodeID) bool {
	if len(n1) != len(n2) {
		return false
	}
	n1s := make(map[tailcfg.NodeID]bool)
	for _, id := range n1 {
		n1s[id] = true
	}
	for _, id := range n2 {
		if !n1s[id] {
			return false
		}
	}
	return true
}

type server struct {
	t          *testing.T
	tmpdir     string
	control    *control.Server
	http       *httptest.Server
	clients    []*client
	check      *tstest.ResourceCheck
	segmentMsg chan map[string]interface{}
}

const segmentKey = "segkey"

func newServer(t *testing.T) *server {
	t.Helper()
	tstest.PanicOnLog()

	logf := t.Logf

	s := &server{
		t:          t,
		check:      tstest.NewResourceCheck(),
		segmentMsg: make(chan map[string]interface{}, 8),
	}

	tmpdir, err := ioutil.TempDir("", "control-test-")
	if err != nil {
		fatal(t, err)
	}
	s.tmpdir = tmpdir

	serveSegment := func(w http.ResponseWriter, r *http.Request) {
		errorf := func(format string, args ...interface{}) {
			msg := fmt.Sprintf(format, args...)
			s.segmentMsg <- map[string]interface{}{
				"error": msg,
			}
			http.Error(w, "segment error: "+msg, 400)
		}

		user, pass, ok := r.BasicAuth()
		if pass != "" {
			errorf("unexpected auth passworkd : %s", user)
			return
		}
		if user != segmentKey {
			errorf("got basic auth user %q, want %q", user, segmentKey)
			return
		}
		if !ok {
			errorf("no basic auth")
		}
		b, err := ioutil.ReadAll(r.Body)
		if err != nil {
			errorf("readall: %v", err)
			return
		}

		m := make(map[string]interface{})
		if err := json.Unmarshal(b, &m); err != nil {
			errorf("unmarshal failed: %v, text:\n%s", err, string(b))
			return
		}
		s.segmentMsg <- m
	}

	s.http = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/identify", "/v1/track":
			serveSegment(w, r)
		default:
			s.control.ServeHTTP(w, r)
		}
	}))
	s.http.Config.ErrorLog = logger.StdLogger(logf)

	s.control, err = control.New(tmpdir, tmpdir, tmpdir, s.http.URL, true, logf)
	if err != nil {
		fatal(t, err)
	}
	s.control.QuietLogging = true
	control.SegmentServer = s.http.URL

	return s
}

func (s *server) close() {
	t := s.t
	t.Helper()
	t.Logf("server.close: shutting down %d clients...\n", len(s.clients))
	for i, c := range s.clients {
		t.Logf("   %d\n", i)
		c.Shutdown()
		t.Logf("   %d CloseIdle\n", i)
		c.cancel()
	}
	// TODO: remove CloseClientConnections when we have a real client shutdown mechanism.
	// The client shutdown should clean up all HTTP connections and calling this will
	// hide any cleanup failures.
	t.Logf("server.close: CloseClientConnections...\n")
	s.http.CloseClientConnections()
	t.Logf("server.close: http.Close...\n")
	s.http.Close()
	s.control.Shutdown()
	// TODO: s.control.Shutdown
	t.Logf("server.close: RemoveAll...\n")
	os.RemoveAll(s.tmpdir)
	t.Logf("server.close: done.\n")
	s.check.Assert(s.t)
}

type statusChange struct {
	New Status
}

func (s *server) newClient(t *testing.T, name string) *client {
	return s.newClientWithKey(t, name, "")
}

func (s *server) newClientWithKey(t *testing.T, name, authKey string) *client {
	t.Helper()

	ch := make(chan statusChange, 1024)
	httpc := s.http.Client()
	var err error
	httpc.Jar, err = cookiejar.New(nil)
	if err != nil {
		fatal(t, err)
	}
	hi := NewHostinfo()
	hi.FrontendLogID = "go-test-only"
	hi.BackendLogID = "go-test-only"
	ctlc, err := NewNoStart(Options{
		ServerURL:      s.http.URL,
		HTTPTestClient: httpc,
		TimeNow:        s.control.TimeNow,
		Logf: func(fmt string, args ...interface{}) {
			t.Helper()
			t.Logf(name+": "+fmt, args...)
		},
		Hostinfo: hi,
		NewDecompressor: func() (Decompressor, error) {
			return zstd.NewReader(nil)
		},
		KeepAlive: true,
		AuthKey:   authKey,
	})
	ctlc.SetStatusFunc(func(new Status) {
		select {
		case ch <- statusChange{New: new}:
		case <-time.After(5 * time.Second):
			fatalf(t, "newClient.statusFunc: stuck.\n")
		}
	})
	if err != nil {
		fatal(t, err)
	}

	c := &client{
		Client:   ctlc,
		s:        s,
		name:     name,
		httpc:    httpc,
		statusCh: ch,
	}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	s.clients = append(s.clients, c)
	ctlc.Start()

	return c
}

type client struct {
	*Client
	s        *server
	name     string
	ctx      context.Context
	cancel   func()
	httpc    *http.Client
	mkey     tailcfg.MachineKey
	nkey     tailcfg.NodeKey
	id       tailcfg.NodeID
	statusCh <-chan statusChange
}

func (c *client) loginAs(t *testing.T, user string) *http.Cookie {
	t.Helper()

	c.Login(nil, 0)
	status := c.waitStatus(t, stateURLVisitRequired)

	return c.postAuthURL(t, user, status.New)
}

func (c *client) postAuthURL(t *testing.T, user string, status Status) *http.Cookie {
	t.Helper()
	authURL := status.URL
	if authURL == "" {
		fatalf(t, "expecting auth URL, got: %v", status)
	}
	return postAuthURL(t, c.ctx, c.httpc, user, authURL)
}

func authURLForPOST(authURL string) string {
	i := strings.Index(authURL, "/a/")
	if i == -1 {
		panic("bad authURL: " + authURL)
	}
	return authURL[:i] + "/login?refresh=true&next_url=" + url.PathEscape(authURL[i:])
}

// postAuthURL manually executes the OAuth login flow, starting at
// authURL and claiming to be user. This flow will only work correctly
// if the control server is configured with the "None" auth provider,
// which blindly accepts the provided user and produces a cookie for
// them. postAuthURL returns the auth cookie produced by the control
// server.
func postAuthURL(t *testing.T, ctx context.Context, httpc *http.Client, user string, authURL string) *http.Cookie {
	t.Helper()

	authURL = authURLForPOST(authURL)
	form := url.Values{"user": []string{user}}
	req, err := http.NewRequest("POST", authURL, strings.NewReader(form.Encode()))
	if err != nil {
		fatal(t, err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpc.Do(req.WithContext(ctx))
	if err != nil {
		fatal(t, err)
	}
	b, _ := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if i := bytes.Index(b, []byte("<body")); i != -1 { // strip off noisy <style> header
		b = b[i:]
	}
	if resp.StatusCode != 200 {
		fatalf(t, "POST %s failed: %q, body: %s", authURL, resp.Status, b)
	}
	cookieURL, err := url.Parse(authURL)
	if err != nil {
		fatal(t, err)
	}
	cookies := httpc.Jar.Cookies(cookieURL)
	if len(cookies) == 0 || cookies[0].Name != "tailcontrol" {
		fatalf(t, "POST %s: bad cookie: %v, body: %s", authURL, cookies, b)
	}
	return cookies[0]
}

func (c *client) checkNoStatus(t *testing.T) {
	t.Helper()
	select {
	case status := <-c.statusCh:
		fatalf(t, "%s: unexpected status change: %v", c.name, status)
	default:
	}
}

func (c *client) readStatus(t *testing.T) (status statusChange) {
	t.Helper()
	select {
	case status = <-c.statusCh:
	case <-time.After(3 * time.Second):
		// TODO(crawshaw): every ~1000 test runs on macOS sees a login get
		// suck in the httpc.Do GET request of loadServerKey.
		// Why? Is this a timing problem, with something causing a pause
		// long enough that the timeout expires? Or is something more
		// sinister going on in the server (or even the HTTP stack)?
		//
		// Extending the timeout to 6 seconds does not solve the problem
		// but does seem to reduce the frequency of flakes.
		//
		// (I have added a runtime.ReadMemStats call here, and have not
		// observed any global pauses greater than 50 microseconds.)
		//
		// NOTE(apenwarr): I can reproduce this more quickly by
		//  running multiple copies of 'go test -count 100' in
		//  parallel, but only on macOS. Increasing the timeout to
		//  10 seconds doesn't seem to help in that case. The
		//  timeout is often, but not always, in fetching the
		//  control key, but I think that's not the essential element.
		pprof.Lookup("goroutine").WriteTo(os.Stdout, 1)
		t.Logf("%s: timeout: no status received\n", c.name)
		fatalf(t, "%s: timeout: no status received", c.name)
	}
	return status
}

func (c *client) status(t *testing.T) (status statusChange) {
	t.Helper()
	status = c.readStatus(t)
	if status.New.Err != "" {
		fatalf(t, "%s state %s: status error: %s", c.name, status.New.state, status.New.Err)
	} else {
		t.Logf("%s state: %s", c.name, status.New.state)
		if status.New.NetMap != nil {
			c.mkey = tailcfg.MachineKey(status.New.Persist.PrivateMachineKey.Public())
			if nkey := status.New.NetMap.NodeKey; nkey != (tailcfg.NodeKey{}) && nkey != c.nkey {
				c.nkey = nkey
				c.id = c.s.control.DB().Node(c.nkey).ID
			}
		}
	}
	return status
}

func (c *client) waitStatus(t *testing.T, want state) statusChange {
	t.Helper()
	status := c.status(t)
	if status.New.state != want {
		fatalf(t, "%s bad state=%s, want %s (%v)", c.name, status.New.state, want, status.New)
	}
	return status
}

// TODO: test client shutdown + recreate
// TODO: test server disconnect/reconnect during followup
// TODO: test network outage downgrade from stateSynchronized -> stateAuthenticated
// TODO: test os/hostname gets sent to server
// TODO: test vpn IP not assigned until machine is authorized
// TODO: test overlapping calls to RefreshLogin
// TODO: test registering a new node for a user+machine key replaces the old
//       node even if the OldNodeKey is not specified by the client.
// TODO: test "does not expire" on server extends expiry in sent network map
