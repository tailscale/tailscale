// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnlocal

import (
	"context"
	"sync"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"

	"tailscale.com/control/controlclient"
	"tailscale.com/ipn"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/types/empty"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/persist"
	"tailscale.com/wgengine"
)

// notifyThrottler receives notifications from an ipn.Backend, blocking
// (with eventual timeout and t.Fatal) if there are too many and complaining
// (also with t.Fatal) if they are too few.
type notifyThrottler struct {
	t *testing.T

	// ch gets replaced frequently. Lock the mutex before getting or
	// setting it, but not while waiting on it.
	mu sync.Mutex
	ch chan ipn.Notify
}

// expect tells the throttler to expect count upcoming notifications.
func (nt *notifyThrottler) expect(count int) {
	nt.mu.Lock()
	nt.ch = make(chan ipn.Notify, count)
	nt.mu.Unlock()
}

// put adds one notification into the throttler's queue.
func (nt *notifyThrottler) put(n ipn.Notify) {
	nt.mu.Lock()
	ch := nt.ch
	nt.mu.Unlock()

	select {
	case ch <- n:
		return
	default:
		nt.t.Fatalf("put: channel full: %v", n)
	}
}

// drain pulls the notifications out of the queue, asserting that there are
// exactly count notifications that have been put so far.
func (nt *notifyThrottler) drain(count int) []ipn.Notify {
	nt.mu.Lock()
	ch := nt.ch
	nt.mu.Unlock()

	nn := []ipn.Notify{}
	for i := 0; i < count; i++ {
		select {
		case n := <-ch:
			nn = append(nn, n)
		case <-time.After(6 * time.Second):
			nt.t.Fatalf("drain: channel empty after %d/%d", i, count)
		}
	}

	// no more notifications expected
	close(ch)

	return nn
}

// mockControl is a mock implementation of controlclient.Client.
// Much of the backend state machine depends on callbacks and state
// in the controlclient.Client, so by controlling it, we can check that
// the state machine works as expected.
type mockControl struct {
	tb         testing.TB
	opts       controlclient.Options
	logf       logger.Logf
	statusFunc func(controlclient.Status)

	mu          sync.Mutex
	calls       []string
	authBlocked bool
	persist     persist.Persist
	machineKey  key.MachinePrivate
}

func newMockControl(tb testing.TB) *mockControl {
	return &mockControl{
		tb:          tb,
		authBlocked: true,
	}
}

func (cc *mockControl) SetStatusFunc(fn func(controlclient.Status)) {
	cc.statusFunc = fn
}

func (cc *mockControl) populateKeys() (newKeys bool) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	if cc.machineKey.IsZero() {
		cc.logf("Copying machineKey.")
		cc.machineKey, _ = cc.opts.GetMachinePrivateKey()
		newKeys = true
	}

	if cc.persist.PrivateNodeKey.IsZero() {
		cc.logf("Generating a new nodekey.")
		cc.persist.OldPrivateNodeKey = cc.persist.PrivateNodeKey
		cc.persist.PrivateNodeKey = key.NewNode()
		newKeys = true
	}

	return newKeys
}

// send publishes a controlclient.Status notification upstream.
// (In our tests here, upstream is the ipnlocal.Local instance.)
func (cc *mockControl) send(err error, url string, loginFinished bool, nm *netmap.NetworkMap) {
	if cc.statusFunc != nil {
		s := controlclient.Status{
			URL:     url,
			NetMap:  nm,
			Persist: &cc.persist,
			Err:     err,
		}
		if loginFinished {
			s.LoginFinished = &empty.Message{}
		} else if url == "" && err == nil && nm == nil {
			s.LogoutFinished = &empty.Message{}
		}
		cc.statusFunc(s)
	}
}

// called records that a particular function name was called.
func (cc *mockControl) called(s string) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	cc.calls = append(cc.calls, s)
}

// assertCalls fails the test if the list of functions that have been called since the
// last time assertCall was run does not match want.
func (cc *mockControl) assertCalls(want ...string) {
	cc.tb.Helper()
	cc.mu.Lock()
	defer cc.mu.Unlock()
	qt.Assert(cc.tb, cc.calls, qt.DeepEquals, want)
	cc.calls = nil
}

// setAuthBlocked changes the return value of AuthCantContinue.
// Auth is blocked if you haven't called Login, the control server hasn't
// provided an auth URL, or it has provided an auth URL and you haven't
// visited it yet.
func (cc *mockControl) setAuthBlocked(blocked bool) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	cc.authBlocked = blocked
}

// Shutdown disconnects the client.
//
// Note that in a normal controlclient, Shutdown would be the last thing you
// do before discarding the object. In this mock, we don't actually discard
// the object, but if you see a call to Shutdown, you should always see a
// call to New right after it, if the object continues to be used.
// (Note that "New" is the ccGen function here; it means ipn.Backend wanted
// to create an entirely new controlclient.)
func (cc *mockControl) Shutdown() {
	cc.logf("Shutdown")
	cc.called("Shutdown")
}

// Login starts a login process.
// Note that in this mock, we don't automatically generate notifications
// about the progress of the login operation. You have to call setAuthBlocked()
// and send() as required by the test.
func (cc *mockControl) Login(t *tailcfg.Oauth2Token, flags controlclient.LoginFlags) {
	cc.logf("Login token=%v flags=%v", t, flags)
	cc.called("Login")
	newKeys := cc.populateKeys()

	interact := (flags & controlclient.LoginInteractive) != 0
	cc.logf("Login: interact=%v newKeys=%v", interact, newKeys)
	cc.setAuthBlocked(interact || newKeys)
}

func (cc *mockControl) StartLogout() {
	cc.logf("StartLogout")
	cc.called("StartLogout")
}

func (cc *mockControl) Logout(ctx context.Context) error {
	cc.logf("Logout")
	cc.called("Logout")
	return nil
}

func (cc *mockControl) SetPaused(paused bool) {
	cc.logf("SetPaused=%v", paused)
	if paused {
		cc.called("pause")
	} else {
		cc.called("unpause")
	}
}

func (cc *mockControl) AuthCantContinue() bool {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	return cc.authBlocked
}

func (cc *mockControl) SetHostinfo(hi *tailcfg.Hostinfo) {
	cc.logf("SetHostinfo: %v", *hi)
	cc.called("SetHostinfo")
}

func (cc *mockControl) SetNetInfo(ni *tailcfg.NetInfo) {
	cc.called("SetNetinfo")
	cc.logf("SetNetInfo: %v", *ni)
	cc.called("SetNetInfo")
}

func (cc *mockControl) UpdateEndpoints(localPort uint16, endpoints []tailcfg.Endpoint) {
	// validate endpoint information here?
	cc.logf("UpdateEndpoints: lp=%v ep=%v", localPort, endpoints)
	cc.called("UpdateEndpoints")
}

func (*mockControl) SetDNS(context.Context, *tailcfg.SetDNSRequest) error {
	panic("unexpected SetDNS call")
}

// A very precise test of the sequence of function calls generated by
// ipnlocal.Local into its controlclient instance, and the events it
// produces upstream into the UI.
//
// [apenwarr] Normally I'm not a fan of "mock" style tests, but the precise
// sequence of this state machine is so important for writing our multiple
// frontends, that it's worth validating it all in one place.
//
// Any changes that affect this test will most likely require carefully
// re-testing all our GUIs (and the CLI) to make sure we didn't break
// anything.
//
// Note also that this test doesn't have any timers, goroutines, or duplicate
// detection. It expects messages to be produced in exactly the right order,
// with no duplicates, without doing network activity (other than through
// controlclient, which we fake, so there's no network activity there either).
//
// TODO: A few messages that depend on magicsock (which actually might have
// network delays) are just ignored for now, which makes the test
// predictable, but maybe a bit less thorough. This is more of an overall
// state machine test than a test of the wgengine+magicsock integration.
func TestStateMachine(t *testing.T) {
	c := qt.New(t)

	logf := t.Logf
	store := new(testStateStorage)
	e, err := wgengine.NewFakeUserspaceEngine(logf, 0)
	if err != nil {
		t.Fatalf("NewFakeUserspaceEngine: %v", err)
	}
	t.Cleanup(e.Close)

	cc := newMockControl(t)
	b, err := NewLocalBackend(logf, "logid", store, nil, e)
	if err != nil {
		t.Fatalf("NewLocalBackend: %v", err)
	}
	b.SetControlClientGetterForTesting(func(opts controlclient.Options) (controlclient.Client, error) {
		cc.mu.Lock()
		cc.opts = opts
		cc.logf = opts.Logf
		cc.authBlocked = true
		cc.persist = cc.opts.Persist
		cc.mu.Unlock()

		cc.logf("ccGen: new mockControl.")
		cc.called("New")
		return cc, nil
	})

	notifies := &notifyThrottler{t: t}
	notifies.expect(0)

	b.SetNotifyCallback(func(n ipn.Notify) {
		if n.State != nil ||
			n.Prefs != nil ||
			n.BrowseToURL != nil ||
			n.LoginFinished != nil {
			logf("\n%v\n\n", n)
			notifies.put(n)
		} else {
			logf("\n(ignored) %v\n\n", n)
		}
	})

	// Check that it hasn't called us right away.
	// The state machine should be idle until we call Start().
	cc.assertCalls()

	// Start the state machine.
	// Since !WantRunning by default, it'll create a controlclient,
	// but not ask it to do anything yet.
	t.Logf("\n\nStart")
	notifies.expect(2)
	c.Assert(b.Start(ipn.Options{StateKey: ipn.GlobalDaemonStateKey}), qt.IsNil)
	{
		// BUG: strictly, it should pause, not unpause, here, since !WantRunning.
		cc.assertCalls("New", "unpause")

		nn := notifies.drain(2)
		cc.assertCalls()
		c.Assert(nn[0].Prefs, qt.IsNotNil)
		c.Assert(nn[1].State, qt.IsNotNil)
		prefs := *nn[0].Prefs
		// Note: a totally fresh system has Prefs.LoggedOut=false by
		// default. We are logged out, but not because the user asked
		// for it, so it doesn't count as Prefs.LoggedOut==true.
		c.Assert(nn[0].Prefs.LoggedOut, qt.IsFalse)
		c.Assert(prefs.WantRunning, qt.IsFalse)
		c.Assert(ipn.NeedsLogin, qt.Equals, *nn[1].State)
		c.Assert(ipn.NeedsLogin, qt.Equals, b.State())
	}

	// Restart the state machine.
	// It's designed to handle frontends coming and going sporadically.
	// Make the sure the restart not only works, but generates the same
	// events as the first time, so UIs always know what to expect.
	t.Logf("\n\nStart2")
	notifies.expect(2)
	c.Assert(b.Start(ipn.Options{StateKey: ipn.GlobalDaemonStateKey}), qt.IsNil)
	{
		// BUG: strictly, it should pause, not unpause, here, since !WantRunning.
		cc.assertCalls("Shutdown", "unpause", "New", "unpause")

		nn := notifies.drain(2)
		cc.assertCalls()
		c.Assert(nn[0].Prefs, qt.IsNotNil)
		c.Assert(nn[1].State, qt.IsNotNil)
		c.Assert(nn[0].Prefs.LoggedOut, qt.IsFalse)
		c.Assert(nn[0].Prefs.WantRunning, qt.IsFalse)
		c.Assert(ipn.NeedsLogin, qt.Equals, *nn[1].State)
		c.Assert(ipn.NeedsLogin, qt.Equals, b.State())
	}

	// Start non-interactive login with no token.
	// This will ask controlclient to start its own Login() process,
	// then wait for us to respond.
	t.Logf("\n\nLogin (noninteractive)")
	notifies.expect(0)
	b.Login(nil)
	{
		cc.assertCalls("Login")
		notifies.drain(0)
		// Note: WantRunning isn't true yet. It'll switch to true
		// after a successful login finishes.
		// (This behaviour is needed so that b.Login() won't
		// start connecting to an old account right away, if one
		// exists when you launch another login.)
	}

	// Attempted non-interactive login with no key; indicate that
	// the user needs to visit a login URL.
	t.Logf("\n\nLogin (url response)")
	notifies.expect(1)
	url1 := "http://localhost:1/1"
	cc.send(nil, url1, false, nil)
	{
		cc.assertCalls("unpause")

		// ...but backend eats that notification, because the user
		// didn't explicitly request interactive login yet, and
		// we're already in NeedsLogin state.
		nn := notifies.drain(1)

		c.Assert(nn[0].Prefs, qt.IsNotNil)
		c.Assert(nn[0].Prefs.LoggedOut, qt.IsFalse)
		c.Assert(nn[0].Prefs.WantRunning, qt.IsFalse)
	}

	// Now we'll try an interactive login.
	// Since we provided an interactive URL earlier, this shouldn't
	// ask control to do anything. Instead backend will emit an event
	// indicating that the UI should browse to the given URL.
	t.Logf("\n\nLogin (interactive)")
	notifies.expect(1)
	b.StartLoginInteractive()
	{
		nn := notifies.drain(1)
		cc.assertCalls("unpause")
		c.Assert(nn[0].BrowseToURL, qt.IsNotNil)
		c.Assert(url1, qt.Equals, *nn[0].BrowseToURL)
	}

	// Sometimes users press the Login button again, in the middle of
	// a login sequence. For example, they might have closed their
	// browser window without logging in, or they waited too long and
	// the login URL expired. If they start another interactive login,
	// we must always get a *new* login URL first.
	t.Logf("\n\nLogin2 (interactive)")
	notifies.expect(0)
	b.StartLoginInteractive()
	{
		notifies.drain(0)
		// backend asks control for another login sequence
		cc.assertCalls("Login")
	}

	// Provide a new interactive login URL.
	t.Logf("\n\nLogin2 (url response)")
	notifies.expect(1)
	url2 := "http://localhost:1/2"
	cc.send(nil, url2, false, nil)
	{
		cc.assertCalls("unpause", "unpause")

		// This time, backend should emit it to the UI right away,
		// because the UI is anxiously awaiting a new URL to visit.
		nn := notifies.drain(1)
		c.Assert(nn[0].BrowseToURL, qt.IsNotNil)
		c.Assert(url2, qt.Equals, *nn[0].BrowseToURL)
	}

	// Pretend that the interactive login actually happened.
	// Controlclient always sends the netmap and LoginFinished at the
	// same time.
	// The backend should propagate this upward for the UI.
	t.Logf("\n\nLoginFinished")
	notifies.expect(3)
	cc.setAuthBlocked(false)
	cc.persist.LoginName = "user1"
	cc.send(nil, "", true, &netmap.NetworkMap{})
	{
		nn := notifies.drain(3)
		// Arguably it makes sense to unpause now, since the machine
		// authorization status is part of the netmap.
		//
		// BUG: backend unblocks wgengine at this point, even though
		// our machine key is not authorized. It probably should
		// wait until it gets into Starting.
		// TODO: (Currently this test doesn't detect that bug, but
		// it's visible in the logs)
		cc.assertCalls("unpause", "unpause", "unpause")
		c.Assert(nn[0].LoginFinished, qt.IsNotNil)
		c.Assert(nn[1].Prefs, qt.IsNotNil)
		c.Assert(nn[2].State, qt.IsNotNil)
		c.Assert(nn[1].Prefs.Persist.LoginName, qt.Equals, "user1")
		c.Assert(ipn.NeedsMachineAuth, qt.Equals, *nn[2].State)
	}

	// Pretend that the administrator has authorized our machine.
	t.Logf("\n\nMachineAuthorized")
	notifies.expect(1)
	// BUG: the real controlclient sends LoginFinished with every
	// notification while it's in StateAuthenticated, but not StateSynced.
	// It should send it exactly once, or every time we're authenticated,
	// but the current code is brittle.
	// (ie. I suspect it would be better to change false->true in send()
	// below, and do the same in the real controlclient.)
	cc.send(nil, "", false, &netmap.NetworkMap{
		MachineStatus: tailcfg.MachineAuthorized,
	})
	{
		nn := notifies.drain(1)
		cc.assertCalls("unpause", "unpause", "unpause")
		c.Assert(nn[0].State, qt.IsNotNil)
		c.Assert(ipn.Starting, qt.Equals, *nn[0].State)
	}

	// TODO: add a fake DERP server to our fake netmap, so we can
	// transition to the Running state here.

	// TODO: test what happens when the admin forcibly deletes our key.
	// (ie. unsolicited logout)

	// TODO: test what happens when our key expires, client side.
	// (and when it gets close to expiring)

	// The user changes their preference to !WantRunning.
	t.Logf("\n\nWantRunning -> false")
	notifies.expect(2)
	b.EditPrefs(&ipn.MaskedPrefs{
		WantRunningSet: true,
		Prefs:          ipn.Prefs{WantRunning: false},
	})
	{
		nn := notifies.drain(2)
		cc.assertCalls("pause")
		// BUG: I would expect Prefs to change first, and state after.
		c.Assert(nn[0].State, qt.IsNotNil)
		c.Assert(nn[1].Prefs, qt.IsNotNil)
		c.Assert(ipn.Stopped, qt.Equals, *nn[0].State)
	}

	// The user changes their preference to WantRunning after all.
	t.Logf("\n\nWantRunning -> true")
	store.awaitWrite()
	notifies.expect(2)
	b.EditPrefs(&ipn.MaskedPrefs{
		WantRunningSet: true,
		Prefs:          ipn.Prefs{WantRunning: true},
	})
	{
		nn := notifies.drain(2)
		// BUG: Login isn't needed here. We never logged out.
		cc.assertCalls("Login", "unpause", "unpause")
		// BUG: I would expect Prefs to change first, and state after.
		c.Assert(nn[0].State, qt.IsNotNil)
		c.Assert(nn[1].Prefs, qt.IsNotNil)
		c.Assert(ipn.Starting, qt.Equals, *nn[0].State)
		c.Assert(store.sawWrite(), qt.IsTrue)
	}

	// Test the fast-path frontend reconnection.
	// This one is very finicky, so we have to force State==Running
	// or it won't use the fast path.
	// TODO: actually get to State==Running, rather than cheating.
	//  That'll require spinning up a fake DERP server and putting it in
	//  the netmap.
	t.Logf("\n\nFastpath Start()")
	notifies.expect(1)
	b.state = ipn.Running
	c.Assert(b.Start(ipn.Options{StateKey: ipn.GlobalDaemonStateKey}), qt.IsNil)
	{
		nn := notifies.drain(1)
		cc.assertCalls()
		c.Assert(nn[0].State, qt.IsNotNil)
		c.Assert(nn[0].LoginFinished, qt.IsNotNil)
		c.Assert(nn[0].NetMap, qt.IsNotNil)
		c.Assert(nn[0].Prefs, qt.IsNotNil)
	}

	// undo the state hack above.
	b.state = ipn.Starting

	// User wants to logout.
	store.awaitWrite()
	t.Logf("\n\nLogout (async)")
	notifies.expect(2)
	b.Logout()
	{
		nn := notifies.drain(2)
		cc.assertCalls("pause", "StartLogout", "pause")
		c.Assert(nn[0].State, qt.IsNotNil)
		c.Assert(nn[1].Prefs, qt.IsNotNil)
		c.Assert(ipn.Stopped, qt.Equals, *nn[0].State)
		c.Assert(nn[1].Prefs.LoggedOut, qt.IsTrue)
		c.Assert(nn[1].Prefs.WantRunning, qt.IsFalse)
		c.Assert(ipn.Stopped, qt.Equals, b.State())
		c.Assert(store.sawWrite(), qt.IsTrue)
	}

	// Let's make the logout succeed.
	t.Logf("\n\nLogout (async) - succeed")
	notifies.expect(1)
	cc.setAuthBlocked(true)
	cc.send(nil, "", false, nil)
	{
		nn := notifies.drain(1)
		cc.assertCalls("unpause", "unpause")
		c.Assert(nn[0].State, qt.IsNotNil)
		c.Assert(ipn.NeedsLogin, qt.Equals, *nn[0].State)
		c.Assert(b.Prefs().LoggedOut, qt.IsTrue)
		c.Assert(b.Prefs().WantRunning, qt.IsFalse)
		c.Assert(ipn.NeedsLogin, qt.Equals, b.State())
	}

	// A second logout should do nothing, since the prefs haven't changed.
	t.Logf("\n\nLogout2 (async)")
	notifies.expect(0)
	b.Logout()
	{
		notifies.drain(0)
		// BUG: the backend has already called StartLogout, and we're
		// still logged out. So it shouldn't call it again.
		cc.assertCalls("StartLogout", "unpause")
		cc.assertCalls()
		c.Assert(b.Prefs().LoggedOut, qt.IsTrue)
		c.Assert(b.Prefs().WantRunning, qt.IsFalse)
		c.Assert(ipn.NeedsLogin, qt.Equals, b.State())
	}

	// Let's acknowledge the second logout too.
	t.Logf("\n\nLogout2 (async) - succeed")
	notifies.expect(0)
	cc.setAuthBlocked(true)
	cc.send(nil, "", false, nil)
	{
		notifies.drain(0)
		cc.assertCalls("unpause", "unpause")
		c.Assert(b.Prefs().LoggedOut, qt.IsTrue)
		c.Assert(b.Prefs().WantRunning, qt.IsFalse)
		c.Assert(ipn.NeedsLogin, qt.Equals, b.State())
	}

	// Try the synchronous logout feature.
	t.Logf("\n\nLogout3 (sync)")
	notifies.expect(0)
	b.LogoutSync(context.Background())
	// NOTE: This returns as soon as cc.Logout() returns, which is okay
	// I guess, since that's supposed to be synchronous.
	{
		notifies.drain(0)
		cc.assertCalls("Logout", "unpause")
		c.Assert(b.Prefs().LoggedOut, qt.IsTrue)
		c.Assert(b.Prefs().WantRunning, qt.IsFalse)
		c.Assert(ipn.NeedsLogin, qt.Equals, b.State())
	}

	// Generate the third logout event.
	t.Logf("\n\nLogout3 (sync) - succeed")
	notifies.expect(0)
	cc.setAuthBlocked(true)
	cc.send(nil, "", false, nil)
	{
		notifies.drain(0)
		cc.assertCalls("unpause", "unpause")
		c.Assert(b.Prefs().LoggedOut, qt.IsTrue)
		c.Assert(b.Prefs().WantRunning, qt.IsFalse)
		c.Assert(ipn.NeedsLogin, qt.Equals, b.State())
	}

	// Oh, you thought we were done? Ha! Now we have to test what
	// happens if the user exits and restarts while logged out.
	// Note that it's explicitly okay to call b.Start() over and over
	// again, every time the frontend reconnects.

	// TODO: test user switching between statekeys.

	// The frontend restarts!
	t.Logf("\n\nStart3")
	notifies.expect(2)
	c.Assert(b.Start(ipn.Options{StateKey: ipn.GlobalDaemonStateKey}), qt.IsNil)
	{
		// BUG: We already called Shutdown(), no need to do it again.
		// BUG: don't unpause because we're not logged in.
		cc.assertCalls("Shutdown", "unpause", "New", "unpause")

		nn := notifies.drain(2)
		cc.assertCalls()
		c.Assert(nn[0].Prefs, qt.IsNotNil)
		c.Assert(nn[1].State, qt.IsNotNil)
		c.Assert(nn[0].Prefs.LoggedOut, qt.IsTrue)
		c.Assert(nn[0].Prefs.WantRunning, qt.IsFalse)
		c.Assert(ipn.NeedsLogin, qt.Equals, *nn[1].State)
		c.Assert(ipn.NeedsLogin, qt.Equals, b.State())
	}

	// Let's break the rules a little. Our control server accepts
	// your invalid login attempt, with no need for an interactive login.
	// (This simulates an admin reviving a key that you previously
	// disabled.)
	t.Logf("\n\nLoginFinished3")
	notifies.expect(3)
	cc.setAuthBlocked(false)
	cc.persist.LoginName = "user2"
	cc.send(nil, "", true, &netmap.NetworkMap{
		MachineStatus: tailcfg.MachineAuthorized,
	})
	{
		nn := notifies.drain(3)
		cc.assertCalls("unpause", "unpause", "unpause")
		c.Assert(nn[0].LoginFinished, qt.IsNotNil)
		c.Assert(nn[1].Prefs, qt.IsNotNil)
		c.Assert(nn[2].State, qt.IsNotNil)
		// Prefs after finishing the login, so LoginName updated.
		c.Assert(nn[1].Prefs.Persist.LoginName, qt.Equals, "user2")
		c.Assert(nn[1].Prefs.LoggedOut, qt.IsFalse)
		c.Assert(nn[1].Prefs.WantRunning, qt.IsTrue)
		c.Assert(ipn.Starting, qt.Equals, *nn[2].State)
	}

	// Now we've logged in successfully. Let's disconnect.
	t.Logf("\n\nWantRunning -> false")
	notifies.expect(2)
	b.EditPrefs(&ipn.MaskedPrefs{
		WantRunningSet: true,
		Prefs:          ipn.Prefs{WantRunning: false},
	})
	{
		nn := notifies.drain(2)
		cc.assertCalls("pause")
		// BUG: I would expect Prefs to change first, and state after.
		c.Assert(nn[0].State, qt.IsNotNil)
		c.Assert(nn[1].Prefs, qt.IsNotNil)
		c.Assert(ipn.Stopped, qt.Equals, *nn[0].State)
		c.Assert(nn[1].Prefs.LoggedOut, qt.IsFalse)
	}

	// One more restart, this time with a valid key, but WantRunning=false.
	t.Logf("\n\nStart4")
	notifies.expect(2)
	c.Assert(b.Start(ipn.Options{StateKey: ipn.GlobalDaemonStateKey}), qt.IsNil)
	{
		// NOTE: cc.Shutdown() is correct here, since we didn't call
		// b.Shutdown() explicitly ourselves.
		// Note: unpause happens because ipn needs to get at least one netmap
		//  on startup, otherwise UIs can't show the node list, login
		//  name, etc when in state ipn.Stopped.
		//  Arguably they shouldn't try. But they currently do.
		nn := notifies.drain(2)
		cc.assertCalls("Shutdown", "unpause", "New", "Login", "unpause")
		c.Assert(nn[0].Prefs, qt.IsNotNil)
		c.Assert(nn[1].State, qt.IsNotNil)
		c.Assert(nn[0].Prefs.WantRunning, qt.IsFalse)
		c.Assert(nn[0].Prefs.LoggedOut, qt.IsFalse)
		c.Assert(ipn.Stopped, qt.Equals, *nn[1].State)
	}

	// When logged in but !WantRunning, ipn leaves us unpaused to retrieve
	// the first netmap. Simulate that netmap being received, after which
	// it should pause us, to avoid wasting CPU retrieving unnecessarily
	// additional netmap updates.
	//
	// TODO: really the various GUIs and prefs should be refactored to
	//  not require the netmap structure at all when starting while
	//  !WantRunning. That would remove the need for this (or contacting
	//  the control server at all when stopped).
	t.Logf("\n\nStart4 -> netmap")
	notifies.expect(0)
	cc.send(nil, "", true, &netmap.NetworkMap{
		MachineStatus: tailcfg.MachineAuthorized,
	})
	{
		notifies.drain(0)
		cc.assertCalls("pause", "pause")
	}

	// Request connection.
	// The state machine didn't call Login() earlier, so now it needs to.
	t.Logf("\n\nWantRunning4 -> true")
	notifies.expect(2)
	b.EditPrefs(&ipn.MaskedPrefs{
		WantRunningSet: true,
		Prefs:          ipn.Prefs{WantRunning: true},
	})
	{
		nn := notifies.drain(2)
		cc.assertCalls("Login", "unpause", "unpause")
		// BUG: I would expect Prefs to change first, and state after.
		c.Assert(nn[0].State, qt.IsNotNil)
		c.Assert(nn[1].Prefs, qt.IsNotNil)
		c.Assert(ipn.Starting, qt.Equals, *nn[0].State)
	}

	// Disconnect.
	t.Logf("\n\nStop")
	notifies.expect(2)
	b.EditPrefs(&ipn.MaskedPrefs{
		WantRunningSet: true,
		Prefs:          ipn.Prefs{WantRunning: false},
	})
	{
		nn := notifies.drain(2)
		cc.assertCalls("pause")
		// BUG: I would expect Prefs to change first, and state after.
		c.Assert(nn[0].State, qt.IsNotNil)
		c.Assert(nn[1].Prefs, qt.IsNotNil)
		c.Assert(ipn.Stopped, qt.Equals, *nn[0].State)
	}

	// We want to try logging in as a different user, while Stopped.
	// First, start the login process (without logging out first).
	t.Logf("\n\nLoginDifferent")
	notifies.expect(1)
	b.StartLoginInteractive()
	url3 := "http://localhost:1/3"
	cc.send(nil, url3, false, nil)
	{
		nn := notifies.drain(1)
		// It might seem like WantRunning should switch to true here,
		// but that would be risky since we already have a valid
		// user account. It might try to reconnect to the old account
		// before the new one is ready. So no change yet.
		//
		// Because the login hasn't yet completed, the old login
		// is still valid, so it's correct that we stay paused.
		cc.assertCalls("Login", "pause", "pause")
		c.Assert(nn[0].BrowseToURL, qt.IsNotNil)
		c.Assert(*nn[0].BrowseToURL, qt.Equals, url3)
	}

	// Now, let's complete the interactive login, using a different
	// user account than before. WantRunning changes to true after an
	// interactive login, so we end up unpaused.
	t.Logf("\n\nLoginDifferent URL visited")
	notifies.expect(3)
	cc.persist.LoginName = "user3"
	cc.send(nil, "", true, &netmap.NetworkMap{
		MachineStatus: tailcfg.MachineAuthorized,
	})
	{
		nn := notifies.drain(3)
		// BUG: pause() being called here is a bad sign.
		//  It means that either the state machine ran at least once
		//  with the old netmap, or it ran with the new login+netmap
		//  and !WantRunning. But since it's a fresh and successful
		//  new login, WantRunning is true, so there was never a
		//  reason to pause().
		cc.assertCalls("pause", "unpause", "unpause")
		c.Assert(nn[0].LoginFinished, qt.IsNotNil)
		c.Assert(nn[1].Prefs, qt.IsNotNil)
		c.Assert(nn[2].State, qt.IsNotNil)
		// Prefs after finishing the login, so LoginName updated.
		c.Assert(nn[1].Prefs.Persist.LoginName, qt.Equals, "user3")
		c.Assert(nn[1].Prefs.LoggedOut, qt.IsFalse)
		c.Assert(nn[1].Prefs.WantRunning, qt.IsTrue)
		c.Assert(ipn.Starting, qt.Equals, *nn[2].State)
	}

	// The last test case is the most common one: restarting when both
	// logged in and WantRunning.
	t.Logf("\n\nStart5")
	notifies.expect(1)
	c.Assert(b.Start(ipn.Options{StateKey: ipn.GlobalDaemonStateKey}), qt.IsNil)
	{
		// NOTE: cc.Shutdown() is correct here, since we didn't call
		// b.Shutdown() ourselves.
		cc.assertCalls("Shutdown", "unpause", "New", "Login", "unpause")

		nn := notifies.drain(1)
		cc.assertCalls()
		c.Assert(nn[0].Prefs, qt.IsNotNil)
		c.Assert(nn[0].Prefs.LoggedOut, qt.IsFalse)
		c.Assert(nn[0].Prefs.WantRunning, qt.IsTrue)
		c.Assert(ipn.NoState, qt.Equals, b.State())
	}

	// Control server accepts our valid key from before.
	t.Logf("\n\nLoginFinished5")
	notifies.expect(1)
	cc.setAuthBlocked(false)
	cc.send(nil, "", true, &netmap.NetworkMap{
		MachineStatus: tailcfg.MachineAuthorized,
	})
	{
		nn := notifies.drain(1)
		cc.assertCalls("unpause", "unpause", "unpause")
		// NOTE: No LoginFinished message since no interactive
		// login was needed.
		c.Assert(nn[0].State, qt.IsNotNil)
		c.Assert(ipn.Starting, qt.Equals, *nn[0].State)
		// NOTE: No prefs change this time. WantRunning stays true.
		// We were in Starting in the first place, so that doesn't
		// change either.
		c.Assert(ipn.Starting, qt.Equals, b.State())
	}
	t.Logf("\n\nExpireKey")
	notifies.expect(1)
	cc.send(nil, "", false, &netmap.NetworkMap{
		Expiry:        time.Now().Add(-time.Minute),
		MachineStatus: tailcfg.MachineAuthorized,
	})
	{
		nn := notifies.drain(1)
		cc.assertCalls("unpause", "unpause")
		c.Assert(nn[0].State, qt.IsNotNil)
		c.Assert(ipn.NeedsLogin, qt.Equals, *nn[0].State)
		c.Assert(ipn.NeedsLogin, qt.Equals, b.State())
		c.Assert(b.isEngineBlocked(), qt.IsTrue)
	}

	t.Logf("\n\nExtendKey")
	notifies.expect(1)
	cc.send(nil, "", false, &netmap.NetworkMap{
		Expiry:        time.Now().Add(time.Minute),
		MachineStatus: tailcfg.MachineAuthorized,
	})
	{
		nn := notifies.drain(1)
		cc.assertCalls("unpause", "unpause", "unpause")
		c.Assert(nn[0].State, qt.IsNotNil)
		c.Assert(ipn.Starting, qt.Equals, *nn[0].State)
		c.Assert(ipn.Starting, qt.Equals, b.State())
		c.Assert(b.isEngineBlocked(), qt.IsFalse)
	}
	notifies.expect(1)
	// Fake a DERP connection.
	b.setWgengineStatus(&wgengine.Status{DERPs: 1}, nil)
	{
		nn := notifies.drain(1)
		cc.assertCalls("unpause")
		c.Assert(nn[0].State, qt.IsNotNil)
		c.Assert(ipn.Running, qt.Equals, *nn[0].State)
		c.Assert(ipn.Running, qt.Equals, b.State())
	}
}

type testStateStorage struct {
	mem     ipn.MemoryStore
	written syncs.AtomicBool
}

func (s *testStateStorage) ReadState(id ipn.StateKey) ([]byte, error) {
	return s.mem.ReadState(id)
}

func (s *testStateStorage) WriteState(id ipn.StateKey, bs []byte) error {
	s.written.Set(true)
	return s.mem.WriteState(id, bs)
}

// awaitWrite clears the "I've seen writes" bit, in prep for a future
// call to sawWrite to see if a write arrived.
func (s *testStateStorage) awaitWrite() { s.written.Set(false) }

// sawWrite reports whether there's been a WriteState call since the most
// recent awaitWrite call.
func (s *testStateStorage) sawWrite() bool {
	v := s.written.Get()
	s.awaitWrite()
	return v
}

func TestWGEngineStatusRace(t *testing.T) {
	t.Skip("test fails")
	c := qt.New(t)
	logf := t.Logf
	eng, err := wgengine.NewFakeUserspaceEngine(logf, 0)
	c.Assert(err, qt.IsNil)
	t.Cleanup(eng.Close)
	b, err := NewLocalBackend(logf, "logid", new(ipn.MemoryStore), nil, eng)
	c.Assert(err, qt.IsNil)

	cc := newMockControl(t)
	b.SetControlClientGetterForTesting(func(opts controlclient.Options) (controlclient.Client, error) {
		cc.mu.Lock()
		defer cc.mu.Unlock()
		cc.logf = opts.Logf
		return cc, nil
	})

	var state ipn.State
	b.SetNotifyCallback(func(n ipn.Notify) {
		if n.State != nil {
			state = *n.State
		}
	})
	wantState := func(want ipn.State) {
		c.Assert(want, qt.Equals, state)
	}

	// Start with the zero value.
	wantState(ipn.NoState)

	// Start the backend.
	err = b.Start(ipn.Options{StateKey: ipn.GlobalDaemonStateKey})
	c.Assert(err, qt.IsNil)
	wantState(ipn.NeedsLogin)

	// Assert that we are logged in and authorized.
	cc.send(nil, "", true, &netmap.NetworkMap{
		MachineStatus: tailcfg.MachineAuthorized,
	})
	wantState(ipn.Starting)

	// Simulate multiple concurrent callbacks from wgengine.
	// Any single callback with DERPS > 0 is enough to transition
	// from Starting to Running, at which point we stay there.
	// Thus if these callbacks occurred serially, in any order,
	// we would end up in state ipn.Running.
	// The same should thus be true if these callbacks occur concurrently.
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			n := 0
			if i == 0 {
				n = 1
			}
			b.setWgengineStatus(&wgengine.Status{DERPs: n}, nil)
		}(i)
	}
	wg.Wait()
	wantState(ipn.Running)
}
