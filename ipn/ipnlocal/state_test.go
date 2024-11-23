// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"

	"tailscale.com/control/controlclient"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/tstest"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
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
	nt.t.Helper()
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
	nt.t.Helper()
	nt.mu.Lock()
	ch := nt.ch
	nt.mu.Unlock()

	nn := []ipn.Notify{}
	for i := range count {
		select {
		case n := <-ch:
			nn = append(nn, n)
		case <-time.After(6 * time.Second):
			nt.t.Fatalf("drain: channel empty after %d/%d", i, count)
		}
	}

	// no more notifications expected
	close(ch)

	nt.t.Log(nn)
	return nn
}

// mockControl is a mock implementation of controlclient.Client.
// Much of the backend state machine depends on callbacks and state
// in the controlclient.Client, so by controlling it, we can check that
// the state machine works as expected.
type mockControl struct {
	tb     testing.TB
	logf   logger.Logf
	opts   controlclient.Options
	paused atomic.Bool

	mu          sync.Mutex
	persist     *persist.Persist
	calls       []string
	authBlocked bool
	shutdown    chan struct{}
}

func newClient(tb testing.TB, opts controlclient.Options) *mockControl {
	return &mockControl{
		tb:          tb,
		authBlocked: true,
		logf:        opts.Logf,
		opts:        opts,
		shutdown:    make(chan struct{}),
		persist:     opts.Persist.Clone(),
	}
}

func (cc *mockControl) assertShutdown(wasPaused bool) {
	cc.tb.Helper()
	select {
	case <-cc.shutdown:
		// ok
	case <-time.After(500 * time.Millisecond):
		cc.tb.Fatalf("timed out waiting for shutdown")
	}
	if wasPaused {
		cc.assertCalls("unpause", "Shutdown")
	} else {
		cc.assertCalls("Shutdown")
	}
}

func (cc *mockControl) populateKeys() (newKeys bool) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	if cc.persist == nil {
		cc.persist = &persist.Persist{}
	}
	if cc.persist != nil && cc.persist.PrivateNodeKey.IsZero() {
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
	if loginFinished {
		cc.mu.Lock()
		cc.authBlocked = false
		cc.mu.Unlock()
	}
	if cc.opts.Observer != nil {
		s := controlclient.Status{
			URL:     url,
			NetMap:  nm,
			Persist: cc.persist.View(),
			Err:     err,
		}
		if loginFinished {
			s.SetStateForTest(controlclient.StateAuthenticated)
		} else if url == "" && err == nil && nm == nil {
			s.SetStateForTest(controlclient.StateNotAuthenticated)
		}
		cc.opts.Observer.SetControlClientStatus(cc, s)
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

// Shutdown disconnects the client.
func (cc *mockControl) Shutdown() {
	cc.logf("Shutdown")
	cc.called("Shutdown")
	close(cc.shutdown)
}

// Login starts a login process. Note that in this mock, we don't automatically
// generate notifications about the progress of the login operation. You have to
// call send() as required by the test.
func (cc *mockControl) Login(flags controlclient.LoginFlags) {
	cc.logf("Login flags=%v", flags)
	cc.called("Login")
	newKeys := cc.populateKeys()

	interact := (flags & controlclient.LoginInteractive) != 0
	cc.logf("Login: interact=%v newKeys=%v", interact, newKeys)
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cc.authBlocked = interact || newKeys
}

func (cc *mockControl) Logout(ctx context.Context) error {
	cc.logf("Logout")
	cc.called("Logout")
	return nil
}

func (cc *mockControl) SetPaused(paused bool) {
	was := cc.paused.Swap(paused)
	if was == paused {
		return
	}
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

func (cc *mockControl) SetTKAHead(head string) {
	cc.logf("SetTKAHead: %s", head)
}

func (cc *mockControl) UpdateEndpoints(endpoints []tailcfg.Endpoint) {
	// validate endpoint information here?
	cc.logf("UpdateEndpoints:  ep=%v", endpoints)
	cc.called("UpdateEndpoints")
}

func (b *LocalBackend) nonInteractiveLoginForStateTest() {
	b.mu.Lock()
	if b.cc == nil {
		panic("LocalBackend.assertClient: b.cc == nil")
	}
	cc := b.cc
	b.mu.Unlock()

	cc.Login(b.loginFlags | controlclient.LoginInteractive)
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
	envknob.Setenv("TAILSCALE_USE_WIP_CODE", "1")
	defer envknob.Setenv("TAILSCALE_USE_WIP_CODE", "")
	c := qt.New(t)

	logf := tstest.WhileTestRunningLogger(t)
	sys := new(tsd.System)
	store := new(testStateStorage)
	sys.Set(store)
	e, err := wgengine.NewFakeUserspaceEngine(logf, sys.Set, sys.HealthTracker(), sys.UserMetricsRegistry())
	if err != nil {
		t.Fatalf("NewFakeUserspaceEngine: %v", err)
	}
	t.Cleanup(e.Close)
	sys.Set(e)

	b, err := NewLocalBackend(logf, logid.PublicID{}, sys, 0)
	if err != nil {
		t.Fatalf("NewLocalBackend: %v", err)
	}
	t.Cleanup(b.Shutdown)
	b.DisablePortMapperForTest()

	var cc, previousCC *mockControl
	b.SetControlClientGetterForTesting(func(opts controlclient.Options) (controlclient.Client, error) {
		previousCC = cc
		cc = newClient(t, opts)

		t.Logf("ccGen: new mockControl.")
		cc.called("New")
		return cc, nil
	})

	notifies := &notifyThrottler{t: t}
	notifies.expect(0)

	b.SetNotifyCallback(func(n ipn.Notify) {
		if n.State != nil ||
			(n.Prefs != nil && n.Prefs.Valid()) ||
			n.BrowseToURL != nil ||
			n.LoginFinished != nil {
			logf("%+v\n\n", n)
			notifies.put(n)
		} else {
			logf("(ignored) %v\n\n", n)
		}
	})

	// Check that it hasn't called us right away.
	// The state machine should be idle until we call Start().
	c.Assert(cc, qt.IsNil)

	// Start the state machine.
	// Since !WantRunning by default, it'll create a controlclient,
	// but not ask it to do anything yet.
	t.Logf("\n\nStart")
	notifies.expect(2)
	c.Assert(b.Start(ipn.Options{}), qt.IsNil)
	{
		// BUG: strictly, it should pause, not unpause, here, since !WantRunning.
		cc.assertCalls("New")

		nn := notifies.drain(2)
		cc.assertCalls()
		c.Assert(nn[0].Prefs, qt.IsNotNil)
		c.Assert(nn[1].State, qt.IsNotNil)
		prefs := nn[0].Prefs
		// Note: a totally fresh system has Prefs.LoggedOut=false by
		// default. We are logged out, but not because the user asked
		// for it, so it doesn't count as Prefs.LoggedOut==true.
		c.Assert(prefs.LoggedOut(), qt.IsTrue)
		c.Assert(prefs.WantRunning(), qt.IsFalse)
		c.Assert(ipn.NeedsLogin, qt.Equals, *nn[1].State)
		c.Assert(ipn.NeedsLogin, qt.Equals, b.State())
	}

	// Restart the state machine.
	// It's designed to handle frontends coming and going sporadically.
	// Make the sure the restart not only works, but generates the same
	// events as the first time, so UIs always know what to expect.
	t.Logf("\n\nStart2")
	notifies.expect(2)
	c.Assert(b.Start(ipn.Options{}), qt.IsNil)
	{
		previousCC.assertShutdown(false)
		cc.assertCalls("New")

		nn := notifies.drain(2)
		cc.assertCalls()
		c.Assert(nn[0].Prefs, qt.IsNotNil)
		c.Assert(nn[1].State, qt.IsNotNil)
		c.Assert(nn[0].Prefs.LoggedOut(), qt.IsTrue)
		c.Assert(nn[0].Prefs.WantRunning(), qt.IsFalse)
		c.Assert(ipn.NeedsLogin, qt.Equals, *nn[1].State)
		c.Assert(ipn.NeedsLogin, qt.Equals, b.State())
	}

	// Start non-interactive login with no token.
	// This will ask controlclient to start its own Login() process,
	// then wait for us to respond.
	t.Logf("\n\nLogin (noninteractive)")
	notifies.expect(0)
	b.nonInteractiveLoginForStateTest()
	{
		cc.assertCalls("Login")
		notifies.drain(0)
		// Note: WantRunning isn't true yet. It'll switch to true
		// after a successful login finishes.
		// (This behaviour is needed so that b.Login() won't
		// start connecting to an old account right away, if one
		// exists when you launch another login.)
		c.Assert(ipn.NeedsLogin, qt.Equals, b.State())
	}

	// Attempted non-interactive login with no key; indicate that
	// the user needs to visit a login URL.
	t.Logf("\n\nLogin (url response)")

	notifies.expect(3)
	b.EditPrefs(&ipn.MaskedPrefs{
		ControlURLSet: true,
		Prefs: ipn.Prefs{
			ControlURL: "https://localhost:1/",
		},
	})
	url1 := "https://localhost:1/1"
	cc.send(nil, url1, false, nil)
	{
		cc.assertCalls()

		// ...but backend eats that notification, because the user
		// didn't explicitly request interactive login yet, and
		// we're already in NeedsLogin state.
		nn := notifies.drain(3)

		c.Assert(nn[1].Prefs, qt.IsNotNil)
		c.Assert(nn[1].Prefs.LoggedOut(), qt.IsTrue)
		c.Assert(nn[1].Prefs.WantRunning(), qt.IsFalse)
		c.Assert(ipn.NeedsLogin, qt.Equals, b.State())
		c.Assert(nn[2].BrowseToURL, qt.IsNotNil)
		c.Assert(url1, qt.Equals, *nn[2].BrowseToURL)
		c.Assert(ipn.NeedsLogin, qt.Equals, b.State())
	}

	// Now we'll try an interactive login.
	// Since we provided an interactive URL earlier, this shouldn't
	// ask control to do anything. Instead backend will emit an event
	// indicating that the UI should browse to the given URL.
	t.Logf("\n\nLogin (interactive)")
	notifies.expect(1)
	b.StartLoginInteractive(context.Background())
	{
		nn := notifies.drain(1)
		cc.assertCalls()
		c.Assert(nn[0].BrowseToURL, qt.IsNotNil)
		c.Assert(url1, qt.Equals, *nn[0].BrowseToURL)
		c.Assert(ipn.NeedsLogin, qt.Equals, b.State())
	}

	// Sometimes users press the Login button again, in the middle of
	// a login sequence. For example, they might have closed their
	// browser window without logging in, or they waited too long and
	// the login URL expired. If they start another interactive login,
	// we must always get a *new* login URL first.
	t.Logf("\n\nLogin2 (interactive)")
	b.authURLTime = time.Now().Add(-time.Hour * 24 * 7) // simulate URL expiration
	notifies.expect(0)
	b.StartLoginInteractive(context.Background())
	{
		notifies.drain(0)
		// backend asks control for another login sequence
		cc.assertCalls("Login")
		c.Assert(ipn.NeedsLogin, qt.Equals, b.State())
	}

	// Provide a new interactive login URL.
	t.Logf("\n\nLogin2 (url response)")
	notifies.expect(1)
	url2 := "https://localhost:1/2"
	cc.send(nil, url2, false, nil)
	{
		cc.assertCalls()

		// This time, backend should emit it to the UI right away,
		// because the UI is anxiously awaiting a new URL to visit.
		nn := notifies.drain(1)
		c.Assert(nn[0].BrowseToURL, qt.IsNotNil)
		c.Assert(url2, qt.Equals, *nn[0].BrowseToURL)
		c.Assert(ipn.NeedsLogin, qt.Equals, b.State())
	}

	// Pretend that the interactive login actually happened.
	// Controlclient always sends the netmap and LoginFinished at the
	// same time.
	// The backend should propagate this upward for the UI.
	t.Logf("\n\nLoginFinished")
	notifies.expect(3)
	cc.persist.UserProfile.LoginName = "user1"
	cc.persist.NodeID = "node1"
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
		cc.assertCalls()
		c.Assert(nn[0].LoginFinished, qt.IsNotNil)
		c.Assert(nn[1].Prefs, qt.IsNotNil)
		c.Assert(nn[2].State, qt.IsNotNil)
		c.Assert(nn[1].Prefs.Persist().UserProfile().LoginName, qt.Equals, "user1")
		c.Assert(ipn.NeedsMachineAuth, qt.Equals, *nn[2].State)
		c.Assert(ipn.NeedsMachineAuth, qt.Equals, b.State())
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
		SelfNode: (&tailcfg.Node{MachineAuthorized: true}).View(),
	})
	{
		nn := notifies.drain(1)
		cc.assertCalls()
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
		cc.assertCalls("Login", "unpause")
		// BUG: I would expect Prefs to change first, and state after.
		c.Assert(nn[0].State, qt.IsNotNil)
		c.Assert(nn[1].Prefs, qt.IsNotNil)
		c.Assert(ipn.Starting, qt.Equals, *nn[0].State)
		c.Assert(store.sawWrite(), qt.IsTrue)
	}

	// undo the state hack above.
	b.state = ipn.Starting

	// User wants to logout.
	store.awaitWrite()
	t.Logf("\n\nLogout")
	notifies.expect(5)
	b.Logout(context.Background())
	{
		nn := notifies.drain(5)
		previousCC.assertCalls("pause", "Logout", "unpause", "Shutdown")
		c.Assert(nn[0].State, qt.IsNotNil)
		c.Assert(*nn[0].State, qt.Equals, ipn.Stopped)

		c.Assert(nn[1].Prefs, qt.IsNotNil)
		c.Assert(nn[1].Prefs.LoggedOut(), qt.IsTrue)
		c.Assert(nn[1].Prefs.WantRunning(), qt.IsFalse)

		cc.assertCalls("New")
		c.Assert(nn[2].State, qt.IsNotNil)
		c.Assert(*nn[2].State, qt.Equals, ipn.NoState)

		c.Assert(nn[3].Prefs, qt.IsNotNil) // emptyPrefs
		c.Assert(nn[3].Prefs.LoggedOut(), qt.IsTrue)
		c.Assert(nn[3].Prefs.WantRunning(), qt.IsFalse)

		c.Assert(nn[4].State, qt.IsNotNil)
		c.Assert(*nn[4].State, qt.Equals, ipn.NeedsLogin)

		c.Assert(b.State(), qt.Equals, ipn.NeedsLogin)

		c.Assert(store.sawWrite(), qt.IsTrue)
	}

	// A second logout should be a no-op as we are in the NeedsLogin state.
	t.Logf("\n\nLogout2")
	notifies.expect(0)
	b.Logout(context.Background())
	{
		notifies.drain(0)
		cc.assertCalls()
		c.Assert(b.Prefs().LoggedOut(), qt.IsTrue)
		c.Assert(b.Prefs().WantRunning(), qt.IsFalse)
		c.Assert(ipn.NeedsLogin, qt.Equals, b.State())
	}

	// A third logout should also be a no-op as the cc should be in
	// AuthCantContinue state.
	t.Logf("\n\nLogout3")
	notifies.expect(3)
	b.Logout(context.Background())
	{
		notifies.drain(0)
		cc.assertCalls()
		c.Assert(b.Prefs().LoggedOut(), qt.IsTrue)
		c.Assert(b.Prefs().WantRunning(), qt.IsFalse)
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
	c.Assert(b.Start(ipn.Options{}), qt.IsNil)
	{
		previousCC.assertShutdown(false)
		// BUG: We already called Shutdown(), no need to do it again.
		// BUG: don't unpause because we're not logged in.
		cc.assertCalls("New")

		nn := notifies.drain(2)
		cc.assertCalls()
		c.Assert(nn[0].Prefs, qt.IsNotNil)
		c.Assert(nn[1].State, qt.IsNotNil)
		c.Assert(nn[0].Prefs.LoggedOut(), qt.IsTrue)
		c.Assert(nn[0].Prefs.WantRunning(), qt.IsFalse)
		c.Assert(ipn.NeedsLogin, qt.Equals, *nn[1].State)
		c.Assert(ipn.NeedsLogin, qt.Equals, b.State())
	}

	// Explicitly set the ControlURL to avoid defaulting to [ipn.DefaultControlURL].
	// This prevents [LocalBackend] from using the production control server during tests
	// and ensures that [LocalBackend.validPopBrowserURL] returns true for the
	// fake interactive login URLs used below. Otherwise, we won't be receiving
	// BrowseToURL notifications as expected.
	// See tailscale/tailscale#11393.
	notifies.expect(1)
	b.EditPrefs(&ipn.MaskedPrefs{
		ControlURLSet: true,
		Prefs: ipn.Prefs{
			ControlURL: "https://localhost:1/",
		},
	})
	notifies.drain(1)

	t.Logf("\n\nStartLoginInteractive3")
	b.StartLoginInteractive(context.Background())
	// We've been logged out, and the previously created profile is now deleted.
	// We're attempting an interactive login for the first time with the new profile,
	// this should result in a call to the control server, which in turn should provide
	// an interactive login URL to visit.
	notifies.expect(2)
	url3 := "https://localhost:1/3"
	cc.send(nil, url3, false, nil)
	{
		nn := notifies.drain(2)
		cc.assertCalls("Login")
		c.Assert(nn[1].BrowseToURL, qt.IsNotNil)
		c.Assert(*nn[1].BrowseToURL, qt.Equals, url3)
	}
	t.Logf("%q visited", url3)
	notifies.expect(3)
	cc.persist.UserProfile.LoginName = "user2"
	cc.persist.NodeID = "node2"
	cc.send(nil, "", true, &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{MachineAuthorized: true}).View(),
	})
	t.Logf("\n\nLoginFinished3")
	{
		nn := notifies.drain(3)
		c.Assert(nn[0].LoginFinished, qt.IsNotNil)
		c.Assert(nn[1].Prefs, qt.IsNotNil)
		c.Assert(nn[1].Prefs.Persist(), qt.IsNotNil)
		// Prefs after finishing the login, so LoginName updated.
		c.Assert(nn[1].Prefs.Persist().UserProfile().LoginName, qt.Equals, "user2")
		c.Assert(nn[1].Prefs.LoggedOut(), qt.IsFalse)
		// If a user initiates an interactive login, they also expect WantRunning to become true.
		c.Assert(nn[1].Prefs.WantRunning(), qt.IsTrue)
		c.Assert(nn[2].State, qt.IsNotNil)
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
		c.Assert(nn[1].Prefs.LoggedOut(), qt.IsFalse)
	}

	// One more restart, this time with a valid key, but WantRunning=false.
	t.Logf("\n\nStart4")
	notifies.expect(2)
	c.Assert(b.Start(ipn.Options{}), qt.IsNil)
	{
		// NOTE: cc.Shutdown() is correct here, since we didn't call
		// b.Shutdown() explicitly ourselves.
		previousCC.assertShutdown(false)

		// Note: unpause happens because ipn needs to get at least one netmap
		//  on startup, otherwise UIs can't show the node list, login
		//  name, etc when in state ipn.Stopped.
		//  Arguably they shouldn't try. But they currently do.
		nn := notifies.drain(2)
		cc.assertCalls("New", "Login")
		c.Assert(nn[0].Prefs, qt.IsNotNil)
		c.Assert(nn[1].State, qt.IsNotNil)
		c.Assert(nn[0].Prefs.WantRunning(), qt.IsFalse)
		c.Assert(nn[0].Prefs.LoggedOut(), qt.IsFalse)
		c.Assert(*nn[1].State, qt.Equals, ipn.Stopped)
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
		SelfNode: (&tailcfg.Node{MachineAuthorized: true}).View(),
	})
	{
		notifies.drain(0)
		cc.assertCalls("pause")
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
		cc.assertCalls("Login", "unpause")
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
	b.StartLoginInteractive(context.Background())
	url4 := "https://localhost:1/4"
	cc.send(nil, url4, false, nil)
	{
		nn := notifies.drain(1)
		// It might seem like WantRunning should switch to true here,
		// but that would be risky since we already have a valid
		// user account. It might try to reconnect to the old account
		// before the new one is ready. So no change yet.
		//
		// Because the login hasn't yet completed, the old login
		// is still valid, so it's correct that we stay paused.
		cc.assertCalls("Login")
		c.Assert(nn[0].BrowseToURL, qt.IsNotNil)
		c.Assert(*nn[0].BrowseToURL, qt.Equals, url4)
	}

	// Now, let's complete the interactive login, using a different
	// user account than before. WantRunning changes to true after an
	// interactive login, so we end up unpaused.
	t.Logf("\n\nLoginDifferent URL visited")
	notifies.expect(3)
	cc.persist.UserProfile.LoginName = "user3"
	cc.persist.NodeID = "node3"
	cc.send(nil, "", true, &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{MachineAuthorized: true}).View(),
	})
	{
		nn := notifies.drain(3)
		// BUG: pause() being called here is a bad sign.
		//  It means that either the state machine ran at least once
		//  with the old netmap, or it ran with the new login+netmap
		//  and !WantRunning. But since it's a fresh and successful
		//  new login, WantRunning is true, so there was never a
		//  reason to pause().
		cc.assertCalls("unpause")
		c.Assert(nn[0].LoginFinished, qt.IsNotNil)
		c.Assert(nn[1].Prefs, qt.IsNotNil)
		c.Assert(nn[2].State, qt.IsNotNil)
		// Prefs after finishing the login, so LoginName updated.
		c.Assert(nn[1].Prefs.Persist().UserProfile().LoginName, qt.Equals, "user3")
		c.Assert(nn[1].Prefs.LoggedOut(), qt.IsFalse)
		c.Assert(nn[1].Prefs.WantRunning(), qt.IsTrue)
		c.Assert(ipn.Starting, qt.Equals, *nn[2].State)
	}

	// The last test case is the most common one: restarting when both
	// logged in and WantRunning.
	t.Logf("\n\nStart5")
	notifies.expect(1)
	c.Assert(b.Start(ipn.Options{}), qt.IsNil)
	{
		// NOTE: cc.Shutdown() is correct here, since we didn't call
		// b.Shutdown() ourselves.
		previousCC.assertShutdown(false)
		cc.assertCalls("New", "Login")

		nn := notifies.drain(1)
		cc.assertCalls()
		c.Assert(nn[0].Prefs, qt.IsNotNil)
		c.Assert(nn[0].Prefs.LoggedOut(), qt.IsFalse)
		c.Assert(nn[0].Prefs.WantRunning(), qt.IsTrue)
		c.Assert(b.State(), qt.Equals, ipn.NoState)
	}

	// Control server accepts our valid key from before.
	t.Logf("\n\nLoginFinished5")
	notifies.expect(1)
	cc.send(nil, "", true, &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{MachineAuthorized: true}).View(),
	})
	{
		nn := notifies.drain(1)
		cc.assertCalls()
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
		Expiry:   time.Now().Add(-time.Minute),
		SelfNode: (&tailcfg.Node{MachineAuthorized: true}).View(),
	})
	{
		nn := notifies.drain(1)
		cc.assertCalls()
		c.Assert(nn[0].State, qt.IsNotNil)
		c.Assert(ipn.NeedsLogin, qt.Equals, *nn[0].State)
		c.Assert(ipn.NeedsLogin, qt.Equals, b.State())
		c.Assert(b.isEngineBlocked(), qt.IsTrue)
	}

	t.Logf("\n\nExtendKey")
	notifies.expect(1)
	cc.send(nil, "", false, &netmap.NetworkMap{
		Expiry:   time.Now().Add(time.Minute),
		SelfNode: (&tailcfg.Node{MachineAuthorized: true}).View(),
	})
	{
		nn := notifies.drain(1)
		cc.assertCalls()
		c.Assert(nn[0].State, qt.IsNotNil)
		c.Assert(ipn.Starting, qt.Equals, *nn[0].State)
		c.Assert(ipn.Starting, qt.Equals, b.State())
		c.Assert(b.isEngineBlocked(), qt.IsFalse)
	}
	notifies.expect(1)
	// Fake a DERP connection.
	b.setWgengineStatus(&wgengine.Status{DERPs: 1, AsOf: time.Now()}, nil)
	{
		nn := notifies.drain(1)
		cc.assertCalls()
		c.Assert(nn[0].State, qt.IsNotNil)
		c.Assert(ipn.Running, qt.Equals, *nn[0].State)
		c.Assert(ipn.Running, qt.Equals, b.State())
	}
}

func TestEditPrefsHasNoKeys(t *testing.T) {
	logf := tstest.WhileTestRunningLogger(t)
	sys := new(tsd.System)
	sys.Set(new(mem.Store))
	e, err := wgengine.NewFakeUserspaceEngine(logf, sys.Set, sys.HealthTracker(), sys.UserMetricsRegistry())
	if err != nil {
		t.Fatalf("NewFakeUserspaceEngine: %v", err)
	}
	t.Cleanup(e.Close)
	sys.Set(e)

	b, err := NewLocalBackend(logf, logid.PublicID{}, sys, 0)
	if err != nil {
		t.Fatalf("NewLocalBackend: %v", err)
	}
	t.Cleanup(b.Shutdown)
	b.hostinfo = &tailcfg.Hostinfo{OS: "testos"}
	b.pm.SetPrefs((&ipn.Prefs{
		Persist: &persist.Persist{
			PrivateNodeKey:    key.NewNode(),
			OldPrivateNodeKey: key.NewNode(),

			LegacyFrontendPrivateMachineKey: key.NewMachine(),
		},
	}).View(), ipn.NetworkProfile{})
	if p := b.pm.CurrentPrefs().Persist(); !p.Valid() || p.PrivateNodeKey().IsZero() {
		t.Fatalf("PrivateNodeKey not set")
	}
	p, err := b.EditPrefs(&ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			Hostname: "foo",
		},
		HostnameSet: true,
	})
	if err != nil {
		t.Fatalf("EditPrefs: %v", err)
	}
	if p.Hostname() != "foo" {
		t.Errorf("Hostname = %q; want foo", p.Hostname())
	}

	if !p.Persist().PrivateNodeKey().IsZero() {
		t.Errorf("PrivateNodeKey = %v; want zero", p.Persist().PrivateNodeKey())
	}

	if !p.Persist().OldPrivateNodeKey().IsZero() {
		t.Errorf("OldPrivateNodeKey = %v; want zero", p.Persist().OldPrivateNodeKey())
	}

	if !p.Persist().LegacyFrontendPrivateMachineKey().IsZero() {
		t.Errorf("LegacyFrontendPrivateMachineKey = %v; want zero", p.Persist().LegacyFrontendPrivateMachineKey())
	}

	if !p.Persist().NetworkLockKey().IsZero() {
		t.Errorf("NetworkLockKey= %v; want zero", p.Persist().NetworkLockKey())
	}
}

type testStateStorage struct {
	mem     mem.Store
	written atomic.Bool
}

func (s *testStateStorage) ReadState(id ipn.StateKey) ([]byte, error) {
	return s.mem.ReadState(id)
}

func (s *testStateStorage) WriteState(id ipn.StateKey, bs []byte) error {
	s.written.Store(true)
	return s.mem.WriteState(id, bs)
}

// awaitWrite clears the "I've seen writes" bit, in prep for a future
// call to sawWrite to see if a write arrived.
func (s *testStateStorage) awaitWrite() { s.written.Store(false) }

// sawWrite reports whether there's been a WriteState call since the most
// recent awaitWrite call.
func (s *testStateStorage) sawWrite() bool {
	v := s.written.Load()
	s.awaitWrite()
	return v
}

func TestWGEngineStatusRace(t *testing.T) {
	t.Skip("test fails")
	c := qt.New(t)
	logf := tstest.WhileTestRunningLogger(t)
	sys := new(tsd.System)
	sys.Set(new(mem.Store))

	eng, err := wgengine.NewFakeUserspaceEngine(logf, sys.Set)
	c.Assert(err, qt.IsNil)
	t.Cleanup(eng.Close)
	sys.Set(eng)
	b, err := NewLocalBackend(logf, logid.PublicID{}, sys, 0)
	c.Assert(err, qt.IsNil)
	t.Cleanup(b.Shutdown)

	var cc *mockControl
	b.SetControlClientGetterForTesting(func(opts controlclient.Options) (controlclient.Client, error) {
		cc = newClient(t, opts)
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
	err = b.Start(ipn.Options{})
	c.Assert(err, qt.IsNil)
	wantState(ipn.NeedsLogin)

	// Assert that we are logged in and authorized.
	cc.send(nil, "", true, &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{MachineAuthorized: true}).View(),
	})
	wantState(ipn.Starting)

	// Simulate multiple concurrent callbacks from wgengine.
	// Any single callback with DERPS > 0 is enough to transition
	// from Starting to Running, at which point we stay there.
	// Thus if these callbacks occurred serially, in any order,
	// we would end up in state ipn.Running.
	// The same should thus be true if these callbacks occur concurrently.
	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			n := 0
			if i == 0 {
				n = 1
			}
			b.setWgengineStatus(&wgengine.Status{AsOf: time.Now(), DERPs: n}, nil)
		}(i)
	}
	wg.Wait()
	wantState(ipn.Running)
}
