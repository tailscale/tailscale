// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"tailscale.com/control/controlclient"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnauth"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/dns"
	"tailscale.com/net/netmon"
	"tailscale.com/net/packet"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/tstest"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/types/netmap"
	"tailscale.com/types/persist"
	"tailscale.com/types/preftype"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/mak"
	"tailscale.com/util/must"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
	"tailscale.com/wgengine/wgint"
)

// notifyThrottler receives notifications from an ipn.Backend, blocking
// (with eventual timeout and t.Fatal) if there are too many and complaining
// (also with t.Fatal) if they are too few.
type notifyThrottler struct {
	t *testing.T

	// ch gets replaced frequently. Lock the mutex before getting or
	// setting it, but not while waiting on it.
	mu     sync.Mutex
	ch     chan ipn.Notify
	putErr error // set by put if the channel is full
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
		err := fmt.Errorf("put: channel full: %v", n)
		nt.t.Log(err)
		nt.mu.Lock()
		nt.putErr = err
		nt.mu.Unlock()
	}
}

// drain pulls the notifications out of the queue, asserting that there are
// exactly count notifications that have been put so far.
func (nt *notifyThrottler) drain(count int) []ipn.Notify {
	nt.t.Helper()
	nt.mu.Lock()
	ch := nt.ch
	putErr := nt.putErr
	nt.mu.Unlock()

	if putErr != nil {
		nt.t.Fatalf("drain: previous call to put errored: %s", putErr)
	}

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
	tb              testing.TB
	logf            logger.Logf
	opts            controlclient.Options
	paused          atomic.Bool
	controlClientID int64

	mu          sync.Mutex
	persist     *persist.Persist
	calls       []string
	authBlocked bool
	shutdown    chan struct{}
}

func newClient(tb testing.TB, opts controlclient.Options) *mockControl {
	return &mockControl{
		tb:              tb,
		authBlocked:     true,
		logf:            opts.Logf,
		opts:            opts,
		shutdown:        make(chan struct{}),
		persist:         opts.Persist.Clone(),
		controlClientID: rand.Int64(),
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

type sendOpt struct {
	err           error
	url           string
	loginFinished bool
	nm            *netmap.NetworkMap
}

// send publishes a controlclient.Status notification upstream.
// (In our tests here, upstream is the ipnlocal.Local instance.)
func (cc *mockControl) send(opts sendOpt) {
	err, url, loginFinished, nm := opts.err, opts.url, opts.loginFinished, opts.nm
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
			s.LoggedIn = true
		}
		cc.opts.Observer.SetControlClientStatus(cc, s)
	}
}

func (cc *mockControl) authenticated(nm *netmap.NetworkMap) {
	if selfUser, ok := nm.UserProfiles[nm.SelfNode.User()]; ok {
		cc.persist.UserProfile = *selfUser.AsStruct()
	}
	cc.persist.NodeID = nm.SelfNode.StableID()
	cc.send(sendOpt{loginFinished: true, nm: nm})
}

func (cc *mockControl) sendAuthURL(nm *netmap.NetworkMap) {
	s := controlclient.Status{
		URL:     "https://example.com/a/foo",
		NetMap:  nm,
		Persist: cc.persist.View(),
	}
	cc.opts.Observer.SetControlClientStatus(cc, s)
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

func (cc *mockControl) SetDiscoPublicKey(key key.DiscoPublic) {
	cc.logf("SetDiscoPublicKey: %v", key)
	cc.called("SetDiscoPublicKey")
}

func (cc *mockControl) ClientID() int64 {
	return cc.controlClientID
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
	runTestStateMachine(t, false)
}

func TestStateMachineSeamless(t *testing.T) {
	runTestStateMachine(t, true)
}

func runTestStateMachine(t *testing.T, seamless bool) {
	envknob.Setenv("TAILSCALE_USE_WIP_CODE", "1")
	defer envknob.Setenv("TAILSCALE_USE_WIP_CODE", "")
	c := qt.New(t)

	logf := tstest.WhileTestRunningLogger(t)
	sys := tsd.NewSystem()
	store := new(testStateStorage)
	sys.Set(store)
	e, err := wgengine.NewFakeUserspaceEngine(logf, sys.Set, sys.HealthTracker.Get(), sys.UserMetricsRegistry(), sys.Bus.Get())
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
		// Verify notification indicates we need login (prefs show logged out)
		c.Assert(nn[1].Prefs == nil || nn[1].Prefs.LoggedOut(), qt.IsTrue)
		// Verify the actual facts about our state
		c.Assert(needsLogin(b), qt.IsTrue)
		c.Assert(hasValidNetMap(b), qt.IsFalse)
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
		// Verify notification indicates we need login
		c.Assert(nn[1].Prefs == nil || nn[1].Prefs.LoggedOut(), qt.IsTrue)
		// Verify the actual facts about our state
		c.Assert(needsLogin(b), qt.IsTrue)
		c.Assert(hasValidNetMap(b), qt.IsFalse)
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
		// Verify we still need login
		c.Assert(needsLogin(b), qt.IsTrue)
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
	cc.send(sendOpt{url: url1})
	{
		cc.assertCalls()

		// ...but backend eats that notification, because the user
		// didn't explicitly request interactive login yet, and
		// we're already in NeedsLogin state.
		nn := notifies.drain(3)

		c.Assert(nn[1].Prefs, qt.IsNotNil)
		c.Assert(nn[1].Prefs.LoggedOut(), qt.IsTrue)
		c.Assert(nn[1].Prefs.WantRunning(), qt.IsFalse)
		// Verify we need URL visit
		c.Assert(hasAuthURL(b), qt.IsTrue)
		c.Assert(nn[2].BrowseToURL, qt.IsNotNil)
		c.Assert(url1, qt.Equals, *nn[2].BrowseToURL)
		c.Assert(isFullyAuthenticated(b), qt.IsFalse)
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
		// Verify we still need to complete login
		c.Assert(needsLogin(b), qt.IsTrue)
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
		// Verify we still need login
		c.Assert(needsLogin(b), qt.IsTrue)
	}

	// Provide a new interactive login URL.
	t.Logf("\n\nLogin2 (url response)")
	notifies.expect(1)
	url2 := "https://localhost:1/2"
	cc.send(sendOpt{url: url2})
	{
		cc.assertCalls()

		// This time, backend should emit it to the UI right away,
		// because the UI is anxiously awaiting a new URL to visit.
		nn := notifies.drain(1)
		c.Assert(nn[0].BrowseToURL, qt.IsNotNil)
		c.Assert(url2, qt.Equals, *nn[0].BrowseToURL)
		// Verify we still need to complete login
		c.Assert(needsLogin(b), qt.IsTrue)
	}

	// Pretend that the interactive login actually happened.
	// Controlclient always sends the netmap and LoginFinished at the
	// same time.
	// The backend should propagate this upward for the UI.
	t.Logf("\n\nLoginFinished")
	notifies.expect(3)
	cc.persist.UserProfile.LoginName = "user1"
	cc.persist.NodeID = "node1"

	// even if seamless is being enabled by default rather than by policy, this is
	// the point where it will first get enabled.
	if seamless {
		sys.ControlKnobs().SeamlessKeyRenewal.Store(true)
	}

	cc.send(sendOpt{loginFinished: true, nm: &netmap.NetworkMap{}})
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
		c.Assert(nn[1].Prefs.Persist().UserProfile().LoginName, qt.Equals, "user1")
		// nn[2] is a state notification after login
		// Verify login finished but need machine auth using backend state
		c.Assert(isFullyAuthenticated(b), qt.IsTrue)
		c.Assert(needsMachineAuth(b), qt.IsTrue)
		nm := b.NetMap()
		c.Assert(nm, qt.IsNotNil)
		// For an empty netmap (after initial login), SelfNode may not be valid yet.
		// In this case, we can't check MachineAuthorized, but needsMachineAuth already verified the state.
		if nm.SelfNode.Valid() {
			c.Assert(nm.SelfNode.MachineAuthorized(), qt.IsFalse)
		}
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
	cc.send(sendOpt{nm: &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{MachineAuthorized: true}).View(),
	}})
	{
		nn := notifies.drain(1)
		cc.assertCalls()
		// nn[0] is a state notification after machine auth granted
		c.Assert(len(nn), qt.Equals, 1)
		// Verify machine authorized using backend state
		nm := b.NetMap()
		c.Assert(nm, qt.IsNotNil)
		c.Assert(nm.SelfNode.Valid(), qt.IsTrue)
		c.Assert(nm.SelfNode.MachineAuthorized(), qt.IsTrue)
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
		// nn[0] is state notification, nn[1] is prefs notification
		c.Assert(nn[1].Prefs, qt.IsNotNil)
		c.Assert(nn[1].Prefs.WantRunning(), qt.IsFalse)
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
		// nn[0] is state notification, nn[1] is prefs notification
		c.Assert(nn[1].Prefs, qt.IsNotNil)
		c.Assert(nn[1].Prefs.WantRunning(), qt.IsTrue)
		c.Assert(store.sawWrite(), qt.IsTrue)
	}

	// User wants to logout.
	store.awaitWrite()
	t.Logf("\n\nLogout")
	notifies.expect(5)
	b.Logout(context.Background(), ipnauth.Self)
	{
		nn := notifies.drain(5)
		previousCC.assertCalls("pause", "Logout", "unpause", "Shutdown")
		// nn[0] is state notification (Stopped)
		c.Assert(nn[0].State, qt.IsNotNil)
		c.Assert(*nn[0].State, qt.Equals, ipn.Stopped)
		// nn[1] is prefs notification after logout
		c.Assert(nn[1].Prefs, qt.IsNotNil)
		c.Assert(nn[1].Prefs.LoggedOut(), qt.IsTrue)
		c.Assert(nn[1].Prefs.WantRunning(), qt.IsFalse)

		cc.assertCalls("New")
		// nn[2] is the initial state notification after New (NoState)
		// nn[3] is prefs notification with emptyPrefs
		c.Assert(nn[3].Prefs, qt.IsNotNil)
		c.Assert(nn[3].Prefs.LoggedOut(), qt.IsTrue)
		c.Assert(nn[3].Prefs.WantRunning(), qt.IsFalse)

		c.Assert(store.sawWrite(), qt.IsTrue)
		// nn[4] is state notification (NeedsLogin)
		// Verify logged out and needs new login using backend state
		c.Assert(needsLogin(b), qt.IsTrue)
		c.Assert(hasValidNetMap(b), qt.IsFalse)
	}

	// A second logout should be a no-op as we are in the NeedsLogin state.
	t.Logf("\n\nLogout2")
	notifies.expect(0)
	b.Logout(context.Background(), ipnauth.Self)
	{
		notifies.drain(0)
		cc.assertCalls()
		c.Assert(b.Prefs().LoggedOut(), qt.IsTrue)
		c.Assert(b.Prefs().WantRunning(), qt.IsFalse)
		// Verify still needs login
		c.Assert(needsLogin(b), qt.IsTrue)
	}

	// A third logout should also be a no-op as the cc should be in
	// AuthCantContinue state.
	t.Logf("\n\nLogout3")
	notifies.expect(3)
	b.Logout(context.Background(), ipnauth.Self)
	{
		notifies.drain(0)
		cc.assertCalls()
		c.Assert(b.Prefs().LoggedOut(), qt.IsTrue)
		c.Assert(b.Prefs().WantRunning(), qt.IsFalse)
		// Verify still needs login
		c.Assert(needsLogin(b), qt.IsTrue)
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
		c.Assert(nn[0].Prefs.LoggedOut(), qt.IsTrue)
		c.Assert(nn[0].Prefs.WantRunning(), qt.IsFalse)
		// Verify notification indicates we need login
		c.Assert(nn[1].Prefs == nil || nn[1].Prefs.LoggedOut(), qt.IsTrue)
		// Verify we need login after restart
		c.Assert(needsLogin(b), qt.IsTrue)
		c.Assert(hasValidNetMap(b), qt.IsFalse)
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
	cc.send(sendOpt{url: url3})
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
	cc.send(sendOpt{loginFinished: true, nm: &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{MachineAuthorized: true}).View(),
	}})
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
		// nn[2] is state notification (Starting) - verify using backend state
		c.Assert(isWantRunning(b), qt.IsTrue)
		c.Assert(isLoggedIn(b), qt.IsTrue)
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
		// nn[0] is state notification (Stopped), nn[1] is prefs notification
		c.Assert(nn[1].Prefs, qt.IsNotNil)
		c.Assert(nn[1].Prefs.WantRunning(), qt.IsFalse)
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

		nn := notifies.drain(2)
		// We already have a netmap for this node,
		// and WantRunning is false, so cc should be paused.
		cc.assertCalls("New", "Login", "pause")
		c.Assert(nn[0].Prefs, qt.IsNotNil)
		c.Assert(nn[0].Prefs.WantRunning(), qt.IsFalse)
		c.Assert(nn[0].Prefs.LoggedOut(), qt.IsFalse)
		// nn[1] is state notification (Stopped)
		// Verify backend shows we're not wanting to run
		c.Assert(isWantRunning(b), qt.IsFalse)
	}

	// When logged in but !WantRunning, ipn leaves us unpaused to retrieve
	// the first netmap. Simulate that netmap being received, after which
	// it should pause us, to avoid wasting CPU retrieving unnecessarily
	// additional netmap updates. Since our LocalBackend instance already
	// has a netmap, we will reset it to nil to simulate the first netmap
	// retrieval.
	b.setNetMapLocked(nil)
	cc.assertCalls("unpause")
	//
	// TODO: really the various GUIs and prefs should be refactored to
	//  not require the netmap structure at all when starting while
	//  !WantRunning. That would remove the need for this (or contacting
	//  the control server at all when stopped).
	t.Logf("\n\nStart4 -> netmap")
	notifies.expect(0)
	cc.send(sendOpt{loginFinished: true, nm: &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{MachineAuthorized: true}).View(),
	}})
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
		// nn[0] is state notification (Starting), nn[1] is prefs notification
		c.Assert(nn[1].Prefs, qt.IsNotNil)
		c.Assert(nn[1].Prefs.WantRunning(), qt.IsTrue)
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
		// nn[0] is state notification (Stopped), nn[1] is prefs notification
		c.Assert(nn[1].Prefs, qt.IsNotNil)
		c.Assert(nn[1].Prefs.WantRunning(), qt.IsFalse)
	}

	// We want to try logging in as a different user, while Stopped.
	// First, start the login process (without logging out first).
	t.Logf("\n\nLoginDifferent")
	notifies.expect(1)
	b.StartLoginInteractive(context.Background())
	url4 := "https://localhost:1/4"
	cc.send(sendOpt{url: url4})
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
	cc.send(sendOpt{loginFinished: true, nm: &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{MachineAuthorized: true}).View(),
	}})
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
		// Prefs after finishing the login, so LoginName updated.
		c.Assert(nn[1].Prefs.Persist().UserProfile().LoginName, qt.Equals, "user3")
		c.Assert(nn[1].Prefs.LoggedOut(), qt.IsFalse)
		c.Assert(nn[1].Prefs.WantRunning(), qt.IsTrue)
		// nn[2] is state notification (Starting) - verify using backend state
		c.Assert(isWantRunning(b), qt.IsTrue)
		c.Assert(isLoggedIn(b), qt.IsTrue)
	}

	// The last test case is the most common one: restarting when both
	// logged in and WantRunning.
	t.Logf("\n\nStart5")
	notifies.expect(2)
	c.Assert(b.Start(ipn.Options{}), qt.IsNil)
	{
		// NOTE: cc.Shutdown() is correct here, since we didn't call
		// b.Shutdown() ourselves.
		previousCC.assertShutdown(false)
		cc.assertCalls("New", "Login")

		nn := notifies.drain(2)
		cc.assertCalls()
		c.Assert(nn[0].Prefs, qt.IsNotNil)
		c.Assert(nn[0].Prefs.LoggedOut(), qt.IsFalse)
		c.Assert(nn[0].Prefs.WantRunning(), qt.IsTrue)
		// nn[1] is state notification (Starting)
		// Verify we're authenticated with valid netmap using backend state
		c.Assert(isFullyAuthenticated(b), qt.IsTrue)
		c.Assert(hasValidNetMap(b), qt.IsTrue)
	}

	// Control server accepts our valid key from before.
	t.Logf("\n\nLoginFinished5")
	notifies.expect(0)
	cc.send(sendOpt{loginFinished: true, nm: &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{MachineAuthorized: true}).View(),
	}})
	{
		notifies.drain(0)
		cc.assertCalls()
		// NOTE: No LoginFinished message since no interactive
		// login was needed.
		// NOTE: No prefs change this time. WantRunning stays true.
		// We were in Starting in the first place, so that doesn't
		// change either, so we don't expect any notifications.
		// Verify we're still authenticated with valid netmap
		c.Assert(isFullyAuthenticated(b), qt.IsTrue)
		c.Assert(hasValidNetMap(b), qt.IsTrue)
	}
	t.Logf("\n\nExpireKey")
	notifies.expect(1)
	cc.send(sendOpt{nm: &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{
			KeyExpiry:         time.Now().Add(-time.Minute),
			MachineAuthorized: true,
		}).View(),
	}})
	{
		nn := notifies.drain(1)
		cc.assertCalls()
		// nn[0] is state notification (NeedsLogin) due to key expiry
		c.Assert(len(nn), qt.Equals, 1)
		// Verify key expired, need new login using backend state
		c.Assert(needsLogin(b), qt.IsTrue)
		c.Assert(b.isEngineBlocked(), qt.IsTrue)
	}

	t.Logf("\n\nExtendKey")
	notifies.expect(1)
	cc.send(sendOpt{nm: &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{
			MachineAuthorized: true,
			KeyExpiry:         time.Now().Add(time.Minute),
		}).View(),
	}})
	{
		nn := notifies.drain(1)
		cc.assertCalls()
		// nn[0] is state notification (Starting) after key extension
		c.Assert(len(nn), qt.Equals, 1)
		// Verify key extended, authenticated again using backend state
		c.Assert(isFullyAuthenticated(b), qt.IsTrue)
		c.Assert(hasValidNetMap(b), qt.IsTrue)
		c.Assert(b.isEngineBlocked(), qt.IsFalse)
	}
	notifies.expect(1)
	// Fake a DERP connection.
	b.setWgengineStatus(&wgengine.Status{DERPs: 1, AsOf: time.Now()}, nil)
	{
		nn := notifies.drain(1)
		cc.assertCalls()
		// nn[0] is state notification (Running) after DERP connection
		c.Assert(len(nn), qt.Equals, 1)
		// Verify we can route traffic using backend state
		c.Assert(canRouteTraffic(b), qt.IsTrue)
	}
}

func TestEditPrefsHasNoKeys(t *testing.T) {
	logf := tstest.WhileTestRunningLogger(t)
	sys := tsd.NewSystem()
	sys.Set(new(mem.Store))
	e, err := wgengine.NewFakeUserspaceEngine(logf, sys.Set, sys.HealthTracker.Get(), sys.UserMetricsRegistry(), sys.Bus.Get())
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

	if !p.Persist().NetworkLockKey().IsZero() {
		t.Errorf("NetworkLockKey= %v; want zero", p.Persist().NetworkLockKey())
	}
}

type testStateStorage struct {
	mem.Store
	written atomic.Bool
}

func (s *testStateStorage) WriteState(id ipn.StateKey, bs []byte) error {
	s.written.Store(true)
	return s.Store.WriteState(id, bs)
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
	sys := tsd.NewSystem()
	sys.Set(new(mem.Store))

	eng, err := wgengine.NewFakeUserspaceEngine(logf, sys.Set, sys.Bus.Get())
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
	cc.send(sendOpt{loginFinished: true, nm: &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{MachineAuthorized: true}).View(),
	}})
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

// TestEngineReconfigOnStateChange verifies that wgengine is properly reconfigured
// when the LocalBackend's state changes, such as when the user logs in, switches
// profiles, or disconnects from Tailscale.
func TestEngineReconfigOnStateChange(t *testing.T) {
	enableLogging := false
	connect := &ipn.MaskedPrefs{Prefs: ipn.Prefs{WantRunning: true}, WantRunningSet: true}
	disconnect := &ipn.MaskedPrefs{Prefs: ipn.Prefs{WantRunning: false}, WantRunningSet: true}
	node1 := buildNetmapWithPeers(
		makePeer(1, withName("node-1"), withAddresses(netip.MustParsePrefix("100.64.1.1/32"))),
	)
	node2 := buildNetmapWithPeers(
		makePeer(2, withName("node-2"), withAddresses(netip.MustParsePrefix("100.64.1.2/32"))),
	)
	node3 := buildNetmapWithPeers(
		makePeer(3, withName("node-3"), withAddresses(netip.MustParsePrefix("100.64.1.3/32"))),
		node1.SelfNode,
		node2.SelfNode,
	)
	routesWithQuad100 := func(extra ...netip.Prefix) []netip.Prefix {
		return append(extra, netip.MustParsePrefix("100.100.100.100/32"))
	}
	hostsFor := func(nm *netmap.NetworkMap) map[dnsname.FQDN][]netip.Addr {
		var hosts map[dnsname.FQDN][]netip.Addr
		appendNode := func(n tailcfg.NodeView) {
			addrs := make([]netip.Addr, 0, n.Addresses().Len())
			for _, addr := range n.Addresses().All() {
				addrs = append(addrs, addr.Addr())
			}
			mak.Set(&hosts, must.Get(dnsname.ToFQDN(n.Name())), addrs)
		}
		if nm != nil && nm.SelfNode.Valid() {
			appendNode(nm.SelfNode)
		}
		for _, n := range nm.Peers {
			appendNode(n)
		}
		return hosts
	}

	tests := []struct {
		name          string
		steps         func(*testing.T, *LocalBackend, func() *mockControl)
		wantState     ipn.State
		wantCfg       *wgcfg.Config
		wantRouterCfg *router.Config
		wantDNSCfg    *dns.Config
	}{
		{
			name: "Initial",
			// The configs are nil until the the LocalBackend is started.
			wantState:     ipn.NoState,
			wantCfg:       nil,
			wantRouterCfg: nil,
			wantDNSCfg:    nil,
		},
		{
			name: "Start",
			steps: func(t *testing.T, lb *LocalBackend, _ func() *mockControl) {
				mustDo(t)(lb.Start(ipn.Options{}))
			},
			// Once started, all configs must be reset and have their zero values.
			wantState:     ipn.NeedsLogin,
			wantCfg:       &wgcfg.Config{},
			wantRouterCfg: &router.Config{},
			wantDNSCfg:    &dns.Config{},
		},
		{
			name: "Start/Connect",
			steps: func(t *testing.T, lb *LocalBackend, _ func() *mockControl) {
				mustDo(t)(lb.Start(ipn.Options{}))
				mustDo2(t)(lb.EditPrefs(connect))
			},
			// Same if WantRunning is true, but the auth is not completed yet.
			wantState:     ipn.NeedsLogin,
			wantCfg:       &wgcfg.Config{},
			wantRouterCfg: &router.Config{},
			wantDNSCfg:    &dns.Config{},
		},
		{
			name: "Start/Connect/Login",
			steps: func(t *testing.T, lb *LocalBackend, cc func() *mockControl) {
				mustDo(t)(lb.Start(ipn.Options{}))
				mustDo2(t)(lb.EditPrefs(connect))
				cc().authenticated(node1)
			},
			// After the auth is completed, the configs must be updated to reflect the node's netmap.
			wantState: ipn.Starting,
			wantCfg: &wgcfg.Config{
				Peers:     []wgcfg.Peer{},
				Addresses: node1.SelfNode.Addresses().AsSlice(),
			},
			wantRouterCfg: &router.Config{
				SNATSubnetRoutes: true,
				NetfilterMode:    preftype.NetfilterOn,
				LocalAddrs:       node1.SelfNode.Addresses().AsSlice(),
				Routes:           routesWithQuad100(),
			},
			wantDNSCfg: &dns.Config{
				Routes: map[dnsname.FQDN][]*dnstype.Resolver{},
				Hosts:  hostsFor(node1),
			},
		},
		{
			name: "Start/Connect/Login/Disconnect",
			steps: func(t *testing.T, lb *LocalBackend, cc func() *mockControl) {
				mustDo(t)(lb.Start(ipn.Options{}))
				mustDo2(t)(lb.EditPrefs(connect))
				cc().authenticated(node1)
				mustDo2(t)(lb.EditPrefs(disconnect))
			},
			// After disconnecting, all configs must be reset and have their zero values.
			wantState:     ipn.Stopped,
			wantCfg:       &wgcfg.Config{},
			wantRouterCfg: &router.Config{},
			wantDNSCfg:    &dns.Config{},
		},
		{
			name: "Start/Connect/Login/NewProfile",
			steps: func(t *testing.T, lb *LocalBackend, cc func() *mockControl) {
				mustDo(t)(lb.Start(ipn.Options{}))
				mustDo2(t)(lb.EditPrefs(connect))
				cc().authenticated(node1)
				mustDo(t)(lb.NewProfile())
			},
			// After switching to a new, empty profile, all configs should be reset
			// and have their zero values until the auth is completed.
			wantState:     ipn.NeedsLogin,
			wantCfg:       &wgcfg.Config{},
			wantRouterCfg: &router.Config{},
			wantDNSCfg:    &dns.Config{},
		},
		{
			name: "Start/Connect/Login/NewProfile/Login",
			steps: func(t *testing.T, lb *LocalBackend, cc func() *mockControl) {
				mustDo(t)(lb.Start(ipn.Options{}))
				mustDo2(t)(lb.EditPrefs(connect))
				cc().authenticated(node1)
				mustDo(t)(lb.NewProfile())
				mustDo2(t)(lb.EditPrefs(connect))
				cc().authenticated(node2)
			},
			// Once the auth is completed, the configs must be updated to reflect the node's netmap.
			wantState: ipn.Starting,
			wantCfg: &wgcfg.Config{
				Peers:     []wgcfg.Peer{},
				Addresses: node2.SelfNode.Addresses().AsSlice(),
			},
			wantRouterCfg: &router.Config{
				SNATSubnetRoutes: true,
				NetfilterMode:    preftype.NetfilterOn,
				LocalAddrs:       node2.SelfNode.Addresses().AsSlice(),
				Routes:           routesWithQuad100(),
			},
			wantDNSCfg: &dns.Config{
				Routes: map[dnsname.FQDN][]*dnstype.Resolver{},
				Hosts:  hostsFor(node2),
			},
		},
		{
			name: "Start/Connect/Login/SwitchProfile",
			steps: func(t *testing.T, lb *LocalBackend, cc func() *mockControl) {
				mustDo(t)(lb.Start(ipn.Options{}))
				mustDo2(t)(lb.EditPrefs(connect))
				cc().authenticated(node1)
				profileID := lb.CurrentProfile().ID()
				mustDo(t)(lb.NewProfile())
				cc().authenticated(node2)
				mustDo(t)(lb.SwitchProfile(profileID))
			},
			// After switching to an existing profile, all configs must be reset
			// and have their zero values until the (non-interactive) login is completed.
			wantState:     ipn.NoState,
			wantCfg:       &wgcfg.Config{},
			wantRouterCfg: &router.Config{},
			wantDNSCfg:    &dns.Config{},
		},
		{
			name: "Start/Connect/Login/SwitchProfile/NonInteractiveLogin",
			steps: func(t *testing.T, lb *LocalBackend, cc func() *mockControl) {
				mustDo(t)(lb.Start(ipn.Options{}))
				mustDo2(t)(lb.EditPrefs(connect))
				cc().authenticated(node1)
				profileID := lb.CurrentProfile().ID()
				mustDo(t)(lb.NewProfile())
				cc().authenticated(node2)
				mustDo(t)(lb.SwitchProfile(profileID))
				cc().authenticated(node1) // complete the login
			},
			// After switching profiles and completing the auth, the configs
			// must be updated to reflect the node's netmap.
			wantState: ipn.Starting,
			wantCfg: &wgcfg.Config{
				Peers:     []wgcfg.Peer{},
				Addresses: node1.SelfNode.Addresses().AsSlice(),
			},
			wantRouterCfg: &router.Config{
				SNATSubnetRoutes: true,
				NetfilterMode:    preftype.NetfilterOn,
				LocalAddrs:       node1.SelfNode.Addresses().AsSlice(),
				Routes:           routesWithQuad100(),
			},
			wantDNSCfg: &dns.Config{
				Routes: map[dnsname.FQDN][]*dnstype.Resolver{},
				Hosts:  hostsFor(node1),
			},
		},
		{
			name: "Start/Connect/Login/WithPeers",
			steps: func(t *testing.T, lb *LocalBackend, cc func() *mockControl) {
				mustDo(t)(lb.Start(ipn.Options{}))
				mustDo2(t)(lb.EditPrefs(connect))
				cc().authenticated(node3)
			},
			wantState: ipn.Starting,
			wantCfg: &wgcfg.Config{
				Peers: []wgcfg.Peer{
					{
						PublicKey: node1.SelfNode.Key(),
						DiscoKey:  node1.SelfNode.DiscoKey(),
					},
					{
						PublicKey: node2.SelfNode.Key(),
						DiscoKey:  node2.SelfNode.DiscoKey(),
					},
				},
				Addresses: node3.SelfNode.Addresses().AsSlice(),
			},
			wantRouterCfg: &router.Config{
				SNATSubnetRoutes: true,
				NetfilterMode:    preftype.NetfilterOn,
				LocalAddrs:       node3.SelfNode.Addresses().AsSlice(),
				Routes:           routesWithQuad100(),
			},
			wantDNSCfg: &dns.Config{
				Routes: map[dnsname.FQDN][]*dnstype.Resolver{},
				Hosts:  hostsFor(node3),
			},
		},
		{
			name: "Start/Connect/Login/Expire",
			steps: func(t *testing.T, lb *LocalBackend, cc func() *mockControl) {
				mustDo(t)(lb.Start(ipn.Options{}))
				mustDo2(t)(lb.EditPrefs(connect))
				cc().authenticated(node1)
				cc().send(sendOpt{nm: &netmap.NetworkMap{
					SelfNode: (&tailcfg.Node{
						KeyExpiry: time.Now().Add(-time.Minute),
					}).View(),
				}})
			},
			wantState:     ipn.NeedsLogin,
			wantCfg:       &wgcfg.Config{},
			wantRouterCfg: &router.Config{},
			wantDNSCfg:    &dns.Config{},
		},
		{
			name: "Start/Connect/Login/InitReauth",
			steps: func(t *testing.T, lb *LocalBackend, cc func() *mockControl) {
				mustDo(t)(lb.Start(ipn.Options{}))
				mustDo2(t)(lb.EditPrefs(connect))
				cc().authenticated(node1)

				// Start the re-auth process:
				lb.StartLoginInteractive(context.Background())
				cc().sendAuthURL(node1)
			},
			// Without seamless renewal, even starting a reauth tears down everything:
			wantState:     ipn.Starting,
			wantCfg:       &wgcfg.Config{},
			wantRouterCfg: &router.Config{},
			wantDNSCfg:    &dns.Config{},
		},
		{
			name: "Start/Connect/Login/InitReauth/Login",
			steps: func(t *testing.T, lb *LocalBackend, cc func() *mockControl) {
				mustDo(t)(lb.Start(ipn.Options{}))
				mustDo2(t)(lb.EditPrefs(connect))
				cc().authenticated(node1)

				// Start the re-auth process:
				lb.StartLoginInteractive(context.Background())
				cc().sendAuthURL(node1)

				// Complete the re-auth process:
				cc().authenticated(node1)
			},
			wantState: ipn.Starting,
			wantCfg: &wgcfg.Config{
				Peers:     []wgcfg.Peer{},
				Addresses: node1.SelfNode.Addresses().AsSlice(),
			},
			wantRouterCfg: &router.Config{
				SNATSubnetRoutes: true,
				NetfilterMode:    preftype.NetfilterOn,
				LocalAddrs:       node1.SelfNode.Addresses().AsSlice(),
				Routes:           routesWithQuad100(),
			},
			wantDNSCfg: &dns.Config{
				Routes: map[dnsname.FQDN][]*dnstype.Resolver{},
				Hosts:  hostsFor(node1),
			},
		},
		{
			name: "Seamless/Start/Connect/Login/InitReauth",
			steps: func(t *testing.T, lb *LocalBackend, cc func() *mockControl) {
				lb.ControlKnobs().SeamlessKeyRenewal.Store(true)
				mustDo(t)(lb.Start(ipn.Options{}))
				mustDo2(t)(lb.EditPrefs(connect))
				cc().authenticated(node1)

				// Start the re-auth process:
				lb.StartLoginInteractive(context.Background())
				cc().sendAuthURL(node1)
			},
			// With seamless renewal, starting a reauth should leave everything up:
			wantState: ipn.Starting,
			wantCfg: &wgcfg.Config{
				Peers:     []wgcfg.Peer{},
				Addresses: node1.SelfNode.Addresses().AsSlice(),
			},
			wantRouterCfg: &router.Config{
				SNATSubnetRoutes: true,
				NetfilterMode:    preftype.NetfilterOn,
				LocalAddrs:       node1.SelfNode.Addresses().AsSlice(),
				Routes:           routesWithQuad100(),
			},
			wantDNSCfg: &dns.Config{
				Routes: map[dnsname.FQDN][]*dnstype.Resolver{},
				Hosts:  hostsFor(node1),
			},
		},
		{
			name: "Seamless/Start/Connect/Login/InitReauth/Login",
			steps: func(t *testing.T, lb *LocalBackend, cc func() *mockControl) {
				lb.ControlKnobs().SeamlessKeyRenewal.Store(true)
				mustDo(t)(lb.Start(ipn.Options{}))
				mustDo2(t)(lb.EditPrefs(connect))
				cc().authenticated(node1)

				// Start the re-auth process:
				lb.StartLoginInteractive(context.Background())
				cc().sendAuthURL(node1)

				// Complete the re-auth process:
				cc().authenticated(node1)
			},
			wantState: ipn.Starting,
			wantCfg: &wgcfg.Config{
				Peers:     []wgcfg.Peer{},
				Addresses: node1.SelfNode.Addresses().AsSlice(),
			},
			wantRouterCfg: &router.Config{
				SNATSubnetRoutes: true,
				NetfilterMode:    preftype.NetfilterOn,
				LocalAddrs:       node1.SelfNode.Addresses().AsSlice(),
				Routes:           routesWithQuad100(),
			},
			wantDNSCfg: &dns.Config{
				Routes: map[dnsname.FQDN][]*dnstype.Resolver{},
				Hosts:  hostsFor(node1),
			},
		},
		{
			name: "Seamless/Start/Connect/Login/Expire",
			steps: func(t *testing.T, lb *LocalBackend, cc func() *mockControl) {
				lb.ControlKnobs().SeamlessKeyRenewal.Store(true)
				mustDo(t)(lb.Start(ipn.Options{}))
				mustDo2(t)(lb.EditPrefs(connect))
				cc().authenticated(node1)
				cc().send(sendOpt{nm: &netmap.NetworkMap{
					SelfNode: (&tailcfg.Node{
						KeyExpiry: time.Now().Add(-time.Minute),
					}).View(),
				}})
			},
			// Even with seamless, if the key we are using expires, we want to disconnect:
			wantState:     ipn.NeedsLogin,
			wantCfg:       &wgcfg.Config{},
			wantRouterCfg: &router.Config{},
			wantDNSCfg:    &dns.Config{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lb, engine, cc := newLocalBackendWithMockEngineAndControl(t, enableLogging)

			if tt.steps != nil {
				tt.steps(t, lb, cc)
			}

			// TODO(bradfitz): this whole event bus settling thing
			// should be unnecessary once the bogus uses of eventbus
			// are removed. (https://github.com/tailscale/tailscale/issues/16369)
			lb.settleEventBus()

			if gotState := lb.State(); gotState != tt.wantState {
				t.Errorf("State: got %v; want %v", gotState, tt.wantState)
			}

			if engine.Config() != nil {
				for _, p := range engine.Config().Peers {
					pKey := p.PublicKey.UntypedHexString()
					_, err := lb.MagicConn().ParseEndpoint(pKey)
					if err != nil {
						t.Errorf("ParseEndpoint(%q) failed: %v", pKey, err)
					}
				}
			}

			opts := []cmp.Option{
				cmpopts.EquateComparable(key.NodePublic{}, key.DiscoPublic{}, netip.Addr{}, netip.Prefix{}),
			}
			if diff := cmp.Diff(tt.wantCfg, engine.Config(), opts...); diff != "" {
				t.Errorf("wgcfg.Config(+got -want): %v", diff)
			}
			if diff := cmp.Diff(tt.wantRouterCfg, engine.RouterConfig(), opts...); diff != "" {
				t.Errorf("router.Config(+got -want): %v", diff)
			}
			if diff := cmp.Diff(tt.wantDNSCfg, engine.DNSConfig(), opts...); diff != "" {
				t.Errorf("dns.Config(+got -want): %v", diff)
			}
		})
	}
}

// TestSendPreservesAuthURL tests that wgengine updates arriving in the middle of
// processing an auth URL doesn't result in the auth URL being cleared.
func TestSendPreservesAuthURL(t *testing.T) {
	runTestSendPreservesAuthURL(t, false)
}

func TestSendPreservesAuthURLSeamless(t *testing.T) {
	runTestSendPreservesAuthURL(t, true)
}

func runTestSendPreservesAuthURL(t *testing.T, seamless bool) {
	var cc *mockControl
	b := newLocalBackendWithTestControl(t, true, func(tb testing.TB, opts controlclient.Options) controlclient.Client {
		cc = newClient(t, opts)
		return cc
	})

	t.Logf("Start")
	b.Start(ipn.Options{
		UpdatePrefs: &ipn.Prefs{
			WantRunning: true,
			ControlURL:  "https://localhost:1/",
		},
	})

	t.Logf("LoginFinished")
	cc.persist.UserProfile.LoginName = "user1"
	cc.persist.NodeID = "node1"

	if seamless {
		b.sys.ControlKnobs().SeamlessKeyRenewal.Store(true)
	}

	cc.send(sendOpt{loginFinished: true, nm: &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{MachineAuthorized: true}).View(),
	}})

	t.Logf("Running")
	b.setWgengineStatus(&wgengine.Status{AsOf: time.Now(), DERPs: 1}, nil)

	t.Logf("Re-auth (StartLoginInteractive)")
	b.StartLoginInteractive(t.Context())

	t.Logf("Re-auth (receive URL)")
	url1 := "https://localhost:1/1"
	cc.send(sendOpt{url: url1})

	// Don't need to wait on anything else - once .send completes, authURL should
	// be set, and once .send has completed, any opportunities for a WG engine
	// status update to trample it have ended as well.
	if b.authURL == "" {
		t.Fatalf("expected authURL to be set")
	} else {
		t.Log("authURL was set")
	}
}

func buildNetmapWithPeers(self tailcfg.NodeView, peers ...tailcfg.NodeView) *netmap.NetworkMap {
	const (
		firstAutoUserID = tailcfg.UserID(10000)
		domain          = "example.com"
		magicDNSSuffix  = ".test.ts.net"
	)

	users := make(map[tailcfg.UserID]tailcfg.UserProfileView)
	makeUserForNode := func(n *tailcfg.Node) {
		var user *tailcfg.UserProfile
		if n.User == 0 {
			n.User = firstAutoUserID + tailcfg.UserID(n.ID)
			user = &tailcfg.UserProfile{
				DisplayName: n.Name,
				LoginName:   n.Name,
			}
		} else if _, ok := users[n.User]; !ok {
			user = &tailcfg.UserProfile{
				DisplayName: fmt.Sprintf("User %d", n.User),
				LoginName:   fmt.Sprintf("user-%d", n.User),
			}
		}
		if user != nil {
			user.ID = n.User
			user.LoginName = strings.Join([]string{user.LoginName, domain}, "@")
			users[n.User] = user.View()
		}
	}

	derpmap := &tailcfg.DERPMap{
		Regions: make(map[int]*tailcfg.DERPRegion),
	}
	makeDERPRegionForNode := func(n *tailcfg.Node) {
		if n.HomeDERP == 0 {
			return // no DERP region
		}
		if _, ok := derpmap.Regions[n.HomeDERP]; !ok {
			r := &tailcfg.DERPRegion{
				RegionID:   n.HomeDERP,
				RegionName: fmt.Sprintf("Region %d", n.HomeDERP),
			}
			r.Nodes = append(r.Nodes, &tailcfg.DERPNode{
				Name:     fmt.Sprintf("%da", n.HomeDERP),
				RegionID: n.HomeDERP,
			})
			derpmap.Regions[n.HomeDERP] = r
		}
	}

	updateNode := func(n tailcfg.NodeView) tailcfg.NodeView {
		mut := n.AsStruct()
		makeUserForNode(mut)
		makeDERPRegionForNode(mut)
		mut.Name = mut.Name + magicDNSSuffix
		return mut.View()
	}

	self = updateNode(self)
	for i := range peers {
		peers[i] = updateNode(peers[i])
	}

	return &netmap.NetworkMap{
		SelfNode:     self,
		Domain:       domain,
		Peers:        peers,
		UserProfiles: users,
		DERPMap:      derpmap,
	}
}

func mustDo(t *testing.T) func(error) {
	t.Helper()
	return func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
}

func mustDo2(t *testing.T) func(any, error) {
	t.Helper()
	return func(_ any, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
}

func newLocalBackendWithMockEngineAndControl(t *testing.T, enableLogging bool) (*LocalBackend, *mockEngine, func() *mockControl) {
	t.Helper()

	logf := logger.Discard
	if enableLogging {
		logf = tstest.WhileTestRunningLogger(t)
	}

	dialer := &tsdial.Dialer{Logf: logf}
	dialer.SetNetMon(netmon.NewStatic())

	bus := eventbustest.NewBus(t)
	sys := tsd.NewSystemWithBus(bus)
	sys.Set(dialer)
	sys.Set(dialer.NetMon())
	dialer.SetBus(bus)

	magicConn, err := magicsock.NewConn(magicsock.Options{
		Logf:              logf,
		EventBus:          sys.Bus.Get(),
		NetMon:            dialer.NetMon(),
		Metrics:           sys.UserMetricsRegistry(),
		HealthTracker:     sys.HealthTracker.Get(),
		DisablePortMapper: true,
	})
	if err != nil {
		t.Fatalf("NewConn failed: %v", err)
	}
	magicConn.SetNetworkUp(dialer.NetMon().InterfaceState().AnyInterfaceUp())
	sys.Set(magicConn)

	engine := newMockEngine()
	sys.Set(engine)
	t.Cleanup(func() {
		engine.Close()
		<-engine.Done()
	})

	lb := newLocalBackendWithSysAndTestControl(t, enableLogging, sys, func(tb testing.TB, opts controlclient.Options) controlclient.Client {
		return newClient(tb, opts)
	})
	return lb, engine, func() *mockControl { return lb.cc.(*mockControl) }
}

var _ wgengine.Engine = (*mockEngine)(nil)

// mockEngine implements [wgengine.Engine].
type mockEngine struct {
	done chan struct{} // closed when Close is called

	mu        sync.Mutex // protects all following fields
	closed    bool
	cfg       *wgcfg.Config
	routerCfg *router.Config
	dnsCfg    *dns.Config

	filter, jailedFilter *filter.Filter

	statusCb wgengine.StatusCallback
}

func newMockEngine() *mockEngine {
	return &mockEngine{
		done: make(chan struct{}),
	}
}

func (e *mockEngine) Reconfig(cfg *wgcfg.Config, routerCfg *router.Config, dnsCfg *dns.Config) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return errors.New("engine closed")
	}
	e.cfg = cfg
	e.routerCfg = routerCfg
	e.dnsCfg = dnsCfg
	return nil
}

func (e *mockEngine) Config() *wgcfg.Config {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cfg
}

func (e *mockEngine) RouterConfig() *router.Config {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.routerCfg
}

func (e *mockEngine) DNSConfig() *dns.Config {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.dnsCfg
}

func (e *mockEngine) PeerForIP(netip.Addr) (_ wgengine.PeerForIP, ok bool) {
	return wgengine.PeerForIP{}, false
}

func (e *mockEngine) GetFilter() *filter.Filter {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.filter
}

func (e *mockEngine) SetFilter(f *filter.Filter) {
	e.mu.Lock()
	e.filter = f
	e.mu.Unlock()
}

func (e *mockEngine) GetJailedFilter() *filter.Filter {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.jailedFilter
}

func (e *mockEngine) SetJailedFilter(f *filter.Filter) {
	e.mu.Lock()
	e.jailedFilter = f
	e.mu.Unlock()
}

func (e *mockEngine) SetStatusCallback(cb wgengine.StatusCallback) {
	e.mu.Lock()
	e.statusCb = cb
	e.mu.Unlock()
}

func (e *mockEngine) RequestStatus() {
	e.mu.Lock()
	cb := e.statusCb
	e.mu.Unlock()
	if cb != nil {
		cb(&wgengine.Status{AsOf: time.Now()}, nil)
	}
}

func (e *mockEngine) ResetAndStop() (*wgengine.Status, error) {
	err := e.Reconfig(&wgcfg.Config{}, &router.Config{}, &dns.Config{})
	if err != nil {
		return nil, err
	}
	return &wgengine.Status{AsOf: time.Now()}, nil
}

func (e *mockEngine) PeerByKey(key.NodePublic) (_ wgint.Peer, ok bool) {
	return wgint.Peer{}, false
}

func (e *mockEngine) SetNetworkMap(*netmap.NetworkMap) {}

func (e *mockEngine) UpdateStatus(*ipnstate.StatusBuilder) {}

func (e *mockEngine) Ping(ip netip.Addr, pingType tailcfg.PingType, size int, cb func(*ipnstate.PingResult)) {
	cb(&ipnstate.PingResult{IP: ip.String(), Err: "not implemented"})
}

func (e *mockEngine) InstallCaptureHook(packet.CaptureCallback) {}

func (e *mockEngine) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}
	e.closed = true
	close(e.done)
}

func (e *mockEngine) Done() <-chan struct{} {
	return e.done
}

// hasValidNetMap returns true if the backend has a valid network map with a valid self node.
func hasValidNetMap(b *LocalBackend) bool {
	nm := b.NetMap()
	return nm != nil && nm.SelfNode.Valid()
}

// needsLogin returns true if the backend needs user login action.
// This is true when logged out, when an auth URL is present (interactive login in progress),
// or when the node key has expired.
func needsLogin(b *LocalBackend) bool {
	// Note: b.Prefs() handles its own locking, so we lock only for authURL and keyExpired access
	b.mu.Lock()
	authURL := b.authURL
	keyExpired := b.keyExpired
	b.mu.Unlock()
	return b.Prefs().LoggedOut() || authURL != "" || keyExpired
}

// needsMachineAuth returns true if the user has logged in but the machine is not yet authorized.
// This includes the case where we have a netmap but no valid SelfNode yet (empty netmap after initial login).
func needsMachineAuth(b *LocalBackend) bool {
	// Note: b.NetMap() and b.Prefs() handle their own locking
	nm := b.NetMap()
	prefs := b.Prefs()
	if prefs.LoggedOut() || nm == nil {
		return false
	}
	// If we have a valid SelfNode, check its MachineAuthorized status
	if nm.SelfNode.Valid() {
		return !nm.SelfNode.MachineAuthorized()
	}
	// Empty netmap (no SelfNode yet) after login also means we need machine auth
	return true
}

// hasAuthURL returns true if an authentication URL is present (user needs to visit a URL).
func hasAuthURL(b *LocalBackend) bool {
	b.mu.Lock()
	authURL := b.authURL
	b.mu.Unlock()
	return authURL != ""
}

// canRouteTraffic returns true if the backend is capable of routing traffic.
// This requires a valid netmap, machine authorization, and WantRunning preference.
func canRouteTraffic(b *LocalBackend) bool {
	// Note: b.NetMap() and b.Prefs() handle their own locking
	nm := b.NetMap()
	prefs := b.Prefs()
	return nm != nil &&
		nm.SelfNode.Valid() &&
		nm.SelfNode.MachineAuthorized() &&
		prefs.WantRunning()
}

// isFullyAuthenticated returns true if the user has completed login and no auth URL is pending.
func isFullyAuthenticated(b *LocalBackend) bool {
	// Note: b.Prefs() handles its own locking, so we lock only for authURL access
	b.mu.Lock()
	authURL := b.authURL
	b.mu.Unlock()
	return !b.Prefs().LoggedOut() && authURL == ""
}

// isWantRunning returns true if the WantRunning preference is set.
func isWantRunning(b *LocalBackend) bool {
	return b.Prefs().WantRunning()
}

// isLoggedIn returns true if the user is logged in (not logged out).
func isLoggedIn(b *LocalBackend) bool {
	return !b.Prefs().LoggedOut()
}
