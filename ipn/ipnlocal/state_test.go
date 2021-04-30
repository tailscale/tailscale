// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnlocal

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"tailscale.com/control/controlclient"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/types/empty"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/persist"
	"tailscale.com/types/wgkey"
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
	opts       controlclient.Options
	logf       logger.Logf
	statusFunc func(controlclient.Status)

	mu          sync.Mutex
	calls       []string
	authBlocked bool
	persist     persist.Persist
	machineKey  wgkey.Private
}

func newMockControl() *mockControl {
	return &mockControl{
		calls:       []string{},
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
		cc.persist.PrivateNodeKey, _ = wgkey.NewPrivate()
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
		}
		if err != nil {
			s.Err = err.Error()
		}
		if loginFinished {
			s.LoginFinished = &empty.Message{}
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

// getCalls returns the list of functions that have been called since the
// last time getCalls was run.
func (cc *mockControl) getCalls() []string {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	r := cc.calls
	cc.calls = []string{}
	return r
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
	assert := assert.New(t)

	logf := t.Logf
	store := new(ipn.MemoryStore)
	e, err := wgengine.NewFakeUserspaceEngine(logf, 0)
	if err != nil {
		t.Fatalf("NewFakeUserspaceEngine: %v", err)
	}

	cc := newMockControl()
	ccGen := func(opts controlclient.Options) (controlclient.Client, error) {
		cc.mu.Lock()
		cc.opts = opts
		cc.logf = opts.Logf
		cc.authBlocked = true
		cc.persist = cc.opts.Persist
		cc.mu.Unlock()

		cc.logf("ccGen: new mockControl.")
		cc.called("New")
		return cc, nil
	}
	b, err := NewLocalBackendWithClientGen(logf, "logid", store, e, ccGen)
	if err != nil {
		t.Fatalf("NewLocalBackend: %v", err)
	}

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
	assert.Equal(cc.getCalls(), []string{})

	// Start the state machine.
	// Since !WantRunning by default, it'll create a controlclient,
	// but not ask it to do anything yet.
	t.Logf("\n\nStart")
	notifies.expect(2)
	assert.Nil(b.Start(ipn.Options{
		StateKey: ipn.GlobalDaemonStateKey,
	}))
	{
		// BUG: strictly, it should pause, not unpause, here, since !WantRunning.
		assert.Equal([]string{"New", "unpause"}, cc.getCalls())

		nn := notifies.drain(2)
		assert.Equal([]string{}, cc.getCalls())
		assert.NotNil(nn[0].Prefs)
		assert.NotNil(nn[1].State)
		prefs := *nn[0].Prefs
		// Note: a totally fresh system has Prefs.LoggedOut=false by
		// default. We are logged out, but not because the user asked
		// for it, so it doesn't count as Prefs.LoggedOut==true.
		assert.Equal(false, nn[0].Prefs.LoggedOut)
		assert.Equal(false, prefs.WantRunning)
		assert.Equal(ipn.NeedsLogin, *nn[1].State)
		assert.Equal(ipn.NeedsLogin, b.State())
	}

	// Restart the state machine.
	// It's designed to handle frontends coming and going sporadically.
	// Make the sure the restart not only works, but generates the same
	// events as the first time, so UIs always know what to expect.
	t.Logf("\n\nStart2")
	notifies.expect(2)
	assert.Nil(b.Start(ipn.Options{
		StateKey: ipn.GlobalDaemonStateKey,
	}))
	{
		// BUG: strictly, it should pause, not unpause, here, since !WantRunning.
		assert.Equal([]string{"Shutdown", "New", "unpause"}, cc.getCalls())

		nn := notifies.drain(2)
		assert.Equal([]string{}, cc.getCalls())
		assert.NotNil(nn[0].Prefs)
		assert.NotNil(nn[1].State)
		assert.Equal(false, nn[0].Prefs.LoggedOut)
		assert.Equal(false, nn[0].Prefs.WantRunning)
		assert.Equal(ipn.NeedsLogin, *nn[1].State)
		assert.Equal(ipn.NeedsLogin, b.State())
	}

	// Start non-interactive login with no token.
	// This will ask controlclient to start its own Login() process,
	// then wait for us to respond.
	t.Logf("\n\nLogin (noninteractive)")
	notifies.expect(0)
	b.Login(nil)
	{
		assert.Equal(cc.getCalls(), []string{"Login"})
		notifies.drain(0)
		// BUG: this should immediately set WantRunning to true.
		// Users don't log in if they don't want to also connect.
		// (Generally, we're inconsistent about who is supposed to
		// update Prefs at what time. But the overall philosophy is:
		// update it when the user's intent changes. This is clearly
		// at the time the user *requests* Login, not at the time
		// the login finishes.)
	}

	// Attempted non-interactive login with no key; indicate that
	// the user needs to visit a login URL.
	t.Logf("\n\nLogin (url response)")
	notifies.expect(1)
	url1 := "http://localhost:1/1"
	cc.send(nil, url1, false, nil)
	{
		assert.Equal([]string{}, cc.getCalls())

		// ...but backend eats that notification, because the user
		// didn't explicitly request interactive login yet, and
		// we're already in NeedsLogin state.
		nn := notifies.drain(1)

		// Trying to log in automatically sets WantRunning.
		// BUG: that should have happened right after Login().
		assert.NotNil(nn[0].Prefs)
		assert.Equal(false, nn[0].Prefs.LoggedOut)
		assert.Equal(true, nn[0].Prefs.WantRunning)
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
		// BUG: UpdateEndpoints shouldn't be called yet.
		// We're still not logged in so there's nothing we can do
		// with it. (And empirically, it's providing an empty list
		// of endpoints.)
		assert.Equal([]string{"UpdateEndpoints"}, cc.getCalls())
		assert.NotNil(nn[0].BrowseToURL)
		assert.Equal(url1, *nn[0].BrowseToURL)
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
		assert.Equal([]string{"Login"}, cc.getCalls())
	}

	// Provide a new interactive login URL.
	t.Logf("\n\nLogin2 (url response)")
	notifies.expect(1)
	url2 := "http://localhost:1/2"
	cc.send(nil, url2, false, nil)
	{
		// BUG: UpdateEndpoints again, this is getting silly.
		assert.Equal([]string{"UpdateEndpoints"}, cc.getCalls())

		// This time, backend should emit it to the UI right away,
		// because the UI is anxiously awaiting a new URL to visit.
		nn := notifies.drain(1)
		assert.NotNil(nn[0].BrowseToURL)
		assert.Equal(url2, *nn[0].BrowseToURL)
	}

	// Pretend that the interactive login actually happened.
	// Controlclient always sends the netmap and LoginFinished at the
	// same time.
	// The backend should propagate this upward for the UI.
	t.Logf("\n\nLoginFinished")
	notifies.expect(2)
	cc.setAuthBlocked(false)
	cc.send(nil, "", true, &netmap.NetworkMap{})
	{
		nn := notifies.drain(2)
		// BUG: still too soon for UpdateEndpoints.
		//
		// Arguably it makes sense to unpause now, since the machine
		// authorization status is part of the netmap.
		//
		// BUG: backend unblocks wgengine at this point, even though
		// our machine key is not authorized. It probably should
		// wait until it gets into Starting.
		// TODO: (Currently this test doesn't detect that bug, but
		// it's visible in the logs)
		assert.Equal([]string{"unpause", "UpdateEndpoints"}, cc.getCalls())
		assert.NotNil(nn[0].LoginFinished)
		assert.NotNil(nn[1].State)
		assert.Equal(ipn.NeedsMachineAuth, *nn[1].State)
	}

	// TODO: check that the logged-in username propagates from control
	// through to the UI notifications. I think it's used as a hint
	// for future logins, to pre-fill the username box? Not really sure
	// how it works.

	// Pretend that the administrator has authorized our machine.
	t.Logf("\n\nMachineAuthorized")
	notifies.expect(1)
	// BUG: the real controlclient sends LoginFinished with every
	// notification while it's in StateAuthenticated, but not StateSynced.
	// We should send it exactly once, or every time we're authenticated,
	// but the current code is brittle.
	// (ie. I suspect it would be better to change false->true in send()
	// below, and do the same in the real controlclient.)
	cc.send(nil, "", false, &netmap.NetworkMap{
		MachineStatus: tailcfg.MachineAuthorized,
	})
	{
		nn := notifies.drain(1)
		assert.Equal([]string{"unpause", "UpdateEndpoints"}, cc.getCalls())
		assert.NotNil(nn[0].State)
		assert.Equal(ipn.Starting, *nn[0].State)
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
		assert.Equal([]string{"pause"}, cc.getCalls())
		// BUG: I would expect Prefs to change first, and state after.
		assert.NotNil(nn[0].State)
		assert.NotNil(nn[1].Prefs)
		assert.Equal(ipn.Stopped, *nn[0].State)
	}

	// The user changes their preference to WantRunning after all.
	t.Logf("\n\nWantRunning -> true")
	notifies.expect(2)
	b.EditPrefs(&ipn.MaskedPrefs{
		WantRunningSet: true,
		Prefs:          ipn.Prefs{WantRunning: true},
	})
	{
		nn := notifies.drain(2)
		// BUG: UpdateEndpoints isn't needed here.
		// BUG: Login isn't needed here. We never logged out.
		assert.Equal([]string{"Login", "unpause", "UpdateEndpoints"}, cc.getCalls())
		// BUG: I would expect Prefs to change first, and state after.
		assert.NotNil(nn[0].State)
		assert.NotNil(nn[1].Prefs)
		assert.Equal(ipn.Starting, *nn[0].State)
	}

	// Test the fast-path frontend reconnection.
	// This one is very finicky, so we have to force State==Running.
	// TODO: actually get to State==Running, rather than cheating.
	//  That'll require spinning up a fake DERP server and putting it in
	//  the netmap.
	t.Logf("\n\nFastpath Start()")
	notifies.expect(1)
	b.state = ipn.Running
	assert.Nil(b.Start(ipn.Options{
		StateKey: ipn.GlobalDaemonStateKey,
	}))
	{
		nn := notifies.drain(1)
		assert.Equal([]string{}, cc.getCalls())
		assert.NotNil(nn[0].State)
		assert.NotNil(nn[0].LoginFinished)
		assert.NotNil(nn[0].NetMap)
		// BUG: Prefs should be sent too, or the UI could end up in
		// a bad state. (iOS, the only current user of this feature,
		// probably wouldn't notice because it happens to not display
		// any prefs. Maybe exit nodes will look weird?)
	}

	// undo the state hack above.
	b.state = ipn.Starting

	// User wants to logout.
	t.Logf("\n\nLogout (async)")
	notifies.expect(2)
	b.Logout()
	{
		nn := notifies.drain(2)
		// BUG: now is not the time to unpause.
		assert.Equal([]string{"unpause", "StartLogout"}, cc.getCalls())
		assert.NotNil(nn[0].State)
		assert.NotNil(nn[1].Prefs)
		assert.Equal(ipn.NeedsLogin, *nn[0].State)
		assert.Equal(true, nn[1].Prefs.LoggedOut)
		assert.Equal(false, nn[1].Prefs.WantRunning)
		assert.Equal(ipn.NeedsLogin, b.State())
	}

	// Let's make the logout succeed.
	t.Logf("\n\nLogout (async) - succeed")
	notifies.expect(1)
	cc.setAuthBlocked(true)
	cc.send(nil, "", false, nil)
	{
		nn := notifies.drain(1)
		assert.Equal([]string{}, cc.getCalls())
		assert.NotNil(nn[0].Prefs)
		assert.Equal(true, nn[0].Prefs.LoggedOut)
		// BUG: WantRunning should be false after manual logout.
		assert.Equal(true, nn[0].Prefs.WantRunning)
		assert.Equal(ipn.NeedsLogin, b.State())
	}

	// A second logout should do nothing, since the prefs haven't changed.
	t.Logf("\n\nLogout2 (async)")
	notifies.expect(1)
	b.Logout()
	{
		nn := notifies.drain(1)
		// BUG: the backend has already called StartLogout, and we're
		// still logged out. So it shouldn't call it again.
		assert.Equal([]string{"StartLogout"}, cc.getCalls())
		// BUG: Prefs should not change here. Already logged out.
		assert.NotNil(nn[0].Prefs)
		assert.Equal(true, nn[0].Prefs.LoggedOut)
		assert.Equal(false, nn[0].Prefs.WantRunning)
		assert.Equal(ipn.NeedsLogin, b.State())
	}

	// Let's acknowledge the second logout too.
	t.Logf("\n\nLogout2 (async) - succeed")
	notifies.expect(1)
	cc.setAuthBlocked(true)
	cc.send(nil, "", false, nil)
	{
		nn := notifies.drain(1)
		assert.Equal([]string{}, cc.getCalls())
		assert.NotNil(nn[0].Prefs)
		assert.Equal(true, nn[0].Prefs.LoggedOut)
		// BUG: second logout shouldn't cause WantRunning->true !!
		assert.Equal(true, nn[0].Prefs.WantRunning)
		assert.Equal(ipn.NeedsLogin, b.State())
	}

	// Try the synchronous logout feature.
	t.Logf("\n\nLogout3 (sync)")
	notifies.expect(1)
	b.LogoutSync(context.Background())
	// NOTE: This returns as soon as cc.Logout() returns, which is okay
	// I guess, since that's supposed to be synchronous.
	{
		nn := notifies.drain(1)
		assert.Equal([]string{"Logout"}, cc.getCalls())
		assert.NotNil(nn[0].Prefs)
		assert.Equal(true, nn[0].Prefs.LoggedOut)
		assert.Equal(false, nn[0].Prefs.WantRunning)
		assert.Equal(ipn.NeedsLogin, b.State())
	}

	// Generate the third logout event.
	t.Logf("\n\nLogout3 (sync) - succeed")
	notifies.expect(1)
	cc.setAuthBlocked(true)
	cc.send(nil, "", false, nil)
	{
		nn := notifies.drain(1)
		assert.Equal([]string{}, cc.getCalls())
		assert.NotNil(nn[0].Prefs)
		assert.Equal(true, nn[0].Prefs.LoggedOut)
		// BUG: third logout shouldn't cause WantRunning->true !!
		assert.Equal(true, nn[0].Prefs.WantRunning)
		assert.Equal(ipn.NeedsLogin, b.State())
	}

	// Shut down the backend.
	t.Logf("\n\nShutdown")
	notifies.expect(0)
	b.Shutdown()
	{
		notifies.drain(0)
		// BUG: I expect a transition to ipn.NoState here.
		assert.Equal(cc.getCalls(), []string{"Shutdown"})
	}

	// Oh, you thought we were done? Ha! Now we have to test what
	// happens if the user exits and restarts while logged out.
	// Note that it's explicitly okay to call b.Start() over and over
	// again, every time the frontend reconnects.
	//
	// BUG: WantRunning is true here (because of the bug above).
	//  We'll have to adjust the following test's expectations if we
	//  fix that.

	// TODO: test user switching between statekeys.

	// The frontend restarts!
	t.Logf("\n\nStart3")
	notifies.expect(2)
	assert.Nil(b.Start(ipn.Options{
		StateKey: ipn.GlobalDaemonStateKey,
	}))
	{
		// BUG: We already called Shutdown(), no need to do it again.
		// BUG: Way too soon for UpdateEndpoints.
		// BUG: don't unpause because we're not logged in.
		assert.Equal([]string{"Shutdown", "New", "UpdateEndpoints", "unpause"}, cc.getCalls())

		nn := notifies.drain(2)
		assert.Equal([]string{}, cc.getCalls())
		assert.NotNil(nn[0].Prefs)
		assert.NotNil(nn[1].State)
		assert.Equal(true, nn[0].Prefs.LoggedOut)
		assert.Equal(true, nn[0].Prefs.WantRunning)
		assert.Equal(ipn.NeedsLogin, *nn[1].State)
		assert.Equal(ipn.NeedsLogin, b.State())
	}

	// Let's break the rules a little. Our control server accepts
	// your invalid login attempt, with no need for an interactive login.
	// (This simulates an admin reviving a key that you previously
	// disabled.)
	t.Logf("\n\nLoginFinished3")
	notifies.expect(3)
	cc.setAuthBlocked(false)
	cc.send(nil, "", true, &netmap.NetworkMap{
		MachineStatus: tailcfg.MachineAuthorized,
	})
	{
		nn := notifies.drain(3)
		assert.Equal([]string{"unpause"}, cc.getCalls())
		assert.NotNil(nn[0].Prefs)
		assert.NotNil(nn[1].LoginFinished)
		assert.NotNil(nn[2].State)
		assert.Equal(false, nn[0].Prefs.LoggedOut)
		assert.Equal(ipn.Starting, *nn[2].State)
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
		assert.Equal([]string{"pause"}, cc.getCalls())
		// BUG: I would expect Prefs to change first, and state after.
		assert.NotNil(nn[0].State)
		assert.NotNil(nn[1].Prefs)
		assert.Equal(ipn.Stopped, *nn[0].State)
		assert.Equal(false, nn[1].Prefs.LoggedOut)
	}

	// One more restart, this time with a valid key, but WantRunning=false.
	t.Logf("\n\nStart4")
	notifies.expect(2)
	assert.Nil(b.Start(ipn.Options{
		StateKey: ipn.GlobalDaemonStateKey,
	}))
	{
		// NOTE: cc.Shutdown() is correct here, since we didn't call
		// b.Shutdown() explicitly ourselves.
		// BUG: UpdateEndpoints should be called here since we're not WantRunning.
		assert.Equal([]string{"Shutdown", "New", "UpdateEndpoints", "Login", "pause"}, cc.getCalls())

		nn := notifies.drain(2)
		assert.Equal([]string{}, cc.getCalls())
		assert.NotNil(nn[0].Prefs)
		assert.NotNil(nn[1].State)
		assert.Equal(false, nn[0].Prefs.WantRunning)
		assert.Equal(false, nn[0].Prefs.LoggedOut)
		assert.Equal(ipn.Stopped, *nn[1].State)
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
		assert.Equal([]string{"Login", "unpause"}, cc.getCalls())
		// BUG: I would expect Prefs to change first, and state after.
		assert.NotNil(nn[0].State)
		assert.NotNil(nn[1].Prefs)
		assert.Equal(ipn.Starting, *nn[0].State)
	}

	// The last test case is the most common one: restarting when both
	// logged in and WantRunning.
	t.Logf("\n\nStart5")
	notifies.expect(1)
	assert.Nil(b.Start(ipn.Options{
		StateKey: ipn.GlobalDaemonStateKey,
	}))
	{
		// NOTE: cc.Shutdown() is correct here, since we didn't call
		// b.Shutdown() ourselves.
		assert.Equal([]string{"Shutdown", "New", "UpdateEndpoints", "Login"}, cc.getCalls())

		nn := notifies.drain(1)
		assert.Equal([]string{}, cc.getCalls())
		assert.NotNil(nn[0].Prefs)
		assert.Equal(false, nn[0].Prefs.LoggedOut)
		assert.Equal(true, nn[0].Prefs.WantRunning)
		assert.Equal(ipn.NoState, b.State())
	}

	// Control server accepts our valid key from before.
	t.Logf("\n\nLoginFinished5")
	notifies.expect(2)
	cc.setAuthBlocked(false)
	cc.send(nil, "", true, &netmap.NetworkMap{
		MachineStatus: tailcfg.MachineAuthorized,
	})
	{
		nn := notifies.drain(2)
		assert.Equal([]string{"unpause"}, cc.getCalls())
		assert.NotNil(nn[0].LoginFinished)
		assert.NotNil(nn[1].State)
		assert.Equal(ipn.Starting, *nn[1].State)
		// NOTE: No prefs change this time. WantRunning stays true.
		// We were in Starting in the first place, so that doesn't
		// change either.
		assert.Equal(ipn.Starting, b.State())
	}
}
