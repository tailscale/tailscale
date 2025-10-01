// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package controlclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/health"
	"tailscale.com/net/sockstats"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/persist"
	"tailscale.com/types/structs"
	"tailscale.com/util/backoff"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/execqueue"
)

type LoginGoal struct {
	_     structs.Incomparable
	flags LoginFlags // flags to use when logging in
	url   string     // auth url that needs to be visited
}

var _ Client = (*Auto)(nil)

// waitUnpause waits until either the client is unpaused or the Auto client is
// shut down. It reports whether the client should keep running (i.e. it's not
// closed).
func (c *Auto) waitUnpause(routineLogName string) (keepRunning bool) {
	c.mu.Lock()
	if !c.paused || c.closed {
		defer c.mu.Unlock()
		return !c.closed
	}
	unpaused := c.unpausedChanLocked()
	c.mu.Unlock()

	c.logf("%s: awaiting unpause", routineLogName)
	return <-unpaused
}

// updateRoutine is responsible for informing the server of worthy changes to
// our local state. It runs in its own goroutine.
func (c *Auto) updateRoutine() {
	defer close(c.updateDone)
	bo := backoff.NewBackoff("updateRoutine", c.logf, 30*time.Second)

	// lastUpdateGenInformed is the value of lastUpdateAt that we've successfully
	// informed the server of.
	var lastUpdateGenInformed updateGen

	for {
		if !c.waitUnpause("updateRoutine") {
			c.logf("updateRoutine: exiting")
			return
		}
		c.mu.Lock()
		gen := c.lastUpdateGen
		ctx := c.mapCtx
		needUpdate := gen > 0 && gen != lastUpdateGenInformed && c.loggedIn
		c.mu.Unlock()

		if !needUpdate {
			// Nothing to do, wait for a signal.
			select {
			case <-ctx.Done():
				continue
			case <-c.updateCh:
				continue
			}
		}

		t0 := c.clock.Now()
		err := c.direct.SendUpdate(ctx)
		d := time.Since(t0).Round(time.Millisecond)
		if err != nil {
			if ctx.Err() == nil {
				c.direct.logf("lite map update error after %v: %v", d, err)
			}
			bo.BackOff(ctx, err)
			continue
		}
		bo.BackOff(ctx, nil)
		c.direct.logf("[v1] successful lite map update in %v", d)

		lastUpdateGenInformed = gen
	}
}

// atomicGen is an atomic int64 generator. It is used to generate monotonically
// increasing numbers for updateGen.
var atomicGen atomic.Int64

func nextUpdateGen() updateGen {
	return updateGen(atomicGen.Add(1))
}

// updateGen is a monotonically increasing number that represents a particular
// update to the local state.
type updateGen int64

// Auto connects to a tailcontrol server for a node.
// It's a concrete implementation of the Client interface.
type Auto struct {
	direct        *Direct // our interface to the server APIs
	clock         tstime.Clock
	logf          logger.Logf
	closed        bool
	updateCh      chan struct{} // readable when we should inform the server of a change
	observer      Observer      // called to update Client status; always non-nil
	observerQueue execqueue.ExecQueue
	shutdownFn    func() // to be called prior to shutdown or nil

	eventSubs eventbus.Monitor

	mu sync.Mutex // mutex guards the following fields

	wantLoggedIn bool   // whether the user wants to be logged in per last method call
	urlToVisit   string // the last url we were told to visit
	expiry       time.Time

	// lastUpdateGen is the gen of last update we had an update worth sending to
	// the server.
	lastUpdateGen updateGen

	lastStatus atomic.Pointer[Status]

	paused         bool        // whether we should stop making HTTP requests
	unpauseWaiters []chan bool // chans that gets sent true (once) on wake, or false on Shutdown
	loggedIn       bool        // true if currently logged in
	loginGoal      *LoginGoal  // non-nil if some login activity is desired
	inMapPoll      bool        // true once we get the first MapResponse in a stream; false when HTTP response ends
	state          State       // TODO(bradfitz): delete this, make it computed by method from other state

	authCtx    context.Context // context used for auth requests
	mapCtx     context.Context // context used for netmap and update requests
	authCancel func()          // cancel authCtx
	mapCancel  func()          // cancel mapCtx
	authDone   chan struct{}   // when closed, authRoutine is done
	mapDone    chan struct{}   // when closed, mapRoutine is done
	updateDone chan struct{}   // when closed, updateRoutine is done
}

// New creates and starts a new Auto.
func New(opts Options) (*Auto, error) {
	c, err := NewNoStart(opts)
	if c != nil {
		c.Start()
	}
	return c, err
}

// NewNoStart creates a new Auto, but without calling Start on it.
func NewNoStart(opts Options) (_ *Auto, err error) {
	direct, err := NewDirect(opts)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			direct.Close()
		}
	}()

	if opts.Observer == nil {
		return nil, errors.New("missing required Options.Observer")
	}
	if opts.Logf == nil {
		opts.Logf = func(fmt string, args ...any) {}
	}
	if opts.Clock == nil {
		opts.Clock = tstime.StdClock{}
	}
	c := &Auto{
		direct:     direct,
		clock:      opts.Clock,
		logf:       opts.Logf,
		updateCh:   make(chan struct{}, 1),
		authDone:   make(chan struct{}),
		mapDone:    make(chan struct{}),
		updateDone: make(chan struct{}),
		observer:   opts.Observer,
		shutdownFn: opts.Shutdown,
	}

	// Set up eventbus client and subscriber
	ec := opts.Bus.Client("controlClient.Auto")
	c.eventSubs = ec.Monitor(c.consumeEventbusTopics(ec))

	c.authCtx, c.authCancel = context.WithCancel(context.Background())
	c.authCtx = sockstats.WithSockStats(c.authCtx, sockstats.LabelControlClientAuto, opts.Logf)

	c.mapCtx, c.mapCancel = context.WithCancel(context.Background())
	c.mapCtx = sockstats.WithSockStats(c.mapCtx, sockstats.LabelControlClientAuto, opts.Logf)

	return c, nil
}

// consumeEventbusTopics consumes events from all relevant
// [eventbus.Subscriber]'s and passes them to their related handler. Events are
// always handled in the order they are received, i.e. the next event is not
// read until the previous event's handler has returned. It returns when the
// [eventbus.Client] is closed.
func (c *Auto) consumeEventbusTopics(ec *eventbus.Client) func(*eventbus.Client) {
	healthChangeSub := eventbus.Subscribe[health.Change](ec)
	return func(cli *eventbus.Client) {
		for {
			select {
			case <-cli.Done():
				return
			case change := <-healthChangeSub.Events():
				if change.WarnableChanged {
					c.direct.ReportWarnableChange(change.Warnable, change.UnhealthyState)
				}
			}
		}
	}
}

// SetPaused controls whether HTTP activity should be paused.
//
// The client can be paused and unpaused repeatedly, unlike Start and Shutdown, which can only be used once.
func (c *Auto) SetPaused(paused bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if paused == c.paused || c.closed {
		return
	}
	c.logf("setPaused(%v)", paused)
	c.paused = paused
	if paused {
		c.cancelMapCtxLocked()
		c.cancelAuthCtxLocked()
		return
	}
	for _, ch := range c.unpauseWaiters {
		ch <- true
	}
	c.unpauseWaiters = nil
}

// Start starts the client's goroutines.
//
// It should only be called for clients created by NewNoStart.
func (c *Auto) Start() {
	go c.authRoutine()
	go c.mapRoutine()
	go c.updateRoutine()
}

// updateControl sends a new OmitPeers, non-streaming map request (to just send
// Hostinfo/Netinfo/Endpoints info, while keeping an existing streaming response
// open).
//
// It should be called whenever there's something new to tell the server.
func (c *Auto) updateControl() {
	gen := nextUpdateGen()
	c.mu.Lock()
	if gen < c.lastUpdateGen {
		// This update is out of date.
		c.mu.Unlock()
		return
	}
	c.lastUpdateGen = gen
	c.mu.Unlock()

	select {
	case c.updateCh <- struct{}{}:
	default:
	}
}

// cancelAuthCtxLocked is like cancelAuthCtx, but assumes the caller holds c.mu.
func (c *Auto) cancelAuthCtxLocked() {
	if c.authCancel != nil {
		c.authCancel()
	}
	if !c.closed {
		c.authCtx, c.authCancel = context.WithCancel(context.Background())
		c.authCtx = sockstats.WithSockStats(c.authCtx, sockstats.LabelControlClientAuto, c.logf)
	}
}

// cancelMapCtxLocked is like cancelMapCtx, but assumes the caller holds c.mu.
func (c *Auto) cancelMapCtxLocked() {
	if c.mapCancel != nil {
		c.mapCancel()
	}
	if !c.closed {
		c.mapCtx, c.mapCancel = context.WithCancel(context.Background())
		c.mapCtx = sockstats.WithSockStats(c.mapCtx, sockstats.LabelControlClientAuto, c.logf)
	}
}

// restartMap cancels the existing mapPoll and liteUpdates, and then starts a
// new one.
func (c *Auto) restartMap() {
	c.mu.Lock()
	c.cancelMapCtxLocked()
	synced := c.inMapPoll
	c.mu.Unlock()

	c.logf("[v1] restartMap: synced=%v", synced)
	c.updateControl()
}

func (c *Auto) authRoutine() {
	defer close(c.authDone)
	bo := backoff.NewBackoff("authRoutine", c.logf, 30*time.Second)

	for {
		if !c.waitUnpause("authRoutine") {
			c.logf("authRoutine: exiting")
			return
		}
		c.mu.Lock()
		goal := c.loginGoal
		ctx := c.authCtx
		if goal != nil {
			c.logf("[v1] authRoutine: %s; wantLoggedIn=%v", c.state, true)
		} else {
			c.logf("[v1] authRoutine: %s; goal=nil paused=%v", c.state, c.paused)
		}
		c.mu.Unlock()

		report := func(err error, msg string) {
			c.logf("[v1] %s: %v", msg, err)
			// don't send status updates for context errors,
			// since context cancelation is always on purpose.
			if ctx.Err() == nil {
				c.sendStatus("authRoutine-report", err, "", nil)
			}
		}

		if goal == nil {
			c.direct.health.SetAuthRoutineInError(nil)
			// Wait for user to Login or Logout.
			<-ctx.Done()
			c.logf("[v1] authRoutine: context done.")
			continue
		}

		c.mu.Lock()
		c.urlToVisit = goal.url
		if goal.url != "" {
			c.state = StateURLVisitRequired
		} else {
			c.state = StateAuthenticating
		}
		c.mu.Unlock()

		var url string
		var err error
		var f string
		if goal.url != "" {
			url, err = c.direct.WaitLoginURL(ctx, goal.url)
			f = "WaitLoginURL"
		} else {
			url, err = c.direct.TryLogin(ctx, goal.flags)
			f = "TryLogin"
		}
		if err != nil {
			c.direct.health.SetAuthRoutineInError(err)
			report(err, f)
			bo.BackOff(ctx, err)
			continue
		}
		if url != "" {
			// goal.url ought to be empty here. However, not all control servers
			// get this right, and logging about it here just generates noise.
			//
			// TODO(bradfitz): I don't follow that comment. Our own testcontrol
			// used by tstest/integration hits this path, in fact.
			if c.direct.panicOnUse {
				panic("tainted client")
			}
			c.mu.Lock()
			c.urlToVisit = url
			c.loginGoal = &LoginGoal{
				flags: LoginDefault,
				url:   url,
			}
			c.state = StateURLVisitRequired
			c.mu.Unlock()

			c.sendStatus("authRoutine-url", err, url, nil)
			if goal.url == url {
				// The server sent us the same URL we already tried,
				// backoff to avoid a busy loop.
				bo.BackOff(ctx, errors.New("login URL not changing"))
			} else {
				bo.BackOff(ctx, nil)
			}
			continue
		}

		// success
		c.direct.health.SetAuthRoutineInError(nil)
		c.mu.Lock()
		c.urlToVisit = ""
		c.loggedIn = true
		c.loginGoal = nil
		c.state = StateAuthenticated
		c.mu.Unlock()

		c.sendStatus("authRoutine-success", nil, "", nil)
		c.restartMap()
		bo.BackOff(ctx, nil)
	}
}

// ExpiryForTests returns the credential expiration time, or the zero value if
// the expiration time isn't known. It's used in tests only.
func (c *Auto) ExpiryForTests() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.expiry
}

// DirectForTest returns the underlying direct client object.
// It's used in tests only.
func (c *Auto) DirectForTest() *Direct {
	return c.direct
}

// unpausedChanLocked returns a new channel that gets sent
// either a true when unpaused or false on Auto.Shutdown.
//
// c.mu must be held
func (c *Auto) unpausedChanLocked() <-chan bool {
	unpaused := make(chan bool, 1)
	c.unpauseWaiters = append(c.unpauseWaiters, unpaused)
	return unpaused
}

// ClientID returns the ClientID of the direct controlClient
func (c *Auto) ClientID() int64 {
	return c.direct.ClientID()
}

// mapRoutineState is the state of Auto.mapRoutine while it's running.
type mapRoutineState struct {
	c  *Auto
	bo *backoff.Backoff
}

var _ NetmapDeltaUpdater = mapRoutineState{}

func (mrs mapRoutineState) UpdateFullNetmap(nm *netmap.NetworkMap) {
	c := mrs.c

	c.mu.Lock()
	ctx := c.mapCtx
	c.inMapPoll = true
	if c.loggedIn {
		c.state = StateSynchronized
	}
	c.expiry = nm.Expiry
	stillAuthed := c.loggedIn
	c.logf("[v1] mapRoutine: netmap received: %s", c.state)
	c.mu.Unlock()

	if stillAuthed {
		c.sendStatus("mapRoutine-got-netmap", nil, "", nm)
	}
	// Reset the backoff timer if we got a netmap.
	mrs.bo.BackOff(ctx, nil)
}

func (mrs mapRoutineState) UpdateNetmapDelta(muts []netmap.NodeMutation) bool {
	c := mrs.c

	c.mu.Lock()
	goodState := c.loggedIn && c.inMapPoll
	ndu, canDelta := c.observer.(NetmapDeltaUpdater)
	c.mu.Unlock()

	if !goodState || !canDelta {
		return false
	}

	ctx, cancel := context.WithTimeout(c.mapCtx, 2*time.Second)
	defer cancel()

	var ok bool
	err := c.observerQueue.RunSync(ctx, func() {
		ok = ndu.UpdateNetmapDelta(muts)
	})
	return err == nil && ok
}

// mapRoutine is responsible for keeping a read-only streaming connection to the
// control server, and keeping the netmap up to date.
func (c *Auto) mapRoutine() {
	defer close(c.mapDone)
	mrs := mapRoutineState{
		c:  c,
		bo: backoff.NewBackoff("mapRoutine", c.logf, 30*time.Second),
	}

	for {
		if !c.waitUnpause("mapRoutine") {
			c.logf("mapRoutine: exiting")
			return
		}

		c.mu.Lock()
		c.logf("[v1] mapRoutine: %s", c.state)
		loggedIn := c.loggedIn
		ctx := c.mapCtx
		c.mu.Unlock()

		report := func(err error, msg string) {
			c.logf("[v1] %s: %v", msg, err)
			err = fmt.Errorf("%s: %w", msg, err)
			// don't send status updates for context errors,
			// since context cancelation is always on purpose.
			if ctx.Err() == nil {
				c.sendStatus("mapRoutine1", err, "", nil)
			}
		}

		if !loggedIn {
			// Wait for something interesting to happen
			c.mu.Lock()
			c.inMapPoll = false
			c.mu.Unlock()

			<-ctx.Done()
			c.logf("[v1] mapRoutine: context done.")
			continue
		}
		c.direct.health.SetOutOfPollNetMap()

		err := c.direct.PollNetMap(ctx, mrs)

		c.direct.health.SetOutOfPollNetMap()
		c.mu.Lock()
		c.inMapPoll = false
		if c.state == StateSynchronized {
			c.state = StateAuthenticated
		}
		paused := c.paused
		c.mu.Unlock()

		if paused {
			mrs.bo.BackOff(ctx, nil)
			c.logf("mapRoutine: paused")
		} else {
			mrs.bo.BackOff(ctx, err)
			report(err, "PollNetMap")
		}
	}
}

func (c *Auto) AuthCantContinue() bool {
	if c == nil {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	return !c.loggedIn && (c.loginGoal == nil || c.loginGoal.url != "")
}

func (c *Auto) SetHostinfo(hi *tailcfg.Hostinfo) {
	if hi == nil {
		panic("nil Hostinfo")
	}
	if !c.direct.SetHostinfo(hi) {
		// No changes. Don't log.
		return
	}

	// Send new Hostinfo to server
	c.updateControl()
}

func (c *Auto) SetNetInfo(ni *tailcfg.NetInfo) {
	if ni == nil {
		panic("nil NetInfo")
	}
	if !c.direct.SetNetInfo(ni) {
		return
	}

	// Send new NetInfo to server
	c.updateControl()
}

// SetTKAHead updates the TKA head hash that map-request infrastructure sends.
func (c *Auto) SetTKAHead(headHash string) {
	if !c.direct.SetTKAHead(headHash) {
		return
	}

	// Send new TKAHead to server
	c.updateControl()
}

// sendStatus can not be called with the c.mu held.
func (c *Auto) sendStatus(who string, err error, url string, nm *netmap.NetworkMap) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	state := c.state
	loggedIn := c.loggedIn
	inMapPoll := c.inMapPoll
	c.mu.Unlock()

	c.logf("[v1] sendStatus: %s: %v", who, state)

	var p persist.PersistView
	if nm != nil && loggedIn && inMapPoll {
		p = c.direct.GetPersist()
	} else {
		// don't send netmap status, as it's misleading when we're
		// not logged in.
		nm = nil
	}
	newSt := &Status{
		URL:     url,
		Persist: p,
		NetMap:  nm,
		Err:     err,
		state:   state,
	}
	c.lastStatus.Store(newSt)

	// Launch a new goroutine to avoid blocking the caller while the observer
	// does its thing, which may result in a call back into the client.
	metricQueued.Add(1)
	c.observerQueue.Add(func() {
		if canSkipStatus(newSt, c.lastStatus.Load()) {
			metricSkippable.Add(1)
			if !c.direct.controlKnobs.DisableSkipStatusQueue.Load() {
				metricSkipped.Add(1)
				return
			}
		}
		c.observer.SetControlClientStatus(c, *newSt)

		// Best effort stop retaining the memory now that we've sent it to the
		// observer (LocalBackend). We CAS here because the caller goroutine is
		// doing a Store which we want to win a race. This is only a memory
		// optimization and is not for correctness.
		//
		// If the CAS fails, that means somebody else's Store replaced our
		// pointer (so mission accomplished: our netmap is no longer retained in
		// any case) and that Store caller will be responsible for removing
		// their own netmap (or losing their race too, down the chain).
		// Eventually the last caller will win this CAS and zero lastStatus.
		c.lastStatus.CompareAndSwap(newSt, nil)
	})
}

var (
	metricQueued    = clientmetric.NewCounter("controlclient_auto_status_queued")
	metricSkippable = clientmetric.NewCounter("controlclient_auto_status_queue_skippable")
	metricSkipped   = clientmetric.NewCounter("controlclient_auto_status_queue_skipped")
)

// canSkipStatus reports whether we can skip sending s1, knowing
// that s2 is enqueued sometime in the future after s1.
//
// s1 must be non-nil. s2 may be nil.
func canSkipStatus(s1, s2 *Status) bool {
	if s2 == nil {
		// Nothing in the future.
		return false
	}
	if s1 == s2 {
		// If the last item in the queue is the same as s1,
		// we can't skip it.
		return false
	}
	if s1.Err != nil || s1.URL != "" {
		// If s1 has an error or a URL, we shouldn't skip it, lest the error go
		// away in s2 or in-between. We want to make sure all the subsystems see
		// it. Plus there aren't many of these, so not worth skipping.
		return false
	}
	if !s1.Persist.Equals(s2.Persist) || s1.state != s2.state {
		// If s1 has a different Persist or state than s2,
		// don't skip it. We only care about skipping the typical
		// entries where the only difference is the NetMap.
		return false
	}
	// If nothing above precludes it, and both s1 and s2 have NetMaps, then
	// we can skip it, because s2's NetMap is a newer version and we can
	// jump straight from whatever state we had before to s2's state,
	// without passing through s1's state first. A NetMap is regrettably a
	// full snapshot of the state, not an incremental delta. We're slowly
	// moving towards passing around only deltas around internally at all
	// layers, but this is explicitly the case where we didn't have a delta
	// path for the message we received over the wire and had to resort
	// to the legacy full NetMap path. And then we can get behind processing
	// these full NetMap snapshots in LocalBackend/wgengine/magicsock/netstack
	// and this path (when it returns true) lets us skip over useless work
	// and not get behind in the queue. This matters in particular for tailnets
	// that are both very large + very churny.
	return s1.NetMap != nil && s2.NetMap != nil
}

func (c *Auto) Login(flags LoginFlags) {
	c.logf("client.Login(%v)", flags)

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	if c.direct != nil && c.direct.panicOnUse {
		panic("tainted client")
	}
	c.wantLoggedIn = true
	c.loginGoal = &LoginGoal{
		flags: flags,
	}
	c.cancelMapCtxLocked()
	c.cancelAuthCtxLocked()
}

var ErrClientClosed = errors.New("client closed")

func (c *Auto) Logout(ctx context.Context) error {
	c.logf("client.Logout()")
	c.mu.Lock()
	c.wantLoggedIn = false
	c.loginGoal = nil
	closed := c.closed
	if c.direct != nil && c.direct.panicOnUse {
		panic("tainted client")
	}
	c.mu.Unlock()

	if closed {
		return ErrClientClosed
	}

	if err := c.direct.TryLogout(ctx); err != nil {
		return err
	}
	c.mu.Lock()
	c.loggedIn = false
	c.state = StateNotAuthenticated
	c.cancelAuthCtxLocked()
	c.cancelMapCtxLocked()
	c.mu.Unlock()

	c.sendStatus("authRoutine-wantout", nil, "", nil)
	return nil
}

func (c *Auto) SetExpirySooner(ctx context.Context, expiry time.Time) error {
	return c.direct.SetExpirySooner(ctx, expiry)
}

// UpdateEndpoints sets the client's discovered endpoints and sends
// them to the control server if they've changed.
//
// It does not retain the provided slice.
func (c *Auto) UpdateEndpoints(endpoints []tailcfg.Endpoint) {
	changed := c.direct.SetEndpoints(endpoints)
	if changed {
		c.updateControl()
	}
}

func (c *Auto) Shutdown() {
	c.eventSubs.Close()

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.logf("client.Shutdown ...")
	shutdownFn := c.shutdownFn

	direct := c.direct
	c.closed = true
	c.observerQueue.Shutdown()
	c.cancelAuthCtxLocked()
	c.cancelMapCtxLocked()
	for _, w := range c.unpauseWaiters {
		w <- false
	}
	c.unpauseWaiters = nil
	c.mu.Unlock()

	if shutdownFn != nil {
		shutdownFn()
	}

	<-c.authDone
	<-c.mapDone
	<-c.updateDone
	if direct != nil {
		direct.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c.observerQueue.Wait(ctx)
	c.logf("Client.Shutdown done.")
}

// NodePublicKey returns the node public key currently in use. This is
// used exclusively in tests.
func (c *Auto) TestOnlyNodePublicKey() key.NodePublic {
	priv := c.direct.GetPersist()
	return priv.PrivateNodeKey().Public()
}

func (c *Auto) TestOnlySetAuthKey(authkey string) {
	c.direct.mu.Lock()
	defer c.direct.mu.Unlock()
	c.direct.authKey = authkey
}

func (c *Auto) TestOnlyTimeNow() time.Time {
	return c.clock.Now()
}

// SetDNS sends the SetDNSRequest request to the control plane server,
// requesting a DNS record be created or updated.
func (c *Auto) SetDNS(ctx context.Context, req *tailcfg.SetDNSRequest) error {
	return c.direct.SetDNS(ctx, req)
}

func (c *Auto) DoNoiseRequest(req *http.Request) (*http.Response, error) {
	return c.direct.DoNoiseRequest(req)
}
