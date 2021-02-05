// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package controlclient implements the client for the Tailscale
// control plane.
//
// It handles authentication, port picking, and collects the local
// network configuration.
package controlclient

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"tailscale.com/logtail/backoff"
	"tailscale.com/tailcfg"
	"tailscale.com/types/empty"
	"tailscale.com/types/logger"
	"tailscale.com/types/persist"
	"tailscale.com/types/structs"
	"tailscale.com/types/wgkey"
)

// State is the high-level state of the client. It is used only in
// unit tests for proper sequencing, don't depend on it anywhere else.
// TODO(apenwarr): eliminate 'state', as it's now obsolete.
type State int

const (
	StateNew = State(iota)
	StateNotAuthenticated
	StateAuthenticating
	StateURLVisitRequired
	StateAuthenticated
	StateSynchronized // connected and received map update
)

func (s State) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

func (s State) String() string {
	switch s {
	case StateNew:
		return "state:new"
	case StateNotAuthenticated:
		return "state:not-authenticated"
	case StateAuthenticating:
		return "state:authenticating"
	case StateURLVisitRequired:
		return "state:url-visit-required"
	case StateAuthenticated:
		return "state:authenticated"
	case StateSynchronized:
		return "state:synchronized"
	default:
		return fmt.Sprintf("state:unknown:%d", int(s))
	}
}

type Status struct {
	_             structs.Incomparable
	LoginFinished *empty.Message
	Err           string
	URL           string
	Persist       *persist.Persist  // locally persisted configuration
	NetMap        *NetworkMap       // server-pushed configuration
	Hostinfo      *tailcfg.Hostinfo // current Hostinfo data
	State         State
}

// Equal reports whether s and s2 are equal.
func (s *Status) Equal(s2 *Status) bool {
	if s == nil && s2 == nil {
		return true
	}
	return s != nil && s2 != nil &&
		(s.LoginFinished == nil) == (s2.LoginFinished == nil) &&
		s.Err == s2.Err &&
		s.URL == s2.URL &&
		reflect.DeepEqual(s.Persist, s2.Persist) &&
		reflect.DeepEqual(s.NetMap, s2.NetMap) &&
		reflect.DeepEqual(s.Hostinfo, s2.Hostinfo) &&
		s.State == s2.State
}

func (s Status) String() string {
	b, err := json.MarshalIndent(s, "", "\t")
	if err != nil {
		panic(err)
	}
	return s.State.String() + " " + string(b)
}

type LoginGoal struct {
	_            structs.Incomparable
	wantLoggedIn bool          // true if we *want* to be logged in
	token        *oauth2.Token // oauth token to use when logging in
	flags        LoginFlags    // flags to use when logging in
	url          string        // auth url that needs to be visited
}

// Client connects to a tailcontrol server for a node.
type Client struct {
	direct   *Direct // our interface to the server APIs
	timeNow  func() time.Time
	logf     logger.Logf
	expiry   *time.Time
	closed   bool
	newMapCh chan struct{} // readable when we must restart a map request

	mu         sync.Mutex   // mutex guards the following fields
	statusFunc func(Status) // called to update Client status

	paused          bool // whether we should stop making HTTP requests
	unpauseWaiters  []chan struct{}
	loggedIn        bool       // true if currently logged in
	loginGoal       *LoginGoal // non-nil if some login activity is desired
	synced          bool       // true if our netmap is up-to-date
	hostinfo        *tailcfg.Hostinfo
	inPollNetMap    bool // true if currently running a PollNetMap
	inLiteMapUpdate bool // true if a lite (non-streaming) map request is outstanding
	inSendStatus    int  // number of sendStatus calls currently in progress
	state           State

	authCtx    context.Context // context used for auth requests
	mapCtx     context.Context // context used for netmap requests
	authCancel func()          // cancel the auth context
	mapCancel  func()          // cancel the netmap context
	quit       chan struct{}   // when closed, goroutines should all exit
	authDone   chan struct{}   // when closed, auth goroutine is done
	mapDone    chan struct{}   // when closed, map goroutine is done
}

// New creates and starts a new Client.
func New(opts Options) (*Client, error) {
	c, err := NewNoStart(opts)
	if c != nil {
		c.Start()
	}
	return c, err
}

// NewNoStart creates a new Client, but without calling Start on it.
func NewNoStart(opts Options) (*Client, error) {
	direct, err := NewDirect(opts)
	if err != nil {
		return nil, err
	}
	if opts.Logf == nil {
		opts.Logf = func(fmt string, args ...interface{}) {}
	}
	if opts.TimeNow == nil {
		opts.TimeNow = time.Now
	}
	c := &Client{
		direct:   direct,
		timeNow:  opts.TimeNow,
		logf:     opts.Logf,
		newMapCh: make(chan struct{}, 1),
		quit:     make(chan struct{}),
		authDone: make(chan struct{}),
		mapDone:  make(chan struct{}),
	}
	c.authCtx, c.authCancel = context.WithCancel(context.Background())
	c.mapCtx, c.mapCancel = context.WithCancel(context.Background())
	return c, nil
}

// SetPaused controls whether HTTP activity should be paused.
//
// The client can be paused and unpaused repeatedly, unlike Start and Shutdown, which can only be used once.
func (c *Client) SetPaused(paused bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if paused == c.paused {
		return
	}
	c.paused = paused
	if paused {
		// Only cancel the map routine. (The auth routine isn't expensive
		// so it's fine to keep it running.)
		c.cancelMapLocked()
	} else {
		for _, ch := range c.unpauseWaiters {
			close(ch)
		}
		c.unpauseWaiters = nil
	}
}

// Start starts the client's goroutines.
//
// It should only be called for clients created by NewNoStart.
func (c *Client) Start() {
	go c.authRoutine()
	go c.mapRoutine()
}

// sendNewMapRequest either sends a new OmitPeers, non-streaming map request
// (to just send Hostinfo/Netinfo/Endpoints info, while keeping an existing
// streaming response open), or start a new streaming one if necessary.
//
// It should be called whenever there's something new to tell the server.
func (c *Client) sendNewMapRequest() {
	c.mu.Lock()

	// If we're not already streaming a netmap, or if we're already stuck
	// in a lite update, then tear down everything and start a new stream
	// (which starts by sending a new map request)
	if !c.inPollNetMap || c.inLiteMapUpdate || !c.loggedIn {
		c.mu.Unlock()
		c.cancelMapSafely()
		return
	}

	// Otherwise, send a lite update that doesn't keep a
	// long-running stream response.
	defer c.mu.Unlock()
	c.inLiteMapUpdate = true
	ctx, cancel := context.WithTimeout(c.mapCtx, 10*time.Second)
	go func() {
		defer cancel()
		t0 := time.Now()
		err := c.direct.SendLiteMapUpdate(ctx)
		d := time.Since(t0).Round(time.Millisecond)
		c.mu.Lock()
		c.inLiteMapUpdate = false
		c.mu.Unlock()
		if err == nil {
			c.logf("[v1] successful lite map update in %v", d)
			return
		}
		if ctx.Err() == nil {
			c.logf("lite map update after %v: %v", d, err)
		}
		// Fall back to restarting the long-polling map
		// request (the old heavy way) if the lite update
		// failed for any reason.
		c.cancelMapSafely()
	}()
}

func (c *Client) cancelAuth() {
	c.mu.Lock()
	if c.authCancel != nil {
		c.authCancel()
	}
	if !c.closed {
		c.authCtx, c.authCancel = context.WithCancel(context.Background())
	}
	c.mu.Unlock()
}

func (c *Client) cancelMapLocked() {
	if c.mapCancel != nil {
		c.mapCancel()
	}
	if !c.closed {
		c.mapCtx, c.mapCancel = context.WithCancel(context.Background())
	}
}

func (c *Client) cancelMapUnsafely() {
	c.mu.Lock()
	c.cancelMapLocked()
	c.mu.Unlock()
}

func (c *Client) cancelMapSafely() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.logf("[v1] cancelMapSafely: synced=%v", c.synced)

	if c.inPollNetMap {
		// received at least one netmap since the last
		// interruption. That means the server has already
		// fully processed our last request, which might
		// include UpdateEndpoints(). Interrupt it and try
		// again.
		c.cancelMapLocked()
	} else {
		// !synced means we either haven't done a netmap
		// request yet, or it hasn't answered yet. So the
		// server is in an undefined state. If we send
		// another netmap request too soon, it might race
		// with the last one, and if we're very unlucky,
		// the new request will be applied before the old one,
		// and the wrong endpoints will get registered. We
		// have to tell the client to abort politely, only
		// after it receives a response to its existing netmap
		// request.
		select {
		case c.newMapCh <- struct{}{}:
			c.logf("[v1] cancelMapSafely: wrote to channel")
		default:
			// if channel write failed, then there was already
			// an outstanding newMapCh request. One is enough,
			// since it'll always use the latest endpoints.
			c.logf("[v1] cancelMapSafely: channel was full")
		}
	}
}

func (c *Client) authRoutine() {
	defer close(c.authDone)
	bo := backoff.NewBackoff("authRoutine", c.logf, 30*time.Second)

	for {
		c.mu.Lock()
		goal := c.loginGoal
		ctx := c.authCtx
		if goal != nil {
			c.logf("authRoutine: %s; wantLoggedIn=%v", c.state, goal.wantLoggedIn)
		} else {
			c.logf("authRoutine: %s; goal=nil", c.state)
		}
		c.mu.Unlock()

		select {
		case <-c.quit:
			c.logf("[v1] authRoutine: quit")
			return
		default:
		}

		report := func(err error, msg string) {
			c.logf("[v1] %s: %v", msg, err)
			err = fmt.Errorf("%s: %v", msg, err)
			// don't send status updates for context errors,
			// since context cancelation is always on purpose.
			if ctx.Err() == nil {
				c.sendStatus("authRoutine-report", err, "", nil)
			}
		}

		if goal == nil {
			// Wait for user to Login or Logout.
			<-ctx.Done()
			c.logf("[v1] authRoutine: context done.")
			continue
		}

		if !goal.wantLoggedIn {
			err := c.direct.TryLogout(ctx)
			if err != nil {
				report(err, "TryLogout")
				bo.BackOff(ctx, err)
				continue
			}

			// success
			c.mu.Lock()
			c.loggedIn = false
			c.loginGoal = nil
			c.state = StateNotAuthenticated
			c.synced = false
			c.mu.Unlock()

			c.sendStatus("authRoutine-wantout", nil, "", nil)
			bo.BackOff(ctx, nil)
		} else { // ie. goal.wantLoggedIn
			c.mu.Lock()
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
				url, err = c.direct.TryLogin(ctx, goal.token, goal.flags)
				f = "TryLogin"
			}
			if err != nil {
				report(err, f)
				bo.BackOff(ctx, err)
				continue
			} else if url != "" {
				if goal.url != "" {
					err = fmt.Errorf("weird: server required a new url?")
					report(err, "WaitLoginURL")
				}

				c.mu.Lock()
				c.loginGoal = &LoginGoal{
					wantLoggedIn: true,
					flags:        LoginDefault,
					url:          url,
				}
				c.state = StateURLVisitRequired
				c.synced = false
				c.mu.Unlock()

				c.sendStatus("authRoutine-url", err, url, nil)
				bo.BackOff(ctx, err)
				continue
			}

			// success
			c.mu.Lock()
			c.loggedIn = true
			c.loginGoal = nil
			c.state = StateAuthenticated
			c.mu.Unlock()

			c.sendStatus("authRoutine-success", nil, "", nil)
			c.cancelMapSafely()
			bo.BackOff(ctx, nil)
		}
	}
}

// Expiry returns the credential expiration time, or the zero time if
// the expiration time isn't known. Used in tests only.
func (c *Client) Expiry() *time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.expiry
}

// Direct returns the underlying direct client object. Used in tests
// only.
func (c *Client) Direct() *Direct {
	return c.direct
}

// unpausedChanLocked returns a new channel that is closed when the
// current Client pause is unpaused.
//
// c.mu must be held
func (c *Client) unpausedChanLocked() <-chan struct{} {
	unpaused := make(chan struct{})
	c.unpauseWaiters = append(c.unpauseWaiters, unpaused)
	return unpaused
}

func (c *Client) mapRoutine() {
	defer close(c.mapDone)
	bo := backoff.NewBackoff("mapRoutine", c.logf, 30*time.Second)

	for {
		c.mu.Lock()
		if c.paused {
			unpaused := c.unpausedChanLocked()
			c.mu.Unlock()
			c.logf("mapRoutine: awaiting unpause")
			select {
			case <-unpaused:
				c.logf("mapRoutine: unpaused")
			case <-c.quit:
				c.logf("mapRoutine: quit")
				return
			}
			continue
		}
		c.logf("mapRoutine: %s", c.state)
		loggedIn := c.loggedIn
		ctx := c.mapCtx
		c.mu.Unlock()

		select {
		case <-c.quit:
			c.logf("mapRoutine: quit")
			return
		default:
		}

		report := func(err error, msg string) {
			c.logf("[v1] %s: %v", msg, err)
			err = fmt.Errorf("%s: %v", msg, err)
			// don't send status updates for context errors,
			// since context cancelation is always on purpose.
			if ctx.Err() == nil {
				c.sendStatus("mapRoutine1", err, "", nil)
			}
		}

		if !loggedIn {
			// Wait for something interesting to happen
			c.mu.Lock()
			c.synced = false
			// c.state is set by authRoutine()
			c.mu.Unlock()

			select {
			case <-ctx.Done():
				c.logf("mapRoutine: context done.")
			case <-c.newMapCh:
				c.logf("mapRoutine: new map needed while idle.")
			}
		} else {
			// Be sure this is false when we're not inside
			// PollNetMap, so that cancelMapSafely() can notify
			// us correctly.
			c.mu.Lock()
			c.inPollNetMap = false
			c.mu.Unlock()

			err := c.direct.PollNetMap(ctx, -1, func(nm *NetworkMap) {
				c.mu.Lock()

				select {
				case <-c.newMapCh:
					c.logf("[v1] mapRoutine: new map request during PollNetMap. canceling.")
					c.cancelMapLocked()

					// Don't emit this netmap; we're
					// about to request a fresh one.
					c.mu.Unlock()
					return
				default:
				}

				c.synced = true
				c.inPollNetMap = true
				if c.loggedIn {
					c.state = StateSynchronized
				}
				exp := nm.Expiry
				c.expiry = &exp
				stillAuthed := c.loggedIn
				state := c.state

				c.mu.Unlock()

				c.logf("[v1] mapRoutine: netmap received: %s", state)
				if stillAuthed {
					c.sendStatus("mapRoutine-got-netmap", nil, "", nm)
				}
			})

			c.mu.Lock()
			c.synced = false
			c.inPollNetMap = false
			if c.state == StateSynchronized {
				c.state = StateAuthenticated
			}
			paused := c.paused
			c.mu.Unlock()

			if paused {
				c.logf("mapRoutine: paused")
				continue
			}

			if err != nil {
				report(err, "PollNetMap")
				bo.BackOff(ctx, err)
				continue
			}
			bo.BackOff(ctx, nil)
		}
	}
}

func (c *Client) AuthCantContinue() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	return !c.loggedIn && (c.loginGoal == nil || c.loginGoal.url != "")
}

func (c *Client) SetStatusFunc(fn func(Status)) {
	c.mu.Lock()
	c.statusFunc = fn
	c.mu.Unlock()
}

func (c *Client) SetHostinfo(hi *tailcfg.Hostinfo) {
	if hi == nil {
		panic("nil Hostinfo")
	}
	if !c.direct.SetHostinfo(hi) {
		// No changes. Don't log.
		return
	}
	c.logf("Hostinfo: %v", hi)

	// Send new Hostinfo to server
	c.sendNewMapRequest()
}

func (c *Client) SetNetInfo(ni *tailcfg.NetInfo) {
	if ni == nil {
		panic("nil NetInfo")
	}
	if !c.direct.SetNetInfo(ni) {
		return
	}
	c.logf("NetInfo: %v", ni)

	// Send new Hostinfo (which includes NetInfo) to server
	c.sendNewMapRequest()
}

func (c *Client) sendStatus(who string, err error, url string, nm *NetworkMap) {
	c.mu.Lock()
	state := c.state
	loggedIn := c.loggedIn
	synced := c.synced
	statusFunc := c.statusFunc
	hi := c.hostinfo
	c.inSendStatus++
	c.mu.Unlock()

	c.logf("[v1] sendStatus: %s: %v", who, state)

	var p *persist.Persist
	var fin *empty.Message
	if state == StateAuthenticated {
		fin = new(empty.Message)
	}
	if nm != nil && loggedIn && synced {
		pp := c.direct.GetPersist()
		p = &pp
	} else {
		// don't send netmap status, as it's misleading when we're
		// not logged in.
		nm = nil
	}
	new := Status{
		LoginFinished: fin,
		URL:           url,
		Persist:       p,
		NetMap:        nm,
		Hostinfo:      hi,
		State:         state,
	}
	if err != nil {
		new.Err = err.Error()
	}
	if statusFunc != nil {
		statusFunc(new)
	}

	c.mu.Lock()
	c.inSendStatus--
	c.mu.Unlock()
}

func (c *Client) Login(t *oauth2.Token, flags LoginFlags) {
	c.logf("client.Login(%v, %v)", t != nil, flags)

	c.mu.Lock()
	c.loginGoal = &LoginGoal{
		wantLoggedIn: true,
		token:        t,
		flags:        flags,
	}
	c.mu.Unlock()

	c.cancelAuth()
}

func (c *Client) Logout() {
	c.logf("client.Logout()")

	c.mu.Lock()
	c.loginGoal = &LoginGoal{
		wantLoggedIn: false,
	}
	c.mu.Unlock()

	c.cancelAuth()
}

func (c *Client) UpdateEndpoints(localPort uint16, endpoints []string) {
	changed := c.direct.SetEndpoints(localPort, endpoints)
	if changed {
		c.sendNewMapRequest()
	}
}

func (c *Client) Shutdown() {
	c.logf("client.Shutdown()")

	c.mu.Lock()
	inSendStatus := c.inSendStatus
	closed := c.closed
	if !closed {
		c.closed = true
		c.statusFunc = nil
	}
	c.mu.Unlock()

	c.logf("client.Shutdown: inSendStatus=%v", inSendStatus)
	if !closed {
		close(c.quit)
		c.cancelAuth()
		<-c.authDone
		c.cancelMapUnsafely()
		<-c.mapDone
		c.logf("Client.Shutdown done.")
	}
}

// NodePublicKey returns the node public key currently in use. This is
// used exclusively in tests.
func (c *Client) TestOnlyNodePublicKey() wgkey.Key {
	priv := c.direct.GetPersist()
	return priv.PrivateNodeKey.Public()
}

func (c *Client) TestOnlySetAuthKey(authkey string) {
	c.direct.mu.Lock()
	defer c.direct.mu.Unlock()
	c.direct.authKey = authkey
}

func (c *Client) TestOnlyTimeNow() time.Time {
	return c.timeNow()
}
