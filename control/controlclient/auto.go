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
)

// TODO(apenwarr): eliminate the 'state' variable, as it's now obsolete.
//  It's used only by the unit tests.
type state int

const (
	stateNew = state(iota)
	stateNotAuthenticated
	stateAuthenticating
	stateURLVisitRequired
	stateAuthenticated
	stateSynchronized // connected and received map update
)

func (s state) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

func (s state) String() string {
	switch s {
	case stateNew:
		return "state:new"
	case stateNotAuthenticated:
		return "state:not-authenticated"
	case stateAuthenticating:
		return "state:authenticating"
	case stateURLVisitRequired:
		return "state:url-visit-required"
	case stateAuthenticated:
		return "state:authenticated"
	case stateSynchronized:
		return "state:synchronized"
	default:
		return fmt.Sprintf("state:unknown:%d", int(s))
	}
}

type Status struct {
	LoginFinished *empty.Message
	Err           string
	URL           string
	Persist       *Persist          // locally persisted configuration
	NetMap        *NetworkMap       // server-pushed configuration
	Hostinfo      *tailcfg.Hostinfo // current Hostinfo data
	state         state
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
		s.state == s2.state
}

func (s Status) String() string {
	b, err := json.MarshalIndent(s, "", "\t")
	if err != nil {
		panic(err)
	}
	return s.state.String() + " " + string(b)
}

type LoginGoal struct {
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

	loggedIn     bool       // true if currently logged in
	loginGoal    *LoginGoal // non-nil if some login activity is desired
	synced       bool       // true if our netmap is up-to-date
	hostinfo     *tailcfg.Hostinfo
	inPollNetMap bool // true if currently running a PollNetMap
	inSendStatus int  // number of sendStatus calls currently in progress
	state        state

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

// Start starts the client's goroutines.
//
// It should only be called for clients created by NewNoStart.
func (c *Client) Start() {
	go c.authRoutine()
	go c.mapRoutine()
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

	c.logf("cancelMapSafely: synced=%v\n", c.synced)

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
			c.logf("cancelMapSafely: wrote to channel\n")
		default:
			// if channel write failed, then there was already
			// an outstanding newMapCh request. One is enough,
			// since it'll always use the latest endpoints.
			c.logf("cancelMapSafely: channel was full\n")
		}
	}
}

func (c *Client) authRoutine() {
	defer close(c.authDone)
	bo := backoff.Backoff{Name: "authRoutine"}

	for {
		c.mu.Lock()
		c.logf("authRoutine: %s\n", c.state)
		expiry := c.expiry
		goal := c.loginGoal
		ctx := c.authCtx
		synced := c.synced
		c.mu.Unlock()

		select {
		case <-c.quit:
			c.logf("authRoutine: quit\n")
			return
		default:
		}

		report := func(err error, msg string) {
			c.logf("%s: %v\n", msg, err)
			err = fmt.Errorf("%s: %v", msg, err)
			// don't send status updates for context errors,
			// since context cancelation is always on purpose.
			if ctx.Err() == nil {
				c.sendStatus("authRoutine1", err, "", nil)
			}
		}

		if goal == nil {
			// Wait for something interesting to happen
			var exp <-chan time.Time
			if expiry != nil && !expiry.IsZero() {
				// if expiry is in the future, don't delay
				// past that time.
				// If it's in the past, then it's already
				// being handled by someone, so no need to
				// wake ourselves up again.
				now := c.timeNow()
				if expiry.Before(now) {
					delay := expiry.Sub(now)
					if delay > 5*time.Second {
						delay = time.Second
					}
					exp = time.After(delay)
				}
			}
			select {
			case <-ctx.Done():
				c.logf("authRoutine: context done.\n")
			case <-exp:
				// Unfortunately the key expiry isn't provided
				// by the control server until mapRequest.
				// So we have to do some hackery with c.expiry
				// in here.
				// TODO(apenwarr): add a key expiry field in RegisterResponse.
				c.logf("authRoutine: key expiration check.\n")
				if synced && expiry != nil && !expiry.IsZero() && expiry.Before(c.timeNow()) {
					c.logf("Key expired; setting loggedIn=false.")

					c.mu.Lock()
					c.loginGoal = &LoginGoal{
						wantLoggedIn: c.loggedIn,
					}
					c.loggedIn = false
					c.expiry = nil
					c.mu.Unlock()
				}
			}
		} else if !goal.wantLoggedIn {
			err := c.direct.TryLogout(c.authCtx)
			if err != nil {
				report(err, "TryLogout")
				bo.BackOff(ctx, err)
				continue
			}

			// success
			c.mu.Lock()
			c.loggedIn = false
			c.loginGoal = nil
			c.state = stateNotAuthenticated
			c.synced = false
			c.mu.Unlock()

			c.sendStatus("authRoutine2", nil, "", nil)
			bo.BackOff(ctx, nil)
		} else { // ie. goal.wantLoggedIn
			c.mu.Lock()
			if goal.url != "" {
				c.state = stateURLVisitRequired
			} else {
				c.state = stateAuthenticating
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
				goal.url = url
				goal.token = nil
				goal.flags = LoginDefault

				c.mu.Lock()
				c.loginGoal = goal
				c.state = stateURLVisitRequired
				c.synced = false
				c.mu.Unlock()

				c.sendStatus("authRoutine3", err, url, nil)
				bo.BackOff(ctx, err)
				continue
			}

			// success
			c.mu.Lock()
			c.loggedIn = true
			c.loginGoal = nil
			c.state = stateAuthenticated
			c.mu.Unlock()

			c.sendStatus("authRoutine4", nil, "", nil)
			c.cancelMapSafely()
			bo.BackOff(ctx, nil)
		}
	}
}

func (c *Client) mapRoutine() {
	defer close(c.mapDone)
	bo := backoff.Backoff{Name: "mapRoutine"}

	for {
		c.mu.Lock()
		c.logf("mapRoutine: %s\n", c.state)
		loggedIn := c.loggedIn
		ctx := c.mapCtx
		c.mu.Unlock()

		select {
		case <-c.quit:
			c.logf("mapRoutine: quit\n")
			return
		default:
		}

		report := func(err error, msg string) {
			c.logf("%s: %v\n", msg, err)
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
				c.logf("mapRoutine: context done.\n")
			case <-c.newMapCh:
				c.logf("mapRoutine: new map needed while idle.\n")
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
					c.logf("mapRoutine: new map request during PollNetMap. canceling.\n")
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
					c.state = stateSynchronized
				}
				exp := nm.Expiry
				c.expiry = &exp
				stillAuthed := c.loggedIn
				state := c.state

				c.mu.Unlock()

				c.logf("mapRoutine: netmap received: %s\n", state)
				if stillAuthed {
					c.sendStatus("mapRoutine2", nil, "", nm)
				}
			})

			c.mu.Lock()
			c.synced = false
			c.inPollNetMap = false
			if c.state == stateSynchronized {
				c.state = stateAuthenticated
			}
			c.mu.Unlock()

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
	c.direct.SetHostinfo(hi)
	// Send new Hostinfo to server
	c.cancelMapSafely()
}

func (c *Client) SetNetInfo(ni *tailcfg.NetInfo) {
	if ni == nil {
		panic("nil NetInfo")
	}
	c.direct.SetNetInfo(ni)
	// Send new Hostinfo (which includes NetInfo) to server
	c.cancelMapSafely()
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

	c.logf("sendStatus: %s: %v\n", who, state)

	var p *Persist
	var fin *empty.Message
	if state == stateAuthenticated {
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
		state:         state,
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
	c.logf("client.Login(%v, %v)\n", t != nil, flags)

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
	c.logf("client.Logout()\n")

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
		c.cancelMapSafely()
	}
}

func (c *Client) Shutdown() {
	c.logf("client.Shutdown()\n")

	c.mu.Lock()
	inSendStatus := c.inSendStatus
	closed := c.closed
	if !closed {
		c.closed = true
		c.statusFunc = nil
	}
	c.mu.Unlock()

	c.logf("client.Shutdown: inSendStatus=%v\n", inSendStatus)
	if !closed {
		close(c.quit)
		c.cancelAuth()
		<-c.authDone
		c.cancelMapUnsafely()
		<-c.mapDone
		c.logf("Client.Shutdown done.\n")
	}
}
