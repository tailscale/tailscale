// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"tailscale.com/client/local"
	"tailscale.com/client/tailscale"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/control/controlclient"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnauth"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tsd"
	"tailscale.com/tstest"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/types/ptr"
	"tailscale.com/util/mak"
	"tailscale.com/wgengine"
)

func TestWaiterSet(t *testing.T) {
	var s waiterSet

	wantLen := func(want int, when string) {
		t.Helper()
		if got := len(s); got != want {
			t.Errorf("%s: len = %v; want %v", when, got, want)
		}
	}
	wantLen(0, "initial")
	var mu sync.Mutex
	ctx, cancel := context.WithCancel(context.Background())

	ready, cleanup := s.add(&mu, ctx)
	wantLen(1, "after add")

	select {
	case <-ready:
		t.Fatal("should not be ready")
	default:
	}
	s.wakeAll()
	<-ready

	wantLen(1, "after fire")
	cleanup()
	wantLen(0, "after cleanup")

	// And again but on an already-expired ctx.
	cancel()
	ready, cleanup = s.add(&mu, ctx)
	<-ready // shouldn't block
	cleanup()
	wantLen(0, "at end")
}

func TestUserConnectDisconnectNonWindows(t *testing.T) {
	enableLogging := false
	if runtime.GOOS == "windows" {
		setGOOSForTest(t, "linux")
	}

	ctx := context.Background()
	server := startDefaultTestIPNServer(t, ctx, enableLogging)

	// UserA connects and starts watching the IPN bus.
	clientA := server.getClientAs("UserA")
	watcherA, _ := clientA.WatchIPNBus(ctx, 0)

	// The concept of "current user" is only relevant on Windows
	// and it should not be set on non-Windows platforms.
	server.checkCurrentUser(nil)

	// Additionally, a different user should be able to connect and use the LocalAPI.
	clientB := server.getClientAs("UserB")
	if _, gotErr := clientB.Status(ctx); gotErr != nil {
		t.Fatalf("Status(%q): want nil; got %v", clientB.User.Name, gotErr)
	}

	// Watching the IPN bus should also work for UserB.
	watcherB, _ := clientB.WatchIPNBus(ctx, 0)

	// And if we send a notification, both users should receive it.
	wantErrMessage := "test error"
	testNotify := ipn.Notify{ErrMessage: ptr.To(wantErrMessage)}
	server.mustBackend().DebugNotify(testNotify)

	if n, err := watcherA.Next(); err != nil {
		t.Fatalf("IPNBusWatcher.Next(%q): %v", clientA.User.Name, err)
	} else if gotErrMessage := n.ErrMessage; gotErrMessage == nil || *gotErrMessage != wantErrMessage {
		t.Fatalf("IPNBusWatcher.Next(%q): want %v; got %v", clientA.User.Name, wantErrMessage, gotErrMessage)
	}

	if n, err := watcherB.Next(); err != nil {
		t.Fatalf("IPNBusWatcher.Next(%q): %v", clientB.User.Name, err)
	} else if gotErrMessage := n.ErrMessage; gotErrMessage == nil || *gotErrMessage != wantErrMessage {
		t.Fatalf("IPNBusWatcher.Next(%q): want %v; got %v", clientB.User.Name, wantErrMessage, gotErrMessage)
	}
}

func TestUserConnectDisconnectOnWindows(t *testing.T) {
	enableLogging := false
	setGOOSForTest(t, "windows")

	ctx := context.Background()
	server := startDefaultTestIPNServer(t, ctx, enableLogging)

	client := server.getClientAs("User")
	_, cancelWatcher := client.WatchIPNBus(ctx, 0)

	// On Windows, however, the current user should be set to the user that connected.
	server.checkCurrentUser(client.User)

	// Cancel the IPN bus watcher request and wait for the server to unblock.
	cancelWatcher()
	server.blockWhileInUse(ctx)

	// The current user should not be set after a disconnect, as no one is
	// currently using the server.
	server.checkCurrentUser(nil)
}

func TestIPNAlreadyInUseOnWindows(t *testing.T) {
	enableLogging := false
	setGOOSForTest(t, "windows")

	ctx := context.Background()
	server := startDefaultTestIPNServer(t, ctx, enableLogging)

	// UserA connects and starts watching the IPN bus.
	clientA := server.getClientAs("UserA")
	clientA.WatchIPNBus(ctx, 0)

	// While UserA is connected, UserB should not be able to connect.
	clientB := server.getClientAs("UserB")
	if _, gotErr := clientB.Status(ctx); gotErr == nil {
		t.Fatalf("Status(%q): want error; got nil", clientB.User.Name)
	} else if wantError := "401 Unauthorized: Tailscale already in use by UserA"; gotErr.Error() != wantError {
		t.Fatalf("Status(%q): want %q; got %q", clientB.User.Name, wantError, gotErr.Error())
	}

	// Current user should still be UserA.
	server.checkCurrentUser(clientA.User)
}

func TestSequentialOSUserSwitchingOnWindows(t *testing.T) {
	enableLogging := false
	setGOOSForTest(t, "windows")

	ctx := context.Background()
	server := startDefaultTestIPNServer(t, ctx, enableLogging)

	connectDisconnectAsUser := func(name string) {
		// User connects and starts watching the IPN bus.
		client := server.getClientAs(name)
		watcher, cancelWatcher := client.WatchIPNBus(ctx, 0)
		defer cancelWatcher()
		go pumpIPNBus(watcher)

		// It should be the current user from the LocalBackend's perspective...
		server.checkCurrentUser(client.User)
		// until it disconnects.
		cancelWatcher()
		server.blockWhileInUse(ctx)
		// Now, the current user should be unset.
		server.checkCurrentUser(nil)
	}

	// UserA logs in, uses Tailscale for a bit, then logs out.
	connectDisconnectAsUser("UserA")
	// Same for UserB.
	connectDisconnectAsUser("UserB")
}

func TestConcurrentOSUserSwitchingOnWindows(t *testing.T) {
	enableLogging := false
	setGOOSForTest(t, "windows")

	ctx := context.Background()
	server := startDefaultTestIPNServer(t, ctx, enableLogging)

	connectDisconnectAsUser := func(name string) {
		// User connects and starts watching the IPN bus.
		client := server.getClientAs(name)
		watcher, cancelWatcher := client.WatchIPNBus(ctx, ipn.NotifyInitialState)
		defer cancelWatcher()

		runtime.Gosched()

		// Get the current user from the LocalBackend's perspective
		// as soon as we're connected.
		gotUID, gotActor := server.mustBackend().CurrentUserForTest()

		// Wait for the first notification to arrive.
		// It will either be the initial state we've requested via [ipn.NotifyInitialState],
		// returned by an actual handler, or a "fake" notification sent by the server
		// itself to indicate that it is being used by someone else.
		n, err := watcher.Next()
		if err != nil {
			t.Fatal(err)
		}

		// If our user lost the race and the IPN is in use by another user,
		// we should just return. For the sake of this test, we're not
		// interested in waiting for the server to become idle.
		if n.State != nil && *n.State == ipn.InUseOtherUser {
			return
		}

		// Otherwise, our user should have been the current user since the time we connected.
		if gotUID != client.User.UID {
			t.Errorf("CurrentUser(Initial): got UID %q; want %q", gotUID, client.User.UID)
			return
		}
		if gotActor, ok := gotActor.(*ipnauth.TestActor); !ok || *gotActor != *client.User {
			t.Errorf("CurrentUser(Initial): got %v; want %v", gotActor, client.User)
			return
		}

		// And should still be the current user (as they're still connected)...
		server.checkCurrentUser(client.User)
	}

	numIterations := 10
	for range numIterations {
		numGoRoutines := 100
		var wg sync.WaitGroup
		wg.Add(numGoRoutines)
		for i := range numGoRoutines {
			// User logs in, uses Tailscale for a bit, then logs out
			// in parallel with other users doing the same.
			go func() {
				defer wg.Done()
				connectDisconnectAsUser("User-" + strconv.Itoa(i))
			}()
		}
		wg.Wait()

		if err := server.blockWhileInUse(ctx); err != nil {
			t.Fatalf("blockWhileInUse: %v", err)
		}

		server.checkCurrentUser(nil)
	}
}

func TestBlockWhileIdentityInUse(t *testing.T) {
	enableLogging := false
	setGOOSForTest(t, "windows")

	ctx := context.Background()
	server := startDefaultTestIPNServer(t, ctx, enableLogging)

	// connectWaitDisconnectAsUser connects as a user with the specified name
	// and keeps the IPN bus watcher alive until the context is canceled.
	// It returns a channel that is closed when done.
	connectWaitDisconnectAsUser := func(ctx context.Context, name string) <-chan struct{} {
		client := server.getClientAs(name)
		watcher, cancelWatcher := client.WatchIPNBus(ctx, 0)

		done := make(chan struct{})
		go func() {
			defer cancelWatcher()
			defer close(done)
			for {
				_, err := watcher.Next()
				if err != nil {
					// There's either an error or the request has been canceled.
					break
				}
			}
		}()
		return done
	}

	for range 100 {
		// Connect as UserA, and keep the connection alive
		// until disconnectUserA is called.
		userAContext, disconnectUserA := context.WithCancel(ctx)
		userADone := connectWaitDisconnectAsUser(userAContext, "UserA")
		disconnectUserA()
		// Check if userB can connect. Calling it directly increases
		// the likelihood of triggering a deadlock due to a race condition
		// in blockWhileIdentityInUse. But the issue also occurs during
		// the normal execution path when UserB connects to the IPN server
		// while UserA is disconnecting.
		userB := server.makeTestUser("UserB", "ClientB")
		server.blockWhileIdentityInUse(ctx, userB)
		<-userADone
	}
}

func setGOOSForTest(tb testing.TB, goos string) {
	tb.Helper()
	envknob.Setenv("TS_DEBUG_FAKE_GOOS", goos)
	tb.Cleanup(func() { envknob.Setenv("TS_DEBUG_FAKE_GOOS", "") })
}

func testLogger(tb testing.TB, enableLogging bool) logger.Logf {
	tb.Helper()
	if enableLogging {
		return tstest.WhileTestRunningLogger(tb)
	}
	return logger.Discard
}

// newTestIPNServer creates a new IPN server for testing, using the specified local backend.
func newTestIPNServer(tb testing.TB, lb *ipnlocal.LocalBackend, enableLogging bool) *Server {
	tb.Helper()
	server := New(testLogger(tb, enableLogging), logid.PublicID{}, lb.NetMon())
	server.lb.Store(lb)
	return server
}

type testIPNClient struct {
	tb testing.TB
	*local.Client
	User *ipnauth.TestActor
}

func (c *testIPNClient) WatchIPNBus(ctx context.Context, mask ipn.NotifyWatchOpt) (*tailscale.IPNBusWatcher, context.CancelFunc) {
	c.tb.Helper()
	ctx, cancelWatcher := context.WithCancel(ctx)
	c.tb.Cleanup(cancelWatcher)
	watcher, err := c.Client.WatchIPNBus(ctx, mask)
	if err != nil {
		c.tb.Fatalf("WatchIPNBus(%q): %v", c.User.Name, err)
	}
	c.tb.Cleanup(func() { watcher.Close() })
	return watcher, cancelWatcher
}

func pumpIPNBus(watcher *tailscale.IPNBusWatcher) {
	for {
		_, err := watcher.Next()
		if err != nil {
			break
		}
	}
}

type testIPNServer struct {
	tb testing.TB
	*Server
	clientID  atomic.Int64
	getClient func(*ipnauth.TestActor) *local.Client

	actorsMu sync.Mutex
	actors   map[string]*ipnauth.TestActor
}

func (s *testIPNServer) getClientAs(name string) *testIPNClient {
	clientID := fmt.Sprintf("Client-%d", 1+s.clientID.Add(1))
	user := s.makeTestUser(name, clientID)
	return &testIPNClient{
		tb:     s.tb,
		Client: s.getClient(user),
		User:   user,
	}
}

func (s *testIPNServer) makeTestUser(name string, clientID string) *ipnauth.TestActor {
	s.actorsMu.Lock()
	defer s.actorsMu.Unlock()
	actor := s.actors[name]
	if actor == nil {
		actor = &ipnauth.TestActor{Name: name}
		if envknob.GOOS() == "windows" {
			// Historically, as of 2025-01-13, IPN does not distinguish between
			// different users on non-Windows devices. Therefore, the UID, which is
			// an [ipn.WindowsUserID], should only be populated when the actual or
			// fake GOOS is Windows.
			actor.UID = ipn.WindowsUserID(fmt.Sprintf("S-1-5-21-1-0-0-%d", 1001+len(s.actors)))
		}
		mak.Set(&s.actors, name, actor)
		s.tb.Cleanup(func() { delete(s.actors, name) })
	}
	actor = ptr.To(*actor)
	actor.CID = ipnauth.ClientIDFrom(clientID)
	return actor
}

func (s *testIPNServer) blockWhileInUse(ctx context.Context) error {
	ready, cleanup := s.zeroReqWaiter.add(&s.mu, ctx)

	s.mu.Lock()
	busy := len(s.activeReqs) != 0
	s.mu.Unlock()

	if busy {
		<-ready
	}
	cleanup()
	return ctx.Err()
}

func (s *testIPNServer) checkCurrentUser(want *ipnauth.TestActor) {
	s.tb.Helper()
	var wantUID ipn.WindowsUserID
	if want != nil {
		wantUID = want.UID
	}
	gotUID, gotActor := s.mustBackend().CurrentUserForTest()
	if gotUID != wantUID {
		s.tb.Errorf("CurrentUser: got UID %q; want %q", gotUID, wantUID)
	}
	if gotActor, ok := gotActor.(*ipnauth.TestActor); ok != (want != nil) || (want != nil && *gotActor != *want) {
		s.tb.Errorf("CurrentUser: got %v; want %v", gotActor, want)
	}
}

// startTestIPNServer starts a [httptest.Server] that hosts the specified IPN server for the
// duration of the test, using the specified base context for incoming requests.
// It returns a function that creates a [local.Client] as a given [ipnauth.TestActor].
func startTestIPNServer(tb testing.TB, baseContext context.Context, server *Server) *testIPNServer {
	tb.Helper()
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actor, err := extractActorFromHeader(r.Header)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			tb.Errorf("extractActorFromHeader: %v", err)
			return
		}
		ctx := newTestContextWithActor(r.Context(), actor)
		server.serveHTTP(w, r.Clone(ctx))
	}))
	ts.Config.Addr = "http://" + apitype.LocalAPIHost
	ts.Config.BaseContext = func(_ net.Listener) context.Context { return baseContext }
	ts.Config.ErrorLog = logger.StdLogger(logger.WithPrefix(server.logf, "ipnserver: "))
	ts.Start()
	tb.Cleanup(ts.Close)
	return &testIPNServer{
		tb:     tb,
		Server: server,
		getClient: func(actor *ipnauth.TestActor) *local.Client {
			return &local.Client{Transport: newTestRoundTripper(ts, actor)}
		},
	}
}

func startDefaultTestIPNServer(tb testing.TB, ctx context.Context, enableLogging bool) *testIPNServer {
	tb.Helper()
	lb := newLocalBackendWithTestControl(tb, newUnreachableControlClient, enableLogging)
	ctx, stopServer := context.WithCancel(ctx)
	tb.Cleanup(stopServer)
	return startTestIPNServer(tb, ctx, newTestIPNServer(tb, lb, enableLogging))
}

type testRoundTripper struct {
	transport http.RoundTripper
	actor     *ipnauth.TestActor
}

// newTestRoundTripper creates a new [http.RoundTripper] that sends requests
// to the specified test server as the specified actor.
func newTestRoundTripper(ts *httptest.Server, actor *ipnauth.TestActor) *testRoundTripper {
	return &testRoundTripper{
		transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var std net.Dialer
			return std.DialContext(ctx, network, ts.Listener.Addr().(*net.TCPAddr).String())
		}},
		actor: actor,
	}
}

const testActorHeaderName = "TS-Test-Actor"

// RoundTrip implements [http.RoundTripper] by forwarding the request to the underlying transport
// and including the test actor's identity in the request headers.
func (rt *testRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	actorJSON, err := json.Marshal(&rt.actor)
	if err != nil {
		// An [http.RoundTripper] must always close the request body, including on error.
		if r.Body != nil {
			r.Body.Close()
		}
		return nil, err
	}

	r = r.Clone(r.Context())
	r.Header.Set(testActorHeaderName, string(actorJSON))
	return rt.transport.RoundTrip(r)
}

// extractActorFromHeader extracts a test actor from the specified request headers.
func extractActorFromHeader(h http.Header) (*ipnauth.TestActor, error) {
	actorJSON := h.Get(testActorHeaderName)
	if actorJSON == "" {
		return nil, errors.New("missing Test-Actor header")
	}
	actor := &ipnauth.TestActor{}
	if err := json.Unmarshal([]byte(actorJSON), &actor); err != nil {
		return nil, fmt.Errorf("invalid Test-Actor header: %v", err)
	}
	return actor, nil
}

type newControlClientFn func(tb testing.TB, opts controlclient.Options) controlclient.Client

func newLocalBackendWithTestControl(tb testing.TB, newControl newControlClientFn, enableLogging bool) *ipnlocal.LocalBackend {
	tb.Helper()

	sys := &tsd.System{}
	store := &mem.Store{}
	sys.Set(store)

	logf := testLogger(tb, enableLogging)
	e, err := wgengine.NewFakeUserspaceEngine(logf, sys.Set, sys.HealthTracker(), sys.UserMetricsRegistry())
	if err != nil {
		tb.Fatalf("NewFakeUserspaceEngine: %v", err)
	}
	tb.Cleanup(e.Close)
	sys.Set(e)

	b, err := ipnlocal.NewLocalBackend(logf, logid.PublicID{}, sys, 0)
	if err != nil {
		tb.Fatalf("NewLocalBackend: %v", err)
	}
	tb.Cleanup(b.Shutdown)
	b.DisablePortMapperForTest()

	b.SetControlClientGetterForTesting(func(opts controlclient.Options) (controlclient.Client, error) {
		return newControl(tb, opts), nil
	})
	return b
}

func newUnreachableControlClient(tb testing.TB, opts controlclient.Options) controlclient.Client {
	tb.Helper()
	opts.ServerURL = "https://127.0.0.1:1"
	cc, err := controlclient.New(opts)
	if err != nil {
		tb.Fatal(err)
	}
	return cc
}

// newTestContextWithActor returns a new context that carries the identity
// of the specified actor and can be used for testing.
// It can be retrieved with [actorFromContext].
func newTestContextWithActor(ctx context.Context, actor ipnauth.Actor) context.Context {
	return actorKey.WithValue(ctx, actorOrError{actor: actor})
}
