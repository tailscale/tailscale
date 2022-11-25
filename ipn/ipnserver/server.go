// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnserver

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"go4.org/mem"
	"tailscale.com/control/controlclient"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnauth"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/localapi"
	"tailscale.com/logtail/backoff"
	"tailscale.com/net/dnsfallback"
	"tailscale.com/net/netutil"
	"tailscale.com/net/tsdial"
	"tailscale.com/smallzstd"
	"tailscale.com/types/logger"
	"tailscale.com/util/systemd"
	"tailscale.com/version/distro"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/monitor"
	"tailscale.com/wgengine/netstack"
)

// Options is the configuration of the Tailscale node agent.
type Options struct {
	// VarRoot is the Tailscale daemon's private writable
	// directory (usually "/var/lib/tailscale" on Linux) that
	// contains the "tailscaled.state" file, the "certs" directory
	// for TLS certs, and the "files" directory for incoming
	// Taildrop files before they're moved to a user directory.
	// If empty, Taildrop and TLS certs don't function.
	VarRoot string

	// AutostartStateKey, if non-empty, immediately starts the agent
	// using the given StateKey. If empty, the agent stays idle and
	// waits for a frontend to start it.
	AutostartStateKey ipn.StateKey

	// SurviveDisconnects specifies how the server reacts to its
	// frontend disconnecting. If true, the server keeps running on
	// its existing state, and accepts new frontend connections. If
	// false, the server dumps its state and becomes idle.
	//
	// This is effectively whether the platform is in "server
	// mode" by default. On Linux, it's true; on Windows, it's
	// false. But on some platforms (currently only Windows), the
	// "server mode" can be overridden at runtime with a change in
	// Prefs.ForceDaemon/WantRunning.
	//
	// To support CLI connections (notably, "tailscale status"),
	// the actual definition of "disconnect" is when the
	// connection count transitions from 1 to 0.
	SurviveDisconnects bool

	// LoginFlags specifies the LoginFlags to pass to the client.
	LoginFlags controlclient.LoginFlags
}

// Server is an IPN backend and its set of 0 or more active localhost
// TCP or unix socket connections talking to that backend.
type Server struct {
	b            *ipnlocal.LocalBackend
	logf         logger.Logf
	backendLogID string
	// resetOnZero is whether to call bs.Reset on transition from
	// 1->0 connections.  That is, this is whether the backend is
	// being run in "client mode" that requires an active GUI
	// connection (such as on Windows by default).  Even if this
	// is true, the ForceDaemon pref can override this.
	resetOnZero bool

	// mu guards the fields that follow.
	// lock order: mu, then LocalBackend.mu
	mu         sync.Mutex
	lastUserID string // tracks last userid; on change, Reset state for paranoia
	allClients map[net.Conn]*ipnauth.ConnIdentity
}

// LocalBackend returns the server's LocalBackend.
func (s *Server) LocalBackend() *ipnlocal.LocalBackend { return s.b }

// bufferIsConnect reports whether br looks like it's likely an HTTP
// CONNECT request.
//
// Invariant: br has already had at least 4 bytes Peek'ed.
func bufferIsConnect(br *bufio.Reader) bool {
	peek, _ := br.Peek(br.Buffered())
	return mem.HasPrefix(mem.B(peek), mem.S("CONN"))
}

func (s *Server) serveConn(ctx context.Context, c net.Conn, logf logger.Logf) {
	// First sniff a few bytes to check its HTTP method.
	br := bufio.NewReader(c)
	c.SetReadDeadline(time.Now().Add(30 * time.Second))
	br.Peek(len("GET / HTTP/1.1\r\n")) // reasonable sniff size to get HTTP method
	c.SetReadDeadline(time.Time{})

	// Handle logtail CONNECT requests early. (See docs on handleProxyConnectConn)
	if bufferIsConnect(br) {
		s.handleProxyConnectConn(ctx, br, c, logf)
		return
	}

	ci, err := s.addConn(c)
	if err != nil {
		fmt.Fprintf(c, "HTTP/1.0 500 Nope\r\nContent-Type: text/plain\r\nX-Content-Type-Options: nosniff\r\n\r\n%s\n", err.Error())
		c.Close()
	}

	// Tell the LocalBackend about the identity we're now running as.
	s.b.SetCurrentUserID(ci.UserID())

	httpServer := &http.Server{
		// Localhost connections are cheap; so only do
		// keep-alives for a short period of time, as these
		// active connections lock the server into only serving
		// that user. If the user has this page open, we don't
		// want another switching user to be locked out for
		// minutes. 5 seconds is enough to let browser hit
		// favicon.ico and such.
		IdleTimeout: 5 * time.Second,
		ErrorLog:    logger.StdLogger(logf),
		Handler:     s.localhostHandler(ci),
	}
	httpServer.Serve(netutil.NewOneConnListener(&protoSwitchConn{s: s, br: br, Conn: c}, nil))
}

// inUseOtherUserError is the error type for when the server is in use
// by a different local user.
type inUseOtherUserError struct{ error }

func (e inUseOtherUserError) Unwrap() error { return e.error }

// checkConnIdentityLocked checks whether the provided identity is
// allowed to connect to the server.
//
// The returned error, when non-nil, will be of type inUseOtherUserError.
//
// s.mu must be held.
func (s *Server) checkConnIdentityLocked(ci *ipnauth.ConnIdentity) error {
	// If clients are already connected, verify they're the same user.
	// This mostly matters on Windows at the moment.
	if len(s.allClients) > 0 {
		var active *ipnauth.ConnIdentity
		for _, active = range s.allClients {
			break
		}
		if active != nil && ci.UserID() != active.UserID() {
			return inUseOtherUserError{fmt.Errorf("Tailscale already in use by %s, pid %d", active.User().Username, active.Pid())}
		}
	}
	if err := s.b.CheckIPNConnectionAllowed(ci); err != nil {
		return inUseOtherUserError{err}
	}
	return nil
}

// localAPIPermissions returns the permissions for the given identity accessing
// the Tailscale local daemon API.
//
// s.mu must not be held.
func (s *Server) localAPIPermissions(ci *ipnauth.ConnIdentity) (read, write bool) {
	switch runtime.GOOS {
	case "windows":
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.checkConnIdentityLocked(ci) == nil {
			return true, true
		}
		return false, false
	case "js":
		return true, true
	}
	if ci.IsUnixSock() {
		return true, !ci.IsReadonlyConn(s.b.OperatorUserID(), logger.Discard)
	}
	return false, false
}

// userIDFromString maps from either a numeric user id in string form
// ("998") or username ("caddy") to its string userid ("998").
// It returns the empty string on error.
func userIDFromString(v string) string {
	if v == "" || isAllDigit(v) {
		return v
	}
	u, err := user.Lookup(v)
	if err != nil {
		return ""
	}
	return u.Uid
}

func isAllDigit(s string) bool {
	for i := 0; i < len(s); i++ {
		if b := s[i]; b < '0' || b > '9' {
			return false
		}
	}
	return true
}

// connCanFetchCerts reports whether ci is allowed to fetch HTTPS
// certs from this server when it wouldn't otherwise be able to.
//
// That is, this reports whether ci should grant additional
// capabilities over what the conn would otherwise be able to do.
//
// For now this only returns true on Unix machines when
// TS_PERMIT_CERT_UID is set the to the userid of the peer
// connection. It's intended to give your non-root webserver access
// (www-data, caddy, nginx, etc) to certs.
func (s *Server) connCanFetchCerts(ci *ipnauth.ConnIdentity) bool {
	if ci.IsUnixSock() && ci.Creds() != nil {
		connUID, ok := ci.Creds().UserID()
		if ok && connUID == userIDFromString(envknob.String("TS_PERMIT_CERT_UID")) {
			return true
		}
	}
	return false
}

// addConn adds c to the server's list of clients.
//
// If the returned error is of type inUseOtherUserError then the
// returned connIdentity is also valid.
func (s *Server) addConn(c net.Conn) (ci *ipnauth.ConnIdentity, err error) {
	ci, err = ipnauth.GetConnIdentity(s.logf, c)
	if err != nil {
		return
	}

	// If the connected user changes, reset the backend server state to make
	// sure node keys don't leak between users.
	var doReset bool
	defer func() {
		if doReset {
			s.logf("identity changed; resetting server")
			s.b.ResetForClientDisconnect()
		}
	}()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.allClients == nil {
		s.allClients = map[net.Conn]*ipnauth.ConnIdentity{}
	}

	if err := s.checkConnIdentityLocked(ci); err != nil {
		return ci, err
	}

	s.allClients[c] = ci

	if s.lastUserID != ci.UserID() {
		if s.lastUserID != "" {
			doReset = true
		}
		s.lastUserID = ci.UserID()
	}
	return ci, nil
}

func (s *Server) removeAndCloseConn(c net.Conn) {
	s.mu.Lock()
	delete(s.allClients, c)
	remain := len(s.allClients)
	s.mu.Unlock()

	if remain == 0 && s.resetOnZero {
		if s.b.InServerMode() {
			s.logf("client disconnected; staying alive in server mode")
		} else {
			s.logf("client disconnected; stopping server")
			s.b.ResetForClientDisconnect()
		}
	}
	c.Close()
}

// Run runs a Tailscale backend service.
// The getEngine func is called repeatedly, once per connection, until it returns an engine successfully.
//
// Deprecated: use New and Server.Run instead.
func Run(ctx context.Context, logf logger.Logf, ln net.Listener, store ipn.StateStore, linkMon *monitor.Mon, dialer *tsdial.Dialer, logid string, getEngine func() (wgengine.Engine, *netstack.Impl, error), opts Options) error {
	getEngine = getEngineUntilItWorksWrapper(getEngine)
	runDone := make(chan struct{})
	defer close(runDone)

	// When the context is closed or when we return, whichever is first, close our listener
	// and all open connections.
	go func() {
		select {
		case <-ctx.Done():
		case <-runDone:
		}
		ln.Close()
	}()
	logf("Listening on %v", ln.Addr())

	bo := backoff.NewBackoff("ipnserver", logf, 30*time.Second)
	var unservedConn net.Conn // if non-nil, accepted, but hasn't served yet

	eng, ns, err := getEngine()
	if err != nil {
		logf("ipnserver: initial getEngine call: %v", err)
		for i := 1; ctx.Err() == nil; i++ {
			c, err := ln.Accept()
			if err != nil {
				logf("%d: Accept: %v", i, err)
				bo.BackOff(ctx, err)
				continue
			}
			logf("ipnserver: try%d: trying getEngine again...", i)
			eng, ns, err = getEngine()
			if err == nil {
				logf("%d: GetEngine worked; exiting failure loop", i)
				unservedConn = c
				break
			}
			logf("ipnserver%d: getEngine failed again: %v", i, err)
			// TODO(bradfitz): queue this error up for the next IPN bus watcher call
			// to get for the Windows GUI? We used to send it over the pre-HTTP
			// protocol to the Windows GUI. Just close it.
			c.Close()
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	if unservedConn != nil {
		ln = &listenerWithReadyConn{
			Listener: ln,
			c:        unservedConn,
		}
	}

	server, err := New(logf, logid, store, eng, dialer, opts)
	if err != nil {
		return err
	}
	if ns != nil {
		ns.SetLocalBackend(server.LocalBackend())
	}
	return server.Run(ctx, ln)
}

// New returns a new Server.
//
// To start it, use the Server.Run method.
func New(logf logger.Logf, logid string, store ipn.StateStore, eng wgengine.Engine, dialer *tsdial.Dialer, opts Options) (*Server, error) {
	b, err := ipnlocal.NewLocalBackend(logf, logid, store, opts.AutostartStateKey, dialer, eng, opts.LoginFlags)
	if err != nil {
		return nil, fmt.Errorf("NewLocalBackend: %v", err)
	}
	b.SetVarRoot(opts.VarRoot)
	b.SetDecompressor(func() (controlclient.Decompressor, error) {
		return smallzstd.NewDecoder(nil)
	})

	if root := b.TailscaleVarRoot(); root != "" {
		dnsfallback.SetCachePath(filepath.Join(root, "derpmap.cached.json"))
	}

	dg := distro.Get()
	switch dg {
	case distro.Synology, distro.TrueNAS, distro.QNAP:
		// See if they have a "Taildrop" share.
		// See https://github.com/tailscale/tailscale/issues/2179#issuecomment-982821319
		path, err := findTaildropDir(dg)
		if err != nil {
			logf("%s Taildrop support: %v", dg, err)
		} else {
			logf("%s Taildrop: using %v", dg, path)
			b.SetDirectFileRoot(path)
			b.SetDirectFileDoFinalRename(true)
		}

	}

	server := &Server{
		b:            b,
		backendLogID: logid,
		logf:         logf,
		resetOnZero:  !opts.SurviveDisconnects,
	}
	return server, nil
}

// Run runs the server, accepting connections from ln forever.
//
// If the context is done, the listener is closed.
func (s *Server) Run(ctx context.Context, ln net.Listener) error {
	defer s.b.Shutdown()

	runDone := make(chan struct{})
	defer close(runDone)

	// When the context is closed or when we return, whichever is first, close our listener
	// and all open connections.
	go func() {
		select {
		case <-ctx.Done():
		case <-runDone:
		}
		ln.Close()
	}()

	if s.b.Prefs().Valid() {
		s.b.Start(ipn.Options{})
	}

	systemd.Ready()
	bo := backoff.NewBackoff("ipnserver", s.logf, 30*time.Second)
	var connNum int
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			s.logf("ipnserver: Accept: %v", err)
			bo.BackOff(ctx, err)
			continue
		}
		connNum++
		go s.serveConn(ctx, c, logger.WithPrefix(s.logf, fmt.Sprintf("ipnserver: conn%d: ", connNum)))
	}
}

// BabysitProc runs the current executable as a child process with the
// provided args, capturing its output, writing it to files, and
// restarting the process on any crashes.
//
// It's only currently (2020-10-29) used on Windows.
func BabysitProc(ctx context.Context, args []string, logf logger.Logf) {

	executable, err := os.Executable()
	if err != nil {
		panic("cannot determine executable: " + err.Error())
	}

	var proc struct {
		mu sync.Mutex
		p  *os.Process
	}

	done := make(chan struct{})
	go func() {
		interrupt := make(chan os.Signal, 1)
		signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
		var sig os.Signal
		select {
		case sig = <-interrupt:
			logf("BabysitProc: got signal: %v", sig)
			close(done)
		case <-ctx.Done():
			logf("BabysitProc: context done")
			sig = os.Kill
			close(done)
		}

		proc.mu.Lock()
		proc.p.Signal(sig)
		proc.mu.Unlock()
	}()

	bo := backoff.NewBackoff("BabysitProc", logf, 30*time.Second)

	for {
		startTime := time.Now()
		log.Printf("exec: %#v %v", executable, args)
		cmd := exec.Command(executable, args...)

		// Create a pipe object to use as the subproc's stdin.
		// When the writer goes away, the reader gets EOF.
		// A subproc can watch its stdin and exit when it gets EOF;
		// this is a very reliable way to have a subproc die when
		// its parent (us) disappears.
		// We never need to actually write to wStdin.
		rStdin, wStdin, err := os.Pipe()
		if err != nil {
			log.Printf("os.Pipe 1: %v", err)
			return
		}

		// Create a pipe object to use as the subproc's stdout/stderr.
		// We'll read from this pipe and send it to logf, line by line.
		// We can't use os.exec's io.Writer for this because it
		// doesn't care about lines, and thus ends up merging multiple
		// log lines into one or splitting one line into multiple
		// logf() calls. bufio is more appropriate.
		rStdout, wStdout, err := os.Pipe()
		if err != nil {
			log.Printf("os.Pipe 2: %v", err)
		}
		go func(r *os.File) {
			defer r.Close()
			rb := bufio.NewReader(r)
			for {
				s, err := rb.ReadString('\n')
				if s != "" {
					logf("%s", s)
				}
				if err != nil {
					break
				}
			}
		}(rStdout)

		cmd.Stdin = rStdin
		cmd.Stdout = wStdout
		cmd.Stderr = wStdout
		err = cmd.Start()

		// Now that the subproc is started, get rid of our copy of the
		// pipe reader. Bad things happen on Windows if more than one
		// process owns the read side of a pipe.
		rStdin.Close()
		wStdout.Close()

		if err != nil {
			log.Printf("starting subprocess failed: %v", err)
		} else {
			proc.mu.Lock()
			proc.p = cmd.Process
			proc.mu.Unlock()

			err = cmd.Wait()
			log.Printf("subprocess exited: %v", err)
		}

		// If the process finishes, clean up the write side of the
		// pipe. We'll make a new one when we restart the subproc.
		wStdin.Close()

		if os.Getenv("TS_DEBUG_RESTART_CRASHED") == "0" {
			log.Fatalf("Process ended.")
		}

		if time.Since(startTime) < 60*time.Second {
			bo.BackOff(ctx, fmt.Errorf("subproc early exit: %v", err))
		} else {
			// Reset the timeout, since the process ran for a while.
			bo.BackOff(ctx, nil)
		}

		select {
		case <-done:
			return
		default:
		}
	}
}

// getEngineUntilItWorksWrapper returns a getEngine wrapper that does
// not call getEngine concurrently and stops calling getEngine once
// it's returned a working engine.
func getEngineUntilItWorksWrapper(getEngine func() (wgengine.Engine, *netstack.Impl, error)) func() (wgengine.Engine, *netstack.Impl, error) {
	var mu sync.Mutex
	var engGood wgengine.Engine
	var nsGood *netstack.Impl
	return func() (wgengine.Engine, *netstack.Impl, error) {
		mu.Lock()
		defer mu.Unlock()
		if engGood != nil {
			return engGood, nsGood, nil
		}
		e, ns, err := getEngine()
		if err != nil {
			return nil, nil, err
		}
		engGood = e
		nsGood = ns
		return e, ns, nil
	}
}

// protoSwitchConn is a net.Conn with which we want to speak HTTP to but
// it's already had a few bytes read from it to determine its HTTP method.
// So we Read from its bufio.Reader. On Close, we we tell the
type protoSwitchConn struct {
	s *Server
	net.Conn
	br        *bufio.Reader
	closeOnce sync.Once
}

func (psc *protoSwitchConn) Read(p []byte) (int, error) { return psc.br.Read(p) }
func (psc *protoSwitchConn) Close() error {
	psc.closeOnce.Do(func() { psc.s.removeAndCloseConn(psc.Conn) })
	return nil
}

func (s *Server) localhostHandler(ci *ipnauth.ConnIdentity) http.Handler {
	lah := localapi.NewHandler(s.b, s.logf, s.backendLogID)
	lah.PermitRead, lah.PermitWrite = s.localAPIPermissions(ci)
	lah.PermitCert = s.connCanFetchCerts(ci)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/localapi/") {
			lah.ServeHTTP(w, r)
			return
		}
		if ci.NotWindows() {
			io.WriteString(w, "<html><title>Tailscale</title><body><h1>Tailscale</h1>This is the local Tailscale daemon.")
			return
		}
		s.ServeHTMLStatus(w, r)
	})
}

// ServeHTMLStatus serves an HTML status page at http://localhost:41112/ for
// Windows and via $DEBUG_LISTENER/debug/ipn when tailscaled's --debug flag
// is used to run a debug server.
func (s *Server) ServeHTMLStatus(w http.ResponseWriter, r *http.Request) {
	// As this is only meant for debug, verify there's no DNS name being used to
	// access this.
	if !strings.HasPrefix(r.Host, "localhost:") && strings.IndexFunc(r.Host, unicode.IsLetter) != -1 {
		http.Error(w, "invalid host", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Security-Policy", `default-src 'none'; frame-ancestors 'none'; script-src 'none'; script-src-elem 'none'; script-src-attr 'none'`)
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	st := s.b.Status()
	// TODO(bradfitz): add LogID and opts to st?
	st.WriteHTML(w)
}

// listenerWithReadyConn is a net.Listener wrapper that has
// one net.Conn ready to be accepted already.
type listenerWithReadyConn struct {
	net.Listener

	mu sync.Mutex
	c  net.Conn // if non-nil, ready to be Accepted
}

func (ln *listenerWithReadyConn) Accept() (net.Conn, error) {
	ln.mu.Lock()
	c := ln.c
	ln.c = nil
	ln.mu.Unlock()
	if c != nil {
		return c, nil
	}
	return ln.Listener.Accept()
}

func findTaildropDir(dg distro.Distro) (string, error) {
	const name = "Taildrop"
	switch dg {
	case distro.Synology:
		return findSynologyTaildropDir(name)
	case distro.TrueNAS:
		return findTrueNASTaildropDir(name)
	case distro.QNAP:
		return findQnapTaildropDir(name)
	}
	return "", fmt.Errorf("%s is an unsupported distro for Taildrop dir", dg)
}

// findSynologyTaildropDir looks for the first volume containing a
// "Taildrop" directory.  We'd run "synoshare --get Taildrop" command
// but on DSM7 at least, we lack permissions to run that.
func findSynologyTaildropDir(name string) (dir string, err error) {
	for i := 1; i <= 16; i++ {
		dir = fmt.Sprintf("/volume%v/%s", i, name)
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			return dir, nil
		}
	}
	return "", fmt.Errorf("shared folder %q not found", name)
}

// findTrueNASTaildropDir returns the first matching directory of
// /mnt/{name} or /mnt/*/{name}
func findTrueNASTaildropDir(name string) (dir string, err error) {
	// If we're running in a jail, a mount point could just be added at /mnt/Taildrop
	dir = fmt.Sprintf("/mnt/%s", name)
	if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
		return dir, nil
	}

	// but if running on the host, it may be something like /mnt/Primary/Taildrop
	fis, err := os.ReadDir("/mnt")
	if err != nil {
		return "", fmt.Errorf("error reading /mnt: %w", err)
	}
	for _, fi := range fis {
		dir = fmt.Sprintf("/mnt/%s/%s", fi.Name(), name)
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			return dir, nil
		}
	}
	return "", fmt.Errorf("shared folder %q not found", name)
}

// findQnapTaildropDir checks if a Shared Folder named "Taildrop" exists.
func findQnapTaildropDir(name string) (string, error) {
	dir := fmt.Sprintf("/share/%s", name)
	fi, err := os.Stat(dir)
	if err != nil {
		return "", fmt.Errorf("shared folder %q not found", name)
	}
	if fi.IsDir() {
		return dir, nil
	}

	// share/Taildrop is usually a symlink to CACHEDEV1_DATA/Taildrop/ or some such.
	fullpath, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", fmt.Errorf("symlink to shared folder %q not found", name)
	}
	if fi, err = os.Stat(fullpath); err == nil && fi.IsDir() {
		return dir, nil // return the symlink, how QNAP set it up
	}
	return "", fmt.Errorf("shared folder %q not found", name)
}
