// The funnelauthdemo command is a local test harness for Authenticated Funnel.
//
// It plays two roles at once against a target node that is serving an
// authenticated Funnel (tailscale funnel --auth):
//
//  1. Fake ingressd: it joins the same tailnet as the target (as the same
//     user), connects to the target's PeerAPI, and performs the /v0/ingress
//     handshake that the real ingressd performs. This makes the target's serve
//     path see a genuine Funnel request (serveHTTPContext.Funnel != nil) without
//     any of the production ingress infrastructure. This requires the target
//     tailscaled to run with TS_ALLOW_SELF_INGRESS=1, since the injector is the
//     same user's node rather than a tag:ingress peer.
//
//  2. Scripted visitor: over the spliced connection it speaks TLS (SNI = the
//     target's MagicDNS name) and drives the full browser login loop — following
//     the 302 to control's /a/oauth_authorize, performing the dev-control CSRF
//     login, following the redirect back to the node callback, and finally
//     fetching the protected page with the resulting ts_funnel_session cookie.
//
// It is intended only for the local OrbStack/Docker demo described in
// specs/login-with-tailscale-funnel/demo. It is not shipped or used in prod.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"
)

func main() {
	log.SetFlags(0)
	var (
		target      = flag.String("target", "", "MagicDNS name of the target funnel node, e.g. app.tailnet.ts.net")
		port        = flag.Int("port", 443, "funnel port on the target")
		path        = flag.String("path", "/", "request path to fetch on the target")
		authKey     = flag.String("authkey", "", "auth key for the injector to join the tailnet (or set TS_AUTHKEY)")
		controlURL  = flag.String("login-server", "", "control URL the injector should join (must match the target's)")
		stateDir    = flag.String("state-dir", "", "tsnet state dir for the injector (default: a temp dir)")
		hostname    = flag.String("hostname", "funnelauth-injector", "hostname for the injector node")
		visitorAddr = flag.String("visitor-addr", "203.0.113.7:40000", "value for the Tailscale-Ingress-Src header (the apparent visitor IP:port)")
		timeout     = flag.Duration("timeout", 90*time.Second, "overall timeout")
	)
	flag.Parse()

	if *target == "" {
		log.Fatal("--target is required (the funnel node's MagicDNS name)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	srv := &tsnet.Server{
		Hostname:   *hostname,
		AuthKey:    *authKey,
		ControlURL: *controlURL,
		Dir:        *stateDir,
	}
	defer srv.Close()

	log.Printf("injector: joining tailnet as %q (control=%q)...", *hostname, *controlURL)
	if _, err := srv.Up(ctx); err != nil {
		log.Fatalf("injector: could not join tailnet: %v", err)
	}
	lc, err := srv.LocalClient()
	if err != nil {
		log.Fatalf("injector: LocalClient: %v", err)
	}

	peerAPI, err := waitForTargetPeerAPI(ctx, lc, *target)
	if err != nil {
		log.Fatalf("injector: locating target PeerAPI: %v", err)
	}
	log.Printf("injector: target %q PeerAPI at %s", *target, peerAPI)

	v := &visitor{
		srv:         srv,
		peerAPIURL:  peerAPI,
		target:      *target,
		port:        *port,
		visitorAddr: *visitorAddr,
	}
	body, err := v.run(ctx, *path)
	if err != nil {
		log.Fatalf("DEMO FAILED: %v", err)
	}
	log.Printf("DEMO OK: authenticated and fetched %s%s\n---\n%s", *target, *path, body)
}

// waitForTargetPeerAPI resolves the target node's PeerAPI base URL from the
// injector's netmap, retrying until the peer appears (the injector may see the
// target a moment after joining).
func waitForTargetPeerAPI(ctx context.Context, lc *local.Client, target string) (string, error) {
	target = strings.TrimSuffix(target, ".")
	for {
		st, err := lc.Status(ctx)
		if err == nil {
			if u := peerAPIFromStatus(st, target); u != "" {
				return u, nil
			}
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("target %q not found among peers before timeout", target)
		case <-time.After(time.Second):
		}
	}
}

func peerAPIFromStatus(st *ipnstate.Status, target string) string {
	for _, p := range st.Peer {
		dns := strings.TrimSuffix(p.DNSName, ".")
		if !strings.EqualFold(dns, target) {
			continue
		}
		if len(p.PeerAPIURL) > 0 {
			return p.PeerAPIURL[0]
		}
	}
	return ""
}

type visitor struct {
	srv         *tsnet.Server
	peerAPIURL  string // http://[fd7a:...]:PORT
	target      string // app.tailnet.ts.net
	port        int
	visitorAddr string
}

// dialIngress opens a fresh connection to the target node's PeerAPI, performs
// the /v0/ingress upgrade handshake, and returns the raw spliced net.Conn (over
// which the caller then speaks TLS, exactly as an internet client would to the
// real ingressd's splice).
func (v *visitor) dialIngress(ctx context.Context) (net.Conn, error) {
	u, err := url.Parse(v.peerAPIURL)
	if err != nil {
		return nil, fmt.Errorf("bad PeerAPI URL %q: %w", v.peerAPIURL, err)
	}
	conn, err := v.srv.Dial(ctx, "tcp", u.Host)
	if err != nil {
		return nil, fmt.Errorf("dialing target PeerAPI %s: %w", u.Host, err)
	}
	targetHostPort := net.JoinHostPort(v.target, fmt.Sprint(v.port))
	req := "POST /v0/ingress HTTP/1.1\r\n" +
		"Host: " + u.Host + "\r\n" +
		"Tailscale-Ingress-Src: " + v.visitorAddr + "\r\n" +
		"Tailscale-Ingress-Target: " + targetHostPort + "\r\n" +
		"Connection: upgrade\r\n" +
		"\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("writing /v0/ingress request: %w", err)
	}
	// Read the status line of the 101 response, but do not consume past the
	// header terminator — after "\r\n\r\n" the bytes are the spliced stream.
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("reading ingress response: %w", err)
	}
	if !strings.Contains(status, "101") {
		conn.Close()
		return nil, fmt.Errorf("expected 101 Switching Protocols, got %q (is TS_ALLOW_SELF_INGRESS=1 set on the target, and AllowFunnel configured for %s?)", strings.TrimSpace(status), targetHostPort)
	}
	// Drain the remaining response headers up to the blank line.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("reading ingress response headers: %w", err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	// Wrap so any bytes buffered by br (there shouldn't be, but be safe) are not lost.
	return &bufferedConn{Conn: conn, r: br}, nil
}

// roundTripFunc turns each HTTP request into a fresh ingress-spliced TLS
// connection to the target. Real ingressd opens one connection per client TCP
// session; for a scripted visitor a per-request connection is simplest and the
// node treats each as an independent funnel request (the ts_funnel_session
// cookie, carried by the cookie jar, is what links them after login).
func (v *visitor) roundTripFunc(ctx context.Context) http.RoundTripper {
	return &http.Transport{
		DisableKeepAlives: true,
		DialTLSContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
			raw, err := v.dialIngress(dctx)
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(raw, &tls.Config{
				ServerName:         v.target, // SNI must be the node's MagicDNS name
				InsecureSkipVerify: true,     // our test client; node presents a dev/ACME cert
				NextProtos:         []string{"http/1.1"},
			})
			if err := tlsConn.HandshakeContext(dctx); err != nil {
				raw.Close()
				return nil, fmt.Errorf("TLS handshake with target: %w", err)
			}
			return tlsConn, nil
		},
	}
}

var csrfRe = regexp.MustCompile(`name="gorilla\.csrf\.Token"\s+value="([^"]+)"`)

// run drives the full authenticated-funnel loop and returns the protected
// page's body on success.
func (v *visitor) run(ctx context.Context, path string) (string, error) {
	jar, _ := cookiejar.New(nil)

	// Client A: talks to the target node over the ingress splice. Its cookie jar
	// holds ts_funnel_state and ts_funnel_session. It does NOT auto-follow
	// redirects to control (a different host); we handle the hop manually.
	nodeClient := &http.Client{
		Transport: v.roundTripFunc(ctx),
		Jar:       jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	base := &url.URL{Scheme: "https", Host: v.target}
	start := base.ResolveReference(&url.URL{Path: path})

	// Step 1: hit the protected page → expect 302 to control /a/oauth_authorize.
	resp, err := nodeClient.Get(start.String())
	if err != nil {
		return "", fmt.Errorf("initial GET: %w", err)
	}
	loc, err := requireRedirect(resp, "initial funnel request")
	if err != nil {
		return "", err
	}
	if !strings.Contains(loc.Path, "/a/oauth_authorize") {
		return "", fmt.Errorf("expected redirect to /a/oauth_authorize, got %s", loc)
	}

	// Step 2 + 3: authenticate to control and obtain the authorization code by
	// following the authorize→login→authorize→callback chain on the control side.
	callbackURL, err := v.controlLoginAndAuthorize(ctx, loc)
	if err != nil {
		return "", err
	}
	if callbackURL.Host != v.target {
		return "", fmt.Errorf("control redirected to unexpected host %q (want %q)", callbackURL.Host, v.target)
	}

	// Step 4: hand the code back to the node callback → sets ts_funnel_session,
	// then 302s to the original page.
	resp, err = nodeClient.Get(callbackURL.String())
	if err != nil {
		return "", fmt.Errorf("callback GET: %w", err)
	}
	if _, err := requireRedirect(resp, "node callback"); err != nil {
		return "", fmt.Errorf("callback did not set session and redirect: %w", err)
	}

	// Step 5: fetch the protected page again; the session cookie should let us in.
	resp, err = nodeClient.Get(start.String())
	if err != nil {
		return "", fmt.Errorf("authenticated GET: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("authenticated request returned %s, want 200", resp.Status)
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return string(b), nil
}

// controlLoginAndAuthorize performs the dev-control login (CSRF scrape + POST)
// and returns the node callback URL (with ?code=...) that control redirects to.
func (v *visitor) controlLoginAndAuthorize(ctx context.Context, authorizeURL *url.URL) (*url.URL, error) {
	jar, _ := cookiejar.New(nil)
	// Client B: talks to control directly (over the tailnet, via the injector's
	// dialer). Holds the tailcontrol session cookie.
	ctrl := &http.Client{
		Transport: &http.Transport{DialContext: v.srv.Dial},
		Jar:       jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	controlBase := &url.URL{Scheme: authorizeURL.Scheme, Host: authorizeURL.Host}

	// GET the authorize URL; unauthenticated → 302 to /login?next_url=...
	resp, err := ctrl.Get(authorizeURL.String())
	if err != nil {
		return nil, fmt.Errorf("GET authorize: %w", err)
	}
	loginLoc, err := requireRedirect(resp, "authorize (unauthenticated)")
	if err != nil {
		// If control did NOT redirect to login, it may have gone straight to the
		// callback (already-authenticated); handle that below.
		if resp.StatusCode == http.StatusFound {
			return nil, err
		}
		return nil, fmt.Errorf("authorize did not bounce to login: %w", err)
	}
	if !strings.Contains(loginLoc.Path, "/login") {
		return nil, fmt.Errorf("expected /login redirect, got %s", loginLoc)
	}

	// GET the login page to scrape the CSRF token.
	loginPage := controlBase.ResolveReference(loginLoc)
	resp, err = ctrl.Get(loginPage.String())
	if err != nil {
		return nil, fmt.Errorf("GET login page: %w", err)
	}
	pageBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	m := csrfRe.FindSubmatch(pageBytes)
	if m == nil {
		return nil, errors.New("could not find gorilla.csrf.Token on the dev-control login page")
	}
	csrf := string(m[1])

	// POST the dev login (force-admin insecure@example.com path).
	form := url.Values{"provider": {"google"}, "gorilla.csrf.Token": {csrf}}
	resp, err = ctrl.PostForm(loginPage.String(), form)
	if err != nil {
		return nil, fmt.Errorf("POST login: %w", err)
	}
	resp.Body.Close()
	// After login control redirects back toward next_url (the authorize URL).

	// Re-drive the authorize URL now that we hold the tailcontrol cookie; for the
	// funnel client consent is auto-skipped, so control 302s to the node callback.
	for range 5 {
		resp, err = ctrl.Get(authorizeURL.String())
		if err != nil {
			return nil, fmt.Errorf("GET authorize (authenticated): %w", err)
		}
		loc, err := requireRedirect(resp, "authorize (authenticated)")
		if err != nil {
			return nil, err
		}
		// Follow control-internal redirects; stop when we're pointed at the node.
		if strings.EqualFold(loc.Host, v.target) || strings.Contains(loc.Path, "/funnel-auth/callback") {
			return loc, nil
		}
		authorizeURL = controlBase.ResolveReference(loc)
	}
	return nil, errors.New("authorize did not redirect to the node callback after login")
}

func requireRedirect(resp *http.Response, what string) (*url.URL, error) {
	defer resp.Body.Close()
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return nil, fmt.Errorf("%s: expected a 3xx redirect, got %s", what, resp.Status)
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		return nil, fmt.Errorf("%s: 3xx with no Location header", what)
	}
	u, err := url.Parse(loc)
	if err != nil {
		return nil, fmt.Errorf("%s: bad Location %q: %w", what, loc, err)
	}
	return u, nil
}

// bufferedConn preserves any bytes already buffered in the bufio.Reader after
// the ingress handshake, so the subsequent TLS client reads them first.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
