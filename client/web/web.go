// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package web provides the Tailscale client for web.
package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"embed"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/gorilla/csrf"
	"tailscale.com/client/tailscale"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/licenses"
	"tailscale.com/net/netutil"
	"tailscale.com/tailcfg"
	"tailscale.com/util/groupmember"
	"tailscale.com/version/distro"
)

// This contains all files needed to build the frontend assets.
// Because we assign this to the blank identifier, it does not actually embed the files.
// However, this does cause `go mod vendor` to include the files when vendoring the package.
// External packages that use the web client can `go mod vendor`, run `yarn build` to
// build the assets, then those asset bundles will be able to be embedded.
//
//go:embed yarn.lock index.html *.js *.json src/*
var _ embed.FS

//go:embed web.html web.css
var embeddedFS embed.FS

var tmpls *template.Template

// Server is the backend server for a Tailscale web client.
type Server struct {
	lc *tailscale.LocalClient

	devMode  bool
	devProxy *httputil.ReverseProxy // only filled when devMode is on

	apiHandler http.Handler // csrf-protected api handler
}

// NewServer constructs a new Tailscale web client server.
//
// lc is an optional parameter. When not filled, NewServer
// initializes its own tailscale.LocalClient.
func NewServer(devMode bool, lc *tailscale.LocalClient) (s *Server, cleanup func()) {
	if lc == nil {
		lc = &tailscale.LocalClient{}
	}
	s = &Server{
		devMode: devMode,
		lc:      lc,
	}
	cleanup = func() {}
	if s.devMode {
		cleanup = s.startDevServer()
		s.addProxyToDevServer()

		// Create new handler for "/api" requests.
		// And protect with gorilla csrf.
		csrfProtect := csrf.Protect(csrfKey())
		s.apiHandler = csrfProtect(&api{s: s})
	}
	s.lc.IncrementCounter(context.Background(), "web_client_initialization", 1)
	return s, cleanup
}

func init() {
	tmpls = template.Must(template.New("").ParseFS(embeddedFS, "*"))
}

// authorize returns the name of the user accessing the web UI after verifying
// whether the user has access to the web UI. The function will write the
// error to the provided http.ResponseWriter.
// Note: This is different from a tailscale user, and is typically the local
// user on the node.
func authorize(w http.ResponseWriter, r *http.Request) (string, error) {
	switch distro.Get() {
	case distro.Synology:
		user, err := synoAuthn()
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return "", err
		}
		if err := authorizeSynology(user); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return "", err
		}
		return user, nil
	case distro.QNAP:
		user, resp, err := qnapAuthn(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return "", err
		}
		if resp.IsAdmin == 0 {
			http.Error(w, err.Error(), http.StatusForbidden)
			return "", err
		}
		return user, nil
	}
	return "", nil
}

// authorizeSynology checks whether the provided user has access to the web UI
// by consulting the membership of the "administrators" group.
func authorizeSynology(name string) error {
	yes, err := groupmember.IsMemberOfGroup("administrators", name)
	if err != nil {
		return err
	}
	if !yes {
		return fmt.Errorf("not a member of administrators group")
	}
	return nil
}

type qnapAuthResponse struct {
	AuthPassed int    `xml:"authPassed"`
	IsAdmin    int    `xml:"isAdmin"`
	AuthSID    string `xml:"authSid"`
	ErrorValue int    `xml:"errorValue"`
}

func qnapAuthn(r *http.Request) (string, *qnapAuthResponse, error) {
	user, err := r.Cookie("NAS_USER")
	if err != nil {
		return "", nil, err
	}
	token, err := r.Cookie("qtoken")
	if err == nil {
		return qnapAuthnQtoken(r, user.Value, token.Value)
	}
	sid, err := r.Cookie("NAS_SID")
	if err == nil {
		return qnapAuthnSid(r, user.Value, sid.Value)
	}
	return "", nil, fmt.Errorf("not authenticated by any mechanism")
}

// qnapAuthnURL returns the auth URL to use by inferring where the UI is
// running based on the request URL. This is necessary because QNAP has so
// many options, see https://github.com/tailscale/tailscale/issues/7108
// and https://github.com/tailscale/tailscale/issues/6903
func qnapAuthnURL(requestUrl string, query url.Values) string {
	in, err := url.Parse(requestUrl)
	scheme := ""
	host := ""
	if err != nil || in.Scheme == "" {
		log.Printf("Cannot parse QNAP login URL %v", err)

		// try localhost and hope for the best
		scheme = "http"
		host = "localhost"
	} else {
		scheme = in.Scheme
		host = in.Host
	}

	u := url.URL{
		Scheme:   scheme,
		Host:     host,
		Path:     "/cgi-bin/authLogin.cgi",
		RawQuery: query.Encode(),
	}

	return u.String()
}

func qnapAuthnQtoken(r *http.Request, user, token string) (string, *qnapAuthResponse, error) {
	query := url.Values{
		"qtoken": []string{token},
		"user":   []string{user},
	}
	return qnapAuthnFinish(user, qnapAuthnURL(r.URL.String(), query))
}

func qnapAuthnSid(r *http.Request, user, sid string) (string, *qnapAuthResponse, error) {
	query := url.Values{
		"sid": []string{sid},
	}
	return qnapAuthnFinish(user, qnapAuthnURL(r.URL.String(), query))
}

func qnapAuthnFinish(user, url string) (string, *qnapAuthResponse, error) {
	// QNAP Force HTTPS mode uses a self-signed certificate. Even importing
	// the QNAP root CA isn't enough, the cert doesn't have a usable CN nor
	// SAN. See https://github.com/tailscale/tailscale/issues/6903
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get(url)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, err
	}
	authResp := &qnapAuthResponse{}
	if err := xml.Unmarshal(out, authResp); err != nil {
		return "", nil, err
	}
	if authResp.AuthPassed == 0 {
		return "", nil, fmt.Errorf("not authenticated")
	}
	return user, authResp, nil
}

func synoAuthn() (string, error) {
	cmd := exec.Command("/usr/syno/synoman/webman/modules/authenticate.cgi")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("auth: %v: %s", err, out)
	}
	return strings.TrimSpace(string(out)), nil
}

func authRedirect(w http.ResponseWriter, r *http.Request) bool {
	if distro.Get() == distro.Synology {
		return synoTokenRedirect(w, r)
	}
	return false
}

func synoTokenRedirect(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("X-Syno-Token") != "" {
		return false
	}
	if r.URL.Query().Get("SynoToken") != "" {
		return false
	}
	if r.Method == "POST" && r.FormValue("SynoToken") != "" {
		return false
	}
	// We need a SynoToken for authenticate.cgi.
	// So we tell the client to get one.
	_, _ = fmt.Fprint(w, synoTokenRedirectHTML)
	return true
}

const synoTokenRedirectHTML = `<html><body>
Redirecting with session token...
<script>
var serverURL = window.location.protocol + "//" + window.location.host;
var req = new XMLHttpRequest();
req.overrideMimeType("application/json");
req.open("GET", serverURL + "/webman/login.cgi", true);
req.onload = function() {
	var jsonResponse = JSON.parse(req.responseText);
	var token = jsonResponse["SynoToken"];
	document.location.href = serverURL + "/webman/3rdparty/Tailscale/?SynoToken=" + token;
};
req.send(null);
</script>
</body></html>
`

// ServeHTTP processes all requests for the Tailscale web client.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.devMode {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			// Pass through to other handlers via CSRF protection.
			s.apiHandler.ServeHTTP(w, r)
			return
		}
		// When in dev mode, proxy to the Vite dev server.
		s.devProxy.ServeHTTP(w, r)
		return
	}

	if authRedirect(w, r) {
		return
	}

	user, err := authorize(w, r)
	if err != nil {
		return
	}

	switch {
	case r.Method == "POST":
		s.servePostNodeUpdate(w, r)
		return
	default:
		s.lc.IncrementCounter(context.Background(), "web_client_page_load", 1)
		s.serveGetNodeData(w, r, user)
		return
	}
}

type nodeData struct {
	Profile           tailcfg.UserProfile
	SynologyUser      string
	Status            string
	DeviceName        string
	IP                string
	AdvertiseExitNode bool
	AdvertiseRoutes   string
	LicensesURL       string
	TUNMode           bool
	IsSynology        bool
	DSMVersion        int // 6 or 7, if IsSynology=true
	IsUnraid          bool
	UnraidToken       string
	IPNVersion        string
}

func (s *Server) getNodeData(ctx context.Context, user string) (*nodeData, error) {
	st, err := s.lc.Status(ctx)
	if err != nil {
		return nil, err
	}
	prefs, err := s.lc.GetPrefs(ctx)
	if err != nil {
		return nil, err
	}
	profile := st.User[st.Self.UserID]
	deviceName := strings.Split(st.Self.DNSName, ".")[0]
	versionShort := strings.Split(st.Version, "-")[0]
	data := &nodeData{
		SynologyUser: user,
		Profile:      profile,
		Status:       st.BackendState,
		DeviceName:   deviceName,
		LicensesURL:  licenses.LicensesURL(),
		TUNMode:      st.TUN,
		IsSynology:   distro.Get() == distro.Synology || envknob.Bool("TS_FAKE_SYNOLOGY"),
		DSMVersion:   distro.DSMVersion(),
		IsUnraid:     distro.Get() == distro.Unraid,
		UnraidToken:  os.Getenv("UNRAID_CSRF_TOKEN"),
		IPNVersion:   versionShort,
	}
	exitNodeRouteV4 := netip.MustParsePrefix("0.0.0.0/0")
	exitNodeRouteV6 := netip.MustParsePrefix("::/0")
	for _, r := range prefs.AdvertiseRoutes {
		if r == exitNodeRouteV4 || r == exitNodeRouteV6 {
			data.AdvertiseExitNode = true
		} else {
			if data.AdvertiseRoutes != "" {
				data.AdvertiseRoutes += ","
			}
			data.AdvertiseRoutes += r.String()
		}
	}
	if len(st.TailscaleIPs) != 0 {
		data.IP = st.TailscaleIPs[0].String()
	}
	return data, nil
}

func (s *Server) serveGetNodeData(w http.ResponseWriter, r *http.Request, user string) {
	data, err := s.getNodeData(r.Context(), user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	buf := new(bytes.Buffer)
	if err := tmpls.ExecuteTemplate(buf, "web.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(buf.Bytes())
}

func (s *Server) serveGetNodeDataJSON(w http.ResponseWriter, r *http.Request, user string) {
	data, err := s.getNodeData(r.Context(), user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(*data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	return
}

type nodeUpdate struct {
	AdvertiseRoutes   string
	AdvertiseExitNode bool
	Reauthenticate    bool
	ForceLogout       bool
}

func (s *Server) servePostNodeUpdate(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	st, err := s.lc.Status(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var postData nodeUpdate
	type mi map[string]any
	if err := json.NewDecoder(r.Body).Decode(&postData); err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(mi{"error": err.Error()})
		return
	}

	routes, err := netutil.CalcAdvertiseRoutes(postData.AdvertiseRoutes, postData.AdvertiseExitNode)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(mi{"error": err.Error()})
		return
	}
	mp := &ipn.MaskedPrefs{
		AdvertiseRoutesSet: true,
		WantRunningSet:     true,
	}
	mp.Prefs.WantRunning = true
	mp.Prefs.AdvertiseRoutes = routes
	log.Printf("Doing edit: %v", mp.Pretty())

	if _, err := s.lc.EditPrefs(r.Context(), mp); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(mi{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	var reauth, logout bool
	if postData.Reauthenticate {
		reauth = true
	}
	if postData.ForceLogout {
		logout = true
	}
	log.Printf("tailscaleUp(reauth=%v, logout=%v) ...", reauth, logout)
	url, err := s.tailscaleUp(r.Context(), st, postData)
	log.Printf("tailscaleUp = (URL %v, %v)", url != "", err)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(mi{"error": err.Error()})
		return
	}
	if url != "" {
		json.NewEncoder(w).Encode(mi{"url": url})
	} else {
		io.WriteString(w, "{}")
	}
	return
}

func (s *Server) tailscaleUp(ctx context.Context, st *ipnstate.Status, postData nodeUpdate) (authURL string, retErr error) {
	if postData.ForceLogout {
		if err := s.lc.Logout(ctx); err != nil {
			return "", fmt.Errorf("Logout error: %w", err)
		}
		return "", nil
	}

	origAuthURL := st.AuthURL
	isRunning := st.BackendState == ipn.Running.String()

	forceReauth := postData.Reauthenticate
	if !forceReauth {
		if origAuthURL != "" {
			return origAuthURL, nil
		}
		if isRunning {
			return "", nil
		}
	}

	// printAuthURL reports whether we should print out the
	// provided auth URL from an IPN notify.
	printAuthURL := func(url string) bool {
		return url != origAuthURL
	}

	watchCtx, cancelWatch := context.WithCancel(ctx)
	defer cancelWatch()
	watcher, err := s.lc.WatchIPNBus(watchCtx, 0)
	if err != nil {
		return "", err
	}
	defer watcher.Close()

	go func() {
		if !isRunning {
			s.lc.Start(ctx, ipn.Options{})
		}
		if forceReauth {
			s.lc.StartLoginInteractive(ctx)
		}
	}()

	for {
		n, err := watcher.Next()
		if err != nil {
			return "", err
		}
		if n.ErrMessage != nil {
			msg := *n.ErrMessage
			return "", fmt.Errorf("backend error: %v", msg)
		}
		if url := n.BrowseToURL; url != nil && printAuthURL(*url) {
			return *url, nil
		}
	}
}

// csrfKey creates a new random csrf token.
// If an error surfaces during key creation,
// the error is logged and the active process terminated.
func csrfKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatal("error generating CSRF key: %w", err)
	}
	return key
}
