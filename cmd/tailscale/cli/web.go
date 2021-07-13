// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cgi"
	"net/url"
	"os/exec"
	"runtime"
	"strings"

	"github.com/peterbourgon/ff/v2/ffcli"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/types/preftype"
	"tailscale.com/util/groupmember"
	"tailscale.com/version/distro"
)

//go:embed web.html
var webHTML string

//go:embed web.css
var webCSS string

//go:embed auth-redirect.html
var authenticationRedirectHTML string

var tmpl *template.Template

func init() {
	tmpl = template.Must(template.New("web.html").Parse(webHTML))
	template.Must(tmpl.New("web.css").Parse(webCSS))
}

type tmplData struct {
	Profile      tailcfg.UserProfile
	SynologyUser string
	Status       string
	DeviceName   string
	IP           string
}

var webCmd = &ffcli.Command{
	Name:       "web",
	ShortUsage: "web [flags]",
	ShortHelp:  "Run a web server for controlling Tailscale",

	LongHelp: strings.TrimSpace(`
"tailscale web" runs a webserver for controlling the Tailscale daemon.

It's primarily intended for use on Synology, QNAP, and other
NAS devices where a web interface is the natural place to control
Tailscale, as opposed to a CLI or a native app.
`),

	FlagSet: (func() *flag.FlagSet {
		webf := flag.NewFlagSet("web", flag.ExitOnError)
		webf.StringVar(&webArgs.listen, "listen", "localhost:8088", "listen address; use port 0 for automatic")
		webf.BoolVar(&webArgs.cgi, "cgi", false, "run as CGI script")
		return webf
	})(),
	Exec: runWeb,
}

var webArgs struct {
	listen string
	cgi    bool
}

func runWeb(ctx context.Context, args []string) error {
	if len(args) > 0 {
		log.Fatalf("too many non-flag arguments: %q", args)
	}

	if webArgs.cgi {
		if err := cgi.Serve(http.HandlerFunc(webHandler)); err != nil {
			log.Printf("tailscale.cgi: %v", err)
			return err
		}
		return nil
	}
	log.Printf("web server running on: %s\n", webArgs.listen)
	return http.ListenAndServe(webArgs.listen, http.HandlerFunc(webHandler))
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
	if err != nil {
		return "", nil, err
	}
	query := url.Values{
		"qtoken": []string{token.Value},
		"user":   []string{user.Value},
	}
	u := url.URL{
		Scheme:   r.URL.Scheme,
		Host:     r.URL.Host,
		Path:     "/cgi-bin/authLogin.cgi",
		RawQuery: query.Encode(),
	}
	resp, err := http.Get(u.String())
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	out, err := ioutil.ReadAll(resp.Body)
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
	return user.Value, authResp, nil
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
	serverURL := r.URL.Scheme + "://" + r.URL.Host
	fmt.Fprintf(w, synoTokenRedirectHTML, serverURL)
	return true
}

const synoTokenRedirectHTML = `<html><body>
Redirecting with session token...
<script>
var serverURL = %q;
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

func webHandler(w http.ResponseWriter, r *http.Request) {
	if authRedirect(w, r) {
		return
	}

	user, err := authorize(w, r)
	if err != nil {
		return
	}

	if r.URL.Path == "/redirect" || r.URL.Path == "/redirect/" {
		w.Write([]byte(authenticationRedirectHTML))
		return
	}

	if r.Method == "POST" {
		type mi map[string]interface{}
		w.Header().Set("Content-Type", "application/json")
		url, err := tailscaleUpForceReauth(r.Context())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(mi{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(mi{"url": url})
		return
	}

	st, err := tailscale.Status(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	profile := st.User[st.Self.UserID]
	deviceName := strings.Split(st.Self.DNSName, ".")[0]
	data := tmplData{
		SynologyUser: user,
		Profile:      profile,
		Status:       st.BackendState,
		DeviceName:   deviceName,
	}
	if len(st.TailscaleIPs) != 0 {
		data.IP = st.TailscaleIPs[0].String()
	}

	buf := new(bytes.Buffer)
	if err := tmpl.Execute(buf, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(buf.Bytes())
}

// TODO(crawshaw): some of this is very similar to the code in 'tailscale up', can we share anything?
func tailscaleUpForceReauth(ctx context.Context) (authURL string, retErr error) {
	prefs := ipn.NewPrefs()
	prefs.ControlURL = ipn.DefaultControlURL
	prefs.WantRunning = true
	prefs.CorpDNS = true
	prefs.AllowSingleHosts = true
	prefs.ForceDaemon = (runtime.GOOS == "windows")

	if distro.Get() == distro.Synology {
		prefs.NetfilterMode = preftype.NetfilterOff
	}

	st, err := tailscale.Status(ctx)
	if err != nil {
		return "", fmt.Errorf("can't fetch status: %v", err)
	}
	origAuthURL := st.AuthURL

	// printAuthURL reports whether we should print out the
	// provided auth URL from an IPN notify.
	printAuthURL := func(url string) bool {
		return url != origAuthURL
	}

	c, bc, pumpCtx, cancel := connect(ctx)
	defer cancel()

	gotEngineUpdate := make(chan bool, 1) // gets value upon an engine update
	go pump(pumpCtx, bc, c)

	bc.SetNotifyCallback(func(n ipn.Notify) {
		if n.Engine != nil {
			select {
			case gotEngineUpdate <- true:
			default:
			}
		}
		if n.ErrMessage != nil {
			msg := *n.ErrMessage
			if msg == ipn.ErrMsgPermissionDenied {
				switch runtime.GOOS {
				case "windows":
					msg += " (Tailscale service in use by other user?)"
				default:
					msg += " (try 'sudo tailscale up [...]')"
				}
			}
			retErr = fmt.Errorf("backend error: %v", msg)
			cancel()
		} else if url := n.BrowseToURL; url != nil && printAuthURL(*url) {
			authURL = *url
			cancel()
		}
	})
	// Wait for backend client to be connected so we know
	// we're subscribed to updates. Otherwise we can miss
	// an update upon its transition to running. Do so by causing some traffic
	// back to the bus that we then wait on.
	bc.RequestEngineStatus()
	select {
	case <-gotEngineUpdate:
	case <-pumpCtx.Done():
		return authURL, pumpCtx.Err()
	}

	bc.SetPrefs(prefs)

	bc.Start(ipn.Options{
		StateKey: ipn.GlobalDaemonStateKey,
	})
	bc.StartLoginInteractive()

	<-pumpCtx.Done() // wait for authURL or complete failure
	if authURL == "" && retErr == nil {
		retErr = pumpCtx.Err()
	}
	if authURL == "" && retErr == nil {
		return "", fmt.Errorf("login failed with no backend error message")
	}
	return authURL, retErr
}
