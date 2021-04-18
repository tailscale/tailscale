// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/http/cgi"
	"os/exec"
	"runtime"
	"strings"

	"github.com/peterbourgon/ff/v2/ffcli"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/types/preftype"
	"tailscale.com/version/distro"
)

//go:embed web.html
var webHTML string

//go:embed web.css
var webCSS string

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
		return cgi.Serve(http.HandlerFunc(webHandler))
	}
	return http.ListenAndServe(webArgs.listen, http.HandlerFunc(webHandler))
}

func auth() (string, error) {
	if distro.Get() == distro.Synology {
		cmd := exec.Command("/usr/syno/synoman/webman/modules/authenticate.cgi")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("auth: %v: %s", err, out)
		}
		return string(out), nil
	}

	return "", nil
}

func synoTokenRedirect(w http.ResponseWriter, r *http.Request) bool {
	if distro.Get() != distro.Synology {
		return false
	}
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

const authenticationRedirectHTML = `
<html>
<head>
	<title>Redirecting...</title>
	<style>
		html,
		body {
			height: 100%;
		}

		html {
			background-color: rgb(249, 247, 246);
			font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans", sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol", "Noto Color Emoji";
			line-height: 1.5;
			-webkit-text-size-adjust: 100%;
			-webkit-font-smoothing: antialiased;
			-moz-osx-font-smoothing: grayscale;
		}

		body {
			display: flex;
			flex-direction: column;
			align-items: center;
			justify-content: center;
		}

		.spinner {
			margin-bottom: 2rem;
			border: 4px rgba(112, 110, 109, 0.5) solid;
			border-left-color: transparent;
			border-radius: 9999px;
			width: 4rem;
			height: 4rem;
			-webkit-animation: spin 700ms linear infinite;
      animation: spin 800ms linear infinite;
		}

		.label {
			color: rgb(112, 110, 109);
			padding-left: 0.4rem;
		}

		@-webkit-keyframes spin {
			to {
				transform: rotate(360deg);
			}
		}

		@keyframes spin {
			to {
				transform: rotate(360deg);
			}
		}
	</style>
</head>
<body>
	<div class="spinner"></div>
	<div class="label">Redirecting...</div>
</body>
`

func webHandler(w http.ResponseWriter, r *http.Request) {
	if synoTokenRedirect(w, r) {
		return
	}

	user, err := auth()
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	if r.URL.Path == "/redirect" || r.URL.Path == "/redirect/" {
		w.Write([]byte(authenticationRedirectHTML))
		return
	}

	if r.Method == "POST" {
		type mi map[string]interface{}
		w.Header().Set("Content-Type", "application/json")
		url, err := tailscaleUp(r.Context())
		if err != nil {
			json.NewEncoder(w).Encode(mi{"error": err})
			return
		}
		json.NewEncoder(w).Encode(mi{"url": url})
		return
	}

	st, err := tailscale.Status(r.Context())
	if err != nil {
		http.Error(w, err.Error(), 500)
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
		http.Error(w, err.Error(), 500)
		return
	}
	w.Write(buf.Bytes())
}

// TODO(crawshaw): some of this is very similar to the code in 'tailscale up', can we share anything?
func tailscaleUp(ctx context.Context) (authURL string, retErr error) {
	prefs := ipn.NewPrefs()
	prefs.ControlURL = ipn.DefaultControlURL
	prefs.WantRunning = true
	prefs.CorpDNS = true
	prefs.AllowSingleHosts = true
	prefs.ForceDaemon = (runtime.GOOS == "windows")

	if distro.Get() == distro.Synology {
		prefs.NetfilterMode = preftype.NetfilterOff
	}

	c, bc, ctx, cancel := connect(ctx)
	defer cancel()

	bc.SetNotifyCallback(func(n ipn.Notify) {
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
		} else if url := n.BrowseToURL; url != nil {
			authURL = *url
			cancel()
		}
	})

	bc.SetPrefs(prefs)

	bc.Start(ipn.Options{
		StateKey: ipn.GlobalDaemonStateKey,
	})
	bc.StartLoginInteractive()
	pump(ctx, bc, c)

	if authURL == "" && retErr == nil {
		return "", fmt.Errorf("login failed with no backend error message")
	}
	return authURL, retErr
}
