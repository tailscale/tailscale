// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// proxy-to-grafana is a reverse proxy which identifies users based on their
// originating Tailscale identity and maps them to corresponding Grafana
// users, creating them if needed.
//
// It uses Grafana's AuthProxy feature:
// https://grafana.com/docs/grafana/latest/auth/auth-proxy/
//
// Set the TS_AUTHKEY environment variable to have this server automatically
// join your tailnet, or look for the logged auth link on first start.
//
// Use this Grafana configuration to enable the auth proxy:
//
//	[auth.proxy]
//	enabled = true
//	header_name = X-WEBAUTH-USER
//	header_property = username
//	auto_sign_up = true
//	whitelist = 127.0.0.1
//	headers = Email:X-Webauth-User, Name:X-Webauth-Name, Role:X-Webauth-Role
//	enable_login_token = true
//
// You can use grants in Tailscale ACL to give users different roles in Grafana.
// For example, to give group:eng the Editor role, add the following to your ACLs:
//
//	 "grants": [
//			{
//				"src": ["group:eng"],
//				"dst": ["tag:grafana"],
//				"app": {
//					"tailscale.com/cap/proxy-to-grafana": [{
//						"role": "editor",
//					}],
//				},
//			},
//	 ],
//
// If multiple roles are specified, the most permissive role is used.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
)

var (
	hostname     = flag.String("hostname", "", "Tailscale hostname to serve on, used as the base name for MagicDNS or subdomain in your domain alias for HTTPS.")
	backendAddr  = flag.String("backend-addr", "", "Address of the Grafana server served over HTTP, in host:port format. Typically localhost:nnnn.")
	tailscaleDir = flag.String("state-dir", "./", "Alternate directory to use for Tailscale state storage. If empty, a default is used.")
	useHTTPS     = flag.Bool("use-https", false, "Serve over HTTPS via your *.ts.net subdomain if enabled in Tailscale admin.")
	loginServer  = flag.String("login-server", "", "URL to alternative control server. If empty, the default Tailscale control is used.")
)

// aclCap is the Tailscale ACL capability used to configure proxy-to-grafana.
const aclCap tailcfg.PeerCapability = "tailscale.com/cap/proxy-to-grafana"

// aclGrant is an access control rule that assigns Grafana permissions
// while provisioning a user.
type aclGrant struct {
	// Role is one of: "viewer", "editor", "admin".
	Role string `json:"role"`
}

// grafanaRole defines possible Grafana roles.
type grafanaRole int

const (
	// Roles are ordered by their permissions, with the least permissive role first.
	// If a user has multiple roles, the most permissive role is used.
	ViewerRole grafanaRole = iota
	EditorRole
	AdminRole
)

// String returns the string representation of a grafanaRole.
// It is used as a header value in the HTTP request to Grafana.
func (r grafanaRole) String() string {
	switch r {
	case ViewerRole:
		return "Viewer"
	case EditorRole:
		return "Editor"
	case AdminRole:
		return "Admin"
	default:
		// A safe default.
		return "Viewer"
	}
}

// roleFromString converts a string to a grafanaRole.
// It is used to parse the role from the ACL grant.
func roleFromString(s string) (grafanaRole, error) {
	switch strings.ToLower(s) {
	case "viewer":
		return ViewerRole, nil
	case "editor":
		return EditorRole, nil
	case "admin":
		return AdminRole, nil
	}
	return ViewerRole, fmt.Errorf("unknown role: %q", s)
}

func main() {
	flag.Parse()
	if *hostname == "" || strings.Contains(*hostname, ".") {
		log.Fatal("missing or invalid --hostname")
	}
	if *backendAddr == "" {
		log.Fatal("missing --backend-addr")
	}
	ts := &tsnet.Server{
		Dir:        *tailscaleDir,
		Hostname:   *hostname,
		ControlURL: *loginServer,
	}

	// TODO(bradfitz,maisem): move this to a method on tsnet.Server probably.
	if err := ts.Start(); err != nil {
		log.Fatalf("Error starting tsnet.Server: %v", err)
	}
	localClient, _ := ts.LocalClient()

	url, err := url.Parse(fmt.Sprintf("http://%s", *backendAddr))
	if err != nil {
		log.Fatalf("couldn't parse backend address: %v", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(url)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		modifyRequest(req, localClient)
	}

	var ln net.Listener
	if *useHTTPS {
		ln, err = ts.Listen("tcp", ":443")
		ln = tls.NewListener(ln, &tls.Config{
			GetCertificate: localClient.GetCertificate,
		})

		go func() {
			// wait for tailscale to start before trying to fetch cert names
			for range 60 {
				st, err := localClient.Status(context.Background())
				if err != nil {
					log.Printf("error retrieving tailscale status; retrying: %v", err)
				} else {
					log.Printf("tailscale status: %v", st.BackendState)
					if st.BackendState == "Running" {
						break
					}
				}
				time.Sleep(time.Second)
			}

			l80, err := ts.Listen("tcp", ":80")
			if err != nil {
				log.Fatal(err)
			}
			name, ok := localClient.ExpandSNIName(context.Background(), *hostname)
			if !ok {
				log.Fatalf("can't get hostname for https redirect")
			}
			if err := http.Serve(l80, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, fmt.Sprintf("https://%s", name), http.StatusMovedPermanently)
			})); err != nil {
				log.Fatal(err)
			}
		}()
	} else {
		ln, err = ts.Listen("tcp", ":80")
	}
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("proxy-to-grafana running at %v, proxying to %v", ln.Addr(), *backendAddr)
	log.Fatal(http.Serve(ln, proxy))
}

func modifyRequest(req *http.Request, localClient whoisIdentitySource) {
	// Delete any existing X-Webauth-* headers to prevent possible spoofing
	// if getting Tailnet identity fails.
	for h := range req.Header {
		if strings.HasPrefix(h, "X-Webauth-") {
			req.Header.Del(h)
		}
	}

	// Set the X-Webauth-* headers only for the /login path
	// With enable_login_token set to true, we get a cookie that handles
	// auth for paths that are not /login
	if req.URL.Path != "/login" {
		return
	}

	user, role, err := getTailscaleIdentity(req.Context(), localClient, req.RemoteAddr)
	if err != nil {
		log.Printf("error getting Tailscale user: %v", err)
		return
	}

	req.Header.Set("X-Webauth-User", user.LoginName)
	req.Header.Set("X-Webauth-Name", user.DisplayName)
	req.Header.Set("X-Webauth-Role", role.String())
}

func getTailscaleIdentity(ctx context.Context, localClient whoisIdentitySource, ipPort string) (*tailcfg.UserProfile, grafanaRole, error) {
	whois, err := localClient.WhoIs(ctx, ipPort)
	if err != nil {
		return nil, ViewerRole, fmt.Errorf("failed to identify remote host: %w", err)
	}
	if whois.Node.IsTagged() {
		return nil, ViewerRole, fmt.Errorf("tagged nodes are not users")
	}
	if whois.UserProfile == nil || whois.UserProfile.LoginName == "" {
		return nil, ViewerRole, fmt.Errorf("failed to identify remote user")
	}

	role := ViewerRole
	grants, err := tailcfg.UnmarshalCapJSON[aclGrant](whois.CapMap, aclCap)
	if err != nil {
		return nil, ViewerRole, fmt.Errorf("failed to unmarshal ACL grants: %w", err)
	}
	for _, g := range grants {
		r, err := roleFromString(g.Role)
		if err != nil {
			return nil, ViewerRole, fmt.Errorf("failed to parse role: %w", err)
		}
		role = max(role, r)
	}

	return whois.UserProfile, role, nil
}

type whoisIdentitySource interface {
	WhoIs(ctx context.Context, ipPort string) (*apitype.WhoIsResponse, error)
}
