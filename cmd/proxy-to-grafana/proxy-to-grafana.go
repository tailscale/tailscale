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
//	headers = Name:X-WEBAUTH-NAME
//	enable_login_token = true
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

	"tailscale.com/client/tailscale"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
)

var (
	hostname     = flag.String("hostname", "", "Tailscale hostname to serve on, used as the base name for MagicDNS or subdomain in your domain alias for HTTPS.")
	backendAddr  = flag.String("backend-addr", "", "Address of the Grafana server served over HTTP, in host:port format. Typically localhost:nnnn.")
	tailscaleDir = flag.String("state-dir", "./", "Alternate directory to use for Tailscale state storage. If empty, a default is used.")
	useHTTPS     = flag.Bool("use-https", false, "Serve over HTTPS via your *.ts.net subdomain if enabled in Tailscale admin.")
)

func main() {
	flag.Parse()
	if *hostname == "" || strings.Contains(*hostname, ".") {
		log.Fatal("missing or invalid --hostname")
	}
	if *backendAddr == "" {
		log.Fatal("missing --backend-addr")
	}
	ts := &tsnet.Server{
		Dir:      *tailscaleDir,
		Hostname: *hostname,
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
			for i := 0; i < 60; i++ {
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

func modifyRequest(req *http.Request, localClient *tailscale.LocalClient) {
	// with enable_login_token set to true, we get a cookie that handles
	// auth for paths that are not /login
	if req.URL.Path != "/login" {
		return
	}

	user, err := getTailscaleUser(req.Context(), localClient, req.RemoteAddr)
	if err != nil {
		log.Printf("error getting Tailscale user: %v", err)
		return
	}

	req.Header.Set("X-Webauth-User", user.LoginName)
	req.Header.Set("X-Webauth-Name", user.DisplayName)
}

func getTailscaleUser(ctx context.Context, localClient *tailscale.LocalClient, ipPort string) (*tailcfg.UserProfile, error) {
	whois, err := localClient.WhoIs(ctx, ipPort)
	if err != nil {
		return nil, fmt.Errorf("failed to identify remote host: %w", err)
	}
	if whois.Node.IsTagged() {
		return nil, fmt.Errorf("tagged nodes are not users")
	}
	if whois.UserProfile == nil || whois.UserProfile.LoginName == "" {
		return nil, fmt.Errorf("failed to identify remote user")
	}

	return whois.UserProfile, nil
}
