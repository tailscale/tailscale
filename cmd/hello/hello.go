// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The hello binary runs hello.ipn.dev.
package main // import "tailscale.com/cmd/hello"

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"

	"tailscale.com/safesocket"
	"tailscale.com/tailcfg"
)

var (
	httpAddr  = flag.String("http", ":80", "address to run an HTTP server on, or empty for none")
	httpsAddr = flag.String("https", ":443", "address to run an HTTPS server on, or empty for none")
)

func main() {
	flag.Parse()
	if !devMode() {
		tmpl = template.Must(template.New("home").Parse(slurpHTML()))
	}

	http.HandleFunc("/", root)
	log.Printf("Starting hello server.")

	errc := make(chan error, 1)
	if *httpAddr != "" {
		log.Printf("running HTTP server on %s", *httpAddr)
		go func() {
			errc <- http.ListenAndServe(*httpAddr, nil)
		}()
	}
	if *httpsAddr != "" {
		log.Printf("running HTTPS server on %s", *httpsAddr)
		go func() {
			errc <- http.ListenAndServeTLS(*httpsAddr,
				"/etc/hello/hello.ipn.dev.crt",
				"/etc/hello/hello.ipn.dev.key",
				nil,
			)
		}()
	}
	log.Fatal(<-errc)
}

func slurpHTML() string {
	slurp, err := ioutil.ReadFile("hello.tmpl.html")
	if err != nil {
		log.Fatal(err)
	}
	return string(slurp)
}

func devMode() bool { return *httpsAddr == "" && *httpAddr != "" }

func getTmpl() (*template.Template, error) {
	if devMode() {
		return template.New("home").Parse(slurpHTML())
	}
	return tmpl, nil
}

var tmpl *template.Template // not used in dev mode, initialized by main after flag parse

type tmplData struct {
	DisplayName   string // "Foo Barberson"
	LoginName     string // "foo@bar.com"
	ProfilePicURL string // "https://..."
	MachineName   string // "imac5k"
	MachineOS     string // "Linux"
	IP            string // "100.2.3.4"
}

func root(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil && *httpsAddr != "" {
		host := r.Host
		if strings.Contains(r.Host, "100.101.102.103") {
			host = "hello.ipn.dev"
		}
		http.Redirect(w, r, "https://"+host, http.StatusFound)
		return
	}
	if r.RequestURI != "/" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "no remote addr", 500)
		return
	}
	tmpl, err := getTmpl()
	if err != nil {
		w.Header().Set("Content-Type", "text/plain")
		http.Error(w, "template error: "+err.Error(), 500)
		return
	}

	who, err := whoIs(ip)
	var data tmplData
	if err != nil {
		if devMode() {
			data = tmplData{
				DisplayName:   "Taily Scalerson",
				LoginName:     "taily@scaler.son",
				ProfilePicURL: "https://placekitten.com/200/200",
				MachineName:   "scaled",
				MachineOS:     "Linux",
				IP:            "100.1.2.3",
			}
		} else {
			log.Printf("whois(%q) error: %v", ip, err)
			http.Error(w, "Your Tailscale works, but we failed to look you up.", 500)
			return
		}
	} else {
		data = tmplData{
			DisplayName:   who.UserProfile.DisplayName,
			LoginName:     who.UserProfile.LoginName,
			ProfilePicURL: who.UserProfile.ProfilePicURL,
			MachineName:   who.Node.ComputedName,
			MachineOS:     who.Node.Hostinfo.OS,
			IP:            ip,
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, data)
}

// tsSockClient does HTTP requests to the local Tailscale daemon.
// The hostname in the HTTP request is ignored.
var tsSockClient = &http.Client{
	Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return safesocket.ConnectDefault()
		},
	},
}

func whoIs(ip string) (*tailcfg.WhoIsResponse, error) {
	res, err := tsSockClient.Get("http://local-tailscaled.sock/localapi/v0/whois?ip=" + url.QueryEscape(ip))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	slurp, _ := ioutil.ReadAll(res.Body)
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %s: %s", res.Status, slurp)
	}
	r := new(tailcfg.WhoIsResponse)
	if err := json.Unmarshal(slurp, r); err != nil {
		if max := 200; len(slurp) > max {
			slurp = slurp[:max]
		}
		return nil, fmt.Errorf("failed to parse JSON WhoIsResponse from %q", slurp)
	}
	return r, nil
}
