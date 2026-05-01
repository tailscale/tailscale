// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package helloserver implements the HTTP server behind hello.ts.net.
package helloserver

import (
	"crypto/tls"
	_ "embed"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

//go:embed hello.tmpl.html
var embeddedTemplate string

var tmpl = template.Must(template.New("home").Parse(embeddedTemplate))

// Server is an HTTP server for hello.ts.net.
//
// The zero value is not valid; populate at least one of HTTPAddr or HTTPSAddr
// before calling Run.
type Server struct {
	// HTTPAddr is the address to run an HTTP server on, or empty for none.
	HTTPAddr string

	// HTTPSAddr is the address to run an HTTPS server on, or empty for none.
	HTTPSAddr string

	// LocalClient is used to look up the identity of incoming requests and
	// to obtain TLS certificates. If nil, the zero value of local.Client is
	// used.
	LocalClient *local.Client
}

func (s *Server) localClient() *local.Client {
	if s.LocalClient != nil {
		return s.LocalClient
	}
	return &local.Client{}
}

// Run starts the configured HTTP and HTTPS servers and blocks until one of
// them returns an error.
func (s *Server) Run() error {
	errc := make(chan error, 1)
	if s.HTTPAddr != "" {
		log.Printf("running HTTP server on %s", s.HTTPAddr)
		go func() {
			errc <- http.ListenAndServe(s.HTTPAddr, s)
		}()
	}
	if s.HTTPSAddr != "" {
		log.Printf("running HTTPS server on %s", s.HTTPSAddr)
		go func() {
			hs := &http.Server{
				Addr:    s.HTTPSAddr,
				Handler: s,
				TLSConfig: &tls.Config{
					GetCertificate: s.localClient().GetCertificate,
				},
				IdleTimeout:       30 * time.Second,
				ReadHeaderTimeout: 20 * time.Second,
				MaxHeaderBytes:    10 << 10,
			}
			errc <- hs.ListenAndServeTLS("", "")
		}()
	}
	return <-errc
}

type tmplData struct {
	DisplayName   string // "Foo Barberson"
	LoginName     string // "foo@bar.com"
	ProfilePicURL string // "https://..."
	MachineName   string // "imac5k"
	MachineOS     string // "Linux"
	IP            string // "100.2.3.4"
}

func tailscaleIP(who *apitype.WhoIsResponse) string {
	if who == nil {
		return ""
	}
	vals, err := tailcfg.UnmarshalNodeCapJSON[string](who.Node.CapMap, tailcfg.NodeAttrNativeIPV4)
	if err == nil && len(vals) > 0 {
		return vals[0]
	}
	for _, nodeIP := range who.Node.Addresses {
		if nodeIP.Addr().Is4() && nodeIP.IsSingleIP() {
			return nodeIP.Addr().String()
		}
	}
	for _, nodeIP := range who.Node.Addresses {
		if nodeIP.IsSingleIP() {
			return nodeIP.Addr().String()
		}
	}
	return ""
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil && s.HTTPSAddr != "" {
		host := r.Host
		if strings.Contains(r.Host, "100.101.102.103") {
			host = "hello.ts.net"
		}
		http.Redirect(w, r, "https://"+host, http.StatusFound)
		return
	}
	if r.RequestURI != "/" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	who, err := s.localClient().WhoIs(r.Context(), r.RemoteAddr)
	if err != nil {
		log.Printf("whois(%q) error: %v", r.RemoteAddr, err)
		http.Error(w, "Your Tailscale works, but we failed to look you up.", 500)
		return
	}
	data := tmplData{
		DisplayName:   who.UserProfile.DisplayName,
		LoginName:     who.UserProfile.LoginName,
		ProfilePicURL: who.UserProfile.ProfilePicURL,
		MachineName:   firstLabel(who.Node.ComputedName),
		MachineOS:     who.Node.Hostinfo.OS(),
		IP:            tailscaleIP(who),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, data)
}

// firstLabel returns s up until the first period, if any.
func firstLabel(s string) string {
	s, _, _ = strings.Cut(s, ".")
	return s
}
