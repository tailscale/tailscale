// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The hello binary runs hello.ts.net.
package main // import "tailscale.com/cmd/hello"

import (
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
)

var (
	httpAddr  = flag.String("http", ":80", "address to run an HTTP server on, or empty for none")
	httpsAddr = flag.String("https", ":443", "address to run an HTTPS server on, or empty for none")
	testIP    = flag.String("test-ip", "", "if non-empty, look up IP and exit before running a server")
)

//go:embed hello.tmpl.html
var embeddedTemplate string

var localClient local.Client

func main() {
	flag.Parse()
	if *testIP != "" {
		res, err := localClient.WhoIs(context.Background(), *testIP)
		if err != nil {
			log.Fatal(err)
		}
		e := json.NewEncoder(os.Stdout)
		e.SetIndent("", "\t")
		e.Encode(res)
		return
	}
	if devMode() {
		// Parse it optimistically
		var err error
		tmpl, err = template.New("home").Parse(embeddedTemplate)
		if err != nil {
			log.Printf("ignoring template error in dev mode: %v", err)
		}
	} else {
		if embeddedTemplate == "" {
			log.Fatalf("embeddedTemplate is empty; must be build with Go 1.16+")
		}
		tmpl = template.Must(template.New("home").Parse(embeddedTemplate))
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
			hs := &http.Server{
				Addr: *httpsAddr,
				TLSConfig: &tls.Config{
					GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
						switch hi.ServerName {
						case "hello.ts.net":
							return localClient.GetCertificate(hi)
						case "hello.ipn.dev":
							c, err := tls.LoadX509KeyPair(
								"/etc/hello/hello.ipn.dev.crt",
								"/etc/hello/hello.ipn.dev.key",
							)
							if err != nil {
								return nil, err
							}
							return &c, nil
						}
						return nil, errors.New("invalid SNI name")
					},
				},
				IdleTimeout:       30 * time.Second,
				ReadHeaderTimeout: 20 * time.Second,
				MaxHeaderBytes:    10 << 10,
			}
			errc <- hs.ListenAndServeTLS("", "")
		}()
	}
	log.Fatal(<-errc)
}

func devMode() bool { return *httpsAddr == "" && *httpAddr != "" }

func getTmpl() (*template.Template, error) {
	if devMode() {
		tmplData, err := os.ReadFile("hello.tmpl.html")
		if os.IsNotExist(err) {
			log.Printf("using baked-in template in dev mode; can't find hello.tmpl.html in current directory")
			return tmpl, nil
		}
		return template.New("home").Parse(string(tmplData))
	}
	return tmpl, nil
}

// tmpl is the template used in prod mode.
// In dev mode it's only used if the template file doesn't exist on disk.
// It's initialized by main after flag parsing.
var tmpl *template.Template

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

func root(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil && *httpsAddr != "" {
		host := r.Host
		if strings.Contains(r.Host, "100.101.102.103") ||
			strings.Contains(r.Host, "hello.ipn.dev") {
			host = "hello.ts.net"
		}
		http.Redirect(w, r, "https://"+host, http.StatusFound)
		return
	}
	if r.RequestURI != "/" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if r.TLS != nil && *httpsAddr != "" && strings.Contains(r.Host, "hello.ipn.dev") {
		http.Redirect(w, r, "https://hello.ts.net", http.StatusFound)
		return
	}
	tmpl, err := getTmpl()
	if err != nil {
		w.Header().Set("Content-Type", "text/plain")
		http.Error(w, "template error: "+err.Error(), 500)
		return
	}

	who, err := localClient.WhoIs(r.Context(), r.RemoteAddr)
	var data tmplData
	if err != nil {
		if devMode() {
			log.Printf("warning: using fake data in dev mode due to whois lookup error: %v", err)
			data = tmplData{
				DisplayName:   "Taily Scalerson",
				LoginName:     "taily@scaler.son",
				ProfilePicURL: "https://placekitten.com/200/200",
				MachineName:   "scaled",
				MachineOS:     "Linux",
				IP:            "100.1.2.3",
			}
		} else {
			log.Printf("whois(%q) error: %v", r.RemoteAddr, err)
			http.Error(w, "Your Tailscale works, but we failed to look you up.", 500)
			return
		}
	} else {
		data = tmplData{
			DisplayName:   who.UserProfile.DisplayName,
			LoginName:     who.UserProfile.LoginName,
			ProfilePicURL: who.UserProfile.ProfilePicURL,
			MachineName:   firstLabel(who.Node.ComputedName),
			MachineOS:     who.Node.Hostinfo.OS(),
			IP:            tailscaleIP(who),
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, data)
}

// firstLabel s up until the first period, if any.
func firstLabel(s string) string {
	s, _, _ = strings.Cut(s, ".")
	return s
}
