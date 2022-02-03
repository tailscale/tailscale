// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"tailscale.com/client/tailscale"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tsweb"
)

var (
	httpAddr  = flag.String("http", ":80", "address to run an HTTP server on, or empty for none")
	httpsAddr = flag.String("https", ":443", "address to run an HTTPS server on, or empty for none")
	testIP    = flag.String("test-ip", "", "if non-empty, look up IP and exit before running a server")
)

//go:embed hello.tmpl.html
var embeddedTemplate string

func main() {
	flag.Parse()
	if *testIP != "" {
		res, err := tailscale.WhoIs(context.Background(), *testIP)
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

	mainAddr := *httpsAddr
	if mainAddr == "" {
		mainAddr = *httpAddr
	}
	httpCfg := tsweb.ServerConfig{
		Name:    "hello",
		Addr:    mainAddr,
		Handler: http.DefaultServeMux,
	}
	server := tsweb.NewServer(httpCfg)
	if server.HTTPS != nil {
		server.HTTPS.TLSConfig.GetCertificate = func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			switch hi.ServerName {
			case "hello.ts.net":
				return tailscale.GetCertificate(hi)
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
		}
	}
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func devMode() bool { return *httpsAddr == "" && *httpAddr != "" }

func getTmpl() (*template.Template, error) {
	if devMode() {
		tmplData, err := ioutil.ReadFile("hello.tmpl.html")
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
		if nodeIP.IP().Is4() && nodeIP.IsSingleIP() {
			return nodeIP.IP().String()
		}
	}
	for _, nodeIP := range who.Node.Addresses {
		if nodeIP.IsSingleIP() {
			return nodeIP.IP().String()
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

	who, err := tailscale.WhoIs(r.Context(), r.RemoteAddr)
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
			MachineOS:     who.Node.Hostinfo.OS,
			IP:            tailscaleIP(who),
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, data)
}

// firstLabel s up until the first period, if any.
func firstLabel(s string) string {
	if i := strings.Index(s, "."); i != -1 {
		return s[:i]
	}
	return s
}
