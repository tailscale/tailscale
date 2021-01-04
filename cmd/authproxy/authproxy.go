package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"time"

	grafanaclient "github.com/nytm/go-grafana-api"
	"inet.af/netaddr"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
)

var spoofAdmin = flag.Bool("spoof-admin", false, "make everybody be an admin")

func main() {
	flag.Parse()
	log.Printf("starting")
	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on %v", ln.Addr())
	target, _ := url.Parse("http://localhost:80")
	rp := httputil.NewSingleHostReverseProxy(target)

	creds, err := ioutil.ReadFile("/etc/grafana/admin-creds.authproxy")
	if err != nil {
		log.Fatal(err)
	}
	userColonPass := strings.TrimSpace(string(creds))
	log.Printf("user pass: %q", userColonPass)

	gc, err := grafanaclient.New(userColonPass, "http://localhost")
	if err != nil {
		log.Fatal(err)
	}

	var (
		addMu sync.Mutex
		added = map[string]bool{}
	)
	addUser := func(email, role string) {
		addMu.Lock()
		defer addMu.Unlock()
		if added[email] {
			return
		}
		added[email] = true
		err := gc.AddOrgUser(1, "email", role)
		log.Printf("adding org user %s as %v: %v", email, role, err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ipp, err := netaddr.ParseIPPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "bad RemoteAddr", 400)
			return
		}
		if !tsaddr.IsTailscaleIP(ipp.IP) {
			http.Error(w, "not a Tailscale IP", 403)
			return
		}
		tstat, err := getTailscaleStatus()
		if err != nil {
			log.Printf("getting Tailscale status: %v", err)
			http.Error(w, "failed to get Tailscale status", 500)
			return
		}
		ro := r.Clone(r.Context())
		if u, ok := tstat.userOfIP(ipp.IP); ok && !strings.HasPrefix(r.RequestURI, "/invite") {
			role := "viewer"
			if strings.HasSuffix(u.LoginName, "@tailscale.com") {
				role = "editor"
			}
			email := strings.Replace(u.LoginName, "@", "-auto@", 1)
			addUser(email, role)
			log.Printf("serving %v, %v, %v", email, r.RemoteAddr, r.RequestURI)
			ro.Header.Add("X-Webauth-User", email)
			ro.Header.Add("X-User-Name", u.DisplayName)
			ro.Header.Add("X-User-Email", email)
		} else {
			log.Printf("serving ??, %v, %v", r.RemoteAddr, r.RequestURI)
		}
		if *spoofAdmin {
			ro.Header.Add("X-Webauth-User", "apenwarr@tailscale.com")
		}
		rp.ServeHTTP(w, ro)
	})
	var hs http.Server
	log.Fatal(hs.Serve(ln))
}

// /etc/grafana/admin-creds.authproxy
// curl -v -X PATCH -u 'apenwarr@tailscale.com:XXXXX' --data '{"role":"Editor"}' -H "Content-Type:application/json" http://localhost:80/api/org/users/

var (
	mu      sync.Mutex
	tsCache *tailscaleStatus
)

func getTailscaleStatus() (*tailscaleStatus, error) {
	mu.Lock()
	defer mu.Unlock()
	if s := tsCache; s != nil && time.Since(s.at) < 10*time.Second {
		return s, nil
	}
	out, err := exec.Command("tailscale", "status", "--json").Output()
	if err != nil {
		return nil, err
	}
	tss := &tailscaleStatus{at: time.Now()}
	if err := json.Unmarshal(out, &tss.s); err != nil {
		return nil, err
	}
	if tss.s.BackendState != "Running" {
		return nil, fmt.Errorf("tailscale not running; in state %q", tss.s.BackendState)
	}
	return tss, nil
}

type tailscaleStatus struct {
	at time.Time
	s  ipnstate.Status
}

func (tss *tailscaleStatus) userOfIP(ip netaddr.IP) (u tailcfg.UserProfile, ok bool) {
	for _, ps := range tss.s.Peer {
		if peerIP, err := netaddr.ParseIP(ps.TailAddr); err == nil && ip == peerIP {
			u, ok = tss.s.User[ps.UserID]
			return
		}
	}
	return u, false
}
