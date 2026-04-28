// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// The tta server is the Tailscale Test Agent.
//
// It runs on each Tailscale node being integration tested and permits the test
// harness to control the node. It connects out to the test drver (rather than
// accepting any TCP connections inbound, which might be blocked depending on
// the scenario being tested) and then the test driver turns the TCP connection
// around and sends request back.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"tailscale.com/atomicfile"
	"tailscale.com/client/local"
	"tailscale.com/hostinfo"
	"tailscale.com/util/mak"
	"tailscale.com/util/must"
	"tailscale.com/util/set"
	"tailscale.com/version/distro"
)

// connContextKeyType is the type of connContextKey, which isn't of type
// `string` to avoid collisions while being used as a context key.
type connContextKeyType string

const (
	// connContextKey is the key for looking up the TCP connection
	// corresponding to an HTTP request coming in from testing
	// infrastructure.
	connContextKey connContextKeyType = "conn-context-key"
)

var (
	driverAddr = flag.String("driver", "test-driver.tailscale:8008", "address of the test driver; by default we use the DNS name test-driver.tailscale which is special cased in the emulated network's DNS server")
)

func absify(cmd string) string {
	if distro.Get() == distro.Gokrazy && !strings.Contains(cmd, "/") {
		return "/user/" + cmd
	}
	return cmd
}

func serveCmd(w http.ResponseWriter, cmd string, args ...string) {
	log.Printf("Got serveCmd for %q %v", cmd, args)
	out, err := exec.Command(absify(cmd), args...).CombinedOutput()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if err != nil {
		w.Header().Set("Exec-Err", err.Error())
		if exiterr, ok := err.(*exec.ExitError); ok {
			w.Header().Set("Exec-Exit-Code", strconv.Itoa(exiterr.ExitCode()))
		}
		w.WriteHeader(500)
		log.Printf("Err on serveCmd for %q %v, %d bytes of output: %v", cmd, args, len(out), err)
	} else {
		w.Header().Set("Exec-Exit-Code", "0")
		log.Printf("Did serveCmd for %q %v, %d bytes of output", cmd, args, len(out))
	}
	w.Write(out)
}

type localClientRoundTripper struct {
	lc local.Client
}

func (rt *localClientRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.RequestURI = ""
	return rt.lc.DoLocalRequest(req)
}

func main() {
	var logBuf logBuffer
	log.SetOutput(io.MultiWriter(os.Stderr, &logBuf))

	if distro.Get() == distro.Gokrazy {
		if !hostinfo.IsNATLabGuestVM() {
			// "Exiting immediately with status code 0 when the
			// GOKRAZY_FIRST_START=1 environment variable is set means “don’t
			// start the program on boot”"
			return
		}
	}
	flag.Parse()

	// On macOS VMs, start polling the host via vsock for an IP assignment.
	// This bypasses DHCP for near-instant network configuration.
	startIPAssignLoop()

	debug := false
	if distro.Get() == distro.Gokrazy {
		cmdLine, _ := os.ReadFile("/proc/cmdline")
		explicitNS := false
		for s := range strings.FieldsSeq(string(cmdLine)) {
			if ns, ok := strings.CutPrefix(s, "tta.nameserver="); ok {
				err := atomicfile.WriteFile("/tmp/resolv.conf", []byte("nameserver "+ns+"\n"), 0644)
				log.Printf("Wrote /tmp/resolv.conf: %v", err)
				explicitNS = true
				continue
			}
			if v, ok := strings.CutPrefix(s, "tta.debug="); ok {
				debug, _ = strconv.ParseBool(v)
				continue
			}
		}
		if !explicitNS {
			nsRx := regexp.MustCompile(`(?m)^nameserver (.*)`)
			for t := time.Now(); time.Since(t) < 10*time.Second; time.Sleep(10 * time.Millisecond) {
				all, _ := os.ReadFile("/etc/resolv.conf")
				if nsRx.Match(all) {
					break
				}
			}
		}
	}

	log.Printf("Tailscale Test Agent running.")

	gokRP := httputil.NewSingleHostReverseProxy(must.Get(url.Parse("http://gokrazy")))
	gokRP.Transport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if network != "tcp" {
				return nil, errors.New("unexpected network")
			}
			if addr != "gokrazy:80" {
				return nil, errors.New("unexpected addr")
			}
			var d net.Dialer
			return d.DialContext(ctx, "unix", "/run/gokrazy-http.sock")
		},
	}

	var ttaMux http.ServeMux // agent mux
	var serveMux http.ServeMux
	serveMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-TTA-GoKrazy") == "1" {
			gokRP.ServeHTTP(w, r)
			return
		}
		ttaMux.ServeHTTP(w, r)
	})

	var hs http.Server
	hs.Handler = &serveMux
	hs.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		return context.WithValue(ctx, connContextKey, c)
	}
	revSt := revDialState{
		needConnCh: make(chan bool, 1),
		debug:      debug,
	}
	hs.ConnState = revSt.connState
	conns := make(chan net.Conn, 1)

	lcRP := httputil.NewSingleHostReverseProxy(must.Get(url.Parse("http://local-tailscaled.sock")))
	lcRP.Transport = new(localClientRoundTripper)
	ttaMux.HandleFunc("/localapi/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Got localapi request: %v", r.URL)
		t0 := time.Now()
		lcRP.ServeHTTP(w, r)
		log.Printf("Did localapi request in %v: %v", time.Since(t0).Round(time.Millisecond), r.URL)
	})

	ttaMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "TTA\n")
		return
	})
	ttaMux.HandleFunc("/up", func(w http.ResponseWriter, r *http.Request) {
		args := []string{"up", "--login-server=http://control.tailscale"}
		if routes := r.URL.Query().Get("advertise-routes"); routes != "" {
			args = append(args, "--advertise-routes="+routes)
		}
		if snat := r.URL.Query().Get("snat-subnet-routes"); snat != "" {
			args = append(args, "--snat-subnet-routes="+snat)
		}
		if r.URL.Query().Get("accept-routes") == "true" {
			args = append(args, "--accept-routes")
		}
		serveCmd(w, "tailscale", args...)
	})
	ttaMux.HandleFunc("/set", func(w http.ResponseWriter, r *http.Request) {
		args := []string{"set"}
		if r.URL.Query().Get("accept-routes") == "true" {
			args = append(args, "--accept-routes")
		}
		if routes := r.URL.Query().Get("advertise-routes"); routes != "" {
			args = append(args, "--advertise-routes="+routes)
		}
		if snat := r.URL.Query().Get("snat-subnet-routes"); snat != "" {
			args = append(args, "--snat-subnet-routes="+snat)
		}
		serveCmd(w, "tailscale", args...)
	})
	ttaMux.HandleFunc("/ip", func(w http.ResponseWriter, r *http.Request) {
		conn, ok := r.Context().Value(connContextKey).(net.Conn)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write([]byte(conn.LocalAddr().String()))
	})
	ttaMux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		if distro.Get() == distro.Gokrazy {
			// The busybox in question here is the breakglass busybox inside the
			// natlab QEMU image.
			serveCmd(w, "/usr/local/bin/busybox", "ping", "-c", "4", "-W", "1", host)
		} else {
			serveCmd(w, "ping", "-c", "4", "-W", "1", host)
		}
	})
	ttaMux.HandleFunc("/add-route", func(w http.ResponseWriter, r *http.Request) {
		prefix := r.URL.Query().Get("prefix")
		via := r.URL.Query().Get("via")
		if prefix == "" || via == "" {
			http.Error(w, "missing prefix or via", http.StatusBadRequest)
			return
		}
		switch runtime.GOOS {
		case "linux":
			serveCmd(w, "ip", "route", "add", prefix, "via", via)
		default:
			http.Error(w, "add-route not supported on "+runtime.GOOS, http.StatusNotImplemented)
		}
	})
	ttaMux.HandleFunc("/start-webserver", func(w http.ResponseWriter, r *http.Request) {
		port := r.URL.Query().Get("port")
		name := r.URL.Query().Get("name")
		if port == "" {
			http.Error(w, "missing port", http.StatusBadRequest)
			return
		}
		if name == "" {
			name = "unnamed"
		}
		log.Printf("Starting webserver on port %s as %q", port, name)
		go func() {
			mux := http.NewServeMux()
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				host, _, _ := net.SplitHostPort(r.RemoteAddr)
				fmt.Fprintf(w, "Hello world I am %s from %s", name, host)
			})
			if err := http.ListenAndServe(":"+port, mux); err != nil {
				log.Printf("webserver on :%s failed: %v", port, err)
			}
		}()
		io.WriteString(w, "OK\n")
	})
	ttaMux.HandleFunc("/taildrop-send", func(w http.ResponseWriter, r *http.Request) {
		to := r.URL.Query().Get("to") // peer's Tailscale IP
		name := r.URL.Query().Get("name")
		if to == "" || name == "" {
			http.Error(w, "missing to or name", http.StatusBadRequest)
			return
		}
		if strings.ContainsAny(name, "/\\") {
			http.Error(w, "bad name", http.StatusBadRequest)
			return
		}
		dir, err := os.MkdirTemp("", "taildrop-send-")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer os.RemoveAll(dir)
		path := filepath.Join(dir, name)
		f, err := os.Create(path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if _, err := io.Copy(f, r.Body); err != nil {
			f.Close()
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := f.Close(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		serveCmd(w, "tailscale", "file", "cp", path, to+":")
	})
	ttaMux.HandleFunc("/taildrop-recv", func(w http.ResponseWriter, r *http.Request) {
		dir, err := os.MkdirTemp("", "taildrop-recv-")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer os.RemoveAll(dir)
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, absify("tailscale"), "file", "get", "--wait", dir)
		if out, err := cmd.CombinedOutput(); err != nil {
			http.Error(w, fmt.Sprintf("tailscale file get: %v\n%s", err, out), http.StatusInternalServerError)
			return
		}
		ents, err := os.ReadDir(dir)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if len(ents) != 1 {
			http.Error(w, fmt.Sprintf("got %d files, want 1", len(ents)), http.StatusInternalServerError)
			return
		}
		data, err := os.ReadFile(filepath.Join(dir, ents[0].Name()))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Taildrop-Filename", ents[0].Name())
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(data)
	})
	ttaMux.HandleFunc("/http-get", func(w http.ResponseWriter, r *http.Request) {
		targetURL := r.URL.Query().Get("url")
		if targetURL == "" {
			http.Error(w, "missing url", http.StatusBadRequest)
			return
		}
		log.Printf("HTTP GET %s", targetURL)
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Use Tailscale's SOCKS5 proxy if available, so traffic to Tailscale
		// subnet routes goes through the WireGuard tunnel instead of the
		// host network stack (which may not have the routes, especially
		// in userspace networking mode).
		client := &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					// Try the Tailscale localapi proxy dialer first.
					host, portStr, err := net.SplitHostPort(addr)
					if err != nil {
						var d net.Dialer
						return d.DialContext(ctx, network, addr)
					}
					port, _ := strconv.ParseUint(portStr, 10, 16)
					var lc local.Client
					conn, err := lc.UserDial(ctx, network, host, uint16(port))
					if err == nil {
						return conn, nil
					}
					log.Printf("http-get: UserDial failed, falling back to direct: %v", err)
					var d net.Dialer
					return d.DialContext(ctx, network, addr)
				},
			},
		}
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.Header().Set("X-Upstream-Status", strconv.Itoa(resp.StatusCode))
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	})
	ttaMux.HandleFunc("/fw", addFirewallHandler)
	ttaMux.HandleFunc("/wg-server-up", func(w http.ResponseWriter, r *http.Request) {
		if wgServerUp == nil {
			http.Error(w, "wg-server-up not supported on this platform", http.StatusNotImplemented)
			return
		}
		wgServerUp(w, r)
	})
	ttaMux.HandleFunc("/logs", func(w http.ResponseWriter, r *http.Request) {
		logBuf.mu.Lock()
		defer logBuf.mu.Unlock()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(logBuf.buf.Bytes())
	})
	go hs.Serve(chanListener(conns))

	// For doing agent operations locally from gokrazy:
	// (e.g. with "wget -O - localhost:8123/fw" or "wget -O - localhost:8123/logs"
	// to get early tta logs before the port 124 connection is established)
	go func() {
		err := http.ListenAndServe("127.0.0.1:8123", &ttaMux)
		if err != nil {
			log.Fatalf("ListenAndServe: %v", err)
		}
	}()

	revSt.runDialOutLoop(conns)
}

// dialCancels tracks cancel funcs for in-flight connect() and sleep contexts.
// resetDialCancels cancels them all so the dial loop retries immediately.
var (
	dialCancelMu sync.Mutex
	dialCancels  set.HandleSet[context.CancelFunc]
)

// registerDialCancel adds a cancel func and returns a handle for removal.
func registerDialCancel(cancel context.CancelFunc) set.Handle {
	dialCancelMu.Lock()
	defer dialCancelMu.Unlock()
	return dialCancels.Add(cancel)
}

// unregisterDialCancel removes a previously registered cancel func.
func unregisterDialCancel(h set.Handle) {
	dialCancelMu.Lock()
	defer dialCancelMu.Unlock()
	delete(dialCancels, h)
}

// resetDialCancels cancels all in-flight connect and sleep contexts,
// causing the dial loop to retry immediately with the updated driver address.
func resetDialCancels() {
	dialCancelMu.Lock()
	defer dialCancelMu.Unlock()
	for h, cancel := range dialCancels {
		cancel()
		delete(dialCancels, h)
	}
}

func connect() (net.Conn, error) {
	d := net.Dialer{
		Control: bypassControlFunc,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	h := registerDialCancel(cancel)
	defer func() {
		cancel()
		unregisterDialCancel(h)
	}()
	c, err := d.DialContext(ctx, "tcp", *driverAddr)
	if err != nil {
		return nil, err
	}
	return c, nil
}

type chanListener <-chan net.Conn

func (cl chanListener) Accept() (net.Conn, error) {
	c, ok := <-cl
	if !ok {
		return nil, errors.New("closed")
	}
	return c, nil
}

func (cl chanListener) Close() error {
	return nil
}

func (cl chanListener) Addr() net.Addr {
	return &net.TCPAddr{
		IP:   net.ParseIP("52.0.0.34"), // TS..DR(iver)
		Port: 123,
	}
}

type revDialState struct {
	needConnCh chan bool
	debug      bool

	mu     sync.Mutex
	newSet set.Set[net.Conn] // conns in StateNew
	onNew  map[net.Conn]func()
}

func (s *revDialState) connState(c net.Conn, cs http.ConnState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	oldLen := len(s.newSet)
	switch cs {
	case http.StateNew:
		if f, ok := s.onNew[c]; ok {
			f()
			delete(s.onNew, c)
		}
		s.newSet.Make()
		s.newSet.Add(c)
	default:
		s.newSet.Delete(c)
	}
	s.vlogf("ConnState: %p now %v; newSet %v=>%v", c, s, oldLen, len(s.newSet))
	if len(s.newSet) < 2 {
		select {
		case s.needConnCh <- true:
		default:
		}
	}
}

func (s *revDialState) waitNeedConnect() {
	for {
		s.mu.Lock()
		need := len(s.newSet) < 2
		s.mu.Unlock()
		if need {
			return
		}
		<-s.needConnCh
	}
}

func (s *revDialState) vlogf(format string, arg ...any) {
	if !s.debug {
		return
	}
	log.Printf(format, arg...)
}

func (s *revDialState) runDialOutLoop(conns chan<- net.Conn) {
	var lastErr string
	connected := false

	for {
		s.vlogf("[dial-driver] waiting need connect...")
		s.waitNeedConnect()
		s.vlogf("[dial-driver] connecting...")
		t0 := time.Now()
		c, err := connect()
		if err != nil {
			s := err.Error()
			if s != lastErr {
				log.Printf("[dial-driver] connect failure: %v", s)
			}
			lastErr = s
			sleepCtx, sleepCancel := context.WithTimeout(context.Background(), time.Second)
			h := registerDialCancel(sleepCancel)
			<-sleepCtx.Done()
			sleepCancel()
			unregisterDialCancel(h)
			continue
		}
		if !connected {
			connected = true
			log.Printf("Connected to %v", *driverAddr)
		}
		s.vlogf("[dial-driver] connected %v => %v after %v", c.LocalAddr(), c.RemoteAddr(), time.Since(t0))

		inHTTP := make(chan struct{})
		s.mu.Lock()
		mak.Set(&s.onNew, c, func() { close(inHTTP) })
		s.mu.Unlock()

		s.vlogf("[dial-driver] sending...")
		conns <- c
		s.vlogf("[dial-driver] sent; waiting")
		select {
		case <-inHTTP:
			s.vlogf("[dial-driver] conn in HTTP")
		case <-time.After(2 * time.Second):
			s.vlogf("[dial-driver] timeout waiting for conn to be accepted into HTTP")
		}
	}
}

func addFirewallHandler(w http.ResponseWriter, r *http.Request) {
	if addFirewall == nil {
		http.Error(w, "firewall not supported", 500)
		return
	}
	err := addFirewall()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	io.WriteString(w, "OK\n")
}

var addFirewall func() error // set by fw_linux.go

// wgServerUp brings up a userspace WireGuard "Mullvad-style" exit-node
// server on this VM. It is set by wgserver_linux.go and is nil on
// non-Linux.
var wgServerUp func(w http.ResponseWriter, r *http.Request)

// logBuffer is a bytes.Buffer that is safe for concurrent use
// intended to capture early logs from the process, even if
// gokrazy's syslog streaming isn't working or yet working.
// It only captures the first 1MB of logs, as that's considered
// plenty for early debugging. At runtime, it's assumed that
// syslog log streaming is working.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (lb *logBuffer) Write(p []byte) (n int, err error) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	const maxSize = 1 << 20 // more than plenty; see type comment
	if lb.buf.Len() > maxSize {
		return len(p), nil
	}
	return lb.buf.Write(p)
}
