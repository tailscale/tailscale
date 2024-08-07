// Copyright (c) Tailscale Inc & AUTHORS
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
	"bufio"
	"bytes"
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
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mitchellh/go-ps"
	"tailscale.com/client/tailscale"
	"tailscale.com/util/must"
	"tailscale.com/util/set"
	"tailscale.com/version/distro"
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
		w.WriteHeader(500)
		log.Printf("Err on serveCmd for %q %v, %d bytes of output: %v", cmd, args, len(out), err)
	} else {
		log.Printf("Did serveCmd for %q %v, %d bytes of output", cmd, args, len(out))
	}
	w.Write(out)
}

type localClientRoundTripper struct {
	lc *tailscale.LocalClient
}

func (rt localClientRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return rt.lc.DoLocalRequest(req)
}

func main() {
	if distro.Get() == distro.Gokrazy {
		cmdLine, _ := os.ReadFile("/proc/cmdline")
		if !bytes.Contains(cmdLine, []byte("tailscale-tta=1")) {
			// "Exiting immediately with status code 0 when the
			// GOKRAZY_FIRST_START=1 environment variable is set means “don’t
			// start the program on boot”"
			return
		}
	}
	flag.Parse()

	if distro.Get() == distro.Gokrazy {
		nsRx := regexp.MustCompile(`(?m)^nameserver (.*)`)
		for t := time.Now(); time.Since(t) < 10*time.Second; time.Sleep(10 * time.Millisecond) {
			all, _ := os.ReadFile("/etc/resolv.conf")
			if nsRx.Match(all) {
				break
			}
		}
	}

	logc, err := net.Dial("tcp", "9.9.9.9:124")
	if err == nil {
		log.SetOutput(logc)
	}

	log.Printf("Tailscale Test Agent running.")

	if distro.Get() == distro.Gokrazy {
		procs, err := ps.Processes()
		if err != nil {
			log.Fatalf("ps.Processes: %v", err)
		}
		killed := false
		for _, p := range procs {
			if p.Executable() == "tailscaled" {
				if op, err := os.FindProcess(p.Pid()); err == nil {
					op.Signal(os.Interrupt)
					killed = true
				}
			}
		}
		log.Printf("killed = %v", killed)
		if killed {
			for {
				_, err := exec.Command(absify("tailscale"), "status", "--json").CombinedOutput()
				if err == nil {
					log.Printf("tailscaled back up")
					break
				}
				log.Printf("tailscale status error; sleeping before trying again...")
				time.Sleep(50 * time.Millisecond)
			}
		}
	}

	var mux http.ServeMux
	var hs http.Server
	hs.Handler = &mux
	var (
		stMu   sync.Mutex
		newSet = set.Set[net.Conn]{} // conns in StateNew
	)
	needConnCh := make(chan bool, 1)
	hs.ConnState = func(c net.Conn, s http.ConnState) {
		stMu.Lock()
		defer stMu.Unlock()
		switch s {
		case http.StateNew:
			newSet.Add(c)
		default:
			newSet.Delete(c)
		}
		if len(newSet) == 0 {
			select {
			case needConnCh <- true:
			default:
			}
		}
	}
	conns := make(chan net.Conn, 1)
	var lc tailscale.LocalClient
	rp := httputil.NewSingleHostReverseProxy(must.Get(url.Parse("http://local-tailscaled.sock")))
	rp.Transport = localClientRoundTripper{&lc}

	mux.Handle("/localapi/", rp)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "TTA\n")
		return
	})
	mux.HandleFunc("/up", func(w http.ResponseWriter, r *http.Request) {
		cmd := exec.Command(absify("tailscale"), "debug", "daemon-logs")
		out, err := cmd.StdoutPipe()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer out.Close()
		cmd.Start()
		defer cmd.Process.Kill()
		go func() {
			bs := bufio.NewScanner(out)
			for bs.Scan() {
				log.Printf("Daemon: %s", bs.Text())
			}
		}()

		serveCmd(w, "tailscale", "up", "--login-server=http://control.tailscale")
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		serveCmd(w, "tailscale", "status", "--json")
	})
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		target := r.FormValue("target")
		cmd := exec.Command(absify("tailscale"), "ping", target)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.(http.Flusher).Flush()
		cmd.Stdout = w
		cmd.Stderr = w
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(w, "error: %v\n", err)
		}
	})
	go hs.Serve(chanListener(conns))

	var lastErr string
	needConnCh <- true
	for {
		<-needConnCh
		c, err := connect()
		log.Printf("Connect: %v", err)
		if err != nil {
			s := err.Error()
			if s != lastErr {
				log.Printf("Connect failure: %v", s)
			}
			lastErr = s
			time.Sleep(time.Second)
			continue
		}
		conns <- c

		time.Sleep(time.Second)
	}
}

func connect() (net.Conn, error) {
	c, err := net.Dial("tcp", *driverAddr)
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
