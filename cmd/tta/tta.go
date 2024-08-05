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
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"tailscale.com/util/set"
	"tailscale.com/version/distro"
)

var (
	driverAddr = flag.String("driver", "test-driver.tailscale:8008", "address of the test driver; by default we use the DNS name test-driver.tailscale which is special cased in the emulated network's DNS server")
)

type chanListener <-chan net.Conn

func serveCmd(w http.ResponseWriter, cmd string, args ...string) {
	if distro.Get() == distro.Gokrazy && !strings.Contains(cmd, "/") {
		cmd = "/user/" + cmd
	}
	out, err := exec.Command(cmd, args...).CombinedOutput()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if err != nil {
		w.Header().Set("Exec-Err", err.Error())
		w.WriteHeader(500)
	}
	w.Write(out)
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
	log.Printf("Tailscale Test Agent running.")

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
		case http.StateClosed:
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

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "TTA\n")
		return
	})
	mux.HandleFunc("/up", func(w http.ResponseWriter, r *http.Request) {
		serveCmd(w, "tailscale", "up", "--auth-key=test")
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		serveCmd(w, "tailscale", "status", "--json")
	})
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		target := r.FormValue("target")
		cmd := exec.Command("tailscale", "ping", target)
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
