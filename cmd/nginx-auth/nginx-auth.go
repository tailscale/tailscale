// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

// Command nginx-auth is a tool that allows users to use Tailscale Whois
// authentication with NGINX as a reverse proxy. This allows users that
// already have a bunch of services hosted on an internal NGINX server
// to point those domains to the Tailscale IP of the NGINX server and
// then seamlessly use Tailscale for authentication.
package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/coreos/go-systemd/activation"
	"tailscale.com/client/tailscale"
)

var (
	sockPath = flag.String("sockpath", "", "the filesystem path for the unix socket this service exposes")
)

func main() {
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		remoteHost := r.Header.Get("Remote-Addr")
		remotePort := r.Header.Get("Remote-Port")
		if remoteHost == "" || remotePort == "" {
			w.WriteHeader(http.StatusBadRequest)
			log.Println("set Remote-Addr to $remote_addr and Remote-Port to $remote_port in your nginx config")
			return
		}

		remoteAddrStr := net.JoinHostPort(remoteHost, remotePort)
		remoteAddr, err := netip.ParseAddrPort(remoteAddrStr)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			log.Printf("remote address and port are not valid: %v", err)
			return
		}

		info, err := tailscale.WhoIs(r.Context(), remoteAddr.String())
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			log.Printf("can't look up %s: %v", remoteAddr, err)
			return
		}

		if info.Node.IsTagged() {
			w.WriteHeader(http.StatusForbidden)
			log.Printf("node %s is tagged", info.Node.Hostinfo.Hostname())
			return
		}

		if expectedCap := r.Header.Get("Expected-Cap"); expectedCap != "" {
			if info.CapMap == nil {
				w.WriteHeader(http.StatusForbidden)
				log.Printf("user %s does not have any caps, wanted: %s", info.Node.Name, url.QueryEscape(expectedCap))
				return
			}

			caps := make([]string, 0, len(info.CapMap))
			for k := range info.CapMap {
				caps = append(caps, string(k))
			}

			if !slices.Contains(caps, expectedCap) {
				w.WriteHeader(http.StatusForbidden)
				log.Printf("user is missing expected cap, has: %s, wanted: %s", strings.Join(caps[:], ","), url.QueryEscape(expectedCap))
				return
			}
		}

		h := w.Header()
		h.Set("Tailscale-Login", strings.Split(info.UserProfile.LoginName, "@")[0])
		h.Set("Tailscale-User", info.UserProfile.LoginName)
		h.Set("Tailscale-Name", info.UserProfile.DisplayName)
		h.Set("Tailscale-Profile-Picture", info.UserProfile.ProfilePicURL)
		w.WriteHeader(http.StatusNoContent)
	})

	if *sockPath != "" {
		_ = os.Remove(*sockPath) // ignore error, this file may not already exist
		ln, err := net.Listen("unix", *sockPath)
		if err != nil {
			log.Fatalf("can't listen on %s: %v", *sockPath, err)
		}
		defer ln.Close()

		log.Printf("listening on %s", *sockPath)
		log.Fatal(http.Serve(ln, mux))
	}

	listeners, err := activation.Listeners()
	if err != nil {
		log.Fatalf("no sockets passed to this service with systemd: %v", err)
	}

	// NOTE(Xe): normally you'd want to make a waitgroup here and then register
	// each listener with it. In this case I want this to blow up horribly if
	// any of the listeners stop working. systemd will restart it due to the
	// socket activation at play.
	//
	// TL;DR: Let it crash, it will come back
	for _, ln := range listeners {
		go func(ln net.Listener) {
			log.Printf("listening on %s", ln.Addr())
			log.Fatal(http.Serve(ln, mux))
		}(ln)
	}

	for {
		select {}
	}
}
