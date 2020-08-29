// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"

	"github.com/peterbourgon/ff/v2/ffcli"
	"tailscale.com/net/interfaces"
	"tailscale.com/net/tshttpproxy"
	"tailscale.com/wgengine/monitor"
)

var debugCmd = &ffcli.Command{
	Name: "debug",
	Exec: runDebug,
	FlagSet: (func() *flag.FlagSet {
		fs := flag.NewFlagSet("debug", flag.ExitOnError)
		fs.BoolVar(&debugArgs.monitor, "monitor", false, "If true, run link monitor forever. Precludes all other options.")
		fs.StringVar(&debugArgs.getURL, "get-url", "", "If non-empty, fetch provided URL.")
		return fs
	})(),
}

var debugArgs struct {
	monitor bool
	getURL  string
}

func runDebug(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return errors.New("unknown arguments")
	}
	if debugArgs.monitor {
		return runMonitor(ctx)
	}
	if debugArgs.getURL != "" {
		return getURL(ctx, debugArgs.getURL)
	}
	return errors.New("only --monitor is available at the moment")
}

func runMonitor(ctx context.Context) error {
	dump := func() {
		st, err := interfaces.GetState()
		if err != nil {
			log.Printf("error getting state: %v", err)
			return
		}
		j, _ := json.MarshalIndent(st, "", "    ")
		os.Stderr.Write(j)
	}
	mon, err := monitor.New(log.Printf, func() {
		log.Printf("Link monitor fired. State:")
		dump()
	})
	if err != nil {
		return err
	}
	log.Printf("Starting link change monitor; initial state:")
	dump()
	mon.Start()
	log.Printf("Started link change monitor; waiting...")
	select {}
}

func getURL(ctx context.Context, urlStr string) error {
	if urlStr == "login" {
		urlStr = "https://login.tailscale.com"
	}
	log.SetOutput(os.Stdout)
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GetConn:           func(hostPort string) { log.Printf("GetConn(%q)", hostPort) },
		GotConn:           func(info httptrace.GotConnInfo) { log.Printf("GotConn: %+v", info) },
		DNSStart:          func(info httptrace.DNSStartInfo) { log.Printf("DNSStart: %+v", info) },
		DNSDone:           func(info httptrace.DNSDoneInfo) { log.Printf("DNSDoneInfo: %+v", info) },
		TLSHandshakeStart: func() { log.Printf("TLSHandshakeStart") },
		TLSHandshakeDone:  func(cs tls.ConnectionState, err error) { log.Printf("TLSHandshakeDone: %+v, %v", cs, err) },
		WroteRequest:      func(info httptrace.WroteRequestInfo) { log.Printf("WroteRequest: %+v", info) },
	})
	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return fmt.Errorf("http.NewRequestWithContext: %v", err)
	}
	proxyURL, err := tshttpproxy.ProxyFromEnvironment(req)
	if err != nil {
		return fmt.Errorf("tshttpproxy.ProxyFromEnvironment: %v", err)
	}
	log.Printf("proxy: %v", proxyURL)
	tr := &http.Transport{
		Proxy:              func(*http.Request) (*url.URL, error) { return proxyURL, nil },
		ProxyConnectHeader: http.Header{},
		DisableKeepAlives:  true,
	}
	if proxyURL != nil {
		auth, err := tshttpproxy.GetAuthHeader(proxyURL)
		if err == nil && auth != "" {
			tr.ProxyConnectHeader.Set("Proxy-Authorization", auth)
		}
		const truncLen = 20
		if len(auth) > truncLen {
			auth = fmt.Sprintf("%s...(%d total bytes)", auth[:truncLen], len(auth))
		}
		log.Printf("tshttpproxy.GetAuthHeader(%v) for Proxy-Auth: = %q, %v", proxyURL, auth, err)
	}
	res, err := tr.RoundTrip(req)
	if err != nil {
		return fmt.Errorf("Transport.RoundTrip: %v", err)
	}
	defer res.Body.Close()
	return res.Write(os.Stdout)
}
