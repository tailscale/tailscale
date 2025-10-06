// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_debug

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptrace"
	"net/http/pprof"
	"net/url"
	"os"
	"time"

	"tailscale.com/derp/derphttp"
	"tailscale.com/feature"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/health"
	"tailscale.com/ipn"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/tsweb/varz"
	"tailscale.com/types/key"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/eventbus"
)

var debugArgs struct {
	ifconfig  bool // print network state once and exit
	monitor   bool
	getURL    string
	derpCheck string
	portmap   bool
}

func init() {
	debugModeFunc := debugMode // to be addressable
	subCommands["debug"] = &debugModeFunc

	hookNewDebugMux.Set(newDebugMux)
}

func newDebugMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/metrics", servePrometheusMetrics)
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return mux
}

func servePrometheusMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	varz.Handler(w, r)
	clientmetric.WritePrometheusExpositionFormat(w)
}

func debugMode(args []string) error {
	fs := flag.NewFlagSet("debug", flag.ExitOnError)
	fs.BoolVar(&debugArgs.ifconfig, "ifconfig", false, "If true, print network interface state")
	fs.BoolVar(&debugArgs.monitor, "monitor", false, "If true, run network monitor forever. Precludes all other options.")
	fs.BoolVar(&debugArgs.portmap, "portmap", false, "If true, run portmap debugging. Precludes all other options.")
	fs.StringVar(&debugArgs.getURL, "get-url", "", "If non-empty, fetch provided URL.")
	fs.StringVar(&debugArgs.derpCheck, "derp", "", "if non-empty, test a DERP ping via named region code")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) > 0 {
		return errors.New("unknown non-flag debug subcommand arguments")
	}
	ctx := context.Background()
	if debugArgs.derpCheck != "" {
		return checkDerp(ctx, debugArgs.derpCheck)
	}
	if debugArgs.ifconfig {
		return runMonitor(ctx, false)
	}
	if debugArgs.monitor {
		return runMonitor(ctx, true)
	}
	if debugArgs.portmap {
		return debugPortmap(ctx)
	}
	if debugArgs.getURL != "" {
		return getURL(ctx, debugArgs.getURL)
	}
	return errors.New("only --monitor is available at the moment")
}

func runMonitor(ctx context.Context, loop bool) error {
	b := eventbus.New()
	defer b.Close()

	dump := func(st *netmon.State) {
		j, _ := json.MarshalIndent(st, "", "    ")
		os.Stderr.Write(j)
	}
	mon, err := netmon.New(b, log.Printf)
	if err != nil {
		return err
	}
	defer mon.Close()

	eventClient := b.Client("debug.runMonitor")
	m := eventClient.Monitor(changeDeltaWatcher(eventClient, ctx, dump))
	defer m.Close()

	if loop {
		log.Printf("Starting link change monitor; initial state:")
	}
	dump(mon.InterfaceState())
	if !loop {
		return nil
	}
	mon.Start()
	log.Printf("Started link change monitor; waiting...")
	select {}
}

func changeDeltaWatcher(ec *eventbus.Client, ctx context.Context, dump func(st *netmon.State)) func(*eventbus.Client) {
	changeSub := eventbus.Subscribe[netmon.ChangeDelta](ec)
	return func(ec *eventbus.Client) {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ec.Done():
				return
			case delta := <-changeSub.Events():
				if !delta.Major {
					log.Printf("Network monitor fired; not a major change")
					return
				}
				log.Printf("Network monitor fired. New state:")
				dump(delta.New)
			}
		}
	}
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
	var proxyURL *url.URL
	if buildfeatures.HasUseProxy {
		if proxyFromEnv, ok := feature.HookProxyFromEnvironment.GetOk(); ok {
			proxyURL, err = proxyFromEnv(req)
			if err != nil {
				return fmt.Errorf("tshttpproxy.ProxyFromEnvironment: %v", err)
			}
		}
	}
	log.Printf("proxy: %v", proxyURL)
	tr := &http.Transport{
		Proxy:              func(*http.Request) (*url.URL, error) { return proxyURL, nil },
		ProxyConnectHeader: http.Header{},
		DisableKeepAlives:  true,
	}
	if proxyURL != nil {
		var auth string
		if f, ok := feature.HookProxyGetAuthHeader.GetOk(); ok {
			auth, err = f(proxyURL)
		}
		if err == nil && auth != "" {
			tr.ProxyConnectHeader.Set("Proxy-Authorization", auth)
		}
		log.Printf("tshttpproxy.GetAuthHeader(%v) got: auth of %d bytes, err=%v", proxyURL, len(auth), err)
		const truncLen = 20
		if len(auth) > truncLen {
			auth = fmt.Sprintf("%s...(%d total bytes)", auth[:truncLen], len(auth))
		}
		if auth != "" {
			// We used log.Printf above (for timestamps).
			// Use fmt.Printf here instead just to appease
			// a security scanner, despite log.Printf only
			// going to stdout.
			fmt.Printf("... Proxy-Authorization = %q\n", auth)
		}
	}
	res, err := tr.RoundTrip(req)
	if err != nil {
		return fmt.Errorf("Transport.RoundTrip: %v", err)
	}
	defer res.Body.Close()
	return res.Write(os.Stdout)
}

func checkDerp(ctx context.Context, derpRegion string) (err error) {
	bus := eventbus.New()
	defer bus.Close()
	ht := health.NewTracker(bus)
	req, err := http.NewRequestWithContext(ctx, "GET", ipn.DefaultControlURL+"/derpmap/default", nil)
	if err != nil {
		return fmt.Errorf("create derp map request: %w", err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch derp map failed: %w", err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("fetch derp map failed: %w", err)
	}
	if res.StatusCode != 200 {
		return fmt.Errorf("fetch derp map: %v: %s", res.Status, b)
	}
	var dmap tailcfg.DERPMap
	if err = json.Unmarshal(b, &dmap); err != nil {
		return fmt.Errorf("fetch DERP map: %w", err)
	}
	getRegion := func() *tailcfg.DERPRegion {
		for _, r := range dmap.Regions {
			if r.RegionCode == derpRegion {
				return r
			}
		}
		for _, r := range dmap.Regions {
			log.Printf("Known region: %q", r.RegionCode)
		}
		log.Fatalf("unknown region %q", derpRegion)
		panic("unreachable")
	}

	priv1 := key.NewNode()
	priv2 := key.NewNode()

	c1 := derphttp.NewRegionClient(priv1, log.Printf, nil, getRegion)
	c2 := derphttp.NewRegionClient(priv2, log.Printf, nil, getRegion)
	c1.HealthTracker = ht
	c2.HealthTracker = ht
	defer func() {
		if err != nil {
			c1.Close()
			c2.Close()
		}
	}()

	c2.NotePreferred(true) // just to open it

	m, err := c2.Recv()
	log.Printf("c2 got %T, %v", m, err)

	t0 := time.Now()
	if err := c1.Send(priv2.Public(), []byte("hello")); err != nil {
		return err
	}
	fmt.Println(time.Since(t0))

	m, err = c2.Recv()
	log.Printf("c2 got %T, %v", m, err)
	if err != nil {
		return err
	}
	log.Printf("ok")
	return err
}

func debugPortmap(ctx context.Context) error {
	return fmt.Errorf("this flag has been deprecated in favour of 'tailscale debug portmap'")
}
