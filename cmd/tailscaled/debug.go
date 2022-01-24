// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strings"
	"time"

	"inet.af/netaddr"
	"tailscale.com/derp/derphttp"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/net/interfaces"
	"tailscale.com/net/portmapper"
	"tailscale.com/net/tshttpproxy"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/monitor"
)

var debugArgs struct {
	ifconfig  bool // print network state once and exit
	monitor   bool
	getURL    string
	derpCheck string
	portmap   bool
}

var debugModeFunc = debugMode // so it can be addressable

func debugMode(args []string) error {
	fs := flag.NewFlagSet("debug", flag.ExitOnError)
	fs.BoolVar(&debugArgs.ifconfig, "ifconfig", false, "If true, print network interface state")
	fs.BoolVar(&debugArgs.monitor, "monitor", false, "If true, run link monitor forever. Precludes all other options.")
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
	dump := func(st *interfaces.State) {
		j, _ := json.MarshalIndent(st, "", "    ")
		os.Stderr.Write(j)
	}
	mon, err := monitor.New(log.Printf)
	if err != nil {
		return err
	}
	mon.RegisterChangeCallback(func(changed bool, st *interfaces.State) {
		if !changed {
			log.Printf("Link monitor fired; no change")
			return
		}
		log.Printf("Link monitor fired. New state:")
		dump(st)
	})
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

func checkDerp(ctx context.Context, derpRegion string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", ipn.DefaultControlURL+"/derpmap/default", nil)
	if err != nil {
		return fmt.Errorf("create derp map request: %w", err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch derp map failed: %w", err)
	}
	defer res.Body.Close()
	b, err := ioutil.ReadAll(io.LimitReader(res.Body, 1<<20))
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

	c1 := derphttp.NewRegionClient(priv1, log.Printf, getRegion)
	c2 := derphttp.NewRegionClient(priv2, log.Printf, getRegion)

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
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	portmapper.VerboseLogs = true
	switch envknob.String("TS_DEBUG_PORTMAP_TYPE") {
	case "":
	case "pmp":
		portmapper.DisablePCP = true
		portmapper.DisableUPnP = true
	case "pcp":
		portmapper.DisablePMP = true
		portmapper.DisableUPnP = true
	case "upnp":
		portmapper.DisablePCP = true
		portmapper.DisablePMP = true
	default:
		log.Fatalf("TS_DEBUG_PORTMAP_TYPE must be one of pmp,pcp,upnp")
	}

	done := make(chan bool, 1)

	var c *portmapper.Client
	logf := log.Printf
	c = portmapper.NewClient(logger.WithPrefix(logf, "portmapper: "), func() {
		logf("portmapping changed.")
		logf("have mapping: %v", c.HaveMapping())

		if ext, ok := c.GetCachedMappingOrStartCreatingOne(); ok {
			logf("cb: mapping: %v", ext)
			select {
			case done <- true:
			default:
			}
			return
		}
		logf("cb: no mapping")
	})
	linkMon, err := monitor.New(logger.WithPrefix(logf, "monitor: "))
	if err != nil {
		return err
	}

	gatewayAndSelfIP := func() (gw, self netaddr.IP, ok bool) {
		if v := os.Getenv("TS_DEBUG_GW_SELF"); strings.Contains(v, "/") {
			i := strings.Index(v, "/")
			gw = netaddr.MustParseIP(v[:i])
			self = netaddr.MustParseIP(v[i+1:])
			return gw, self, true
		}
		return linkMon.GatewayAndSelfIP()
	}

	c.SetGatewayLookupFunc(gatewayAndSelfIP)

	gw, selfIP, ok := gatewayAndSelfIP()
	if !ok {
		logf("no gateway or self IP; %v", linkMon.InterfaceState())
		return nil
	}
	logf("gw=%v; self=%v", gw, selfIP)

	uc, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		return err
	}
	defer uc.Close()
	c.SetLocalPort(uint16(uc.LocalAddr().(*net.UDPAddr).Port))

	res, err := c.Probe(ctx)
	if err != nil {
		return fmt.Errorf("Probe: %v", err)
	}
	logf("Probe: %+v", res)

	if !res.PCP && !res.PMP && !res.UPnP {
		logf("no portmapping services available")
		return nil
	}

	if ext, ok := c.GetCachedMappingOrStartCreatingOne(); ok {
		logf("mapping: %v", ext)
	} else {
		logf("no mapping")
	}

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
