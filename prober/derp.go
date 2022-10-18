// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package prober

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// derpProber dynamically manages several probes for each DERP server
// based on the current DERPMap.
type derpProber struct {
	p            *Prober
	derpMapURL   string
	udpInterval  time.Duration
	meshInterval time.Duration
	tlsInterval  time.Duration

	// Probe functions that can be overriden for testing.
	tlsProbeFn  func(string) ProbeFunc
	udpProbeFn  func(string, int) ProbeFunc
	meshProbeFn func(string, string) ProbeFunc

	sync.Mutex
	lastDERPMap   *tailcfg.DERPMap
	lastDERPMapAt time.Time
	nodes         map[string]*tailcfg.DERPNode
	probes        map[string]*Probe
}

// DERP creates a new derpProber.
func DERP(p *Prober, derpMapURL string, udpInterval, meshInterval, tlsInterval time.Duration) (*derpProber, error) {
	d := &derpProber{
		p:            p,
		derpMapURL:   derpMapURL,
		udpInterval:  udpInterval,
		meshInterval: meshInterval,
		tlsInterval:  tlsInterval,
		tlsProbeFn:   TLS,
		nodes:        make(map[string]*tailcfg.DERPNode),
		probes:       make(map[string]*Probe),
	}
	d.udpProbeFn = d.ProbeUDP
	d.meshProbeFn = d.probeMesh
	return d, nil
}

// ProbeMap fetches the DERPMap and creates/destroys probes for each
// DERP server as necessary. It should get regularly executed as a
// probe function itself.
func (d *derpProber) ProbeMap(ctx context.Context) error {
	if err := d.updateMap(ctx); err != nil {
		return err
	}

	wantProbes := map[string]bool{}
	d.Lock()
	defer d.Unlock()

	for _, region := range d.lastDERPMap.Regions {
		for _, server := range region.Nodes {
			labels := map[string]string{
				"region":    region.RegionCode,
				"region_id": strconv.Itoa(region.RegionID),
				"hostname":  server.HostName,
			}

			n := fmt.Sprintf("derp/%s/%s/tls", region.RegionCode, server.Name)
			wantProbes[n] = true
			if d.probes[n] == nil {
				log.Printf("adding DERP TLS probe for %s (%s)", server.Name, region.RegionName)
				d.probes[n] = d.p.Run(n, d.tlsInterval, labels, d.tlsProbeFn(server.HostName+":443"))
			}

			for idx, ipStr := range []string{server.IPv6, server.IPv4} {
				n = fmt.Sprintf("derp/%s/%s/udp", region.RegionCode, server.Name)
				if idx == 0 {
					n = n + "6"
				}

				if ipStr == "" || server.STUNPort == -1 {
					continue
				}

				wantProbes[n] = true
				if d.probes[n] == nil {
					log.Printf("adding DERP UDP probe for %s (%s)", server.Name, n)
					d.probes[n] = d.p.Run(n, d.udpInterval, labels, d.udpProbeFn(ipStr, server.STUNPort))
				}
			}

			for _, to := range region.Nodes {
				n = fmt.Sprintf("derp/%s/%s/%s/mesh", region.RegionCode, server.Name, to.Name)
				wantProbes[n] = true
				if d.probes[n] == nil {
					log.Printf("adding DERP mesh probe for %s->%s (%s)", server.Name, to.Name, region.RegionName)
					d.probes[n] = d.p.Run(n, d.meshInterval, labels, d.meshProbeFn(server.HostName, to.HostName))
				}
			}
		}
	}

	for n, probe := range d.probes {
		if !wantProbes[n] {
			log.Printf("removing DERP probe %s", n)
			probe.Close()
			delete(d.probes, n)
		}
	}

	return nil
}

func (d *derpProber) probeMesh(from, to string) ProbeFunc {
	return func(ctx context.Context) error {
		d.Lock()
		dm := d.lastDERPMap
		fromN, ok := d.nodes[from]
		if !ok {
			d.Unlock()
			return fmt.Errorf("could not find derp node %s", from)
		}
		toN, ok := d.nodes[to]
		if !ok {
			d.Unlock()
			return fmt.Errorf("could not find derp node %s", to)
		}
		d.Unlock()

		// TODO: instead of ignoring latency, export it as a separate metric.
		_, err := derpProbeNodePair(ctx, dm, fromN, toN)
		return err
	}
}

func (d *derpProber) updateMap(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", d.derpMapURL, nil)
	if err != nil {
		return nil
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		d.Lock()
		defer d.Unlock()
		if d.lastDERPMap != nil && time.Since(d.lastDERPMapAt) < 10*time.Minute {
			log.Printf("Error while fetching DERP map, using cached one: %s", err)
			// Assume that control is restarting and use
			// the same one for a bit.
			return nil
		}
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("fetching %s: %s", d.derpMapURL, res.Status)
	}
	dm := new(tailcfg.DERPMap)
	if err := json.NewDecoder(res.Body).Decode(dm); err != nil {
		return fmt.Errorf("decoding %s JSON: %v", d.derpMapURL, err)
	}

	d.Lock()
	defer d.Unlock()
	d.lastDERPMap = dm
	d.lastDERPMapAt = time.Now()
	d.nodes = make(map[string]*tailcfg.DERPNode)
	for _, reg := range d.lastDERPMap.Regions {
		for _, n := range reg.Nodes {
			if existing, ok := d.nodes[n.HostName]; ok {
				return fmt.Errorf("derpmap has duplicate nodes: %+v and %+v", existing, n)
			}
			d.nodes[n.HostName] = n
		}
	}
	return nil
}

func (d *derpProber) ProbeUDP(ipaddr string, port int) ProbeFunc {
	return func(ctx context.Context) error {
		_, err := derpProbeUDP(ctx, ipaddr, port)
		return err
	}
}

func derpProbeUDP(ctx context.Context, ipStr string, port int) (latency time.Duration, err error) {
	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return 0, err
	}
	defer pc.Close()
	uc := pc.(*net.UDPConn)

	tx := stun.NewTxID()
	req := stun.Request(tx)

	if port == 0 {
		port = 3478
	}
	for {
		ip := net.ParseIP(ipStr)
		_, err := uc.WriteToUDP(req, &net.UDPAddr{IP: ip, Port: port})
		if err != nil {
			return 0, err
		}
		// Binding requests and responses are fairly small (~40 bytes),
		// but in practice a STUN response can be up to the size of the
		// path MTU, so we use a jumbo frame size buffer here.
		buf := make([]byte, 9000)
		uc.SetReadDeadline(time.Now().Add(2 * time.Second))
		t0 := time.Now()
		n, _, err := uc.ReadFromUDP(buf)
		d := time.Since(t0)
		if err != nil {
			if ctx.Err() != nil {
				return 0, fmt.Errorf("timeout reading from %v: %v", ip, err)
			}
			if d < time.Second {
				return 0, fmt.Errorf("error reading from %v: %v", ip, err)
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		txBack, _, err := stun.ParseResponse(buf[:n])
		if err != nil {
			return 0, fmt.Errorf("parsing STUN response from %v: %v", ip, err)
		}
		if txBack != tx {
			return 0, fmt.Errorf("read wrong tx back from %v", ip)
		}
		if latency == 0 || d < latency {
			latency = d
		}
		break
	}
	return latency, nil
}

func derpProbeNodePair(ctx context.Context, dm *tailcfg.DERPMap, from, to *tailcfg.DERPNode) (latency time.Duration, err error) {
	fromc, err := newConn(ctx, dm, from)
	if err != nil {
		return 0, err
	}
	defer fromc.Close()
	toc, err := newConn(ctx, dm, to)
	if err != nil {
		return 0, err
	}
	defer toc.Close()

	// Wait a bit for from's node to hear about to existing on the
	// other node in the region, in the case where the two nodes
	// are different.
	if from.Name != to.Name {
		time.Sleep(100 * time.Millisecond) // pretty arbitrary
	}

	// Make a random packet
	pkt := make([]byte, 8)
	crand.Read(pkt)

	t0 := time.Now()

	// Send the random packet.
	sendc := make(chan error, 1)
	go func() {
		sendc <- fromc.Send(toc.SelfPublicKey(), pkt)
	}()
	select {
	case <-ctx.Done():
		return 0, fmt.Errorf("timeout sending via %q: %w", from.Name, ctx.Err())
	case err := <-sendc:
		if err != nil {
			return 0, fmt.Errorf("error sending via %q: %w", from.Name, err)
		}
	}

	// Receive the random packet.
	recvc := make(chan any, 1) // either derp.ReceivedPacket or error
	go func() {
		for {
			m, err := toc.Recv()
			if err != nil {
				recvc <- err
				return
			}
			switch v := m.(type) {
			case derp.ReceivedPacket:
				recvc <- v
			default:
				log.Printf("%v: ignoring Recv frame type %T", to.Name, v)
				// Loop.
			}
		}
	}()
	select {
	case <-ctx.Done():
		return 0, fmt.Errorf("timeout receiving from %q: %w", to.Name, ctx.Err())
	case v := <-recvc:
		if err, ok := v.(error); ok {
			return 0, fmt.Errorf("error receiving from %q: %w", to.Name, err)
		}
		p := v.(derp.ReceivedPacket)
		if p.Source != fromc.SelfPublicKey() {
			return 0, fmt.Errorf("got data packet from unexpected source, %v", p.Source)
		}
		if !bytes.Equal(p.Data, pkt) {
			return 0, fmt.Errorf("unexpected data packet %q", p.Data)
		}
	}
	return time.Since(t0), nil
}

func newConn(ctx context.Context, dm *tailcfg.DERPMap, n *tailcfg.DERPNode) (*derphttp.Client, error) {
	// To avoid spamming the log with regular connection messages.
	l := logger.Filtered(log.Printf, func(s string) bool {
		return !strings.Contains(s, "derphttp.Client.Connect: connecting to")
	})
	priv := key.NewNode()
	dc := derphttp.NewRegionClient(priv, l, func() *tailcfg.DERPRegion {
		rid := n.RegionID
		return &tailcfg.DERPRegion{
			RegionID:   rid,
			RegionCode: fmt.Sprintf("%s-%s", dm.Regions[rid].RegionCode, n.Name),
			RegionName: dm.Regions[rid].RegionName,
			Nodes:      []*tailcfg.DERPNode{n},
		}
	})
	dc.IsProber = true
	err := dc.Connect(ctx)
	if err != nil {
		return nil, err
	}
	cs, ok := dc.TLSConnectionState()
	if !ok {
		dc.Close()
		return nil, errors.New("no TLS state")
	}
	if len(cs.PeerCertificates) == 0 {
		dc.Close()
		return nil, errors.New("no peer certificates")
	}
	if cs.ServerName != n.HostName {
		dc.Close()
		return nil, fmt.Errorf("TLS server name %q != derp hostname %q", cs.ServerName, n.HostName)
	}

	errc := make(chan error, 1)
	go func() {
		m, err := dc.Recv()
		if err != nil {
			errc <- err
			return
		}
		switch m.(type) {
		case derp.ServerInfoMessage:
			errc <- nil
		default:
			errc <- fmt.Errorf("unexpected first message type %T", errc)
		}
	}()
	select {
	case err := <-errc:
		if err != nil {
			go dc.Close()
			return nil, err
		}
	case <-ctx.Done():
		go dc.Close()
		return nil, fmt.Errorf("timeout waiting for ServerInfoMessage: %w", ctx.Err())
	}
	return dc, nil
}
