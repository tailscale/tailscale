// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package prober

import (
	"bytes"
	"cmp"
	"context"
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"tailscale.com/client/tailscale"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/net/stun"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// derpProber dynamically manages several probes for each DERP server
// based on the current DERPMap.
type derpProber struct {
	p            *Prober
	derpMapURL   string // or "local"
	udpInterval  time.Duration
	meshInterval time.Duration
	tlsInterval  time.Duration

	// Optional bandwidth probing.
	bwInterval  time.Duration
	bwProbeSize int64

	// Optionally restrict probes to a single regionCode.
	regionCode string

	// Probe class for fetching & updating the DERP map.
	ProbeMap ProbeClass

	// Probe classes for probing individual derpers.
	tlsProbeFn  func(string) ProbeClass
	udpProbeFn  func(string, int) ProbeClass
	meshProbeFn func(string, string) ProbeClass
	bwProbeFn   func(string, string, int64) ProbeClass

	sync.Mutex
	lastDERPMap   *tailcfg.DERPMap
	lastDERPMapAt time.Time
	nodes         map[string]*tailcfg.DERPNode
	probes        map[string]*Probe
}

type DERPOpt func(*derpProber)

// WithBandwidthProbing enables bandwidth probing. When enabled, a payload of
// `size` bytes will be regularly transferred through each DERP server, and each
// pair of DERP servers in every region.
func WithBandwidthProbing(interval time.Duration, size int64) DERPOpt {
	return func(d *derpProber) {
		d.bwInterval = interval
		d.bwProbeSize = size
	}
}

// WithMeshProbing enables mesh probing. When enabled, a small message will be
// transferred through each DERP server and each pair of DERP servers.
func WithMeshProbing(interval time.Duration) DERPOpt {
	return func(d *derpProber) {
		d.meshInterval = interval
	}
}

// WithSTUNProbing enables STUN/UDP probing, with a STUN request being sent
// to each DERP server every `interval`.
func WithSTUNProbing(interval time.Duration) DERPOpt {
	return func(d *derpProber) {
		d.udpInterval = interval
	}
}

// WithTLSProbing enables TLS probing that will check TLS certificate on port
// 443 of each DERP server every `interval`.
func WithTLSProbing(interval time.Duration) DERPOpt {
	return func(d *derpProber) {
		d.tlsInterval = interval
	}
}

// WithRegion restricts probing to the specified region identified by its code
// (e.g. "lax"). This is case sensitive.
func WithRegion(regionCode string) DERPOpt {
	return func(d *derpProber) {
		d.regionCode = regionCode
	}
}

// DERP creates a new derpProber.
//
// If derpMapURL is "local", the DERPMap is fetched via
// the local machine's tailscaled.
func DERP(p *Prober, derpMapURL string, opts ...DERPOpt) (*derpProber, error) {
	d := &derpProber{
		p:          p,
		derpMapURL: derpMapURL,
		tlsProbeFn: TLS,
		nodes:      make(map[string]*tailcfg.DERPNode),
		probes:     make(map[string]*Probe),
	}
	d.ProbeMap = ProbeClass{
		Probe: d.probeMapFn,
		Class: "derp_map",
	}
	for _, o := range opts {
		o(d)
	}
	d.udpProbeFn = d.ProbeUDP
	d.meshProbeFn = d.probeMesh
	d.bwProbeFn = d.probeBandwidth
	return d, nil
}

// probeMapFn fetches the DERPMap and creates/destroys probes for each
// DERP server as necessary. It should get regularly executed as a
// probe function itself.
func (d *derpProber) probeMapFn(ctx context.Context) error {
	if err := d.updateMap(ctx); err != nil {
		return err
	}

	wantProbes := map[string]bool{}
	d.Lock()
	defer d.Unlock()

	for _, region := range d.lastDERPMap.Regions {
		if d.skipRegion(region) {
			continue
		}

		for _, server := range region.Nodes {
			labels := Labels{
				"region":    region.RegionCode,
				"region_id": strconv.Itoa(region.RegionID),
				"hostname":  server.HostName,
			}

			if d.tlsInterval > 0 {
				n := fmt.Sprintf("derp/%s/%s/tls", region.RegionCode, server.Name)
				wantProbes[n] = true
				if d.probes[n] == nil {
					log.Printf("adding DERP TLS probe for %s (%s) every %v", server.Name, region.RegionName, d.tlsInterval)
					derpPort := cmp.Or(server.DERPPort, 443)
					d.probes[n] = d.p.Run(n, d.tlsInterval, labels, d.tlsProbeFn(fmt.Sprintf("%s:%d", server.HostName, derpPort)))
				}
			}

			if d.udpInterval > 0 {
				for idx, ipStr := range []string{server.IPv6, server.IPv4} {
					n := fmt.Sprintf("derp/%s/%s/udp", region.RegionCode, server.Name)
					if idx == 0 {
						n += "6"
					}

					if ipStr == "" || server.STUNPort == -1 {
						continue
					}

					wantProbes[n] = true
					if d.probes[n] == nil {
						log.Printf("adding DERP UDP probe for %s (%s) every %v", server.Name, n, d.udpInterval)
						d.probes[n] = d.p.Run(n, d.udpInterval, labels, d.udpProbeFn(ipStr, server.STUNPort))
					}
				}
			}

			for _, to := range region.Nodes {
				if d.meshInterval > 0 {
					n := fmt.Sprintf("derp/%s/%s/%s/mesh", region.RegionCode, server.Name, to.Name)
					wantProbes[n] = true
					if d.probes[n] == nil {
						log.Printf("adding DERP mesh probe for %s->%s (%s) every %v", server.Name, to.Name, region.RegionName, d.meshInterval)
						d.probes[n] = d.p.Run(n, d.meshInterval, labels, d.meshProbeFn(server.Name, to.Name))
					}
				}

				if d.bwInterval > 0 && d.bwProbeSize > 0 {
					n := fmt.Sprintf("derp/%s/%s/%s/bw", region.RegionCode, server.Name, to.Name)
					wantProbes[n] = true
					if d.probes[n] == nil {
						log.Printf("adding DERP bandwidth probe for %s->%s (%s) %v bytes every %v", server.Name, to.Name, region.RegionName, d.bwProbeSize, d.bwInterval)
						d.probes[n] = d.p.Run(n, d.bwInterval, labels, d.bwProbeFn(server.Name, to.Name, d.bwProbeSize))
					}
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

// probeMesh returs a probe class that sends a test packet through a pair of DERP
// servers (or just one server, if 'from' and 'to' are the same). 'from' and 'to'
// are expected to be names (DERPNode.Name) of two DERP servers in the same region.
func (d *derpProber) probeMesh(from, to string) ProbeClass {
	derpPath := "mesh"
	if from == to {
		derpPath = "single"
	}
	return ProbeClass{
		Probe: func(ctx context.Context) error {
			fromN, toN, err := d.getNodePair(from, to)
			if err != nil {
				return err
			}

			dm := d.lastDERPMap
			return derpProbeNodePair(ctx, dm, fromN, toN)
		},
		Class:  "derp_mesh",
		Labels: Labels{"derp_path": derpPath},
	}
}

// probeBandwidth returs a probe class that sends a payload of a given size
// through a pair of DERP servers (or just one server, if 'from' and 'to' are
// the same). 'from' and 'to' are expected to be names (DERPNode.Name) of two
// DERP servers in the same region.
func (d *derpProber) probeBandwidth(from, to string, size int64) ProbeClass {
	derpPath := "mesh"
	if from == to {
		derpPath = "single"
	}
	var transferTime expvar.Float
	return ProbeClass{
		Probe: func(ctx context.Context) error {
			fromN, toN, err := d.getNodePair(from, to)
			if err != nil {
				return err
			}
			return derpProbeBandwidth(ctx, d.lastDERPMap, fromN, toN, size, &transferTime)
		},
		Class:  "derp_bw",
		Labels: Labels{"derp_path": derpPath},
		Metrics: func(l prometheus.Labels) []prometheus.Metric {
			return []prometheus.Metric{
				prometheus.MustNewConstMetric(prometheus.NewDesc("derp_bw_probe_size_bytes", "Payload size of the bandwidth prober", nil, l), prometheus.GaugeValue, float64(size)),
				prometheus.MustNewConstMetric(prometheus.NewDesc("derp_bw_transfer_time_seconds_total", "Time it took to transfer data", nil, l), prometheus.CounterValue, transferTime.Value()),
			}
		},
	}
}

// getNodePair returns DERPNode objects for two DERP servers based on their
// short names.
func (d *derpProber) getNodePair(n1, n2 string) (ret1, ret2 *tailcfg.DERPNode, _ error) {
	d.Lock()
	defer d.Unlock()
	ret1, ok := d.nodes[n1]
	if !ok {
		return nil, nil, fmt.Errorf("could not find derp node %s", n1)
	}
	ret2, ok = d.nodes[n2]
	if !ok {
		return nil, nil, fmt.Errorf("could not find derp node %s", n2)
	}
	return ret1, ret2, nil
}

var tsLocalClient tailscale.LocalClient

// updateMap refreshes the locally-cached DERP map.
func (d *derpProber) updateMap(ctx context.Context) error {
	var dm *tailcfg.DERPMap
	if d.derpMapURL == "local" {
		var err error
		dm, err = tsLocalClient.CurrentDERPMap(ctx)
		if err != nil {
			return err
		}
	} else {
		req, err := http.NewRequestWithContext(ctx, "GET", d.derpMapURL, nil)
		if err != nil {
			return err
		}
		res, err := httpOrFileClient.Do(req)
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
		dm = new(tailcfg.DERPMap)
		if err := json.NewDecoder(res.Body).Decode(dm); err != nil {
			return fmt.Errorf("decoding %s JSON: %v", d.derpMapURL, err)
		}
	}

	d.Lock()
	defer d.Unlock()
	d.lastDERPMap = dm
	d.lastDERPMapAt = time.Now()
	d.nodes = make(map[string]*tailcfg.DERPNode)
	for _, reg := range d.lastDERPMap.Regions {
		if d.skipRegion(reg) {
			continue
		}

		for _, n := range reg.Nodes {
			if existing, ok := d.nodes[n.Name]; ok {
				return fmt.Errorf("derpmap has duplicate nodes: %+v and %+v", existing, n)
			}
			// Allow the prober to monitor nodes marked as
			// STUN only in the default map
			n.STUNOnly = false
			d.nodes[n.Name] = n
		}
	}
	return nil
}

func (d *derpProber) ProbeUDP(ipaddr string, port int) ProbeClass {
	return ProbeClass{
		Probe: func(ctx context.Context) error {
			return derpProbeUDP(ctx, ipaddr, port)
		},
		Class: "derp_udp",
	}
}

func (d *derpProber) skipRegion(region *tailcfg.DERPRegion) bool {
	return d.regionCode != "" && region.RegionCode != d.regionCode
}

func derpProbeUDP(ctx context.Context, ipStr string, port int) error {
	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return err
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
			return err
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
				return fmt.Errorf("timeout reading from %v: %v", ip, err)
			}
			if d < time.Second {
				return fmt.Errorf("error reading from %v: %v", ip, err)
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		txBack, _, err := stun.ParseResponse(buf[:n])
		if err != nil {
			return fmt.Errorf("parsing STUN response from %v: %v", ip, err)
		}
		if txBack != tx {
			return fmt.Errorf("read wrong tx back from %v", ip)
		}
		break
	}
	return nil
}

// derpProbeBandwidth sends a payload of a given size between two local
// DERP clients connected to two DERP servers.
func derpProbeBandwidth(ctx context.Context, dm *tailcfg.DERPMap, from, to *tailcfg.DERPNode, size int64, transferTime *expvar.Float) (err error) {
	// This probe uses clients with isProber=false to avoid spamming the derper logs with every packet
	// sent by the bandwidth probe.
	fromc, err := newConn(ctx, dm, from, false)
	if err != nil {
		return err
	}
	defer fromc.Close()
	toc, err := newConn(ctx, dm, to, false)
	if err != nil {
		return err
	}
	defer toc.Close()

	// Wait a bit for from's node to hear about to existing on the
	// other node in the region, in the case where the two nodes
	// are different.
	if from.Name != to.Name {
		time.Sleep(100 * time.Millisecond) // pretty arbitrary
	}

	start := time.Now()
	defer func() { transferTime.Add(time.Since(start).Seconds()) }()

	if err := runDerpProbeNodePair(ctx, from, to, fromc, toc, size); err != nil {
		// Record pubkeys on failed probes to aid investigation.
		return fmt.Errorf("%s -> %s: %w",
			fromc.SelfPublicKey().ShortString(),
			toc.SelfPublicKey().ShortString(), err)
	}
	return nil
}

// derpProbeNodePair sends a small packet between two local DERP clients
// connected to two DERP servers.
func derpProbeNodePair(ctx context.Context, dm *tailcfg.DERPMap, from, to *tailcfg.DERPNode) (err error) {
	fromc, err := newConn(ctx, dm, from, true)
	if err != nil {
		return err
	}
	defer fromc.Close()
	toc, err := newConn(ctx, dm, to, true)
	if err != nil {
		return err
	}
	defer toc.Close()

	// Wait a bit for from's node to hear about to existing on the
	// other node in the region, in the case where the two nodes
	// are different.
	if from.Name != to.Name {
		time.Sleep(100 * time.Millisecond) // pretty arbitrary
	}

	const meshProbePacketSize = 8
	if err := runDerpProbeNodePair(ctx, from, to, fromc, toc, meshProbePacketSize); err != nil {
		// Record pubkeys on failed probes to aid investigation.
		return fmt.Errorf("%s -> %s: %w",
			fromc.SelfPublicKey().ShortString(),
			toc.SelfPublicKey().ShortString(), err)
	}
	return nil
}

// probePackets stores a pregenerated slice of probe packets keyed by their total size.
var probePackets syncs.Map[int64, [][]byte]

// packetsForSize returns a slice of packet payloads with a given total size.
func packetsForSize(size int64) [][]byte {
	// For a small payload, create a unique random packet.
	if size <= derp.MaxPacketSize {
		pkt := make([]byte, size)
		crand.Read(pkt)
		return [][]byte{pkt}
	}

	// For a large payload, create a bunch of packets once and re-use them
	// across probes.
	pkts, _ := probePackets.LoadOrInit(size, func() [][]byte {
		const packetSize = derp.MaxPacketSize
		var pkts [][]byte
		for remaining := size; remaining > 0; remaining -= packetSize {
			pkt := make([]byte, min(remaining, packetSize))
			crand.Read(pkt)
			pkts = append(pkts, pkt)
		}
		return pkts
	})
	return pkts
}

// runDerpProbeNodePair takes two DERP clients (fromc and toc) connected to two
// DERP servers (from and to) and sends a test payload of a given size from one
// to another.
func runDerpProbeNodePair(ctx context.Context, from, to *tailcfg.DERPNode, fromc, toc *derphttp.Client, size int64) error {
	// To avoid derper dropping enqueued packets, limit the number of packets in flight.
	// The value here is slightly smaller than perClientSendQueueDepth in derp_server.go
	inFlight := syncs.NewSemaphore(30)

	pkts := packetsForSize(size)

	// Send the packets.
	sendc := make(chan error, 1)
	go func() {
		for idx, pkt := range pkts {
			inFlight.AcquireContext(ctx)
			if err := fromc.Send(toc.SelfPublicKey(), pkt); err != nil {
				sendc <- fmt.Errorf("sending packet %d: %w", idx, err)
				return
			}
		}
	}()

	// Receive the packets.
	recvc := make(chan error, 1)
	go func() {
		defer close(recvc) // to break out of 'select' below.
		idx := 0
		for {
			m, err := toc.Recv()
			if err != nil {
				recvc <- fmt.Errorf("after %d data packets: %w", idx, err)
				return
			}
			switch v := m.(type) {
			case derp.ReceivedPacket:
				inFlight.Release()
				if v.Source != fromc.SelfPublicKey() {
					recvc <- fmt.Errorf("got data packet %d from unexpected source, %v", idx, v.Source)
					return
				}
				if got, want := v.Data, pkts[idx]; !bytes.Equal(got, want) {
					recvc <- fmt.Errorf("unexpected data packet %d (out of %d)", idx, len(pkts))
					return
				}
				idx += 1
				if idx == len(pkts) {
					return
				}

			case derp.KeepAliveMessage:
				// Silently ignore.
			default:
				log.Printf("%v: ignoring Recv frame type %T", to.Name, v)
				// Loop.
			}
		}
	}()

	select {
	case <-ctx.Done():
		return fmt.Errorf("timeout: %w", ctx.Err())
	case err := <-sendc:
		if err != nil {
			return fmt.Errorf("error sending via %q: %w", from.Name, err)
		}
	case err := <-recvc:
		if err != nil {
			return fmt.Errorf("error receiving from %q: %w", to.Name, err)
		}
	}
	return nil
}

func newConn(ctx context.Context, dm *tailcfg.DERPMap, n *tailcfg.DERPNode, isProber bool) (*derphttp.Client, error) {
	// To avoid spamming the log with regular connection messages.
	l := logger.Filtered(log.Printf, func(s string) bool {
		return !strings.Contains(s, "derphttp.Client.Connect: connecting to")
	})
	priv := key.NewNode()
	dc := derphttp.NewRegionClient(priv, l, netmon.NewStatic(), func() *tailcfg.DERPRegion {
		rid := n.RegionID
		return &tailcfg.DERPRegion{
			RegionID:   rid,
			RegionCode: fmt.Sprintf("%s-%s", dm.Regions[rid].RegionCode, n.Name),
			RegionName: dm.Regions[rid].RegionName,
			Nodes:      []*tailcfg.DERPNode{n},
		}
	})
	dc.IsProber = isProber
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

var httpOrFileClient = &http.Client{Transport: httpOrFileTransport()}

func httpOrFileTransport() http.RoundTripper {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.RegisterProtocol("file", http.NewFileTransport(http.Dir("/")))
	return tr
}
