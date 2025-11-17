// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package prober

import (
	"bytes"
	"cmp"
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	wgconn "github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"go4.org/netipx"
	"tailscale.com/client/local"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/net/stun"
	"tailscale.com/net/tstun"
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
	meshKey      key.DERPMesh
	udpInterval  time.Duration
	meshInterval time.Duration
	tlsInterval  time.Duration

	// Optional bandwidth probing.
	bwInterval      time.Duration
	bwProbeSize     int64
	bwTUNIPv4Prefix *netip.Prefix // or nil to not use TUN

	// Optional queuing delay probing.
	qdPacketsPerSecond int // in packets per second
	qdPacketTimeout    time.Duration

	// Optionally restrict probes to a single regionCodeOrID.
	regionCodeOrID string

	// Probe class for fetching & updating the DERP map.
	ProbeMap ProbeClass

	// Probe classes for probing individual derpers.
	tlsProbeFn  func(string, *tls.Config) ProbeClass
	udpProbeFn  func(string, int) ProbeClass
	meshProbeFn func(string, string) ProbeClass
	bwProbeFn   func(string, string, int64) ProbeClass
	qdProbeFn   func(string, string, int, time.Duration, key.DERPMesh) ProbeClass

	sync.Mutex
	lastDERPMap   *tailcfg.DERPMap
	lastDERPMapAt time.Time
	nodes         map[string]*tailcfg.DERPNode
	probes        map[string]*Probe
}

type DERPOpt func(*derpProber)

// WithBandwidthProbing enables bandwidth probing. When enabled, a payload of
// `size` bytes will be regularly transferred through each DERP server, and each
// pair of DERP servers in every region. If tunAddress is specified, probes will
// use a TCP connection over a TUN device at this address in order to exercise
// TCP-in-TCP in similar fashion to TCP over Tailscale via DERP.
func WithBandwidthProbing(interval time.Duration, size int64, tunAddress string) DERPOpt {
	return func(d *derpProber) {
		d.bwInterval = interval
		d.bwProbeSize = size
		if tunAddress != "" {
			prefix, err := netip.ParsePrefix(fmt.Sprintf("%s/30", tunAddress))
			if err != nil {
				log.Fatalf("failed to parse IP prefix from bw-tun-ipv4-addr: %v", err)
			}
			d.bwTUNIPv4Prefix = &prefix
		}
	}
}

// WithQueuingDelayProbing enables/disables queuing delay probing. qdSendRate
// is the number of packets sent per second. qdTimeout is the amount of time
// after which a sent packet is considered to have timed out.
func WithQueuingDelayProbing(qdPacketsPerSecond int, qdPacketTimeout time.Duration) DERPOpt {
	return func(d *derpProber) {
		d.qdPacketsPerSecond = qdPacketsPerSecond
		d.qdPacketTimeout = qdPacketTimeout
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

// WithRegionCodeOrID restricts probing to the specified region identified by its code
// (e.g. "lax") or its id (e.g. "17"). This is case sensitive.
func WithRegionCodeOrID(regionCode string) DERPOpt {
	return func(d *derpProber) {
		d.regionCodeOrID = regionCode
	}
}

func WithMeshKey(meshKey key.DERPMesh) DERPOpt {
	return func(d *derpProber) {
		d.meshKey = meshKey
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
	d.qdProbeFn = d.probeQueuingDelay
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
					d.probes[n] = d.p.Run(n, d.tlsInterval, labels, d.tlsProbeFn(fmt.Sprintf("%s:%d", server.HostName, derpPort), nil))
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

				if d.bwInterval != 0 && d.bwProbeSize > 0 {
					n := fmt.Sprintf("derp/%s/%s/%s/bw", region.RegionCode, server.Name, to.Name)
					wantProbes[n] = true
					if d.probes[n] == nil {
						tunString := ""
						if d.bwTUNIPv4Prefix != nil {
							tunString = " (TUN)"
						}
						log.Printf("adding%s DERP bandwidth probe for %s->%s (%s) %v bytes every %v", tunString, server.Name, to.Name, region.RegionName, d.bwProbeSize, d.bwInterval)
						d.probes[n] = d.p.Run(n, d.bwInterval, labels, d.bwProbeFn(server.Name, to.Name, d.bwProbeSize))
					}
				}

				if d.qdPacketsPerSecond > 0 {
					n := fmt.Sprintf("derp/%s/%s/%s/qd", region.RegionCode, server.Name, to.Name)
					wantProbes[n] = true
					if d.probes[n] == nil {
						log.Printf("adding DERP queuing delay probe for %s->%s (%s)", server.Name, to.Name, region.RegionName)
						d.probes[n] = d.p.Run(n, -10*time.Second, labels, d.qdProbeFn(server.Name, to.Name, d.qdPacketsPerSecond, d.qdPacketTimeout, d.meshKey))
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

// probeMesh returns a probe class that sends a test packet through a pair of DERP
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
			return derpProbeNodePair(ctx, dm, fromN, toN, d.meshKey)
		},
		Class:  "derp_mesh",
		Labels: Labels{"derp_path": derpPath},
	}
}

// probeBandwidth returns a probe class that sends a payload of a given size
// through a pair of DERP servers (or just one server, if 'from' and 'to' are
// the same). 'from' and 'to' are expected to be names (DERPNode.Name) of two
// DERP servers in the same region.
func (d *derpProber) probeBandwidth(from, to string, size int64) ProbeClass {
	derpPath := "mesh"
	if from == to {
		derpPath = "single"
	}
	var transferTimeSeconds expvar.Float
	var totalBytesTransferred expvar.Float
	return ProbeClass{
		Probe: func(ctx context.Context) error {
			fromN, toN, err := d.getNodePair(from, to)
			if err != nil {
				return err
			}
			return derpProbeBandwidth(ctx, d.lastDERPMap, fromN, toN, size, &transferTimeSeconds, &totalBytesTransferred, d.bwTUNIPv4Prefix, d.meshKey)
		},
		Class: "derp_bw",
		Labels: Labels{
			"derp_path":  derpPath,
			"tcp_in_tcp": strconv.FormatBool(d.bwTUNIPv4Prefix != nil),
		},
		Metrics: func(lb prometheus.Labels) []prometheus.Metric {
			metrics := []prometheus.Metric{
				prometheus.MustNewConstMetric(prometheus.NewDesc("derp_bw_probe_size_bytes", "Payload size of the bandwidth prober", nil, lb), prometheus.GaugeValue, float64(size)),
				prometheus.MustNewConstMetric(prometheus.NewDesc("derp_bw_transfer_time_seconds_total", "Time it took to transfer data", nil, lb), prometheus.CounterValue, transferTimeSeconds.Value()),
			}
			if d.bwTUNIPv4Prefix != nil {
				// For TCP-in-TCP probes, also record cumulative bytes transferred.
				metrics = append(metrics, prometheus.MustNewConstMetric(prometheus.NewDesc("derp_bw_bytes_total", "Amount of data transferred", nil, lb), prometheus.CounterValue, totalBytesTransferred.Value()))
			}
			return metrics
		},
	}
}

// probeQueuingDelay returns a probe class that continuously sends packets
// through a pair of DERP servers (or just one server, if 'from' and 'to' are
// the same) at a rate of `packetsPerSecond` packets per second in order to
// measure queuing delays. Packets arriving after `packetTimeout` don't contribute
// to the queuing delay measurement and are recorded as dropped. 'from' and 'to' are
// expected to be names (DERPNode.Name) of two DERP servers in the same region,
// and may refer to the same server.
func (d *derpProber) probeQueuingDelay(from, to string, packetsPerSecond int, packetTimeout time.Duration, meshKey key.DERPMesh) ProbeClass {
	derpPath := "mesh"
	if from == to {
		derpPath = "single"
	}
	var packetsDropped expvar.Float
	qdh := newHistogram([]float64{.005, .01, .025, .05, .1, .25, .5, 1})
	return ProbeClass{
		Probe: func(ctx context.Context) error {
			fromN, toN, err := d.getNodePair(from, to)
			if err != nil {
				return err
			}
			return derpProbeQueuingDelay(ctx, d.lastDERPMap, fromN, toN, packetsPerSecond, packetTimeout, &packetsDropped, qdh, meshKey)
		},
		Class:  "derp_qd",
		Labels: Labels{"derp_path": derpPath},
		Metrics: func(lb prometheus.Labels) []prometheus.Metric {
			qdh.mx.Lock()
			result := []prometheus.Metric{
				prometheus.MustNewConstMetric(prometheus.NewDesc("derp_qd_probe_dropped_packets", "Total packets dropped", nil, lb), prometheus.CounterValue, float64(packetsDropped.Value())),
				prometheus.MustNewConstHistogram(prometheus.NewDesc("derp_qd_probe_delays_seconds", "Distribution of queuing delays", nil, lb), qdh.count, qdh.sum, maps.Clone(qdh.bucketedCounts)),
			}
			qdh.mx.Unlock()
			return result
		},
	}
}

// derpProbeQueuingDelay continuously sends data between two local DERP clients
// connected to two DERP servers in order to measure queuing delays. From and to
// can be the same server.
func derpProbeQueuingDelay(ctx context.Context, dm *tailcfg.DERPMap, from, to *tailcfg.DERPNode, packetsPerSecond int, packetTimeout time.Duration, packetsDropped *expvar.Float, qdh *histogram, meshKey key.DERPMesh) (err error) {
	// This probe uses clients with isProber=false to avoid spamming the derper
	// logs with every packet sent by the queuing delay probe.
	fromc, err := newConn(ctx, dm, from, false, meshKey)
	if err != nil {
		return err
	}
	defer fromc.Close()
	toc, err := newConn(ctx, dm, to, false, meshKey)
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

	if err := runDerpProbeQueuingDelayContinously(ctx, from, to, fromc, toc, packetsPerSecond, packetTimeout, packetsDropped, qdh); err != nil {
		// Record pubkeys on failed probes to aid investigation.
		return fmt.Errorf("%s -> %s: %w",
			fromc.SelfPublicKey().ShortString(),
			toc.SelfPublicKey().ShortString(), err)
	}
	return nil
}

func runDerpProbeQueuingDelayContinously(ctx context.Context, from, to *tailcfg.DERPNode, fromc, toc *derphttp.Client, packetsPerSecond int, packetTimeout time.Duration, packetsDropped *expvar.Float, qdh *histogram) error {
	// Make sure all goroutines have finished.
	var wg sync.WaitGroup
	defer wg.Wait()

	// Close the clients to make sure goroutines that are reading/writing from them terminate.
	defer fromc.Close()
	defer toc.Close()

	type txRecord struct {
		at  time.Time
		seq uint64
	}
	// txRecords is sized to hold enough transmission records to keep timings
	// for packets up to their timeout. As records age out of the front of this
	// list, if the associated packet arrives, we won't have a txRecord for it
	// and will consider it to have timed out.
	txRecords := make([]txRecord, 0, packetsPerSecond*int(packetTimeout.Seconds()))
	var txRecordsMu sync.Mutex

	// applyTimeouts walks over txRecords and expires any records that are older
	// than packetTimeout, recording in metrics that they were removed.
	applyTimeouts := func() {
		txRecordsMu.Lock()
		defer txRecordsMu.Unlock()

		now := time.Now()
		recs := txRecords[:0]
		for _, r := range txRecords {
			if now.Sub(r.at) > packetTimeout {
				packetsDropped.Add(1)
			} else {
				recs = append(recs, r)
			}
		}
		txRecords = recs
	}

	// Send the packets.
	sendErrC := make(chan error, 1)
	// TODO: construct a disco CallMeMaybe in the same fashion as magicsock, e.g. magic bytes, src pub, seal payload.
	// DERP server handling of disco may vary from non-disco, and we may want to measure queue delay of both.
	pkt := make([]byte, 260) // the same size as a CallMeMaybe packet observed on a Tailscale client.
	crand.Read(pkt)

	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(time.Second / time.Duration(packetsPerSecond))
		defer t.Stop()

		toDERPPubKey := toc.SelfPublicKey()
		seq := uint64(0)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				applyTimeouts()
				txRecordsMu.Lock()
				if len(txRecords) == cap(txRecords) {
					txRecords = slices.Delete(txRecords, 0, 1)
					packetsDropped.Add(1)
					log.Printf("unexpected: overflow in txRecords")
				}
				txRecords = append(txRecords, txRecord{time.Now(), seq})
				txRecordsMu.Unlock()
				binary.BigEndian.PutUint64(pkt, seq)
				seq++
				if err := fromc.Send(toDERPPubKey, pkt); err != nil {
					sendErrC <- fmt.Errorf("sending packet %w", err)
					return
				}
			}
		}
	}()

	// Receive the packets.
	recvFinishedC := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(recvFinishedC) // to break out of 'select' below.
		fromDERPPubKey := fromc.SelfPublicKey()
		for {
			m, err := toc.Recv()
			if err != nil {
				recvFinishedC <- err
				return
			}
			switch v := m.(type) {
			case derp.ReceivedPacket:
				now := time.Now()
				if v.Source != fromDERPPubKey {
					recvFinishedC <- fmt.Errorf("got data packet from unexpected source, %v", v.Source)
					return
				}
				seq := binary.BigEndian.Uint64(v.Data)
				txRecordsMu.Lock()
			findTxRecord:
				for i, record := range txRecords {
					switch {
					case record.seq == seq:
						rtt := now.Sub(record.at)
						qdh.add(rtt.Seconds())
						txRecords = slices.Delete(txRecords, i, i+1)
						break findTxRecord
					case record.seq > seq:
						// No sent time found, probably a late arrival already
						// recorded as drop by sender when deleted.
						break findTxRecord
					case record.seq < seq:
						continue
					}
				}
				txRecordsMu.Unlock()

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
	case err := <-sendErrC:
		return fmt.Errorf("error sending via %q: %w", from.Name, err)
	case err := <-recvFinishedC:
		if err != nil {
			return fmt.Errorf("error receiving from %q: %w", to.Name, err)
		}
	}
	return nil
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

var tsLocalClient local.Client

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
	initLabels := make(Labels)
	ip := net.ParseIP(ipaddr)

	if ip.To4() != nil {
		initLabels["address_family"] = "ipv4"
	} else if ip.To16() != nil { // Will return an IPv4 as 16 byte, so ensure the check for IPv4 precedes this
		initLabels["address_family"] = "ipv6"
	} else {
		initLabels["address_family"] = "unknown"
	}

	return ProbeClass{
		Probe: func(ctx context.Context) error {
			return derpProbeUDP(ctx, ipaddr, port)
		},
		Class:  "derp_udp",
		Labels: initLabels,
	}
}

func (d *derpProber) skipRegion(region *tailcfg.DERPRegion) bool {
	return d.regionCodeOrID != "" && region.RegionCode != d.regionCodeOrID && strconv.Itoa(region.RegionID) != d.regionCodeOrID
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
// DERP clients connected to two DERP servers.If tunIPv4Address is specified,
// probes will use a TCP connection over a TUN device at this address in order
// to exercise TCP-in-TCP in similar fashion to TCP over Tailscale via DERP.
func derpProbeBandwidth(ctx context.Context, dm *tailcfg.DERPMap, from, to *tailcfg.DERPNode, size int64, transferTimeSeconds, totalBytesTransferred *expvar.Float, tunIPv4Prefix *netip.Prefix, meshKey key.DERPMesh) (err error) {
	// This probe uses clients with isProber=false to avoid spamming the derper logs with every packet
	// sent by the bandwidth probe.
	fromc, err := newConn(ctx, dm, from, false, meshKey)
	if err != nil {
		return err
	}
	defer fromc.Close()
	toc, err := newConn(ctx, dm, to, false, meshKey)
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

	if tunIPv4Prefix != nil {
		err = derpProbeBandwidthTUN(ctx, transferTimeSeconds, totalBytesTransferred, from, to, fromc, toc, size, tunIPv4Prefix)
	} else {
		err = derpProbeBandwidthDirect(ctx, transferTimeSeconds, from, to, fromc, toc, size)
	}

	if err != nil {
		// Record pubkeys on failed probes to aid investigation.
		return fmt.Errorf("%s -> %s: %w",
			fromc.SelfPublicKey().ShortString(),
			toc.SelfPublicKey().ShortString(), err)
	}
	return nil
}

// derpProbeNodePair sends a small packet between two local DERP clients
// connected to two DERP servers.
func derpProbeNodePair(ctx context.Context, dm *tailcfg.DERPMap, from, to *tailcfg.DERPNode, meshKey key.DERPMesh) (err error) {
	fromc, err := newConn(ctx, dm, from, true, meshKey)
	if err != nil {
		return err
	}
	defer fromc.Close()
	toc, err := newConn(ctx, dm, to, true, meshKey)
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
		toDERPPubKey := toc.SelfPublicKey()
		for idx, pkt := range pkts {
			inFlight.AcquireContext(ctx)
			if err := fromc.Send(toDERPPubKey, pkt); err != nil {
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
		fromDERPPubKey := fromc.SelfPublicKey()
		for {
			m, err := toc.Recv()
			if err != nil {
				recvc <- fmt.Errorf("after %d data packets: %w", idx, err)
				return
			}
			switch v := m.(type) {
			case derp.ReceivedPacket:
				inFlight.Release()
				if v.Source != fromDERPPubKey {
					recvc <- fmt.Errorf("got data packet %d from unexpected source, %v", idx, v.Source)
					return
				}
				// This assumes that the packets are received reliably and in order.
				// The DERP protocol does not guarantee this, but this probe assumes it.
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

// derpProbeBandwidthDirect takes two DERP clients (fromc and toc) connected to two
// DERP servers (from and to) and sends a test payload of a given size from one
// to another using runDerpProbeNodePair. The time taken to finish the transfer is
// recorded in `transferTimeSeconds`.
func derpProbeBandwidthDirect(ctx context.Context, transferTimeSeconds *expvar.Float, from, to *tailcfg.DERPNode, fromc, toc *derphttp.Client, size int64) error {
	start := time.Now()
	defer func() { transferTimeSeconds.Add(time.Since(start).Seconds()) }()

	return runDerpProbeNodePair(ctx, from, to, fromc, toc, size)
}

// derpProbeBandwidthTUNMu ensures that TUN bandwidth probes don't run concurrently.
// This is necessary to avoid conflicts trying to create the TUN device, and
// it also has the nice benefit of preventing concurrent bandwidth probes from
// influencing each other's results.
//
// This guards derpProbeBandwidthTUN.
var derpProbeBandwidthTUNMu sync.Mutex

// derpProbeBandwidthTUN takes two DERP clients (fromc and toc) connected to two
// DERP servers (from and to) and sends a test payload of a given size from one
// to another over a TUN device at an address at the start of the usable host IP
// range that the given tunAddress lives in. The time taken to finish the transfer
// is recorded in `transferTimeSeconds`.
func derpProbeBandwidthTUN(ctx context.Context, transferTimeSeconds, totalBytesTransferred *expvar.Float, from, to *tailcfg.DERPNode, fromc, toc *derphttp.Client, size int64, prefix *netip.Prefix) error {
	// Make sure all goroutines have finished.
	var wg sync.WaitGroup
	defer wg.Wait()

	// Close the clients to make sure goroutines that are reading/writing from them terminate.
	defer fromc.Close()
	defer toc.Close()

	ipRange := netipx.RangeOfPrefix(*prefix)
	// Start of the usable host IP range from the address we have been passed in.
	ifAddr := ipRange.From().Next()
	// Destination address to dial. This is the next address in the range from
	// our ifAddr to ensure that the underlying networking stack is actually being
	// utilized instead of being optimized away and treated as a loopback. Packets
	// sent to this address will be routed over the TUN.
	destinationAddr := ifAddr.Next()

	derpProbeBandwidthTUNMu.Lock()
	defer derpProbeBandwidthTUNMu.Unlock()

	// Temporarily set up a TUN device with which to simulate a real client TCP connection
	// tunneling over DERP. Use `tstun.DefaultTUNMTU()` (e.g., 1280) as our MTU as this is
	// the minimum safe MTU used by Tailscale.
	dev, err := tun.CreateTUN(tunName, int(tstun.DefaultTUNMTU()))
	if err != nil {
		return fmt.Errorf("failed to create TUN device: %w", err)
	}
	defer func() {
		if err := dev.Close(); err != nil {
			log.Printf("failed to close TUN device: %s", err)
		}
	}()
	mtu, err := dev.MTU()
	if err != nil {
		return fmt.Errorf("failed to get TUN MTU: %w", err)
	}

	name, err := dev.Name()
	if err != nil {
		return fmt.Errorf("failed to get device name: %w", err)
	}

	// Perform platform specific configuration of the TUN device.
	err = configureTUN(*prefix, name)
	if err != nil {
		return fmt.Errorf("failed to configure tun: %w", err)
	}

	// Depending on platform, we need some space for headers at the front
	// of TUN I/O op buffers. The below constant is more than enough space
	// for any platform that this might run on.
	tunStartOffset := device.MessageTransportHeaderSize

	// This goroutine reads packets from the TUN device and evaluates if they
	// are IPv4 packets destined for loopback via DERP. If so, it performs L3 NAT
	// (swap src/dst) and writes them towards DERP in order to loopback via the
	// `toc` DERP client. It only reports errors to `tunReadErrC`.
	wg.Add(1)
	tunReadErrC := make(chan error, 1)
	go func() {
		defer wg.Done()

		numBufs := wgconn.IdealBatchSize
		bufs := make([][]byte, 0, numBufs)
		sizes := make([]int, numBufs)
		for range numBufs {
			bufs = append(bufs, make([]byte, mtu+tunStartOffset))
		}

		destinationAddrBytes := destinationAddr.AsSlice()
		scratch := make([]byte, 4)
		toDERPPubKey := toc.SelfPublicKey()
		for {
			n, err := dev.Read(bufs, sizes, tunStartOffset)
			if err != nil {
				tunReadErrC <- err
				return
			}

			for i := range n {
				pkt := bufs[i][tunStartOffset : sizes[i]+tunStartOffset]
				// Skip everything except valid IPv4 packets
				if len(pkt) < 20 {
					// Doesn't even have a full IPv4 header
					continue
				}
				if pkt[0]>>4 != 4 {
					// Not IPv4
					continue
				}

				if !bytes.Equal(pkt[16:20], destinationAddrBytes) {
					// Unexpected dst address
					continue
				}

				copy(scratch, pkt[12:16])
				copy(pkt[12:16], pkt[16:20])
				copy(pkt[16:20], scratch)

				if err := fromc.Send(toDERPPubKey, pkt); err != nil {
					tunReadErrC <- err
					return
				}
			}
		}
	}()

	// This goroutine reads packets from the `toc` DERP client and writes them towards the TUN.
	// It only reports errors to `recvErrC` channel.
	wg.Add(1)
	recvErrC := make(chan error, 1)
	go func() {
		defer wg.Done()

		buf := make([]byte, mtu+tunStartOffset)
		bufs := make([][]byte, 1)

		fromDERPPubKey := fromc.SelfPublicKey()
		for {
			m, err := toc.Recv()
			if err != nil {
				recvErrC <- fmt.Errorf("failed to receive: %w", err)
				return
			}
			switch v := m.(type) {
			case derp.ReceivedPacket:
				if v.Source != fromDERPPubKey {
					recvErrC <- fmt.Errorf("got data packet from unexpected source, %v", v.Source)
					return
				}
				pkt := v.Data
				copy(buf[tunStartOffset:], pkt)
				bufs[0] = buf[:len(pkt)+tunStartOffset]
				if _, err := dev.Write(bufs, tunStartOffset); err != nil {
					recvErrC <- fmt.Errorf("failed to write to TUN device: %w", err)
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

	// Start a listener to receive the data
	ln, err := net.Listen("tcp", net.JoinHostPort(ifAddr.String(), "0"))
	if err != nil {
		return fmt.Errorf("failed to listen: %s", err)
	}
	defer ln.Close()

	// 128KB by default
	const writeChunkSize = 128 << 10

	randData := make([]byte, writeChunkSize)
	_, err = crand.Read(randData)
	if err != nil {
		return fmt.Errorf("failed to initialize random data: %w", err)
	}

	// Dial ourselves
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		return fmt.Errorf("failed to split address %q: %w", ln.Addr().String(), err)
	}

	connAddr := net.JoinHostPort(destinationAddr.String(), port)
	conn, err := net.Dial("tcp", connAddr)
	if err != nil {
		return fmt.Errorf("failed to dial address %q: %w", connAddr, err)
	}
	defer conn.Close()

	// Timing only includes the actual sending and receiving of data.
	start := time.Now()

	// This goroutine reads data from the TCP stream being looped back via DERP.
	// It reports to `readFinishedC` when `size` bytes have been read, or if an
	// error occurs.
	wg.Add(1)
	readFinishedC := make(chan error, 1)
	go func() {
		defer wg.Done()

		readConn, err := ln.Accept()
		if err != nil {
			readFinishedC <- err
			return
		}
		defer readConn.Close()
		deadline, ok := ctx.Deadline()
		if ok {
			// Don't try reading past our context's deadline.
			if err := readConn.SetReadDeadline(deadline); err != nil {
				readFinishedC <- fmt.Errorf("unable to set read deadline: %w", err)
				return
			}
		}
		n, err := io.CopyN(io.Discard, readConn, size)
		// Measure transfer time and bytes transferred irrespective of whether it succeeded or failed.
		transferTimeSeconds.Add(time.Since(start).Seconds())
		totalBytesTransferred.Add(float64(n))
		readFinishedC <- err
	}()

	// This goroutine sends data to the TCP stream being looped back via DERP.
	// It only reports errors to `sendErrC`.
	wg.Add(1)
	sendErrC := make(chan error, 1)
	go func() {
		defer wg.Done()

		for wrote := 0; wrote < int(size); wrote += len(randData) {
			b := randData
			if wrote+len(randData) > int(size) {
				// This is the last chunk and we don't need the whole thing
				b = b[0 : int(size)-wrote]
			}
			if _, err := conn.Write(b); err != nil {
				sendErrC <- fmt.Errorf("failed to write to conn: %w", err)
				return
			}
		}
	}()

	select {
	case <-ctx.Done():
		return fmt.Errorf("timeout: %w", ctx.Err())
	case err := <-tunReadErrC:
		return fmt.Errorf("error reading from TUN via %q: %w", from.Name, err)
	case err := <-sendErrC:
		return fmt.Errorf("error sending via %q: %w", from.Name, err)
	case err := <-recvErrC:
		return fmt.Errorf("error receiving from %q: %w", to.Name, err)
	case err := <-readFinishedC:
		if err != nil {
			return fmt.Errorf("error reading from %q to TUN: %w", to.Name, err)
		}
	}

	return nil
}

func newConn(ctx context.Context, dm *tailcfg.DERPMap, n *tailcfg.DERPNode, isProber bool, meshKey key.DERPMesh) (*derphttp.Client, error) {
	// To avoid spamming the log with regular connection messages.
	logf := logger.Filtered(log.Printf, func(s string) bool {
		return !strings.Contains(s, "derphttp.Client.Connect: connecting to")
	})
	priv := key.NewNode()
	dc := derphttp.NewRegionClient(priv, logf, netmon.NewStatic(), func() *tailcfg.DERPRegion {
		rid := n.RegionID
		return &tailcfg.DERPRegion{
			RegionID:   rid,
			RegionCode: fmt.Sprintf("%s-%s", dm.Regions[rid].RegionCode, n.Name),
			RegionName: dm.Regions[rid].RegionName,
			Nodes:      []*tailcfg.DERPNode{n},
		}
	})
	dc.IsProber = isProber
	dc.MeshKey = meshKey
	err := dc.Connect(ctx)
	if err != nil {
		return nil, err
	}

	// Only verify TLS state if this is a prober.
	if isProber {
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
			errc <- fmt.Errorf("unexpected first message type %T", m)
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
