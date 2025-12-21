// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_netlog && !ts_omit_logtail

// Package netlog provides a logger that monitors a TUN device and
// periodically records any traffic into a log stream.
package netlog

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"time"

	"tailscale.com/health"
	"tailscale.com/logpolicy"
	"tailscale.com/logtail"
	"tailscale.com/net/netmon"
	"tailscale.com/net/sockstats"
	"tailscale.com/net/tsaddr"
	"tailscale.com/syncs"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/types/netlogfunc"
	"tailscale.com/types/netlogtype"
	"tailscale.com/types/netmap"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/set"
	"tailscale.com/wgengine/router"

	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
)

// pollPeriod specifies how often to poll for network traffic.
const pollPeriod = 5 * time.Second

// Device is an abstraction over a tunnel device or a magic socket.
// Both *tstun.Wrapper and *magicsock.Conn implement this interface.
type Device interface {
	SetConnectionCounter(netlogfunc.ConnectionCounter)
}

type noopDevice struct{}

func (noopDevice) SetConnectionCounter(netlogfunc.ConnectionCounter) {}

// Logger logs statistics about every connection.
// At present, it only logs connections within a tailscale network.
// By default, exit node traffic is not logged for privacy reasons
// unless the Tailnet administrator opts-into explicit logging.
// The zero value is ready for use.
type Logger struct {
	mu   syncs.Mutex // protects all fields below
	logf logger.Logf

	// shutdownLocked shuts down the logger.
	// The mutex must be held when calling.
	shutdownLocked func(context.Context) error

	record      record      // the current record of network connection flows
	recordLen   int         // upper bound on JSON length of record
	recordsChan chan record // set to nil when shutdown
	flushTimer  *time.Timer // fires when record should flush to recordsChan

	// Information about Tailscale nodes.
	// These are read-only once updated by ReconfigNetworkMap.
	selfNode nodeUser
	allNodes map[netip.Addr]nodeUser // includes selfNode; nodeUser values are always valid

	// Information about routes.
	// These are read-only once updated by ReconfigRoutes.
	routeAddrs    set.Set[netip.Addr]
	routePrefixes []netip.Prefix
}

// Running reports whether the logger is running.
func (nl *Logger) Running() bool {
	nl.mu.Lock()
	defer nl.mu.Unlock()
	return nl.shutdownLocked != nil
}

var testClient *http.Client

// Startup starts an asynchronous network logger that monitors
// statistics for the provided tun and/or sock device.
//
// The tun [Device] captures packets within the tailscale network,
// where at least one address is usually a tailscale IP address.
// The source is usually from the perspective of the current node.
// If one of the other endpoint is not a tailscale IP address,
// then it suggests the use of a subnet router or exit node.
// For example, when using a subnet router, the source address is
// the tailscale IP address of the current node, and
// the destination address is an IP address within the subnet range.
// In contrast, when acting as a subnet router, the source address is
// an IP address within the subnet range, and the destination is a
// tailscale IP address that initiated the subnet proxy connection.
// In this case, the node acting as a subnet router is acting on behalf
// of some remote endpoint within the subnet range.
// The tun is used to populate the VirtualTraffic, SubnetTraffic,
// and ExitTraffic fields in [netlogtype.Message].
//
// The sock [Device] captures packets at the magicsock layer.
// The source is always a tailscale IP address and the destination
// is a non-tailscale IP address to contact for that particular tailscale node.
// The IP protocol and source port are always zero.
// The sock is used to populated the PhysicalTraffic field in [netlogtype.Message].
//
// The netMon parameter is optional; if non-nil it's used to do faster interface lookups.
func (nl *Logger) Startup(logf logger.Logf, nm *netmap.NetworkMap, nodeLogID, domainLogID logid.PrivateID, tun, sock Device, netMon *netmon.Monitor, health *health.Tracker, bus *eventbus.Bus, logExitFlowEnabledEnabled bool) error {
	nl.mu.Lock()
	defer nl.mu.Unlock()

	if nl.shutdownLocked != nil {
		return fmt.Errorf("network logger already running")
	}
	nl.selfNode, nl.allNodes = makeNodeMaps(nm)

	// Startup a log stream to Tailscale's logging service.
	if logf == nil {
		logf = log.Printf
	}
	httpc := &http.Client{Transport: logpolicy.NewLogtailTransport(logtail.DefaultHost, netMon, health, logf)}
	if testClient != nil {
		httpc = testClient
	}
	logger := logtail.NewLogger(logtail.Config{
		Collection:    "tailtraffic.log.tailscale.io",
		PrivateID:     nodeLogID,
		CopyPrivateID: domainLogID,
		Bus:           bus,
		Stderr:        io.Discard,
		CompressLogs:  true,
		HTTPC:         httpc,
		// TODO(joetsai): Set Buffer? Use an in-memory buffer for now.

		// Include process sequence numbers to identify missing samples.
		IncludeProcID:       true,
		IncludeProcSequence: true,
	}, logf)
	logger.SetSockstatsLabel(sockstats.LabelNetlogLogger)

	// Register the connection tracker into the TUN device.
	tun = cmp.Or[Device](tun, noopDevice{})
	tun.SetConnectionCounter(nl.updateVirtConn)

	// Register the connection tracker into magicsock.
	sock = cmp.Or[Device](sock, noopDevice{})
	sock.SetConnectionCounter(nl.updatePhysConn)

	// Startup a goroutine to record log messages.
	// This is done asynchronously so that the cost of serializing
	// the network flow log message never stalls processing of packets.
	nl.record = record{}
	nl.recordLen = 0
	nl.recordsChan = make(chan record, 100)
	recorderDone := make(chan struct{})
	go func(recordsChan chan record) {
		defer close(recorderDone)
		for rec := range recordsChan {
			msg := rec.toMessage(false, !logExitFlowEnabledEnabled)
			if b, err := jsonv2.Marshal(msg, jsontext.AllowInvalidUTF8(true)); err != nil {
				if nl.logf != nil {
					nl.logf("netlog: json.Marshal error: %v", err)
				}
			} else {
				logger.Logf("%s", b)
			}
		}
	}(nl.recordsChan)

	// Register the mechanism for shutting down.
	nl.shutdownLocked = func(ctx context.Context) error {
		tun.SetConnectionCounter(nil)
		sock.SetConnectionCounter(nil)

		// Flush and process all pending records.
		nl.flushRecordLocked()
		close(nl.recordsChan)
		nl.recordsChan = nil
		<-recorderDone
		recorderDone = nil

		// Try to upload all pending records.
		err := logger.Shutdown(ctx)

		// Purge state.
		nl.shutdownLocked = nil
		nl.selfNode = nodeUser{}
		nl.allNodes = nil
		nl.routeAddrs = nil
		nl.routePrefixes = nil

		return err
	}

	return nil
}

var (
	tailscaleServiceIPv4 = tsaddr.TailscaleServiceIP()
	tailscaleServiceIPv6 = tsaddr.TailscaleServiceIPv6()
)

func (nl *Logger) updateVirtConn(proto ipproto.Proto, src, dst netip.AddrPort, packets, bytes int, recv bool) {
	// Network logging is defined as traffic between two Tailscale nodes.
	// Traffic with the internal Tailscale service is not with another node
	// and should not be logged. It also happens to be a high volume
	// amount of discrete traffic flows (e.g., DNS lookups).
	switch dst.Addr() {
	case tailscaleServiceIPv4, tailscaleServiceIPv6:
		return
	}

	nl.mu.Lock()
	defer nl.mu.Unlock()

	// Lookup the connection and increment the counts.
	nl.initRecordLocked()
	conn := netlogtype.Connection{Proto: proto, Src: src, Dst: dst}
	cnts, found := nl.record.virtConns[conn]
	if !found {
		cnts.connType = nl.addNewVirtConnLocked(conn)
	}
	if recv {
		cnts.RxPackets += uint64(packets)
		cnts.RxBytes += uint64(bytes)
	} else {
		cnts.TxPackets += uint64(packets)
		cnts.TxBytes += uint64(bytes)
	}
	nl.record.virtConns[conn] = cnts
}

// addNewVirtConnLocked adds the first insertion of a physical connection.
// The [Logger.mu] must be held.
func (nl *Logger) addNewVirtConnLocked(c netlogtype.Connection) connType {
	// Check whether this is the first insertion of the src and dst node.
	// If so, compute the additional JSON bytes that would be added
	// to the record for the node information.
	var srcNodeLen, dstNodeLen int
	srcNode, srcSeen := nl.record.seenNodes[c.Src.Addr()]
	if !srcSeen {
		srcNode = nl.allNodes[c.Src.Addr()]
		if srcNode.Valid() {
			srcNodeLen = srcNode.jsonLen()
		}
	}
	dstNode, dstSeen := nl.record.seenNodes[c.Dst.Addr()]
	if !dstSeen {
		dstNode = nl.allNodes[c.Dst.Addr()]
		if dstNode.Valid() {
			dstNodeLen = dstNode.jsonLen()
		}
	}

	// Check whether the additional [netlogtype.ConnectionCounts]
	// and [netlogtype.Node] information would exceed [maxLogSize].
	if nl.recordLen+netlogtype.MaxConnectionCountsJSONSize+srcNodeLen+dstNodeLen > maxLogSize {
		nl.flushRecordLocked()
		nl.initRecordLocked()
	}

	// Insert newly seen src and/or dst nodes.
	if !srcSeen && srcNode.Valid() {
		nl.record.seenNodes[c.Src.Addr()] = srcNode
	}
	if !dstSeen && dstNode.Valid() {
		nl.record.seenNodes[c.Dst.Addr()] = dstNode
	}
	nl.recordLen += netlogtype.MaxConnectionCountsJSONSize + srcNodeLen + dstNodeLen

	// Classify the traffic type.
	var srcIsSelfNode bool
	if nl.selfNode.Valid() {
		srcIsSelfNode = nl.selfNode.Addresses().ContainsFunc(func(p netip.Prefix) bool {
			return c.Src.Addr() == p.Addr() && p.IsSingleIP()
		})
	}
	switch {
	case srcIsSelfNode && dstNode.Valid():
		return virtualTraffic
	case srcIsSelfNode:
		// TODO: Should we swap src for the node serving as the proxy?
		// It is relatively useless always using the self IP address.
		if nl.withinRoutesLocked(c.Dst.Addr()) {
			return subnetTraffic // a client using another subnet router
		} else {
			return exitTraffic // a client using exit an exit node
		}
	case dstNode.Valid():
		if nl.withinRoutesLocked(c.Src.Addr()) {
			return subnetTraffic // serving as a subnet router
		} else {
			return exitTraffic // serving as an exit node
		}
	default:
		return unknownTraffic
	}
}

func (nl *Logger) updatePhysConn(proto ipproto.Proto, src, dst netip.AddrPort, packets, bytes int, recv bool) {
	nl.mu.Lock()
	defer nl.mu.Unlock()

	// Lookup the connection and increment the counts.
	nl.initRecordLocked()
	conn := netlogtype.Connection{Proto: proto, Src: src, Dst: dst}
	cnts, found := nl.record.physConns[conn]
	if !found {
		nl.addNewPhysConnLocked(conn)
	}
	if recv {
		cnts.RxPackets += uint64(packets)
		cnts.RxBytes += uint64(bytes)
	} else {
		cnts.TxPackets += uint64(packets)
		cnts.TxBytes += uint64(bytes)
	}
	nl.record.physConns[conn] = cnts
}

// addNewPhysConnLocked adds the first insertion of a physical connection.
// The [Logger.mu] must be held.
func (nl *Logger) addNewPhysConnLocked(c netlogtype.Connection) {
	// Check whether this is the first insertion of the src node.
	var srcNodeLen int
	srcNode, srcSeen := nl.record.seenNodes[c.Src.Addr()]
	if !srcSeen {
		srcNode = nl.allNodes[c.Src.Addr()]
		if srcNode.Valid() {
			srcNodeLen = srcNode.jsonLen()
		}
	}

	// Check whether the additional [netlogtype.ConnectionCounts]
	// and [netlogtype.Node] information would exceed [maxLogSize].
	if nl.recordLen+netlogtype.MaxConnectionCountsJSONSize+srcNodeLen > maxLogSize {
		nl.flushRecordLocked()
		nl.initRecordLocked()
	}

	// Insert newly seen src and/or dst nodes.
	if !srcSeen && srcNode.Valid() {
		nl.record.seenNodes[c.Src.Addr()] = srcNode
	}
	nl.recordLen += netlogtype.MaxConnectionCountsJSONSize + srcNodeLen
}

// initRecordLocked initialize the current record if uninitialized.
// The [Logger.mu] must be held.
func (nl *Logger) initRecordLocked() {
	if nl.recordLen != 0 {
		return
	}
	nl.record = record{
		selfNode:  nl.selfNode,
		start:     time.Now().UTC(),
		seenNodes: make(map[netip.Addr]nodeUser),
		virtConns: make(map[netlogtype.Connection]countsType),
		physConns: make(map[netlogtype.Connection]netlogtype.Counts),
	}
	nl.recordLen = netlogtype.MinMessageJSONSize + nl.selfNode.jsonLen()

	// Start a time to auto-flush the record.
	// Avoid tickers since continually waking up a goroutine
	// is expensive on battery powered devices.
	nl.flushTimer = time.AfterFunc(pollPeriod, func() {
		nl.mu.Lock()
		defer nl.mu.Unlock()
		if !nl.record.start.IsZero() && time.Since(nl.record.start) > pollPeriod/2 {
			nl.flushRecordLocked()
		}
	})
}

// flushRecordLocked flushes the current record if initialized.
// The [Logger.mu] must be held.
func (nl *Logger) flushRecordLocked() {
	if nl.recordLen == 0 {
		return
	}
	nl.record.end = time.Now().UTC()
	if nl.recordsChan != nil {
		select {
		case nl.recordsChan <- nl.record:
		default:
			if nl.logf != nil {
				nl.logf("netlog: dropped record due to processing backlog")
			}
		}
	}
	if nl.flushTimer != nil {
		nl.flushTimer.Stop()
		nl.flushTimer = nil
	}
	nl.record = record{}
	nl.recordLen = 0
}

func makeNodeMaps(nm *netmap.NetworkMap) (selfNode nodeUser, allNodes map[netip.Addr]nodeUser) {
	if nm == nil {
		return
	}
	allNodes = make(map[netip.Addr]nodeUser)
	if nm.SelfNode.Valid() {
		selfNode = nodeUser{nm.SelfNode, nm.UserProfiles[nm.SelfNode.User()]}
		for _, addr := range nm.SelfNode.Addresses().All() {
			if addr.IsSingleIP() {
				allNodes[addr.Addr()] = selfNode
			}
		}
	}
	for _, peer := range nm.Peers {
		if peer.Valid() {
			for _, addr := range peer.Addresses().All() {
				if addr.IsSingleIP() {
					allNodes[addr.Addr()] = nodeUser{peer, nm.UserProfiles[peer.User()]}
				}
			}
		}
	}
	return selfNode, allNodes
}

// ReconfigNetworkMap configures the network logger with an updated netmap.
func (nl *Logger) ReconfigNetworkMap(nm *netmap.NetworkMap) {
	selfNode, allNodes := makeNodeMaps(nm) // avoid holding lock while making maps
	nl.mu.Lock()
	nl.selfNode, nl.allNodes = selfNode, allNodes
	nl.mu.Unlock()
}

func makeRouteMaps(cfg *router.Config) (addrs set.Set[netip.Addr], prefixes []netip.Prefix) {
	addrs = make(set.Set[netip.Addr])
	insertPrefixes := func(rs []netip.Prefix) {
		for _, p := range rs {
			if p.IsSingleIP() {
				addrs.Add(p.Addr())
			} else {
				prefixes = append(prefixes, p)
			}
		}
	}
	insertPrefixes(cfg.LocalAddrs)
	insertPrefixes(cfg.Routes)
	insertPrefixes(cfg.SubnetRoutes)
	return addrs, prefixes
}

// ReconfigRoutes configures the network logger with updated routes.
// The cfg is used to classify the types of connections captured by
// the tun Device passed to Startup.
func (nl *Logger) ReconfigRoutes(cfg *router.Config) {
	addrs, prefixes := makeRouteMaps(cfg) // avoid holding lock while making maps
	nl.mu.Lock()
	nl.routeAddrs, nl.routePrefixes = addrs, prefixes
	nl.mu.Unlock()
}

// withinRoutesLocked reports whether a is within the configured routes,
// which should only contain Tailscale addresses and subnet routes.
// The [Logger.mu] must be held.
func (nl *Logger) withinRoutesLocked(a netip.Addr) bool {
	if nl.routeAddrs.Contains(a) {
		return true
	}
	for _, p := range nl.routePrefixes {
		if p.Contains(a) && p.Bits() > 0 {
			return true
		}
	}
	return false
}

// Shutdown shuts down the network logger.
// This attempts to flush out all pending log messages.
// Even if an error is returned, the logger is still shut down.
func (nl *Logger) Shutdown(ctx context.Context) error {
	nl.mu.Lock()
	defer nl.mu.Unlock()
	if nl.shutdownLocked == nil {
		return nil
	}
	return nl.shutdownLocked(ctx)
}
