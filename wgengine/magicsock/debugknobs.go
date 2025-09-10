// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios && !js

package magicsock

import (
	"log"
	"net/netip"
	"strings"
	"sync"

	"tailscale.com/envknob"
)

// Various debugging and experimental tweakables, set by environment
// variable.
var (
	// debugDisco prints verbose logs of active discovery events as
	// they happen.
	debugDisco = envknob.RegisterBool("TS_DEBUG_DISCO")
	// debugPeerMap prints verbose logs of changes to the peermap.
	debugPeerMap = envknob.RegisterBool("TS_DEBUG_MAGICSOCK_PEERMAP")
	// debugOmitLocalAddresses removes all local interface addresses
	// from magicsock's discovered local endpoints. Used in some tests.
	debugOmitLocalAddresses = envknob.RegisterBool("TS_DEBUG_OMIT_LOCAL_ADDRS")
	// logDerpVerbose logs all received DERP packets, including their
	// full payload.
	logDerpVerbose = envknob.RegisterBool("TS_DEBUG_DERP")
	// debugReSTUNStopOnIdle unconditionally enables the "shut down
	// STUN if magicsock is idle" behavior that normally only triggers
	// on mobile devices, lowers the shutdown interval, and logs more
	// verbosely about idle measurements.
	debugReSTUNStopOnIdle = envknob.RegisterBool("TS_DEBUG_RESTUN_STOP_ON_IDLE")
	// debugAlwaysDERP disables the use of UDP, forcing all peer communication over DERP.
	debugAlwaysDERP = envknob.RegisterBool("TS_DEBUG_ALWAYS_USE_DERP")
	// debugDERPAddr sets the derp address manually, overriding the DERP map from control.
	debugUseDERPAddr = envknob.RegisterString("TS_DEBUG_USE_DERP_ADDR")
	// debugDERPUseHTTP tells clients to connect to DERP via HTTP on port 3340 instead of
	// HTTPS on 443.
	debugUseDERPHTTP = envknob.RegisterBool("TS_DEBUG_USE_DERP_HTTP")
	// debugEnableSilentDisco disables the use of heartbeatTimer on the endpoint struct
	// and attempts to handle disco silently. See issue #540 for details.
	debugEnableSilentDisco = envknob.RegisterBool("TS_DEBUG_ENABLE_SILENT_DISCO")
	// debugSendCallMeUnknownPeer sends a CallMeMaybe to a non-existent destination every
	// time we send a real CallMeMaybe to test the PeerGoneNotHere logic.
	debugSendCallMeUnknownPeer = envknob.RegisterBool("TS_DEBUG_SEND_CALLME_UNKNOWN_PEER")
	// debugBindSocket prints extra debugging about socket rebinding in magicsock.
	debugBindSocket = envknob.RegisterBool("TS_DEBUG_MAGICSOCK_BIND_SOCKET")
	// debugRingBufferMaxSizeBytes overrides the default size of the endpoint
	// history ringbuffer.
	debugRingBufferMaxSizeBytes = envknob.RegisterInt("TS_DEBUG_MAGICSOCK_RING_BUFFER_MAX_SIZE_BYTES")
	// debugEnablePMTUD enables the peer MTU feature, which does path MTU
	// discovery on UDP connections between peers. Currently (2023-09-05)
	// this only turns on the don't fragment bit for the magicsock UDP
	// sockets.
	//
	//lint:ignore U1000 used on Linux/Darwin only
	debugEnablePMTUD = envknob.RegisterOptBool("TS_DEBUG_ENABLE_PMTUD")
	// debugPMTUD prints extra debugging about peer MTU path discovery.
	//
	//lint:ignore U1000 used on Linux/Darwin only
	debugPMTUD = envknob.RegisterBool("TS_DEBUG_PMTUD")
	// debugNeverDirectUDP disables the use of direct UDP connections, forcing
	// all peer communication over DERP or peer relay.
	debugNeverDirectUDP = envknob.RegisterBool("TS_DEBUG_NEVER_DIRECT_UDP")
	// Hey you! Adding a new debugknob? Make sure to stub it out in the
	// debugknobs_stubs.go file too.
)

// inTest reports whether the running program is a test that set the
// IN_TS_TEST environment variable.
//
// Unlike the other debug tweakables above, this one needs to be
// checked every time at runtime, because tests set this after program
// startup.
func inTest() bool { return envknob.Bool("IN_TS_TEST") }

// pretendpoints returns TS_DEBUG_PRETENDPOINT as []AddrPort, if set.
// See https://github.com/tailscale/tailscale/issues/12578 and
// https://github.com/tailscale/tailscale/pull/12735.
//
// It can be between 0 and 3 comma-separated AddrPorts.
var pretendpoints = sync.OnceValue(func() (ret []netip.AddrPort) {
	all := envknob.String("TS_DEBUG_PRETENDPOINT")
	const max = 3
	remain := all
	for remain != "" && len(ret) < max {
		var s string
		s, remain, _ = strings.Cut(remain, ",")
		ap, err := netip.ParseAddrPort(s)
		if err != nil {
			log.Printf("ignoring invalid AddrPort %q in TS_DEBUG_PRETENDPOINT %q: %v", s, all, err)
			continue
		}
		ret = append(ret, ap)
	}
	return
})
