// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios && !js

package magicsock

import (
	"tailscale.com/envknob"
)

const linkDebug = true

// Various debugging and experimental tweakables, set by environment
// variable.
var (
	// debugDisco prints verbose logs of active discovery events as
	// they happen.
	debugDisco = envknob.RegisterBool("TS_DEBUG_DISCO")
	// debugOmitLocalAddresses removes all local interface addresses
	// from magicsock's discovered local endpoints. Used in some tests.
	debugOmitLocalAddresses = envknob.RegisterBool("TS_DEBUG_OMIT_LOCAL_ADDRS")
	// debugUseDerpRoute temporarily (2020-03-22) controls whether DERP
	// reverse routing is enabled (Issue 150).
	debugUseDerpRoute = envknob.RegisterOptBool("TS_DEBUG_ENABLE_DERP_ROUTE")
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
	// Hey you! Adding a new debugknob? Make sure to stub it out in the debugknob_stubs.go
	// file too.
)

// inTest reports whether the running program is a test that set the
// IN_TS_TEST environment variable.
//
// Unlike the other debug tweakables above, this one needs to be
// checked every time at runtime, because tests set this after program
// startup.
func inTest() bool { return envknob.Bool("IN_TS_TEST") }
