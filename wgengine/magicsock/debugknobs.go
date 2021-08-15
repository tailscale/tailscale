// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !ios
// +build !ios

package magicsock

import (
	"os"
	"strconv"
)

// Various debugging and experimental tweakables, set by environment
// variable.
var (
	// logPacketDests prints the known addresses for a peer every time
	// they change, in the legacy (non-discovery) endpoint code only.
	logPacketDests, _ = strconv.ParseBool(os.Getenv("TS_DEBUG_LOG_PACKET_DESTS"))
	// debugDisco prints verbose logs of active discovery events as
	// they happen.
	debugDisco, _ = strconv.ParseBool(os.Getenv("TS_DEBUG_DISCO"))
	// debugOmitLocalAddresses removes all local interface addresses
	// from magicsock's discovered local endpoints. Used in some tests.
	debugOmitLocalAddresses, _ = strconv.ParseBool(os.Getenv("TS_DEBUG_OMIT_LOCAL_ADDRS"))
	// debugUseDerpRoute temporarily (2020-03-22) controls whether DERP
	// reverse routing is enabled (Issue 150). It will become always true
	// later.
	debugUseDerpRouteEnv = os.Getenv("TS_DEBUG_ENABLE_DERP_ROUTE")
	debugUseDerpRoute, _ = strconv.ParseBool(debugUseDerpRouteEnv)
	// logDerpVerbose logs all received DERP packets, including their
	// full payload.
	logDerpVerbose, _ = strconv.ParseBool(os.Getenv("TS_DEBUG_DERP"))
	// debugReSTUNStopOnIdle unconditionally enables the "shut down
	// STUN if magicsock is idle" behavior that normally only triggers
	// on mobile devices, lowers the shutdown interval, and logs more
	// verbosely about idle measurements.
	debugReSTUNStopOnIdle, _ = strconv.ParseBool(os.Getenv("TS_DEBUG_RESTUN_STOP_ON_IDLE"))
	// debugAlwaysDERP disables the use of UDP, forcing all peer communication over DERP.
	debugAlwaysDERP, _ = strconv.ParseBool(os.Getenv("TS_DEBUG_ALWAYS_USE_DERP"))
)

// inTest reports whether the running program is a test that set the
// IN_TS_TEST environment variable.
//
// Unlike the other debug tweakables above, this one needs to be
// checked every time at runtime, because tests set this after program
// startup.
func inTest() bool {
	inTest, _ := strconv.ParseBool(os.Getenv("IN_TS_TEST"))
	return inTest
}
