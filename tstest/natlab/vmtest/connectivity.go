// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest

import (
	"fmt"
	"time"
)

// AddNodeFunc is used to describe a func passed to [Env.RunConnectivityTest]
// and [Env.RunConnectivityTestViaPeerRelay].
type AddNodeFunc func(*Env) *Node

// RunConnectivityTest adds the specified nodes to the network and then
// verifies that a Disco ping from n1 to n2 completes within 30 seconds.
func (env *Env) RunConnectivityTest(name string, pingRoute PingRoute, n1, n2 AddNodeFunc) {
	n1(env)
	n2(env)

	discoPingStep := env.AddStep(
		fmt.Sprintf("[%s] Ping a → b Disco (want %s)", name, pingRoute))
	env.Start()

	discoPingStep.Begin()
	if err := env.PingExpect(env.nodes[0], env.nodes[1], pingRoute, 30*time.Second); err != nil {
		discoPingStep.End(err)
		env.t.Error(err)
	}
	discoPingStep.End(nil)
}

// RunConnectivityTestViaPeerRelay is like [Env.RunConnectivityTest] but adds a
// third node that is configured as a peer-relay server (via
// [Env.EnableRelayServer]) and verifies that a Disco ping from n1 to n2 rides
// the relay ([PingRoutePeerRelay]) within 60 seconds.
//
// The Env must be created with the [PeerRelayGrants] option; without those
// grants magicsock does not consider any peer a candidate relay server. For
// the relay path to actually win, n1 and n2 should be behind NATs that make a
// direct path impossible (e.g. vnet.HardNAT with no portmapping services) and
// the relay's STUN-discovered WAN endpoint must be reachable from both (e.g.
// vnet.One2OneNAT).
func (env *Env) RunConnectivityTestViaPeerRelay(name string, n1, n2, relay AddNodeFunc) {
	a := n1(env)
	b := n2(env)
	r := relay(env)

	enableRelayStep := env.AddStep(
		fmt.Sprintf("[%s] Enable peer-relay server on %s", name, r.Name()))
	discoPingStep := env.AddStep(
		fmt.Sprintf("[%s] Ping a → b Disco (want %s)", name, PingRoutePeerRelay))
	env.Start()

	enableRelayStep.Begin()
	if err := env.EnableRelayServer(r); err != nil {
		enableRelayStep.Fatal(err)
	}
	enableRelayStep.End(nil)

	// 60s budget, double RunConnectivityTest's: the relay server was only
	// just enabled via EditPrefs, so a and b must first learn its endpoint
	// from a netmap update and allocate a relay session before a disco ping
	// can ride it. Matches TestPeerRelay's budget.
	discoPingStep.Begin()
	if err := env.PingExpect(a, b, PingRoutePeerRelay, 60*time.Second); err != nil {
		env.DumpStatus(a)
		env.DumpStatus(b)
		env.DumpStatus(r)
		discoPingStep.End(err)
		env.t.Error(err)
		return
	}
	discoPingStep.End(nil)
}
