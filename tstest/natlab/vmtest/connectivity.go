// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest

import (
	"fmt"
	"time"
)

// AddNodeFunc is used to describe a func passed to [RunConnectivityTestExpect].
type AddNodeFunc func(*Env) *Node

// RunConnectivityTestExpect adds the specified nodes to the network and then
// verifies that a Disco ping from n1 to n2 completes within 30 seconds.
func (e *Env) RunConnectivityTestExpect(name string, pingRoute PingRoute, n1, n2 AddNodeFunc) {
	node1 := n1(e)
	node2 := n2(e)

	discoPingStep := e.AddStep(
		fmt.Sprintf("[%s] Ping a → b Disco (want %s)", name, pingRoute))
	e.Start()

	discoPingStep.Begin()
	if err := e.PingExpect(node1, node2, pingRoute, 30*time.Second); err != nil {
		discoPingStep.End(err)
		e.t.Error(err)
		return
	}
	discoPingStep.End(nil)
}

// RunConnectivityTest adds the specified nodes to the network and then
// verifies that a Disco ping from n1 to n2 completes within 30 seconds.
func (e *Env) RunConnectivityTest(name string, n1, n2 AddNodeFunc) PingRoute {
	e.t.Helper()
	node1 := n1(e)
	node2 := n2(e)
	if node1 == nil || node2 == nil {
		e.t.Skip("skipping test; not applicable combination")
	}

	discoPingStep := e.AddStep(
		fmt.Sprintf("[%s] Ping a → b Disco", name))
	e.Start()

	discoPingStep.Begin()
	pRes, err := e.PingSettle(node1, node2, 10*time.Second)
	if err != nil {
		discoPingStep.End(err)
		e.t.Error(err)
		return PingRouteNil
	}
	pRoute := classifyPing(pRes)
	discoPingStep.End(nil)
	return pRoute
}
