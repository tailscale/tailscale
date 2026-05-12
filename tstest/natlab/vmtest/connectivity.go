// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest

import (
	"fmt"
	"time"
)

// AddNodeFunc is used to describe a func passed to [RunConnectivityTest].
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
