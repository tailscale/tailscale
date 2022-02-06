// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tcp

import (
	"math"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// cubicState stores the variables related to TCP CUBIC congestion
// control algorithm state.
//
// See: https://tools.ietf.org/html/rfc8312.
// +stateify savable
type cubicState struct {
	stack.TCPCubicState

	// numCongestionEvents tracks the number of congestion events since last
	// RTO.
	numCongestionEvents int

	s *sender
}

// newCubicCC returns a partially initialized cubic state with the constants
// beta and c set and t set to current time.
func newCubicCC(s *sender) *cubicState {
	return &cubicState{
		TCPCubicState: stack.TCPCubicState{
			T:    s.ep.stack.Clock().NowMonotonic(),
			Beta: 0.7,
			C:    0.4,
		},
		s: s,
	}
}

// enterCongestionAvoidance is used to initialize cubic in cases where we exit
// SlowStart without a real congestion event taking place. This can happen when
// a connection goes back to slow start due to a retransmit and we exceed the
// previously lowered ssThresh without experiencing packet loss.
//
// Refer: https://tools.ietf.org/html/rfc8312#section-4.8
func (c *cubicState) enterCongestionAvoidance() {
	// See: https://tools.ietf.org/html/rfc8312#section-4.7 &
	// https://tools.ietf.org/html/rfc8312#section-4.8
	if c.numCongestionEvents == 0 {
		c.K = 0
		c.T = c.s.ep.stack.Clock().NowMonotonic()
		c.WLastMax = c.WMax
		c.WMax = float64(c.s.SndCwnd)
	}
}

// updateSlowStart will update the congestion window as per the slow-start
// algorithm used by NewReno. If after adjusting the congestion window we cross
// the ssThresh then it will return the number of packets that must be consumed
// in congestion avoidance mode.
func (c *cubicState) updateSlowStart(packetsAcked int) int {
	// Don't let the congestion window cross into the congestion
	// avoidance range.
	newcwnd := c.s.SndCwnd + packetsAcked
	enterCA := false
	if newcwnd >= c.s.Ssthresh {
		newcwnd = c.s.Ssthresh
		c.s.SndCAAckCount = 0
		enterCA = true
	}

	packetsAcked -= newcwnd - c.s.SndCwnd
	c.s.SndCwnd = newcwnd
	if enterCA {
		c.enterCongestionAvoidance()
	}
	return packetsAcked
}

// Update updates cubic's internal state variables. It must be called on every
// ACK received.
// Refer: https://tools.ietf.org/html/rfc8312#section-4
func (c *cubicState) Update(packetsAcked int) {
	if c.s.SndCwnd < c.s.Ssthresh {
		packetsAcked = c.updateSlowStart(packetsAcked)
		if packetsAcked == 0 {
			return
		}
	} else {
		c.s.rtt.Lock()
		srtt := c.s.rtt.TCPRTTState.SRTT
		c.s.rtt.Unlock()
		c.s.SndCwnd = c.getCwnd(packetsAcked, c.s.SndCwnd, srtt)
	}
}

// cubicCwnd computes the CUBIC congestion window after t seconds from last
// congestion event.
func (c *cubicState) cubicCwnd(t float64) float64 {
	return c.C*math.Pow(t, 3.0) + c.WMax
}

// getCwnd returns the current congestion window as computed by CUBIC.
// Refer: https://tools.ietf.org/html/rfc8312#section-4
func (c *cubicState) getCwnd(packetsAcked, sndCwnd int, srtt time.Duration) int {
	elapsed := c.s.ep.stack.Clock().NowMonotonic().Sub(c.T)
	elapsedSeconds := elapsed.Seconds()

	// Compute the window as per Cubic after 'elapsed' time
	// since last congestion event.
	c.WC = c.cubicCwnd(elapsedSeconds - c.K)

	// Compute the TCP friendly estimate of the congestion window.
	c.WEst = c.WMax*c.Beta + (3.0*((1.0-c.Beta)/(1.0+c.Beta)))*(elapsedSeconds/srtt.Seconds())

	// Make sure in the TCP friendly region CUBIC performs at least
	// as well as Reno.
	if c.WC < c.WEst && float64(sndCwnd) < c.WEst {
		// TCP Friendly region of cubic.
		return int(c.WEst)
	}

	// In Concave/Convex region of CUBIC, calculate what CUBIC window
	// will be after 1 RTT and use that to grow congestion window
	// for every ack.
	tEst := (elapsed + srtt).Seconds()
	wtRtt := c.cubicCwnd(tEst - c.K)
	// As per 4.3 for each received ACK cwnd must be incremented
	// by (w_cubic(t+RTT) - cwnd/cwnd.
	cwnd := float64(sndCwnd)
	for i := 0; i < packetsAcked; i++ {
		// Concave/Convex regions of cubic have the same formulas.
		// See: https://tools.ietf.org/html/rfc8312#section-4.3
		cwnd += (wtRtt - cwnd) / cwnd
	}
	return int(cwnd)
}

// HandleLossDetected implements congestionControl.HandleLossDetected.
func (c *cubicState) HandleLossDetected() {
	// See: https://tools.ietf.org/html/rfc8312#section-4.5
	c.numCongestionEvents++
	c.T = c.s.ep.stack.Clock().NowMonotonic()
	c.WLastMax = c.WMax
	c.WMax = float64(c.s.SndCwnd)

	c.fastConvergence()
	c.reduceSlowStartThreshold()
}

// HandleRTOExpired implements congestionContrl.HandleRTOExpired.
func (c *cubicState) HandleRTOExpired() {
	// See: https://tools.ietf.org/html/rfc8312#section-4.6
	c.T = c.s.ep.stack.Clock().NowMonotonic()
	c.numCongestionEvents = 0
	c.WLastMax = c.WMax
	c.WMax = float64(c.s.SndCwnd)

	c.fastConvergence()

	// We lost a packet, so reduce ssthresh.
	c.reduceSlowStartThreshold()

	// Reduce the congestion window to 1, i.e., enter slow-start. Per
	// RFC 5681, page 7, we must use 1 regardless of the value of the
	// initial congestion window.
	c.s.SndCwnd = 1
}

// fastConvergence implements the logic for Fast Convergence algorithm as
// described in https://tools.ietf.org/html/rfc8312#section-4.6.
func (c *cubicState) fastConvergence() {
	if c.WMax < c.WLastMax {
		c.WLastMax = c.WMax
		c.WMax = c.WMax * (1.0 + c.Beta) / 2.0
	} else {
		c.WLastMax = c.WMax
	}
	// Recompute k as wMax may have changed.
	c.K = math.Cbrt(c.WMax * (1 - c.Beta) / c.C)
}

// PostRecovery implemements congestionControl.PostRecovery.
func (c *cubicState) PostRecovery() {
	c.T = c.s.ep.stack.Clock().NowMonotonic()
}

// reduceSlowStartThreshold returns new SsThresh as described in
// https://tools.ietf.org/html/rfc8312#section-4.7.
func (c *cubicState) reduceSlowStartThreshold() {
	c.s.Ssthresh = int(math.Max(float64(c.s.SndCwnd)*c.Beta, 2.0))
}
