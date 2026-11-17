// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netstack

import (
	"bytes"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/usermetric"
)

func TestOutboundQueueFullMetrics(t *testing.T) {
	route := map[*stack.PacketBuffer]outboundQueue{}
	ep := newLinkEndpoint(1, 1280, "", groNotSupported, func(pkt *stack.PacketBuffer) outboundQueue { return route[pkt] })
	t.Cleanup(ep.Close)
	ns := &Impl{linkEP: ep, ipstack: stack.New(stack.Options{})}
	t.Cleanup(func() { ns.ipstack.Close(); ns.ipstack.Wait() })
	stacksForMetrics.Store(ns, struct{}{})
	t.Cleanup(func() { stacksForMetrics.Delete(ns) })
	var reg usermetric.Registry
	ns.SetMetricsRegistry(&reg)
	debug := ns.ExpVar() // must reflect updates after registration

	// With one slot per queue, the second WireGuard and loopback packets are
	// dropped. A full queue must not drop later packets bound for other queues.
	var released atomic.Int32
	var pkts stack.PacketBufferList
	for _, q := range []outboundQueue{outboundToWireGuard, outboundToWireGuard, outboundToHost, outboundLoopback, outboundLoopback} {
		pkt := newQueueTestPacket(&released)
		route[pkt] = q
		pkts.PushBack(pkt)
	}
	n, err := ep.WritePackets(pkts)
	pkts.DecRef()
	if _, ok := err.(*tcpip.ErrNoBufferSpace); !ok || n != 3 {
		t.Fatalf("WritePackets = %d, %v; want 3, ErrNoBufferSpace", n, err)
	}
	if got := released.Load(); got != 2 {
		t.Errorf("released = %d, want 2", got)
	}
	want := map[string]int64{"wireguard": 1, "host": 0, "loopback": 1}
	for q, name := range map[outboundQueue]string{outboundToWireGuard: "wireguard", outboundToHost: "host", outboundLoopback: "loopback"} {
		if got := ep.queueFullDropped[q].Value(); got != want[name] {
			t.Errorf("%s queue-full drops = %d, want %d", name, got, want[name])
		}
		if s := fmt.Sprintf("\"counter_outbound_queue_full_dropped_packets_%s\": %d", name, want[name]); !strings.Contains(debug.String(), s) {
			t.Errorf("debug metrics missing %s: %s", s, debug.String())
		}
	}
	if buildfeatures.HasUserMetrics {
		rr := httptest.NewRecorder()
		reg.Handler(rr, httptest.NewRequest("GET", "/metrics", nil))
		if s := "tailscaled_outbound_dropped_packets_total{reason=\"queue_full\"} 1\n"; !strings.Contains(rr.Body.String(), s) {
			t.Errorf("user metrics missing %q: %s", s, rr.Body.String())
		}
	}
	if buildfeatures.HasClientMetrics {
		// Client metrics sum all queues of all instances.
		other := &Impl{linkEP: newLinkEndpoint(0, 1280, "", groNotSupported, nil), ipstack: ns.ipstack}
		other.linkEP.queueFullDropped[outboundToHost].Add(2)
		stacksForMetrics.Store(other, struct{}{})
		t.Cleanup(func() { stacksForMetrics.Delete(other); other.linkEP.Close() })
		var b bytes.Buffer
		clientmetric.WritePrometheusExpositionFormat(&b)
		if s := "netstack_outbound_queue_full_dropped_packets 4\n"; !strings.Contains(b.String(), s) {
			t.Errorf("client metrics missing %q: %s", s, b.String())
		}
	}

	// Shutdown loss is not queue-full loss.
	ep.Close()
	pkt := newQueueTestPacket(&released)
	route[pkt] = outboundToWireGuard
	var closedPkts stack.PacketBufferList
	closedPkts.PushBack(pkt)
	n, err = ep.WritePackets(closedPkts)
	closedPkts.DecRef()
	if _, ok := err.(*tcpip.ErrClosedForSend); !ok || n != 0 {
		t.Errorf("closed WritePackets = %d, %v", n, err)
	}
	if got := ep.queueFullDroppedTotal(); got != 2 {
		t.Errorf("closed write changed queue-full drops to %d, want 2", got)
	}
}
