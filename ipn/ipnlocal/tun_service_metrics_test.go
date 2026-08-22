// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_serve && !ts_omit_usermetrics

package ipnlocal

import (
	"net/netip"
	"testing"

	"github.com/tailscale/wireguard-go/tun/tuntest"
	"tailscale.com/ipn"
	"tailscale.com/net/packet"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
)

func TestTUNServiceMetricsWiring(t *testing.T) {
	bus := eventbustest.NewBus(t)
	channelTUN := tuntest.NewChannelTUN()
	sys := tsd.NewSystemWithBus(bus)
	engine, err := wgengine.NewUserspaceEngine(logger.Discard, wgengine.Config{
		Tun:           channelTUN.TUN(),
		SetSubsystem:  sys.Set,
		HealthTracker: sys.HealthTracker.Get(),
		Metrics:       sys.UserMetricsRegistry(),
		EventBus:      bus,
	})
	if err != nil {
		t.Fatal(err)
	}
	sys.Set(engine)
	t.Cleanup(engine.Close)

	tun := sys.Tun.Get()
	// Match production, where Wrapper can start before LocalBackend.
	tun.Start()
	b := newTestLocalBackendWithSys(t, sys)
	tun.SetFilter(filter.NewAllowAllForTest(t.Logf))

	serviceIP := netip.MustParseAddr("100.64.0.10")
	peerIP := netip.MustParseAddr("100.64.0.20")
	const serviceName = tailcfg.ServiceName("svc:foo")
	b.ForTest().SetIPServiceMappings(netmap.IPServiceMappings{
		serviceIP: serviceName,
	})
	if got := counterValue(b.tunServiceMetrics.inbound, serviceName.String()); got != -1 {
		t.Fatalf("inbound before ServeConfig load = %d; want absent", got)
	}

	b.ForTest().SetServeConfig((&ipn.ServeConfig{
		Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
			serviceName: {Tun: true},
		},
	}).View())

	if got := counterValue(b.tunServiceMetrics.inbound, serviceName.String()); got != 0 {
		t.Fatalf("initial inbound = %d; want zero-valued series", got)
	}
	if got := counterValue(b.tunServiceMetrics.outbound, serviceName.String()); got != 0 {
		t.Fatalf("initial outbound = %d; want zero-valued series", got)
	}

	inboundPacket := packet.Generate(packet.UDP4Header{
		IP4Header: packet.IP4Header{Src: peerIP, Dst: serviceIP},
		SrcPort:   1234,
		DstPort:   5678,
	}, []byte("request"))
	delivered := make(chan []byte, 1)
	go func() { delivered <- <-channelTUN.Inbound }()
	if n, err := tun.Write([][]byte{inboundPacket}, 0); err != nil || n != 1 {
		t.Fatalf("Write = %d, %v; want 1, nil", n, err)
	}
	<-delivered
	if got := counterValue(b.tunServiceMetrics.inbound, serviceName.String()); got != int64(len(inboundPacket)) {
		t.Fatalf("inbound = %d; want %d", got, len(inboundPacket))
	}

	// Removing an assignment stops attribution but keeps the counter series
	// for the lifetime of the process.
	b.ForTest().SetIPServiceMappings(nil)
	go func() { delivered <- <-channelTUN.Inbound }()
	if n, err := tun.Write([][]byte{inboundPacket}, 0); err != nil || n != 1 {
		t.Fatalf("Write after mapping removal = %d, %v; want 1, nil", n, err)
	}
	<-delivered
	if got, want := counterValue(b.tunServiceMetrics.inbound, serviceName.String()), int64(len(inboundPacket)); got != want {
		t.Fatalf("inbound after mapping removal = %d; want %d", got, want)
	}
	if got := counterValue(b.tunServiceMetrics.outbound, serviceName.String()); got != 0 {
		t.Fatalf("outbound after mapping removal = %d; want 0", got)
	}

	// Userspace Serve Services are excluded.
	const userspaceService = tailcfg.ServiceName("svc:userspace")
	b.ForTest().SetServeConfig((&ipn.ServeConfig{
		Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
			userspaceService: {Tun: false},
		},
	}).View())
	b.ForTest().SetIPServiceMappings(netmap.IPServiceMappings{
		serviceIP: userspaceService,
	})
	if got := counterValue(b.tunServiceMetrics.inbound, userspaceService.String()); got != -1 {
		t.Fatalf("inbound for non-TUN Service = %d; want absent", got)
	}

	// Kubernetes ingress Services do not have ServeConfig entries.
	const kernelService = tailcfg.ServiceName("svc:kernel")
	b.ForTest().SetServeConfig((&ipn.ServeConfig{}).View())
	b.ForTest().SetIPServiceMappings(netmap.IPServiceMappings{
		serviceIP: kernelService,
	})
	if got := counterValue(b.tunServiceMetrics.inbound, kernelService.String()); got != 0 {
		t.Fatalf("initial inbound for kernel-forwarded Service = %d; want zero-valued series", got)
	}
	if got := counterValue(b.tunServiceMetrics.outbound, kernelService.String()); got != 0 {
		t.Fatalf("initial outbound for kernel-forwarded Service = %d; want zero-valued series", got)
	}

	kernelPacket := packet.Generate(packet.UDP4Header{
		IP4Header: packet.IP4Header{Src: peerIP, Dst: serviceIP},
		SrcPort:   1234,
		DstPort:   5678,
	}, []byte("kernel request"))
	go func() { delivered <- <-channelTUN.Inbound }()
	if n, err := tun.Write([][]byte{kernelPacket}, 0); err != nil || n != 1 {
		t.Fatalf("kernel-forwarded Write = %d, %v; want 1, nil", n, err)
	}
	<-delivered
	if got := counterValue(b.tunServiceMetrics.inbound, kernelService.String()); got != int64(len(kernelPacket)) {
		t.Fatalf("kernel-forwarded inbound = %d; want %d", got, len(kernelPacket))
	}
}
