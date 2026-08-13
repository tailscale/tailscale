// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package localrelay

import (
	"context"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/ipv4"
	"tailscale.com/types/key"
	"tailscale.com/util/set"
)

const (
	DiscoveryPort = 41643
	multicastIP   = "239.192.0.1"
	announceEvery = 5 * time.Second
)

func Advertise(ctx context.Context, logf func(string, ...any), disco key.DiscoPublic, port uint16) error {
	if port == 0 {
		return nil
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return err
	}
	defer conn.Close()

	pc := ipv4.NewPacketConn(conn)
	if err := pc.SetMulticastTTL(1); err != nil {
		return err
	}
	_ = pc.SetMulticastLoopback(false)

	group := &net.UDPAddr{IP: net.ParseIP(multicastIP), Port: DiscoveryPort}
	payload := MarshalAdvertisement(disco, port)

	send := func() {
		ifaces, err := multicastInterfaces()
		if err != nil {
			if logf != nil {
				logf("local relay discovery: interface enumeration failed: %v", err)
			}
			return
		}
		for _, iface := range ifaces {
			if err := pc.SetMulticastInterface(iface); err != nil {
				continue
			}
			if _, err := pc.WriteTo(payload, nil, group); err != nil && logf != nil {
				logf("local relay discovery: advertise on %s failed: %v", iface.Name, err)
			}
		}
	}

	send()
	t := time.NewTicker(announceEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			send()
		}
	}
}

func Listen(ctx context.Context, callback func(netip.AddrPort, key.DiscoPublic)) error {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: DiscoveryPort})
	if err != nil {
		return err
	}
	defer conn.Close()

	pc := ipv4.NewPacketConn(conn)
	group := &net.UDPAddr{IP: net.ParseIP(multicastIP), Port: DiscoveryPort}
	ifaces, err := multicastInterfaces()
	if err != nil {
		return err
	}
	for _, iface := range ifaces {
		_ = pc.JoinGroup(iface, group)
	}

	buf := make([]byte, 2048)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}
		disco, port, err := ParseAdvertisement(buf[:n])
		if err != nil || src == nil {
			continue
		}
		ip := src.IP.To4()
		if ip == nil {
			continue
		}
		var v4 [4]byte
		copy(v4[:], ip)
		callback(netip.AddrPortFrom(netip.AddrFrom4(v4), port), disco)
	}
}

func multicastInterfaces() ([]*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out set.Set[*net.Interface]
	out.Make()
	for i := range ifaces {
		iface := &ifaces[i]
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagMulticast == 0 {
			continue
		}
		out.Add(iface)
	}
	return out.Slice(), nil
}
