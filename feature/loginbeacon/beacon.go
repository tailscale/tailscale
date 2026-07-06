// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_loginbeacon

// Package loginbeacon lets a Tailscale device with a pending browseToURL
// hand that URL off to any already-authenticated node on the same LAN.
// It multicasts a beacon carrying an ephemeral X25519 public key; an
// approving node responds with its own ephemeral key; the requester seals
// its auth URL to the approver, who opens it and drives the normal sign-in
// flow. Both endpoints are OS- and UI-agnostic; the beacon runs on the
// smallest headless appliance and the approver is any node whose client
// implements the protocol.
//
// Wire format, discovery, and threat model are in wire.go.
package loginbeacon

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
	"tailscale.com/types/logger"
)

// MulticastGroup / MulticastPort are the well-known IPv4 destination for
// beacons. The group is inside 239.255.0.0/16 (RFC 2365, IPv4 Local Scope)
// so packets stay on the link.
var MulticastGroup = net.IPv4(239, 255, 42, 42)

const MulticastPort = 41421

const beaconInterval = 5 * time.Second

type Config struct {
	Hostname   string
	DeviceKind string
	DeviceID   string
	AuthURL    func() string
	// OnApproved fires once when the sender has sealed the auth URL to a
	// valid approver. approverName is untrusted (empty or "localhost"
	// possible); callers must sanitize before display.
	OnApproved func(approverName string)
	Logf       logger.Logf
}

type Sender struct {
	cfg      Config
	conn     *net.UDPConn
	pc       *ipv4.PacketConn
	dst      *net.UDPAddr
	deviceID [16]byte
	outIface string

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu           sync.Mutex
	sessURL      string
	sessRID      requestID
	sessKey      ephemeralKey
	approvedRIDs map[requestID]bool
}

func Start(ctx context.Context, cfg Config) (*Sender, error) {
	if cfg.AuthURL == nil {
		return nil, errors.New("loginbeacon: Config.AuthURL is required")
	}
	if cfg.Logf == nil {
		return nil, errors.New("loginbeacon: Config.Logf is required")
	}
	if len(cfg.Hostname) > maxHostname {
		cfg.Hostname = cfg.Hostname[:maxHostname]
	}
	if len(cfg.DeviceKind) > maxDeviceKind {
		cfg.DeviceKind = cfg.DeviceKind[:maxDeviceKind]
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("loginbeacon: opening UDP socket: %w", err)
	}
	pc := ipv4.NewPacketConn(conn)
	// Inside a packet-tunnel network extension, the default outbound route
	// is the tunnel's utun interface. Force multicast onto a physical LAN
	// interface so beacons reach the wire.
	outIface := pickPhysicalMulticastInterface()
	if outIface != nil {
		if err := pc.SetMulticastInterface(outIface); err != nil {
			cfg.Logf("loginbeacon: SetMulticastInterface(%s): %v", outIface.Name, err)
		}
	}
	// TTL 1 keeps beacons on-link. Leave MULTICAST_LOOP at its default (on)
	// so both same-host tests and shared-network production work; we don't
	// join the group on the send socket, so we won't process our own frames.
	_ = pc.SetMulticastTTL(1)

	sctx, cancel := context.WithCancel(ctx)
	s := &Sender{
		cfg:          cfg,
		conn:         conn,
		pc:           pc,
		dst:          &net.UDPAddr{IP: MulticastGroup, Port: MulticastPort},
		deviceID:     hashDeviceID(cfg.DeviceID),
		outIface:     ifaceName(outIface),
		ctx:          sctx,
		cancel:       cancel,
		approvedRIDs: make(map[requestID]bool),
	}
	s.wg.Add(2)
	go s.sendLoop()
	go s.recvLoop()
	cfg.Logf("loginbeacon: sender started local=%s dst=%s outIface=%s", conn.LocalAddr(), s.dst, s.outIface)
	return s, nil
}

func (s *Sender) Stop() {
	s.cancel()
	s.conn.Close()
	s.wg.Wait()

	s.mu.Lock()
	s.sessKey.zero()
	s.sessURL = ""
	s.mu.Unlock()
}

func (s *Sender) sendLoop() {
	defer s.wg.Done()
	t := time.NewTicker(beaconInterval)
	defer t.Stop()

	s.tick() // don't make approvers wait a full interval for the first packet
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
			s.tick()
		}
	}
}

func (s *Sender) tick() {
	url := s.cfg.AuthURL()
	if url == "" {
		s.mu.Lock()
		if s.sessURL != "" {
			s.sessKey.zero()
			s.sessURL = ""
		}
		s.mu.Unlock()
		return
	}

	m, err := s.getOrStartSession(url)
	if err != nil {
		s.cfg.Logf("loginbeacon: session start: %v", err)
		return
	}
	pkt, err := marshalBeacon(m)
	if err != nil {
		s.cfg.Logf("loginbeacon: marshal beacon: %v", err)
		return
	}
	if _, err := s.conn.WriteToUDP(pkt, s.dst); err != nil {
		s.cfg.Logf("loginbeacon: send beacon: %v", err)
		return
	}
	s.cfg.Logf("loginbeacon: sent beacon rid=%x via %s", m.RequestID[:4], s.outIface)
}

// pickPhysicalMulticastInterface returns the "best" LAN interface for
// multicast egress, excluding tunnel-like devices (utunN, tunN, ppp) and
// AWDL. Returns nil if none is suitable; the kernel default is used then.
func pickPhysicalMulticastInterface() *net.Interface {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var best *net.Interface
	for i := range ifs {
		iface := ifs[i]
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagMulticast == 0 {
			continue
		}
		name := iface.Name
		if name == "lo0" || name == "lo" {
			continue
		}
		if strings.HasPrefix(name, "utun") || strings.HasPrefix(name, "tun") ||
			strings.HasPrefix(name, "ppp") || strings.HasPrefix(name, "awdl") {
			continue
		}
		addrs, _ := iface.Addrs()
		hasV4 := false
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				hasV4 = true
				break
			}
		}
		if !hasV4 {
			continue
		}
		// Prefer en0/eth0-like names when possible; otherwise take the first
		// suitable interface.
		if strings.HasPrefix(name, "en") || strings.HasPrefix(name, "eth") ||
			strings.HasPrefix(name, "wlan") {
			b := iface
			return &b
		}
		if best == nil {
			b := iface
			best = &b
		}
	}
	return best
}

func ifaceName(i *net.Interface) string {
	if i == nil {
		return "default"
	}
	return i.Name
}

// getOrStartSession rotates the request ID and ephemeral keypair whenever
// AuthURL changes, so crypto material never outlives the URL that authorized it.
func (s *Sender) getOrStartSession(url string) (*beaconMsg, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sessURL != url {
		var rid requestID
		if _, err := rand.Read(rid[:]); err != nil {
			return nil, err
		}
		k, err := newEphemeralKey()
		if err != nil {
			return nil, err
		}
		s.sessKey.zero()
		s.sessRID = rid
		s.sessKey = k
		s.sessURL = url
		s.cfg.Logf("loginbeacon: new session rid=%x", rid[:4])
	}

	return &beaconMsg{
		RequestID:    s.sessRID,
		SenderEphPub: s.sessKey.pub,
		UnixSec:      time.Now().Unix(),
		Hostname:     s.cfg.Hostname,
		DeviceKind:   s.cfg.DeviceKind,
		DeviceIDHash: s.deviceID,
	}, nil
}

func (s *Sender) recvLoop() {
	defer s.wg.Done()
	buf := make([]byte, maxWireSize)
	for {
		n, src, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			s.cfg.Logf("loginbeacon: read: %v", err)
			continue
		}
		s.handlePacket(buf[:n], src)
	}
}

func (s *Sender) handlePacket(pkt []byte, src *net.UDPAddr) {
	t, rid, err := parseHeader(pkt)
	if err != nil {
		return
	}
	if t != msgTypeApproval {
		return
	}

	m, err := parseApproval(pkt)
	if err != nil {
		s.cfg.Logf("loginbeacon: bad approval: %v", err)
		return
	}
	if delta := time.Now().Unix() - m.UnixSec; delta > 60 || delta < -60 {
		return
	}

	s.mu.Lock()
	if s.sessURL == "" || s.sessRID != rid {
		s.mu.Unlock()
		return
	}
	if s.approvedRIDs[rid] {
		// SECURITY: first-approval-wins per session. Anyone on the LAN who
		// sees the beacon can race to send a fake approval; if the honest
		// approver wins, this fake is dropped. If the attacker wins, the
		// honest approver never gets a decryptable URL and the user retries.
		s.mu.Unlock()
		return
	}
	url := s.sessURL
	priv := s.sessKey.priv
	s.approvedRIDs[rid] = true
	s.mu.Unlock()

	sealed, err := sealURL(priv, m.ApproverEphPub, rid, url)
	if err != nil {
		s.cfg.Logf("loginbeacon: seal url: %v", err)
		return
	}
	pkt2, err := marshalSealedURL(sealed)
	if err != nil {
		s.cfg.Logf("loginbeacon: marshal sealed: %v", err)
		return
	}
	if _, err := s.conn.WriteToUDP(pkt2, src); err != nil {
		s.cfg.Logf("loginbeacon: send sealed url: %v", err)
		return
	}
	s.cfg.Logf("loginbeacon: sent sealed url to %s (rid=%x approver=%q)", src, rid[:4], m.ApproverName)
	if s.cfg.OnApproved != nil {
		s.cfg.OnApproved(m.ApproverName)
	}
}
