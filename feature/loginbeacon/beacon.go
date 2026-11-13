// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_loginbeacon

// Package loginbeacon lets a Tailscale device with a pending browseToURL
// hand that URL off to an approving node on the same LAN.
// It multicasts a beacon carrying an ephemeral X25519 public key; an
// approving node responds with its own ephemeral key; the requester seals
// its auth URL to the approver, who opens it and drives the normal sign-in
// flow. Both endpoints are OS- and UI-agnostic; the beacon runs on the
// smallest headless appliance and the approver is any node whose client
// implements the protocol.
//
// Version 1 encrypts URL delivery but does not authenticate device identities.
// No security-code exchange is implemented; a hostile LAN participant can race
// an honest approver. Wire layouts are documented in wire.go.
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
	"tailscale.com/feature/loginbeacon/api"
	"tailscale.com/types/logger"
)

// MulticastGroup / MulticastPort are the well-known IPv4 destination for
// beacons. The group is inside 239.255.0.0/16 (RFC 2365, IPv4 Local Scope)
// so packets stay on the link.
var MulticastGroup = net.IPv4(239, 255, 42, 42)

const MulticastPort = 41421

const beaconInterval = 5 * time.Second

// approvalWindow bounds exclusive handling, not the validity of a delivered URL.
const approvalWindow = 60 * time.Second

type Config struct {
	Hostname   string
	DeviceKind string
	DeviceID   string
	AuthURL    func() string
	// OnApproved fires after the first clean URL send in each handling window. It
	// does not prove receipt or authenticate the approver. approverName is
	// untrusted (empty or "localhost" possible); sanitize before display.
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

	mu               sync.Mutex
	sessURL          string
	sessRID          requestID
	cancelToken      [32]byte
	sessKey          ephemeralKey
	sessExpires      time.Time
	approverPub      [32]byte
	sealedReply      []byte // retransmitted only to the selected approver key
	approvalNotified bool
	resumeAt         time.Time // zero while the selected response has not been sent
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
			cfg.Logf("SetMulticastInterface(%s): %v", outIface.Name, err)
		}
	}
	// TTL 1 keeps beacons on-link. Leave MULTICAST_LOOP at its default (on)
	// so both same-host tests and shared-network production work; we don't
	// join the group on the send socket, so we won't process our own frames.
	_ = pc.SetMulticastTTL(1)

	sctx, cancel := context.WithCancel(ctx)
	s := &Sender{
		cfg:      cfg,
		conn:     conn,
		pc:       pc,
		dst:      &net.UDPAddr{IP: MulticastGroup, Port: MulticastPort},
		deviceID: hashDeviceID(cfg.DeviceID),
		outIface: ifaceName(outIface),
		ctx:      sctx,
		cancel:   cancel,
	}
	s.wg.Add(2)
	go s.sendLoop()
	go s.recvLoop()
	cfg.Logf("sender started local=%s dst=%s outIface=%s", conn.LocalAddr(), s.dst, s.outIface)
	return s, nil
}

func (s *Sender) Stop() {
	s.cancel()
	s.mu.Lock()
	s.withdrawLocked()
	s.mu.Unlock()
	s.conn.Close()
	s.wg.Wait()
}

func (s *Sender) sendLoop() {
	defer s.wg.Done()
	defer func() {
		s.mu.Lock()
		s.withdrawLocked()
		s.mu.Unlock()
		s.conn.Close() // unblock recvLoop after the final cancellation send
	}()
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
		s.withdrawLocked()
		s.mu.Unlock()
		return
	}

	m, err := s.getOrStartSession(url)
	if err != nil {
		s.cfg.Logf("session start: %v", err)
		return
	}
	if m == nil {
		return
	} // the request is paused or expired
	pkt, err := marshalBeacon(m)
	if err != nil {
		s.cfg.Logf("marshal beacon: %v", err)
		return
	}
	// Serialize the final eligibility check and send with recipient selection.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessURL == "" || (s.ctx != nil && s.ctx.Err() != nil) || s.sealedReply != nil || s.sessRID != m.RequestID {
		return
	}
	if _, err := s.conn.WriteToUDP(pkt, s.dst); err != nil {
		s.cfg.Logf("send beacon: %v", err)
		return
	}
	s.cfg.Logf("sent beacon rid=%x via %s", m.RequestID[:4], s.outIface)
}

// withdrawLocked sends a best-effort goodbye before retiring the session. A
// short burst tolerates individual lost datagrams; receiver expiry covers a
// lost burst, process death, or a disconnected network.
func (s *Sender) withdrawLocked() {
	if s.sessURL == "" {
		return
	}
	if s.conn != nil && s.dst != nil {
		packet := marshalCancel(s.cancelToken)
		for range 3 {
			if _, err := s.conn.WriteToUDP(packet, s.dst); err != nil {
				s.cfg.Logf("send cancellation: %v", err)
				break
			}
		}
	}
	s.sessKey.zero()
	s.sessURL = ""
	s.sealedReply = nil
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
		if !hasIPv4Address(iface) {
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

func hasIPv4Address(iface net.Interface) bool {
	addrs, _ := iface.Addrs()
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			return true
		}
	}
	return false
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
	if s.ctx != nil && s.ctx.Err() != nil {
		return nil, nil
	}

	if s.sessURL != url {
		var token [32]byte
		if _, err := rand.Read(token[:]); err != nil {
			return nil, err
		}
		k, err := newEphemeralKey()
		if err != nil {
			return nil, err
		}
		s.withdrawLocked()
		rid := cancellationID(token)
		s.cancelToken = token
		s.sessRID = rid
		s.sessKey = k
		s.sessURL = url
		s.sessExpires = time.Now().Add(api.RequestRetention)
		s.approverPub = [32]byte{}
		s.sealedReply = nil
		s.approvalNotified = false
		s.resumeAt = time.Time{}
		s.cfg.Logf("new session rid=%x", rid[:4])
	}

	if !time.Now().Before(s.sessExpires) {
		// Keep sessURL so an unchanged, expired URL cannot start a new session.
		if s.sessKey.priv != ([32]byte{}) {
			url := s.sessURL
			s.withdrawLocked()
			s.sessURL = url
		}
		return nil, nil
	}
	if s.sealedReply != nil {
		// Only a broadcast tick reopens approval, including after a send error.
		if s.resumeAt.IsZero() || time.Now().Before(s.resumeAt) {
			return nil, nil
		}
		s.approverPub = [32]byte{}
		s.sealedReply = nil
		s.approvalNotified = false
		s.resumeAt = time.Time{}
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
	buf := make([]byte, maxWireSize+1)
	for {
		n, src, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			s.cfg.Logf("read: %v", err)
			continue
		}
		if n > maxWireSize {
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
		s.cfg.Logf("bad approval: %v", err)
		return
	}
	if delta := time.Now().Unix() - m.UnixSec; delta > 60 || delta < -60 {
		return
	}

	response, err := s.approvalResponse(m)
	if err != nil {
		s.cfg.Logf("approval rejected: %v", err)
		return
	}
	if response == nil {
		return
	}
	// A clean UDP write does not prove delivery. Keep retries to the selected
	// key available, without extending its handling window on retransmission.
	currentURL := s.cfg.AuthURL()
	s.mu.Lock()
	if currentURL == "" || currentURL != s.sessURL || s.sessRID != rid || s.approverPub != m.ApproverEphPub {
		s.mu.Unlock()
		return
	}
	_, sendErr := s.conn.WriteToUDP(response, src)
	notify := s.finishSendLocked(time.Now(), sendErr)
	s.mu.Unlock()
	if sendErr != nil {
		s.cfg.Logf("send sealed url: %v", sendErr)
		return
	}
	if notify && s.cfg.OnApproved != nil {
		s.cfg.OnApproved(m.ApproverName)
	}
}

// approvalResponse validates and seals before selecting an approver. A malformed
// key must not consume the session. Reusing the sealed bytes permits packet-loss
// retries to the same key without releasing the URL to another approver.
// This remains unauthenticated: a security-code exchange is still required to
// protect against an active LAN participant winning the initial approval race.
func (s *Sender) approvalResponse(m *approvalMsg) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessURL == "" || s.sessRID != m.RequestID || !time.Now().Before(s.sessExpires) {
		return nil, nil
	}
	if s.sealedReply != nil {
		if (!s.resumeAt.IsZero() && !time.Now().Before(s.resumeAt)) || s.approverPub != m.ApproverEphPub {
			return nil, nil
		}
		return s.sealedReply, nil
	}
	sealed, err := sealURL(s.sessKey.priv, m.ApproverEphPub, m.RequestID, s.sessURL)
	if err != nil {
		return nil, err
	}
	response, err := marshalSealedURL(sealed)
	if err != nil {
		return nil, err
	}
	s.approverPub = m.ApproverEphPub
	s.sealedReply = response
	return response, nil
}

// finishSendLocked is called with mu held after attempting URL transmission.
// Even failed sends remain paused until the next broadcast tick.
func (s *Sender) finishSendLocked(now time.Time, err error) (notify bool) {
	if err != nil {
		// Do not release a successful claim because a later retry failed.
		if !s.approvalNotified {
			s.resumeAt = now
		}
		return false
	}
	if s.approvalNotified {
		return false
	}
	s.resumeAt = now.Add(approvalWindow)
	s.approvalNotified = true
	return true
}
