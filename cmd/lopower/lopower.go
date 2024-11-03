// The lopower server is a "Little Opinionated Proxy Over
// Wireguard-Encrypted Route". It bridges a static WireGuard
// client into a Tailscale network.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	qrcode "github.com/skip2/go-qrcode"
	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
	"tailscale.com/net/packet"
	"tailscale.com/net/tsaddr"
	"tailscale.com/syncs"
	"tailscale.com/tsnet"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/must"
	"tailscale.com/wgengine/wgcfg"
)

var (
	wgListenPort   = flag.Int("wg-port", 51820, "port number to listen on for WireGuard from the client")
	confDir        = flag.String("dir", filepath.Join(os.Getenv("HOME"), ".config/lopower"), "directory to store configuration in")
	wgPubHost      = flag.String("wg-host", "0.0.0.1", "IP address of lopower's WireGuard server that's accessible from the client")
	qrListenAddr   = flag.String("qr-listen", "127.0.0.1:8014", "HTTP address to serve a QR code for client's WireGuard configuration, or empty for none")
	printConfig    = flag.Bool("print-config", true, "print the client's WireGuard configuration to stdout on startup")
	includeV4      = flag.Bool("include-v4", true, "include IPv4 (CGNAT) in the WireGuard configuration; incompatible with some carriers. IPv6 is always included.")
	verbosePackets = flag.Bool("verbose-packets", false, "log packet contents")
)

type config struct {
	PrivKey key.NodePrivate // the proxy server's key
	Peers   []Peer

	// V4 and V6 are the local IPs.
	V4 netip.Addr
	V6 netip.Addr

	// CIDRs are used to allocate IPs to peers.
	V4CIDR netip.Prefix
	V6CIDR netip.Prefix
}

// IsLocalIP reports whether ip is one of the local IPs.
func (c *config) IsLocalIP(ip netip.Addr) bool {
	return ip.IsValid() && (ip == c.V4 || ip == c.V6)
}

type Peer struct {
	PrivKey key.NodePrivate // e.g. proxy client's
	V4      netip.Addr
	V6      netip.Addr
}

func (lp *lpServer) storeConfigLocked() {
	path := filepath.Join(lp.dir, "config.json")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		log.Fatalf("os.MkdirAll(%q): %v", filepath.Dir(path), err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("os.OpenFile(%q): %v", path, err)
	}
	defer f.Close()
	must.Do(json.NewEncoder(f).Encode(lp.c))
	if err := f.Close(); err != nil {
		log.Fatalf("f.Close: %v", err)
	}
}

func (lp *lpServer) loadConfig() {
	path := filepath.Join(lp.dir, "config.json")
	f, err := os.Open(path)
	if err == nil {
		defer f.Close()
		var cfg *config
		must.Do(json.NewDecoder(f).Decode(&cfg))
		if len(cfg.Peers) > 0 { // as early version didn't set this
			lp.mu.Lock()
			defer lp.mu.Unlock()
			lp.c = cfg
		}
		return
	}
	if !os.IsNotExist(err) {
		log.Fatalf("os.OpenFile(%q): %v", path, err)
	}
	const defaultV4CIDR = "10.90.0.0/24"
	const defaultV6CIDR = "fd7a:115c:a1e0:9909::/64" // 9909 = above QWERTY "LOPO"(wer)
	c := &config{
		PrivKey: key.NewNode(),
		V4CIDR:  netip.MustParsePrefix(defaultV4CIDR),
		V6CIDR:  netip.MustParsePrefix(defaultV6CIDR),
	}
	c.V4 = c.V4CIDR.Addr().Next()
	c.V6 = c.V6CIDR.Addr().Next()
	c.Peers = append(c.Peers, Peer{
		PrivKey: key.NewNode(),
		V4:      c.V4.Next(),
		V6:      c.V6.Next(),
	})

	lp.mu.Lock()
	defer lp.mu.Unlock()
	lp.c = c
	lp.storeConfigLocked()
	return
}

func (lp *lpServer) reconfig() {
	lp.mu.Lock()
	wc := &wgcfg.Config{
		Name:       "lopower0",
		PrivateKey: lp.c.PrivKey,
		ListenPort: uint16(*wgListenPort),
		Addresses: []netip.Prefix{
			netip.PrefixFrom(lp.c.V4, 32),
			netip.PrefixFrom(lp.c.V6, 128),
		},
	}
	for _, p := range lp.c.Peers {
		wc.Peers = append(wc.Peers, wgcfg.Peer{
			PublicKey: p.PrivKey.Public(),
			AllowedIPs: []netip.Prefix{
				netip.PrefixFrom(p.V4, 32),
				netip.PrefixFrom(p.V6, 128),
			},
		})
	}
	lp.mu.Unlock()
	must.Do(wgcfg.ReconfigDevice(lp.d, wc, log.Printf))
}

func newLP(ctx context.Context) *lpServer {
	logf := log.Printf
	deviceLogger := &device.Logger{
		Verbosef: logger.Discard,
		Errorf:   logf,
	}
	lp := &lpServer{
		ctx:    ctx,
		dir:    *confDir,
		readCh: make(chan *stack.PacketBuffer, 16),
	}
	lp.loadConfig()
	lp.initNetstack(ctx)
	nst := &nsTUN{
		lp:      lp,
		closeCh: make(chan struct{}),
		evChan:  make(chan tun.Event),
	}

	wgdev := wgcfg.NewDevice(nst, conn.NewDefaultBind(), deviceLogger)
	lp.d = wgdev
	must.Do(wgdev.Up())
	lp.reconfig()

	if *printConfig {
		log.Printf("Device Wireguard config is:\n%s", lp.wgConfigForQR())
	}

	lp.startTSNet(ctx)
	return lp
}

type lpServer struct {
	dir    string
	tsnet  *tsnet.Server
	d      *device.Device
	ns     *stack.Stack
	ctx    context.Context // canceled on shutdown
	linkEP *channel.Endpoint
	readCh chan *stack.PacketBuffer // from gvisor/dns server => out to network

	// protocolConns tracks the number of active connections for each connection.
	// It is used to add and remove protocol addresses from netstack as needed.
	protocolConns syncs.Map[tcpip.ProtocolAddress, *atomic.Int32]

	mu sync.Mutex // protects following
	c  *config
}

// MaxPacketSize is the maximum size (in bytes)
// of a packet that can be injected into lpServer.
const MaxPacketSize = device.MaxContentSize
const nicID = 1

func (lp *lpServer) initNetstack(ctx context.Context) error {
	ns := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			icmp.NewProtocol4,
			udp.NewProtocol,
		},
	})
	lp.ns = ns
	sackEnabledOpt := tcpip.TCPSACKEnabled(true) // TCP SACK is disabled by default
	if tcpipErr := ns.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabledOpt); tcpipErr != nil {
		return fmt.Errorf("SetTransportProtocolOption SACK: %v", tcpipErr)
	}
	lp.linkEP = channel.New(512, 1280, "")
	if tcpipProblem := ns.CreateNIC(nicID, lp.linkEP); tcpipProblem != nil {
		return fmt.Errorf("CreateNIC: %v", tcpipProblem)
	}
	ns.SetPromiscuousMode(nicID, true)

	lp.mu.Lock()
	v4, v6 := lp.c.V4, lp.c.V6
	lp.mu.Unlock()
	prefix := tcpip.AddrFrom4Slice(v4.AsSlice()).WithPrefix()
	if *includeV4 {
		if tcpProb := ns.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
			Protocol:          ipv4.ProtocolNumber,
			AddressWithPrefix: prefix,
		}, stack.AddressProperties{}); tcpProb != nil {
			return errors.New(tcpProb.String())
		}
	}
	prefix = tcpip.AddrFrom16Slice(v6.AsSlice()).WithPrefix()
	if tcpProb := ns.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol:          ipv6.ProtocolNumber,
		AddressWithPrefix: prefix,
	}, stack.AddressProperties{}); tcpProb != nil {
		return errors.New(tcpProb.String())
	}

	ipv4Subnet, err := tcpip.NewSubnet(tcpip.AddrFromSlice(make([]byte, 4)), tcpip.MaskFromBytes(make([]byte, 4)))
	if err != nil {
		return fmt.Errorf("could not create IPv4 subnet: %v", err)
	}
	ipv6Subnet, err := tcpip.NewSubnet(tcpip.AddrFromSlice(make([]byte, 16)), tcpip.MaskFromBytes(make([]byte, 16)))
	if err != nil {
		return fmt.Errorf("could not create IPv6 subnet: %v", err)
	}

	routes := []tcpip.Route{{
		Destination: ipv4Subnet,
		NIC:         nicID,
	}, {
		Destination: ipv6Subnet,
		NIC:         nicID,
	}}
	if !*includeV4 {
		routes = routes[1:]
	}

	ns.SetRouteTable(routes)

	const tcpReceiveBufferSize = 0 // default
	const maxInFlightConnectionAttempts = 8192
	tcpFwd := tcp.NewForwarder(ns, tcpReceiveBufferSize, maxInFlightConnectionAttempts, lp.acceptTCP)
	udpFwd := udp.NewForwarder(ns, lp.acceptUDP)
	ns.SetTransportProtocolHandler(tcp.ProtocolNumber, func(tei stack.TransportEndpointID, pb *stack.PacketBuffer) (handled bool) {
		return tcpFwd.HandlePacket(tei, pb)
	})
	ns.SetTransportProtocolHandler(udp.ProtocolNumber, func(tei stack.TransportEndpointID, pb *stack.PacketBuffer) (handled bool) {
		return udpFwd.HandlePacket(tei, pb)
	})

	go func() {
		for {
			pkt := lp.linkEP.ReadContext(ctx)
			if pkt == nil {
				if ctx.Err() != nil {
					// Return without logging.
					log.Printf("linkEP.ReadContext: %v", ctx.Err())
					return
				}
				continue
			}
			size := pkt.Size()
			if size > MaxPacketSize || size == 0 {
				pkt.DecRef()
				continue
			}
			select {
			case lp.readCh <- pkt:
			case <-ctx.Done():
			}
		}
	}()
	return nil
}

func netaddrIPFromNetstackIP(s tcpip.Address) netip.Addr {
	switch s.Len() {
	case 4:
		return netip.AddrFrom4(s.As4())
	case 16:
		return netip.AddrFrom16(s.As16()).Unmap()
	}
	return netip.Addr{}
}

func (lp *lpServer) trackProtocolAddr(destIP netip.Addr) (untrack func()) {
	pa := tcpip.ProtocolAddress{
		AddressWithPrefix: tcpip.AddrFromSlice(destIP.AsSlice()).WithPrefix(),
	}
	if destIP.Is4() {
		pa.Protocol = ipv4.ProtocolNumber
	} else if destIP.Is6() {
		pa.Protocol = ipv6.ProtocolNumber
	}

	addrConns, _ := lp.protocolConns.LoadOrInit(pa, func() *atomic.Int32 { return new(atomic.Int32) })
	if addrConns.Add(1) == 1 {
		lp.ns.AddProtocolAddress(nicID, pa, stack.AddressProperties{
			PEB:        stack.CanBePrimaryEndpoint, // zero value default
			ConfigType: stack.AddressConfigStatic,  // zero value default
		})
	}
	return func() {
		if addrConns.Add(-1) == 0 {
			lp.ns.RemoveAddress(nicID, pa.AddressWithPrefix.Address)
		}
	}
}

func (lp *lpServer) acceptUDP(r *udp.ForwarderRequest) {
	log.Printf("acceptUDP: %v", r.ID())
	destIP := netaddrIPFromNetstackIP(r.ID().LocalAddress)
	untrack := lp.trackProtocolAddr(destIP)
	var wq waiter.Queue
	ep, udpErr := r.CreateEndpoint(&wq)
	if udpErr != nil {
		log.Printf("CreateEndpoint: %v", udpErr)
		return
	}
	go func() {
		defer untrack()
		defer ep.Close()
		reqDetails := r.ID()

		clientRemoteIP := netaddrIPFromNetstackIP(reqDetails.RemoteAddress)
		destPort := reqDetails.LocalPort
		if !clientRemoteIP.IsValid() {
			log.Printf("acceptUDP: invalid remote IP %v", reqDetails.RemoteAddress)
			return
		}

		randPort := rand.IntN(65536-1024) + 1024
		v4, v6 := lp.tsnet.TailscaleIPs()
		var listenAddr netip.Addr
		if destIP.Is4() {
			listenAddr = v4
		} else {
			listenAddr = v6
		}
		backendConn, err := lp.tsnet.ListenPacket("udp", fmt.Sprintf("%s:%d", listenAddr, randPort))
		if err != nil {
			log.Printf("ListenPacket: %v", err)
			return
		}
		defer backendConn.Close()
		clientConn := gonet.NewUDPConn(&wq, ep)
		defer clientConn.Close()
		errCh := make(chan error, 2)
		go func() (err error) {
			defer func() { errCh <- err }()
			var buf [64]byte
			for {
				n, _, err := backendConn.ReadFrom(buf[:])
				if err != nil {
					log.Printf("UDP read: %v", err)
					return err
				}
				_, err = clientConn.Write(buf[:n])
				if err != nil {
					return err
				}
			}
		}()
		dstAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", destIP, destPort))
		if err != nil {
			log.Printf("ResolveUDPAddr: %v", err)
			return
		}
		go func() (err error) {
			defer func() { errCh <- err }()
			var buf [2048]byte
			for {
				n, err := clientConn.Read(buf[:])
				if err != nil {
					log.Printf("UDP read: %v", err)
					return err
				}
				_, err = backendConn.WriteTo(buf[:n], dstAddr)
				if err != nil {
					return err
				}
			}
		}()
		err = <-errCh
		if err != nil {
			log.Printf("io.Copy: %v", err)
		}
	}()
}

func (lp *lpServer) acceptTCP(r *tcp.ForwarderRequest) {
	log.Printf("acceptTCP: %v", r.ID())
	reqDetails := r.ID()
	destIP := netaddrIPFromNetstackIP(reqDetails.LocalAddress)
	clientRemoteIP := netaddrIPFromNetstackIP(reqDetails.RemoteAddress)
	destPort := reqDetails.LocalPort
	if !clientRemoteIP.IsValid() {
		log.Printf("acceptTCP: invalid remote IP %v", reqDetails.RemoteAddress)
		r.Complete(true) // sends a RST
		return
	}
	untrack := lp.trackProtocolAddr(destIP)
	defer untrack()

	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
		log.Printf("CreateEndpoint: %v", tcpErr)
		r.Complete(true)
		return
	}
	defer ep.Close()
	ep.SocketOptions().SetKeepAlive(true)

	dialCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	c, err := lp.tsnet.Dial(dialCtx, "tcp", fmt.Sprintf("%s:%d", destIP, destPort))
	cancel()
	if err != nil {
		log.Printf("Dial(%s:%d): %v", destIP, destPort, err)
		r.Complete(true) // sends a RST
		return
	}
	defer c.Close()

	tc := gonet.NewTCPConn(&wq, ep)
	defer tc.Close()
	r.Complete(false)

	if destPort == 53 && lp.c.IsLocalIP(destIP) {
		// TODO(bradfitz,maisem): do TCP DNS server here.
		// ...
	}

	errc := make(chan error, 2)
	go func() { _, err := io.Copy(tc, c); errc <- err }()
	go func() { _, err := io.Copy(c, tc); errc <- err }()
	err = <-errc
	if err != nil {
		log.Printf("io.Copy: %v", err)
	}
}

func (lp *lpServer) wgConfigForQR() string {
	var b strings.Builder

	p := lp.c.Peers[0]
	privHex, _ := p.PrivKey.MarshalText()
	privHex = bytes.TrimPrefix(privHex, []byte("privkey:"))
	priv := make([]byte, 32)
	got, err := hex.Decode(priv, privHex)
	if err != nil || got != 32 {
		log.Printf("marshal text was: %q", privHex)
		log.Fatalf("bad private key: %v, % bytes", err, got)
	}
	privb64 := base64.StdEncoding.EncodeToString(priv)

	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\n", privb64)
	fmt.Fprintf(&b, "Address = %v,%v\n", p.V6, p.V4)

	pubBin, _ := lp.c.PrivKey.Public().MarshalBinary()
	if len(pubBin) != 34 {
		log.Fatalf("bad pubkey length: %d", len(pubBin))
	}
	pubBin = pubBin[2:] // trim off "np"
	pubb64 := base64.StdEncoding.EncodeToString(pubBin)

	fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %v\n", pubb64)
	if *includeV4 {
		fmt.Fprintf(&b, "AllowedIPs = %v/32,%v/128,%v,%v\n", lp.c.V4, lp.c.V6, tsaddr.TailscaleULARange(), tsaddr.CGNATRange())
	} else {
		fmt.Fprintf(&b, "AllowedIPs = %v/128,%v\n", lp.c.V6, tsaddr.TailscaleULARange())
	}
	fmt.Fprintf(&b, "Endpoint = %v\n", net.JoinHostPort(*wgPubHost, fmt.Sprint(*wgListenPort)))

	return b.String()
}

func (lp *lpServer) serveQR() {
	ln, err := net.Listen("tcp", *qrListenAddr)
	if err != nil {
		log.Fatalf("qr: %v", err)
	}
	log.Printf("# Serving QR code at http://%s/", ln.Addr())
	hs := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "image/png")
			conf := lp.wgConfigForQR()
			v, err := qrcode.Encode(conf, qrcode.Medium, 512)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Write(v)
		}),
	}
	if err := hs.Serve(ln); err != nil {
		log.Fatalf("qr: %v", err)
	}
}

type nsTUN struct {
	lp      *lpServer
	closeCh chan struct{}
	evChan  chan tun.Event
}

func (t *nsTUN) File() *os.File {
	panic("nsTUN.File() called, which makes no sense")
}

func (t *nsTUN) Close() error {
	close(t.closeCh)
	close(t.evChan)
	return nil
}

// Read reads packets from gvisor (or the DNS server) to send out to the network.
func (t *nsTUN) Read(out [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-t.closeCh:
		return 0, io.EOF
	case resPacket := <-t.lp.readCh:
		defer resPacket.DecRef()
		pkt := out[0][offset:]
		n := copy(pkt, resPacket.NetworkHeader().Slice())
		n += copy(pkt[n:], resPacket.TransportHeader().Slice())
		n += copy(pkt[n:], resPacket.Data().AsRange().ToSlice())
		if *verbosePackets {
			log.Printf("[v] nsTUN.Read (out): % 02x", pkt[:n])
		}
		sizes[0] = n
		return 1, nil
	}
}

// Write accepts incoming packets. The packets begin at buffs[:][offset:],
// like wireguard-go/tun.Device.Write. Write is called per-peer via
// wireguard-go/device.Peer.RoutineSequentialReceiver, so it MUST be
// thread-safe.
func (t *nsTUN) Write(buffs [][]byte, offset int) (int, error) {
	var pkt packet.Parsed
	for _, buff := range buffs {
		raw := buff[offset:]
		pkt.Decode(raw)
		packetBuf := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(slices.Clone(raw)),
		})
		if *verbosePackets {
			log.Printf("[v] nsTUN.Write (in): % 02x", raw)
		}
		if pkt.IPProto == ipproto.UDP && pkt.Dst.Port() == 53 && t.lp.c.IsLocalIP(pkt.Dst.Addr()) {
			// Handle DNS queries before sending to gvisor.
			t.lp.handleDNSUDPQuery(raw)
			continue
		}
		if pkt.IPVersion == 4 {
			t.lp.linkEP.InjectInbound(ipv4.ProtocolNumber, packetBuf)
		} else if pkt.IPVersion == 6 {
			t.lp.linkEP.InjectInbound(ipv6.ProtocolNumber, packetBuf)
		}
	}
	return len(buffs), nil
}

func (t *nsTUN) Flush() error             { return nil }
func (t *nsTUN) MTU() (int, error)        { return 1500, nil }
func (t *nsTUN) Name() (string, error)    { return "nstun", nil }
func (t *nsTUN) Events() <-chan tun.Event { return t.evChan }
func (t *nsTUN) BatchSize() int           { return 1 }

func (lp *lpServer) startTSNet(ctx context.Context) {
	hostname, err := os.Hostname()
	if err != nil {
		log.Fatal(err)
	}

	ts := &tsnet.Server{
		Dir:       filepath.Join(lp.dir, "tsnet"),
		Hostname:  hostname,
		UserLogf:  log.Printf,
		Ephemeral: false,
	}
	lp.tsnet = ts
	ts.PreStart = func() error {
		dnsMgr := ts.Sys().DNSManager.Get()
		dnsMgr.SetForceAAAA(true)

		// Force fallback resolvers to Google and Cloudflare as an ultimate
		// fallback in case the Tailnet DNS servers are not set/forced. Normally
		// tailscaled would resort to using the OS DNS resolvers, but
		// tsnet/userspace binaries don't do that (yet?), so this is the
		// "Opionated" part of the "LOPOWER" name. The opinion is just using
		// big providers known to work. (Normally stock tailscaled never
		// makes such opinions and never defaults to any big provider, unless
		// you're already running on that big provider's network so have
		// already indicated you're fine with them.))
		dnsMgr.SetForceFallbackResolvers([]*dnstype.Resolver{
			{Addr: "8.8.8.8"},
			{Addr: "1.1.1.1"},
		})
		return nil
	}

	if _, err := ts.Up(ctx); err != nil {
		log.Fatal(err)
	}
}

// filteredDNSQuery wraps the MagicDNS server response but filters out A record responses
// for *.ts.net if IPv4 is not enabled. This is so the e.g. a phone on a CGNAT-using
// network doesn't prefer the "A" record over AAAA when dialing and dial into the
// the carrier's CGNAT range into of the AAAA record into the Tailscale IPv6 ULA range.
func (lp *lpServer) filteredDNSQuery(ctx context.Context, q []byte, family string, from netip.AddrPort) ([]byte, error) {
	m, ok := lp.tsnet.Sys().DNSManager.GetOK()
	if !ok {
		return nil, errors.New("DNSManager not ready")
	}
	origRes, err := m.Query(ctx, q, family, from)
	if err != nil {
		return nil, err
	}
	if *includeV4 {
		return origRes, nil
	}

	// Filter out *.ts.net A records.

	var msg dnsmessage.Message
	if err := msg.Unpack(origRes); err != nil {
		return nil, err
	}
	newAnswers := msg.Answers[:0]
	for _, a := range msg.Answers {
		name := a.Header.Name.String()
		if a.Header.Type == dnsmessage.TypeA && strings.HasSuffix(name, ".ts.net.") {
			// Drop.
			continue
		}
		newAnswers = append(newAnswers, a)
	}

	if len(newAnswers) == len(msg.Answers) {
		// Nothing was filtered. No need to reencode it.
		return origRes, nil
	}

	msg.Answers = newAnswers
	return msg.Pack()
}

// caller owns the raw memory.
func (lp *lpServer) handleDNSUDPQuery(raw []byte) {
	var pkt packet.Parsed
	pkt.Decode(raw)
	if pkt.IPProto != ipproto.UDP || pkt.Dst.Port() != 53 || !lp.c.IsLocalIP(pkt.Dst.Addr()) {
		panic("caller error")
	}

	dnsRes, err := lp.filteredDNSQuery(context.Background(), pkt.Payload(), "udp", pkt.Src)
	if err != nil {
		log.Printf("DNS query error: %v", err)
		return
	}

	ipLayer := mkIPLayer(layers.IPProtocolUDP, pkt.Dst.Addr(), pkt.Src.Addr())
	udpLayer := &layers.UDP{
		SrcPort: 53,
		DstPort: layers.UDPPort(pkt.Src.Port()),
	}

	resPkt, err := mkPacket(ipLayer, udpLayer, gopacket.Payload(dnsRes))
	if err != nil {
		log.Printf("mkPacket: %v", err)
		return
	}
	pktBuf := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(resPkt),
	})
	select {
	case lp.readCh <- pktBuf:
	case <-lp.ctx.Done():
	}
}

type serializableNetworkLayer interface {
	gopacket.SerializableLayer
	gopacket.NetworkLayer
}

func mkIPLayer(proto layers.IPProtocol, src, dst netip.Addr) serializableNetworkLayer {
	if src.Is4() {
		return &layers.IPv4{
			Protocol: proto,
			SrcIP:    src.AsSlice(),
			DstIP:    dst.AsSlice(),
		}
	}
	if src.Is6() {
		return &layers.IPv6{
			NextHeader: proto,
			SrcIP:      src.AsSlice(),
			DstIP:      dst.AsSlice(),
		}
	}
	panic("invalid src IP")
}

// mkPacket is a serializes a number of layers into a packet.
//
// It's a convenience wrapper around gopacket.SerializeLayers
// that does some things automatically:
//
// * layers.IPv4/IPv6 Version is set to 4/6 if not already set
// * layers.IPv4/IPv6 TTL/HopLimit is set to 64 if not already set
// * the TCP/UDP/ICMPv6 checksum is set based on the network layer
//
// The provided layers in ll must be sorted from lowest (e.g. *layers.Ethernet)
// to highest. (Depending on the need, the first layer will be either *layers.Ethernet
// or *layers.IPv4/IPv6).
func mkPacket(ll ...gopacket.SerializableLayer) ([]byte, error) {
	var nl gopacket.NetworkLayer
	for _, la := range ll {
		switch la := la.(type) {
		case *layers.IPv4:
			nl = la
			if la.Version == 0 {
				la.Version = 4
			}
			if la.TTL == 0 {
				la.TTL = 64
			}
		case *layers.IPv6:
			nl = la
			if la.Version == 0 {
				la.Version = 6
			}
			if la.HopLimit == 0 {
				la.HopLimit = 64
			}
		}
	}
	for _, la := range ll {
		switch la := la.(type) {
		case *layers.TCP:
			la.SetNetworkLayerForChecksum(nl)
		case *layers.UDP:
			la.SetNetworkLayerForChecksum(nl)
		case *layers.ICMPv6:
			la.SetNetworkLayerForChecksum(nl)
		}
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ll...); err != nil {
		return nil, fmt.Errorf("serializing packet: %v", err)
	}
	return buf.Bytes(), nil
}

func main() {
	flag.Parse()
	log.Printf("lopower starting")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	lp := newLP(ctx)

	if *qrListenAddr != "" {
		go lp.serveQR()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, unix.SIGTERM, os.Interrupt)
	<-sigCh
}
