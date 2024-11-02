// The lopower server is a "Little Opinionated Proxy Over
// Wireguard-Encrypted Route". It bridges a static WireGuard
// client into a Tailscale network.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"tailscale.com/net/packet"
	"tailscale.com/tsnet"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/must"
	"tailscale.com/wgengine/wgcfg"
)

var (
	wgListenAddr = flag.String("wg-listen", ":51820", "address to listen on for WireGuard from the client")
	qrListenAddr = flag.String("qr-listen", "127.0.0.1:8014", "HTTP address to serve a QR code for client's WireGuard configuration")
)

type config struct {
	PrivKey key.NodePrivate
	Peers   []Peer

	// V4 and V6 are the local IPs.
	V4 netip.Addr
	V6 netip.Addr

	// CIDRs are used to allocate IPs to peers.
	V4CIDR netip.Prefix
	V6CIDR netip.Prefix
}

type Peer struct {
	PubKey key.NodePublic
	V4     netip.Addr
	V6     netip.Addr
}

func storeConfig(cfg *config) {
	path := filepath.Join(os.Getenv("HOME"), ".config/lopower/config.json")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		log.Fatalf("os.MkdirAll(%q): %v", filepath.Dir(path), err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("os.OpenFile(%q): %v", path, err)
	}
	defer f.Close()
	must.Do(json.NewEncoder(f).Encode(cfg))
	if err := f.Close(); err != nil {
		log.Fatalf("f.Close: %v", err)
	}
}

func loadConfig() *config {
	path := filepath.Join(os.Getenv("HOME"), ".config/lopower/config.json")
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err == nil {
		var cfg *config
		must.Do(json.NewDecoder(f).Decode(&cfg))
		return cfg
	}
	if !os.IsNotExist(err) {
		log.Fatalf("os.OpenFile(%q): %v", path, err)
	}
	const defaultV4CIDR = "10.90.0.0/24"
	const defaultV6CIDR = "fd7a:115c:a1e0:1900::/64"
	c := &config{
		PrivKey: key.NewNode(),
		V4CIDR:  netip.MustParsePrefix(defaultV4CIDR),
		V6CIDR:  netip.MustParsePrefix(defaultV6CIDR),
	}
	c.V4 = c.V4CIDR.Addr().Next()
	c.V6 = c.V6CIDR.Addr().Next()
	storeConfig(c)
	return c
}

func (lp *lpServer) reconfig() {
	wc := &wgcfg.Config{
		Name:       "lopower0",
		PrivateKey: lp.c.PrivKey,
		Addresses: []netip.Prefix{
			netip.PrefixFrom(lp.c.V4, 32),
			netip.PrefixFrom(lp.c.V6, 128),
		},
	}
	for _, p := range lp.c.Peers {
		wc.Peers = append(wc.Peers, wgcfg.Peer{
			PublicKey: p.PubKey,
			AllowedIPs: []netip.Prefix{
				netip.PrefixFrom(p.V4, 32),
				netip.PrefixFrom(p.V6, 128),
			},
		})
	}
	must.Do(wgcfg.ReconfigDevice(lp.d, wc, log.Printf))
}

type lpServer struct {
	c      *config
	d      *device.Device
	ns     *stack.Stack
	linkEP *channel.Endpoint
}

// MaxPacketSize is the maximum size (in bytes)
// of a packet that can be injected into lpServer.
const MaxPacketSize = device.MaxContentSize

func (lp *lpServer) initNetstack(ctx context.Context) error {
	ns := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
			arp.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			icmp.NewProtocol4,
		},
	})
	sackEnabledOpt := tcpip.TCPSACKEnabled(true) // TCP SACK is disabled by default
	tcpipErr := ns.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabledOpt)
	if tcpipErr != nil {
		return fmt.Errorf("SetTransportProtocolOption SACK: %v", tcpipErr)
	}
	lp.linkEP = channel.New(512, 1280, "")
	const nicID = 1
	if tcpipProblem := ns.CreateNIC(nicID, lp.linkEP); tcpipProblem != nil {
		return fmt.Errorf("CreateNIC: %v", tcpipProblem)
	}
	ns.SetPromiscuousMode(nicID, true)
	ns.SetSpoofing(nicID, true)

	var routes []tcpip.Route

	{
		prefix := tcpip.AddrFrom4Slice(lp.c.V4.AsSlice()).WithPrefix()
		if tcpProb := ns.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
			Protocol:          ipv4.ProtocolNumber,
			AddressWithPrefix: prefix,
		}, stack.AddressProperties{}); tcpProb != nil {
			return errors.New(tcpProb.String())
		}

		ipv4Subnet, err := tcpip.NewSubnet(tcpip.AddrFromSlice(make([]byte, 4)), tcpip.MaskFromBytes(make([]byte, 4)))
		if err != nil {
			return fmt.Errorf("could not create IPv4 subnet: %v", err)
		}
		routes = append(routes, tcpip.Route{
			Destination: ipv4Subnet,
			NIC:         nicID,
		})
	}
	{
		prefix := tcpip.AddrFrom16(lp.c.V6.As16()).WithPrefix()
		if tcpProb := ns.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
			Protocol:          ipv6.ProtocolNumber,
			AddressWithPrefix: prefix,
		}, stack.AddressProperties{}); tcpProb != nil {
			return errors.New(tcpProb.String())
		}

		ipv6Subnet, err := tcpip.NewSubnet(tcpip.AddrFromSlice(make([]byte, 16)), tcpip.MaskFromBytes(make([]byte, 16)))
		if err != nil {
			return fmt.Errorf("could not create IPv6 subnet: %v", err)
		}
		routes = append(routes, tcpip.Route{
			Destination: ipv6Subnet,
			NIC:         nicID,
		})
	}

	ns.SetRouteTable(routes)

	const tcpReceiveBufferSize = 0 // default
	const maxInFlightConnectionAttempts = 8192
	tcpFwd := tcp.NewForwarder(ns, tcpReceiveBufferSize, maxInFlightConnectionAttempts, lp.acceptTCP)
	ns.SetTransportProtocolHandler(tcp.ProtocolNumber, func(tei stack.TransportEndpointID, pb *stack.PacketBuffer) (handled bool) {
		return tcpFwd.HandlePacket(tei, pb)
	})

	go func() {
		for {
			pkt := lp.linkEP.ReadContext(ctx)
			if pkt == nil {
				if ctx.Err() != nil {
					// Return without logging.
					return
				}
				continue
			}
			size := pkt.Size()
			if size > MaxPacketSize || size == 0 {
				pkt.DecRef()
				continue
			}
		}
	}()
	return nil
}

func (lp *lpServer) acceptTCP(*tcp.ForwarderRequest) {
	// TODO
}

type nsTUN struct {
	lp      *lpServer
	closeCh chan struct{}
	readCh  chan *stack.PacketBuffer
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

func (t *nsTUN) Read(out [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-t.closeCh:
		return 0, io.EOF
	case resPacket := <-t.readCh:
		defer resPacket.DecRef()
		pkt := out[0][offset:]
		n := copy(pkt, resPacket.NetworkHeader().Slice())
		n += copy(pkt[n:], resPacket.TransportHeader().Slice())
		n += copy(pkt[n:], resPacket.Data().AsRange().ToSlice())
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
		pkt.Decode(buff[offset:])
		packetBuf := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(slices.Clone(buff[offset:])),
		})
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

func startTSNet(ctx context.Context) {
	hostname, err := os.Hostname()
	if err != nil {
		log.Fatal(err)
	}

	ts := &tsnet.Server{
		Hostname:  hostname,
		UserLogf:  log.Printf,
		Ephemeral: false,
	}

	if _, err := ts.Up(ctx); err != nil {
		log.Fatal(err)
	}
}

func main() {
	flag.Parse()

	logf := log.Printf
	deviceLogger := &device.Logger{
		Verbosef: logger.Discard,
		Errorf:   logf,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lp := &lpServer{
		c: loadConfig(),
	}
	lp.initNetstack(ctx)
	nst := &nsTUN{
		lp:      lp,
		closeCh: make(chan struct{}),
		evChan:  make(chan tun.Event),
	}
	wgdev := wgcfg.NewDevice(nst, conn.NewDefaultBind(), deviceLogger)
	defer wgdev.Close()
	lp.d = wgdev
	must.Do(wgdev.Up())
	lp.reconfig()

	// startTSNet(ctx)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, unix.SIGTERM, os.Interrupt)
	<-sigCh
}
