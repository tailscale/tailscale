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
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
	"tailscale.com/net/packet"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tsnet"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/must"
	"tailscale.com/wgengine/wgcfg"
)

var (
	wgListenPort = flag.Int("wg-port", 51820, "port number to listen on for WireGuard from the client")
	confDir      = flag.String("dir", filepath.Join(os.Getenv("HOME"), ".config/lopower"), "directory to store configuration in")
	wgPubHost    = flag.String("wg-host", "0.0.0.1", "public IP address of lopower's WireGuard server")
	qrListenAddr = flag.String("qr-listen", "127.0.0.1:8014", "HTTP address to serve a QR code for client's WireGuard configuration, or empty for none")
	printConfig  = flag.Bool("print-config", true, "print the client's WireGuard configuration to stdout on startup")
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
		// Verbosef: logf,
		Errorf: logf,
	}
	lp := &lpServer{
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
	linkEP *channel.Endpoint
	readCh chan *stack.PacketBuffer

	mu sync.Mutex // protects following
	c  *config
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
	lp.mu.Lock()
	v4, v6 := lp.c.V4, lp.c.V6
	lp.mu.Unlock()

	{
		prefix := tcpip.AddrFrom4Slice(v4.AsSlice()).WithPrefix()
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
		prefix := tcpip.AddrFrom16(v6.As16()).WithPrefix()
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

func (lp *lpServer) acceptTCP(r *tcp.ForwarderRequest) {
	log.Printf("acceptTCP: %v", r.ID())
	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
		log.Printf("CreateEndpoint: %v", tcpErr)
		r.Complete(true)
		return
	}
	log.Printf("created endpoint %v", ep)
	defer ep.Close()
	ep.SocketOptions().SetKeepAlive(true)
	reqDetails := r.ID()

	clientRemoteIP := netaddrIPFromNetstackIP(reqDetails.RemoteAddress)
	destIP := netaddrIPFromNetstackIP(reqDetails.LocalAddress)
	destPort := reqDetails.LocalPort
	if !clientRemoteIP.IsValid() {
		log.Printf("acceptTCP: invalid remote IP %v", reqDetails.RemoteAddress)
		r.Complete(true) // sends a RST
		return
	}
	log.Printf("request from %v to %v:%d", clientRemoteIP, destIP, destPort)

	dialCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	c, err := lp.tsnet.Dial(dialCtx, "tcp", fmt.Sprintf("%s:%d", destIP, destPort))
	cancel()
	if err != nil {
		log.Printf("Dial(%s:%d): %v", destIP, destPort, err)
		r.Complete(true) // sends a RST
		return
	}
	defer c.Close()
	log.Printf("Connected to %s:%d", destIP, destPort)

	tc := gonet.NewTCPConn(&wq, ep)
	defer tc.Close()
	r.Complete(false)
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

	fmt.Fprintf(&b, "[Peer]\nPublicKey = %v\n", pubb64)
	fmt.Fprintf(&b, "AllowedIPs = %v/32,%v/128,%v,%v\n", lp.c.V4, lp.c.V6, tsaddr.TailscaleULARange(), tsaddr.CGNATRange())
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

func (lp *lpServer) startTSNet(ctx context.Context) {
	hostname, err := os.Hostname()
	if err != nil {
		log.Fatal(err)
	}

	lp.tsnet = &tsnet.Server{
		Dir:       filepath.Join(lp.dir, "tsnet"),
		Hostname:  hostname,
		UserLogf:  log.Printf,
		Ephemeral: false,
	}

	if _, err := lp.tsnet.Up(ctx); err != nil {
		log.Fatal(err)
	}
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
