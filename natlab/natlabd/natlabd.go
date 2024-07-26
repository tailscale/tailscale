package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"go4.org/mem"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
	"tailscale.com/net/stun"
	"tailscale.com/syncs"
)

var (
	listen = flag.String("listen", "/tmp/qemu.sock", "path to listen on")
)

const nicID = 1

func main() {
	log.Printf("natlabd.")
	flag.Parse()

	srv, err := net.Listen("unix", *listen)
	if err != nil {
		log.Fatal(err)
	}
	s, err := newServer()
	if err != nil {
		log.Fatalf("newServer: %v", err)
	}

	for {
		c, err := srv.Accept()
		if err != nil {
			log.Printf("Accept: %v", err)
			continue
		}
		go s.serveConn(c)
	}
}

func (s *Server) initStack() error {
	s.ns = stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			arp.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			icmp.NewProtocol4,
		},
	})
	sackEnabledOpt := tcpip.TCPSACKEnabled(true) // TCP SACK is disabled by default
	tcpipErr := s.ns.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabledOpt)
	if tcpipErr != nil {
		return fmt.Errorf("SetTransportProtocolOption SACK: %v", tcpipErr)
	}
	s.linkEP = channel.New(512, 1500, tcpip.LinkAddress(gwMAC))
	if tcpipProblem := s.ns.CreateNIC(nicID, s.linkEP); tcpipProblem != nil {
		return fmt.Errorf("CreateNIC: %v", tcpipProblem)
	}
	s.ns.SetPromiscuousMode(nicID, true)
	s.ns.SetSpoofing(nicID, true)

	prefix := tcpip.AddrFrom4Slice(gwIP.AsSlice()).WithPrefix()
	prefix.PrefixLen = 24
	if tcpProb := s.ns.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: prefix,
	}, stack.AddressProperties{}); tcpProb != nil {
		return errors.New(tcpProb.String())
	}

	ipv4Subnet, err := tcpip.NewSubnet(tcpip.AddrFromSlice(make([]byte, 4)), tcpip.MaskFromBytes(make([]byte, 4)))
	if err != nil {
		return fmt.Errorf("could not create IPv4 subnet: %v", err)
	}
	s.ns.SetRouteTable([]tcpip.Route{
		{
			Destination: ipv4Subnet,
			NIC:         nicID,
		},
	})

	const tcpReceiveBufferSize = 0 // default
	const maxInFlightConnectionAttempts = 8192
	tcpFwd := tcp.NewForwarder(s.ns, tcpReceiveBufferSize, maxInFlightConnectionAttempts, s.acceptTCP)
	s.ns.SetTransportProtocolHandler(tcp.ProtocolNumber, func(tei stack.TransportEndpointID, pb *stack.PacketBuffer) (handled bool) {
		log.Printf("TCP packet: %+v", tei)
		return tcpFwd.HandlePacket(tei, pb)
	})

	go func() {
		for {
			pkt := s.linkEP.ReadContext(s.shutdownCtx)
			if pkt.IsNil() {
				if s.shutdownCtx.Err() != nil {
					// Return without logging.
					return
				}
				log.Printf("ReadContext got nil packet")
				continue
			}

			ipRaw := pkt.ToView().AsSlice()
			log.Printf("Read packet from linkEP: % 02x", ipRaw)
			goPkt := gopacket.NewPacket(
				ipRaw,
				layers.LayerTypeIPv4, gopacket.Lazy)
			layerV4 := goPkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			eth := &layers.Ethernet{
				SrcMAC:       gwMAC,
				DstMAC:       client1mac.HWAddr(),
				EthernetType: layers.EthernetTypeIPv4,
			}
			buffer := gopacket.NewSerializeBuffer()
			options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
			sls := []gopacket.SerializableLayer{
				eth,
			}
			for _, layer := range goPkt.Layers() {
				sl, ok := layer.(gopacket.SerializableLayer)
				if !ok {
					log.Fatalf("layer %s is not serializable", layer.LayerType().String())
				}
				switch gl := layer.(type) {
				case *layers.TCP:
					gl.SetNetworkLayerForChecksum(layerV4)
				case *layers.UDP:
					gl.SetNetworkLayerForChecksum(layerV4)
				}
				sls = append(sls, sl)
			}

			if err := gopacket.SerializeLayers(buffer, options, sls...); err != nil {
				log.Printf("Serialize error: %v", err)
				continue
			}
			if writeFunc, ok := s.writeFunc.Load(client1mac); ok {
				writeFunc(buffer.Bytes())
				log.Printf("wrote packet to client: % 02x", buffer.Bytes())
			} else {
				log.Printf("No writeFunc for %v", client1mac)
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

func stringifyTEI(tei stack.TransportEndpointID) string {
	localHostPort := net.JoinHostPort(tei.LocalAddress.String(), strconv.Itoa(int(tei.LocalPort)))
	remoteHostPort := net.JoinHostPort(tei.RemoteAddress.String(), strconv.Itoa(int(tei.RemotePort)))
	return fmt.Sprintf("%s -> %s", remoteHostPort, localHostPort)
}

func (s *Server) acceptTCP(r *tcp.ForwarderRequest) {
	reqDetails := r.ID()

	log.Printf("AcceptTCP: %v", stringifyTEI(reqDetails))
	clientRemoteIP := netaddrIPFromNetstackIP(reqDetails.RemoteAddress)
	destIP := netaddrIPFromNetstackIP(reqDetails.LocalAddress)
	if !clientRemoteIP.IsValid() {
		r.Complete(true) // sends a RST
		return
	}

	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		log.Printf("CreateEndpoint error for %s: %v", stringifyTEI(reqDetails), err)
		r.Complete(true) // sends a RST
		return
	}
	ep.SocketOptions().SetKeepAlive(true)

	if reqDetails.LocalPort == 123 {
		r.Complete(false)
		tc := gonet.NewTCPConn(&wq, ep)
		io.WriteString(tc, "Hello Andrew from Go\nGoodbye.\n")
		tc.Close()
		return
	}

	if destIP == fakeControlplaneIP {
		c, err := net.Dial("tcp", "controlplane.tailscale.com:"+strconv.Itoa(int(reqDetails.LocalPort)))
		if err != nil {
			r.Complete(true)
			log.Printf("Dial controlplane: %v", err)
			return
		}
		defer c.Close()
		tc := gonet.NewTCPConn(&wq, ep)
		defer tc.Close()
		r.Complete(false)
		errc := make(chan error, 2)
		go func() { _, err := io.Copy(tc, c); errc <- err }()
		go func() { _, err := io.Copy(c, tc); errc <- err }()
		<-errc
	}
}

var gwMAC = net.HardwareAddr{0x52, 0x54, 0x00, 0x01, 0x01, 0x01}

var (
	fakeDNSIP          = netip.AddrFrom4([4]byte{4, 11, 4, 11})
	fakeControlplaneIP = netip.AddrFrom4([4]byte{52, 52, 0, 1})
)

var gwIP = netip.AddrFrom4([4]byte{192, 168, 1, 1})

var client1mac = MAC{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee}

type MAC [6]byte

func (m MAC) HWAddr() net.HardwareAddr {
	return net.HardwareAddr(m[:])
}

func (m MAC) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}

type Server struct {
	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc

	writeFunc syncs.Map[MAC, func([]byte)] // MAC -> func to write to that MAC

	ns     *stack.Stack
	linkEP *channel.Endpoint
}

func newServer() (*Server, error) {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		shutdownCtx:    ctx,
		shutdownCancel: cancel,
	}
	if err := s.initStack(); err != nil {
		return nil, fmt.Errorf("newServer: initStack: %v", err)
	}
	return s, nil
}

func (s *Server) MacOfIP(ip netip.Addr) (MAC, bool) {
	if ip == gwIP {
		return MAC(gwMAC), true
	}
	return MAC{}, false
}

func (s *Server) HWAddr(mac MAC) net.HardwareAddr {
	// TODO: cache
	return net.HardwareAddr(mac[:])
}

// IPv4ForDNS returns the IP address for the given DNS query name (for IPv4 A
// queries only).
func (s *Server) IPv4ForDNS(qname string) (netip.Addr, bool) {
	switch qname {
	case "dns":
		return fakeDNSIP, true
	case "controlplane.tailscale.com":
		return fakeControlplaneIP, true
	}
	return netip.Addr{}, false
}

func (s *Server) serveConn(uc net.Conn) {
	log.Printf("Got conn")
	defer uc.Close()

	bw := bufio.NewWriterSize(uc, 2<<10)
	var writeMu sync.Mutex
	writePkt := func(pkt []byte) {
		if pkt == nil {
			return
		}
		writeMu.Lock()
		defer writeMu.Unlock()
		hdr := binary.BigEndian.AppendUint32(bw.AvailableBuffer()[:0], uint32(len(pkt)))
		if _, err := bw.Write(hdr); err != nil {
			log.Printf("Write hdr: %v", err)
			return
		}
		if _, err := bw.Write(pkt); err != nil {
			log.Printf("Write pkt: %v", err)
			return
		}
		if err := bw.Flush(); err != nil {
			log.Printf("Flush: %v", err)
		}
	}
	s.writeFunc.Store(client1mac, writePkt)

	buf := make([]byte, 16<<10)
	for {
		if _, err := io.ReadFull(uc, buf[:4]); err != nil {
			log.Printf("ReadFull header: %v", err)
			return
		}
		n := binary.BigEndian.Uint32(buf[:4])

		if _, err := io.ReadFull(uc, buf[4:4+n]); err != nil {
			log.Printf("ReadFull pkt: %v", err)
			return
		}

		packetRaw := buf[4 : 4+n] // raw ethernet frame
		packet := gopacket.NewPacket(packetRaw, layers.LayerTypeEthernet, gopacket.Lazy)
		ll, ok := packet.LinkLayer().(*layers.Ethernet)
		if !ok {
			continue
		}

		if ll.EthernetType == layers.EthernetTypeARP {
			res, err := s.createARPResponse(packet)
			if err != nil {
				log.Printf("createARPResponse: %v", err)
			} else {
				writePkt(res)
			}
			continue
		}

		if ll.EthernetType != layers.EthernetTypeIPv4 {
			if ll.EthernetType != layers.EthernetTypeIPv6 {
				log.Printf("Dropping non-IP packet: %v", ll.EthernetType)
			}
			continue
		}

		if isDHCPRequest(packet) {
			res, err := s.createDHCPResponse(packet)
			if err != nil {
				log.Printf("createDHCPResponse: %v", err)
				continue
			}
			writePkt(res)
			continue
		}

		if isMDNSQuery(packet) || isIGMP(packet) {
			// Don't log. Spammy for now.
			continue
		}

		if isDNSRequest(packet) {
			res, err := s.createDNSResponse(packet)
			if err != nil {
				log.Printf("createDNSResponse: %v", err)
				continue
			}
			writePkt(res)
			continue
		}

		if isSTUNRequest(packet) {
			log.Printf("STUN request in")
			res, err := s.createSTUNResponse(packet)
			if err != nil {
				log.Printf("createSTUNResponse: %v", err)
				continue
			}
			writePkt(res)
			continue
		}

		if shouldInterceptTCP(packet) {
			ipp := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			pktCopy := make([]byte, 0, len(ipp.Contents)+len(ipp.Payload))
			pktCopy = append(pktCopy, ipp.Contents...)
			pktCopy = append(pktCopy, ipp.Payload...)
			packetBuf := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(pktCopy),
			})
			s.linkEP.InjectInbound(header.IPv4ProtocolNumber, packetBuf)

			// var list stack.PacketBufferList
			// list.PushBack(packetBuf)
			// n, err := s.linkEP.WritePackets(list)
			// log.Printf("Injected: %v, %v", n, err)

			packetBuf.DecRef()
			continue
		}

		log.Printf("Got packet: %v", packet)
	}
}

func (s *Server) createDHCPResponse(request gopacket.Packet) ([]byte, error) {
	ethLayer := request.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	ipLayer := request.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	udpLayer := request.Layer(layers.LayerTypeUDP).(*layers.UDP)
	dhcpLayer := request.Layer(layers.LayerTypeDHCPv4).(*layers.DHCPv4)

	response := &layers.DHCPv4{
		Operation:    layers.DHCPOpReply,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  6,
		Xid:          dhcpLayer.Xid,
		ClientHWAddr: dhcpLayer.ClientHWAddr,
		Flags:        dhcpLayer.Flags,
		YourClientIP: net.IP{192, 168, 1, 100},
		Options: []layers.DHCPOption{
			{
				Type:   layers.DHCPOptServerID,
				Data:   net.IP{192, 168, 1, 1}, // DHCP server's IP
				Length: 4,
			},
		},
	}

	var msgType layers.DHCPMsgType
	for _, opt := range dhcpLayer.Options {
		if opt.Type == layers.DHCPOptMessageType && opt.Length > 0 {
			msgType = layers.DHCPMsgType(opt.Data[0])
		}
	}
	switch msgType {
	case layers.DHCPMsgTypeDiscover:
		response.Options = append(response.Options, layers.DHCPOption{
			Type:   layers.DHCPOptMessageType,
			Data:   []byte{byte(layers.DHCPMsgTypeOffer)},
			Length: 1,
		})
	case layers.DHCPMsgTypeRequest:
		response.Options = append(response.Options,
			layers.DHCPOption{
				Type:   layers.DHCPOptMessageType,
				Data:   []byte{byte(layers.DHCPMsgTypeAck)},
				Length: 1,
			},
			layers.DHCPOption{
				Type:   layers.DHCPOptLeaseTime,
				Data:   binary.BigEndian.AppendUint32(nil, 3600), // hour? sure.
				Length: 4,
			},
			layers.DHCPOption{
				Type:   layers.DHCPOptRouter,
				Data:   net.IP{192, 168, 1, 1},
				Length: 4,
			},
			layers.DHCPOption{
				Type:   layers.DHCPOptDNS,
				Data:   fakeDNSIP.AsSlice(),
				Length: 4,
			},
			layers.DHCPOption{
				Type:   layers.DHCPOptSubnetMask,
				Data:   []byte{255, 255, 255, 0},
				Length: 4,
			},
		)

	}

	eth := &layers.Ethernet{
		SrcMAC:       gwMAC,
		DstMAC:       ethLayer.SrcMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    ipLayer.DstIP,
		DstIP:    ipLayer.SrcIP,
	}

	udp := &layers.UDP{
		SrcPort: udpLayer.DstPort,
		DstPort: udpLayer.SrcPort,
	}
	udp.SetNetworkLayerForChecksum(ip)

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buffer, options,
		eth,
		ip,
		udp,
		response,
	); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

func isDHCPRequest(pkt gopacket.Packet) bool {
	v4, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok || v4.Protocol != layers.IPProtocolUDP {
		return false
	}
	udp, ok := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
	return ok && udp.DstPort == 67 && udp.SrcPort == 68
}

func isIGMP(pkt gopacket.Packet) bool {
	return pkt.Layer(layers.LayerTypeIGMP) != nil
}

func isMDNSQuery(pkt gopacket.Packet) bool {
	udp, ok := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
	// TODO(bradfitz): also check IPv4 DstIP=224.0.0.251 (or whatever)
	return ok && udp.SrcPort == 5353 && udp.DstPort == 5353
}

func shouldInterceptTCP(pkt gopacket.Packet) bool {
	tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok {
		return false
	}
	ipv4, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok {
		return false
	}
	if tcp.DstPort == 123 {
		return true
	}
	if tcp.DstPort == 80 || tcp.DstPort == 443 {
		dstIP, _ := netip.AddrFromSlice(ipv4.DstIP.To4())
		if dstIP == fakeControlplaneIP {
			return true
		}
	}
	return false
}

// isDNSRequest reports whether pkt is a DNS request to the fake DNS server.
func isDNSRequest(pkt gopacket.Packet) bool {
	udp, ok := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if !ok || udp.DstPort != 53 {
		return false
	}
	ip, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok {
		return false
	}
	dstIP, ok := netip.AddrFromSlice(ip.DstIP)
	if !ok || dstIP != fakeDNSIP {
		return false
	}
	dns, ok := pkt.Layer(layers.LayerTypeDNS).(*layers.DNS)
	return ok && dns.QR == false && len(dns.Questions) > 0
}

// isSTUNRequest reports whether pkt is a STUN request to any STUN server.
func isSTUNRequest(pkt gopacket.Packet) bool {
	udp, ok := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
	return ok && udp.DstPort == 3478
}

func (s *Server) createSTUNResponse(pkt gopacket.Packet) ([]byte, error) {
	ethLayer := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	ipLayer := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	udpLayer := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)

	stunPay := udpLayer.Payload
	txid, err := stun.ParseBindingRequest(stunPay)
	if err != nil {
		log.Printf("invalid STUN request: %v", err)
		return nil, nil
	}
	stunRes := stun.Response(txid, netip.AddrPortFrom(gwIP, 31234))

	eth2 := &layers.Ethernet{
		SrcMAC:       ethLayer.DstMAC,
		DstMAC:       ethLayer.SrcMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip2 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    ipLayer.DstIP,
		DstIP:    ipLayer.SrcIP,
	}
	udp2 := &layers.UDP{
		SrcPort: udpLayer.DstPort,
		DstPort: udpLayer.SrcPort,
	}
	udp2.SetNetworkLayerForChecksum(ip2)

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buffer, options, eth2, ip2, udp2, gopacket.Payload(stunRes)); err != nil {
		return nil, err
	}
	resRaw := buffer.Bytes()
	back := gopacket.NewPacket(resRaw, layers.LayerTypeEthernet, gopacket.Default)
	log.Printf("made STUN reply: %v", back)

	return resRaw, nil
}

func (s *Server) createDNSResponse(pkt gopacket.Packet) ([]byte, error) {
	ethLayer := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	ipLayer := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	udpLayer := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
	dnsLayer := pkt.Layer(layers.LayerTypeDNS).(*layers.DNS)

	if dnsLayer.OpCode != layers.DNSOpCodeQuery || dnsLayer.QR || len(dnsLayer.Questions) == 0 {
		return nil, nil
	}

	response := &layers.DNS{
		ID:           dnsLayer.ID,
		QR:           true,
		AA:           true,
		TC:           false,
		RD:           dnsLayer.RD,
		RA:           true,
		OpCode:       layers.DNSOpCodeQuery,
		ResponseCode: layers.DNSResponseCodeNoErr,
	}

	var names []string
	for _, q := range dnsLayer.Questions {
		response.QDCount++
		response.Questions = append(response.Questions, q)

		if mem.HasSuffix(mem.B(q.Name), mem.S(".pool.ntp.org")) {
			// Just drop DNS queries for NTP servers. For Debian/etc guests used
			// during development. Not needed. Assume VM guests get correct time
			// via their hypervisor.
			return nil, nil
		}

		names = append(names, q.Type.String()+"/"+string(q.Name))
		if q.Class != layers.DNSClassIN || q.Type != layers.DNSTypeA {
			continue
		}

		if ip, ok := s.IPv4ForDNS(string(q.Name)); ok {
			log.Printf("IP for %q: %v", q.Name, ip)
			response.ANCount++
			response.Answers = append(response.Answers, layers.DNSResourceRecord{
				Name:  q.Name,
				Type:  q.Type,
				Class: q.Class,
				IP:    ip.AsSlice(),
				TTL:   60,
			})
		}
	}

	eth2 := &layers.Ethernet{
		SrcMAC:       ethLayer.DstMAC,
		DstMAC:       ethLayer.SrcMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip2 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    ipLayer.DstIP,
		DstIP:    ipLayer.SrcIP,
	}
	udp2 := &layers.UDP{
		SrcPort: udpLayer.DstPort,
		DstPort: udpLayer.SrcPort,
	}
	udp2.SetNetworkLayerForChecksum(ip2)

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buffer, options, eth2, ip2, udp2, response); err != nil {
		return nil, err
	}

	if len(response.Answers) > 0 {
		back := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Lazy)
		log.Printf("Generated: %v", back)
	} else {
		log.Printf("made empty response for %q", names)
	}

	return buffer.Bytes(), nil
}

func (s *Server) createARPResponse(pkt gopacket.Packet) ([]byte, error) {
	ethLayer := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	arpLayer, ok := pkt.Layer(layers.LayerTypeARP).(*layers.ARP)
	if !ok ||
		arpLayer.Operation != layers.ARPRequest ||
		arpLayer.AddrType != layers.LinkTypeEthernet ||
		arpLayer.Protocol != layers.EthernetTypeIPv4 ||
		arpLayer.HwAddressSize != 6 ||
		arpLayer.ProtAddressSize != 4 ||
		len(arpLayer.DstProtAddress) != 4 {
		return nil, nil
	}

	wantIP := netip.AddrFrom4([4]byte(arpLayer.DstProtAddress))
	mac, ok := s.MacOfIP(wantIP)
	if !ok {
		return nil, nil
	}

	eth := &layers.Ethernet{
		SrcMAC:       s.HWAddr(mac),
		DstMAC:       ethLayer.SrcMAC,
		EthernetType: layers.EthernetTypeARP,
	}

	a2 := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   s.HWAddr(mac),
		SourceProtAddress: arpLayer.DstProtAddress,
		DstHwAddress:      ethLayer.SrcMAC,
		DstProtAddress:    arpLayer.SourceProtAddress,
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buffer, options, eth, a2); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

type NetworkID string

type Node struct {
	Name string // globally unique
	MAC  MAC    // copied from World.Nodes key

	LANIP netip.Addr // IP address on the LAN, from DHCP. Optional.

	Network NetworkID
}

type World struct {
	Nodes   map[MAC]*Node
	Network map[NetworkID]*Network
}

type Network struct {
	EasyNAT          bool
	HardNAT          bool
	StatefulFirewall bool       // only applicable if !HardNAT && !EasyNAT
	WANIP            netip.Addr // IP address on the WAN
}
