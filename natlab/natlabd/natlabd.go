package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"io"
	"log"
	"net"
	"net/netip"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	listen = flag.String("listen", "/tmp/qemu.sock", "path to listen on")
)

func main() {
	log.Printf("natlabd.")
	flag.Parse()

	srv, err := net.Listen("unix", *listen)
	if err != nil {
		log.Fatal(err)
	}
	var s Server
	for {
		c, err := srv.Accept()
		if err != nil {
			log.Printf("Accept: %v", err)
			continue
		}
		go s.serveConn(c)
	}
}

var gwMAC = net.HardwareAddr{0x52, 0x54, 0x00, 0x01, 0x01, 0x01}

type MAC [6]byte

type Server struct {
}

func (s *Server) MacOfIP(ip netip.Addr) (MAC, bool) {
	if ip == netip.AddrFrom4([4]byte{192, 168, 1, 1}) {
		return MAC(gwMAC), true
	}
	return MAC{}, false
}

func (s *Server) HWAddr(mac MAC) net.HardwareAddr {
	// TODO: cache
	return net.HardwareAddr(mac[:])
}

func (s *Server) serveConn(uc net.Conn) {
	log.Printf("Got conn")
	defer uc.Close()

	bw := bufio.NewWriterSize(uc, 2<<10)
	writePkt := func(pkt []byte) {
		if pkt == nil {
			return
		}
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

		packet := gopacket.NewPacket(buf[4:4+n], layers.LayerTypeEthernet, gopacket.Lazy)
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
			res, err := createDHCPResponse(packet)
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

		log.Printf("Got packet: %v", packet)
	}
}

func createDHCPResponse(request gopacket.Packet) ([]byte, error) {
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
				Data:   net.IP{8, 8, 4, 4},
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

type Node struct {
	Name  string     // globally unique
	LanIP netip.Addr // IP address on the LAN, from DHCP. Optional.
}

type World struct {
	Nodes map[string]*Node
}

type Network struct {
}
