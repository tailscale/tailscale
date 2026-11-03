// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vnet

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"maps"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"time"

	"tailscale.com/util/mak"
)

// PxP packets
const (
	opcodeANNOUNCE = 0 // external address lookup in NAT-PMP
	opcodeMAP      = 1 // MAP UDP in NAT-PMP

	protocolUDP = 17

	versionNATPMP = 0
	versionPCP    = 2

	resultSuccess       = 0
	resultUnsuppVersion = 1

	opcodeResponseBit = 128
)

// router's UPnP HTTP server, as advertised in its SSDP responses
const upnpHTTPPort = 5000

const upnpServer = "natlab/1.0 UPnP/1.1 natlab-igd/1.0"

// minimal UPnP root device description
const upnpRootDesc = `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>1</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:2</deviceType>
    <friendlyName>natlab router</friendlyName>
    <UDN>uuid:00000000-0000-0000-0000-000000000000</UDN>
    <serviceList>
      <service>
        <serviceType>urn:schemas-upnp-org:service:WANIPConnection:2</serviceType>
        <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
        <controlURL>/ctl/IPConn</controlURL>
      </service>
    </serviceList>
  </device>
</root>
`

func (n *network) handleSSDPRequest(req UDPPacket) {
	if !n.svcs.Contains(UPnP) {
		return
	}
	if !bytes.HasPrefix(req.Payload, []byte("M-SEARCH ")) {
		n.logf("vnet: ignoring SSDP packet that isn't an M-SEARCH % 02x", req.Payload)
		return
	}
	res := fmt.Appendf(nil, "HTTP/1.1 200 OK\r\n"+
		"CACHE-CONTROL: max-age=1800\r\n"+
		"EXT:\r\n"+
		"LOCATION: http://%v/rootDesc.xml\r\n"+
		"SERVER: "+upnpServer+"\r\n"+
		"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:2\r\n"+
		"USN: uuid:00000000-0000-0000-0000-000000000000::urn:schemas-upnp-org:device:InternetGatewayDevice:2\r\n"+
		"BOOTID.UPNP.ORG: 1\r\n"+
		"\r\n",
		netip.AddrPortFrom(n.lanIP4.Addr(), upnpHTTPPort))
	n.WriteUDPPacketNoNAT(UDPPacket{
		Src:     req.Dst,
		Dst:     req.Src,
		Payload: res,
	})
}

func (n *network) upnpHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", upnpServer)
		switch {
		case r.Method == "GET" && r.URL.Path == "/rootDesc.xml":
			w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)
			io.WriteString(w, upnpRootDesc)
		case r.Method == "POST" && r.URL.Path == "/ctl/IPConn":
			n.handleUPnPControl(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// TODO(fmarier): return SOAP errors instead of plain HTTP errors
func (n *network) handleUPnPControl(w http.ResponseWriter, r *http.Request) {
	var env struct {
		Body struct {
			Action struct {
				XMLName        xml.Name
				InternalClient netip.Addr `xml:"NewInternalClient"`
				InternalPort   uint16     `xml:"NewInternalPort"`
				ExternalPort   uint16     `xml:"NewExternalPort"`
				LeaseDuration  uint32     `xml:"NewLeaseDuration"`
			} `xml:",any"`
		}
	}
	if err := xml.NewDecoder(r.Body).Decode(&env); err != nil {
		n.logf("UPnP control request with invalid XML: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	action := env.Body.Action
	name := action.XMLName.Local

	var out string
	switch name {
	case "GetExternalIPAddress":
		out = fmt.Sprintf("<NewExternalIPAddress>%v</NewExternalIPAddress>", n.wanIP4)
	case "AddAnyPortMapping":
		if !action.InternalClient.IsValid() {
			n.logf("UPnP map request without a valid NewInternalClient")
			http.Error(w, "missing NewInternalClient", http.StatusBadRequest)
			return
		}
		if action.InternalPort == 0 {
			n.logf("UPnP map request for %v without a NewInternalPort", action.InternalClient)
			http.Error(w, "missing NewInternalPort", http.StatusBadRequest)
			return
		}
		// TODO(fmarier): reject wildcard value (0) in ExternalPort
		// TODO(fmarier): spec says NewLeaseDuration of 0 needs to be treated as 604800 seconds
		gotPort, ok := n.doPortMap(action.InternalClient, action.InternalPort, action.ExternalPort, int(action.LeaseDuration), UPnP)
		if !ok {
			n.logf("UPnP map request for %v:%d failed", action.InternalClient, action.InternalPort)
			http.Error(w, "port mapping failed", http.StatusInternalServerError)
			return
		}
		out = fmt.Sprintf("<NewReservedPort>%d</NewReservedPort>", gotPort)
	default:
		// TODO(fmarier): handle portmap releases (DeletePortMapping)
		n.logf("TODO: handle UPnP action %q", name)
		http.Error(w, "unsupported action", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)
	fmt.Fprintf(w, `<?xml version="1.0"?>`+
		`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">`+
		`<s:Body><u:%sResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:2">%s</u:%sResponse></s:Body></s:Envelope>`,
		name, out, name)
}

func (n *network) handlePxPRequest(req UDPPacket) {
	if req.Payload[1]&opcodeResponseBit != 0 {
		n.logf("vnet: ignoring NAT-PMP/PCP packet with response bit set % 02x", req.Payload)
		return
	}
	switch req.Payload[0] {
	case versionNATPMP:
		switch {
		case n.svcs.Contains(NATPMP):
			n.handleNATPMPRequest(req)
		case n.svcs.Contains(PCP):
			n.writePCPUnsuppVersion(req)
		}
	case versionPCP:
		switch {
		case n.svcs.Contains(PCP):
			n.handlePCPRequest(req)
		case n.svcs.Contains(NATPMP):
			n.writeNATPMPUnsuppVersion(req)
		}
	default:
		n.logf("vnet: ignoring NAT-PMP/PCP packet with unknown version % 02x", req.Payload)
	}
}

func (n *network) writeNATPMPUnsuppVersion(req UDPPacket) {
	res := make([]byte, 0, 8)
	res = append(res,
		versionNATPMP,
		0, // opcode is 0 as per https://www.rfc-editor.org/rfc/rfc6886#section-3.5
		0, resultUnsuppVersion,
	)
	epoch := uint32(time.Now().Unix())
	res = binary.BigEndian.AppendUint32(res, epoch)
	n.WriteUDPPacketNoNAT(UDPPacket{
		Src:     req.Dst,
		Dst:     req.Src,
		Payload: res,
	})
}

func (n *network) writePCPUnsuppVersion(req UDPPacket) {
	opcode := req.Payload[1]
	res := make([]byte, 0, 24)
	res = append(res,
		versionPCP,
		opcodeResponseBit|opcode,
		0, // reserved
		resultUnsuppVersion,
	)
	lifetimeSec := uint32(1800) // 30 min
	res = binary.BigEndian.AppendUint32(res, lifetimeSec)
	epoch := uint32(time.Now().Unix())
	res = binary.BigEndian.AppendUint32(res, epoch)
	res = append(res, make([]byte, 12)...) // reserved (96 bits)
	n.WriteUDPPacketNoNAT(UDPPacket{
		Src:     req.Dst,
		Dst:     req.Src,
		Payload: res,
	})
}

func (n *network) handleNATPMPRequest(req UDPPacket) {
	if !n.svcs.Contains(NATPMP) {
		return
	}
	if len(req.Payload) < 2 || req.Payload[0] != versionNATPMP {
		n.logf("vnet: ignoring invalid NAT-PMP packet % 02x", req.Payload)
		return
	}

	if len(req.Payload) == 2 && req.Payload[1] == opcodeANNOUNCE {
		// https://www.rfc-editor.org/rfc/rfc6886#section-3.2

		res := make([]byte, 0, 12)
		res = append(res,
			versionNATPMP,
			opcodeResponseBit|opcodeANNOUNCE,
			0, resultSuccess,
		)
		epoch := uint32(time.Now().Unix())
		res = binary.BigEndian.AppendUint32(res, epoch)
		wan4 := n.wanIP4.As4()
		res = append(res, wan4[:]...)
		n.WriteUDPPacketNoNAT(UDPPacket{
			Src:     req.Dst,
			Dst:     req.Src,
			Payload: res,
		})
		return
	}

	if len(req.Payload) == 12 && req.Payload[1] == opcodeMAP {
		// https://www.rfc-editor.org/rfc/rfc6886#section-3.3
		// "00 01 00 00 ed 40 00 00 00 00 1c 20" =>
		//   00 ver
		//   01 op=map UDP
		//   00 00 reserved  (0 in request; in response, this is the result code)
		//   ed 40 internal port 60736
		//   00 00 suggested external port
		//   00 00 1c 20 suggested lifetime in seconds (7200 sec = 2 hours)
		internalPort := binary.BigEndian.Uint16(req.Payload[4:6])
		wantExtPort := binary.BigEndian.Uint16(req.Payload[6:8])
		lifetimeSec := binary.BigEndian.Uint32(req.Payload[8:12])
		gotPort, ok := n.doPortMap(req.Src.Addr(), internalPort, wantExtPort, int(lifetimeSec), NATPMP)
		if !ok {
			// TODO(fmarier): handle portmap releases properly
			n.logf("NAT-PMP map request for %v:%d failed", req.Src.Addr(), internalPort)
			return
		}
		res := make([]byte, 0, 16)
		res = append(res,
			versionNATPMP,
			opcodeResponseBit|opcodeMAP,
			0, resultSuccess,
		)
		epoch := uint32(time.Now().Unix())
		res = binary.BigEndian.AppendUint32(res, epoch)
		res = binary.BigEndian.AppendUint16(res, internalPort)
		res = binary.BigEndian.AppendUint16(res, gotPort)
		res = binary.BigEndian.AppendUint32(res, lifetimeSec)
		n.WriteUDPPacketNoNAT(UDPPacket{
			Src:     req.Dst,
			Dst:     req.Src,
			Payload: res,
		})
		return
	}

	n.logf("TODO: handle NAT-PMP packet % 02x", req.Payload)
}

func (n *network) handlePCPRequest(req UDPPacket) {
	if !n.svcs.Contains(PCP) {
		return
	}

	if len(req.Payload) < 24 || req.Payload[0] != versionPCP {
		n.logf("vnet: ignoring invalid PCP packet % 02x", req.Payload)
		return
	}
	// TODO(fmarier): check that client address in the packet matches req.Src

	if len(req.Payload) == 24 && req.Payload[1] == opcodeANNOUNCE {
		// https://www.rfc-editor.org/rfc/rfc6887#section-14
		// "02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff ff 0a 07 01 66" =>
		//   02 ver
		//   00 op=announce
		//   00 00 reserved
		//   00 00 00 00 requested lifetime in seconds
		//   00 00 00 00 00 00 00 00 00 00 ff ff 0a 07 01 66 client IP (10.7.1.102)
		res := make([]byte, 0, 24)
		res = append(res,
			versionPCP,
			opcodeResponseBit|opcodeANNOUNCE,
			0, // reserved
			resultSuccess,
			0, 0, 0, 0, // lifetime (0 for ANNOUNCE)
		)
		epoch := uint32(time.Now().Unix())
		res = binary.BigEndian.AppendUint32(res, epoch)
		res = append(res, make([]byte, 12)...) // reserved (96 bits)

		// "02 80 00 00 00 00 00 00 6a c9 62 fb 00 00 00 00 00 00 00 00 00 00 00 00" =>
		//   02 ver
		//   80 op=announce+128
		//   00 reserved
		//   00 result=success
		//   00 00 00 00 lifetime in seconds
		//   6a c9 62 fb epoch (2026-10-09T21:56:11 UTC)
		//   00 00 00 00 00 00 00 00 00 00 00 00 reserved
		n.WriteUDPPacketNoNAT(UDPPacket{
			Src:     req.Dst,
			Dst:     req.Src,
			Payload: res,
		})
		return
	}

	if len(req.Payload) == 60 && req.Payload[1] == opcodeMAP && req.Payload[36] == protocolUDP {
		// https://www.rfc-editor.org/rfc/rfc6887#section-11
		// "02 01 00 00 00 00 1c 20 00 00 00 00 00 00 00 00 00 00 ff ff 0a 07 01 66 95 bc b5 d9 3d 07 ec bb c8 b3 bd 4f 11 00 00 00 9f 40 00 00 00 00 00 00 00 00 00 00 00 00 ff ff 00 00 00 00" =>
		//   02 ver
		//   01 op=map
		//   00 00 reserved
		//   00 00 1c 20 requested lifetime in seconds (7200 sec = 2 hours)
		//   00 00 00 00 00 00 00 00 00 00 ff ff 0a 07 01 66 client IP (10.7.1.102)
		//   95 bc b5 d9 3d 07 ec bb c8 b3 bd 4f nonce
		//   11 protocol (17 = UDP)
		//   00 00 00 reserved
		//   9f 40 internal port 40768
		//   00 00 suggested external port
		//   00 00 00 00 00 00 00 00 00 00 ff ff 00 00 00 00 suggested external IP
		lifetimeSec := binary.BigEndian.Uint32(req.Payload[4:8])
		internalPort := binary.BigEndian.Uint16(req.Payload[40:42])
		// TODO(fmarier): reject wildcard mappings (internalPort = 0)
		wantExtPort := binary.BigEndian.Uint16(req.Payload[42:44])
		// TODO(fmarier): reject wantedExtAddr that doesn't match IP version
		nonce := req.Payload[24:36]
		// TODO(fmarier): pass the nonce into doPortmap so that it can be checked on renewals/deletions
		gotPort, ok := n.doPortMap(req.Src.Addr(), internalPort, wantExtPort, int(lifetimeSec), PCP)
		if !ok {
			// TODO(fmarier): handle portmap releases
			n.logf("PCP map request for %v:%d failed", req.Src.Addr(), internalPort)
			return
		}
		res := make([]byte, 0, 60)
		res = append(res,
			versionPCP,
			opcodeResponseBit|opcodeMAP,
			0, // reserved
			resultSuccess,
		)
		res = binary.BigEndian.AppendUint32(res, lifetimeSec)
		epoch := uint32(time.Now().Unix())
		res = binary.BigEndian.AppendUint32(res, epoch)
		res = append(res, make([]byte, 12)...) // reserved (96 bits)
		res = append(res, nonce...)
		res = append(res,
			protocolUDP,
			0, 0, 0, // reserved
		)
		res = binary.BigEndian.AppendUint16(res, internalPort)
		res = binary.BigEndian.AppendUint16(res, gotPort)
		wan4 := n.wanIP4.As16()
		res = append(res, wan4[:]...) // TODO(fmarier): handle non-zero requested external addresses

		// "02 81 00 00 00 00 1c 20 6a c9 62 fb 00 00 00 00 00 00 00 00 00 00 00 00 95 bc b5 d9 3d 07 ec bb c8 b3 bd 4f 11 00 00 00 9f 40 e6 59 00 00 00 00 00 00 00 00 00 00 ff ff 02 01 01 01" =>
		//   02 vers
		//   81 op=map+128
		//   00 reserved
		//   00 result=success
		//   00 00 1c 20 lifetime in seconds (7200 sec = 2 hours)
		//   6a c9 62 fb epoch (2026-10-09T21:56:11 UTC)
		//   00 00 00 00 00 00 00 00 00 00 00 00 reserved
		//   95 bc b5 d9 3d 07 ec bb c8 b3 bd 4f nonce
		//   11 protocol (17 = UDP)
		//   00 00 00 reserved
		//   9f 40 internal port 40768
		//   e6 59 external port 58969
		//   00 00 00 00 00 00 00 00 00 00 ff ff 02 01 01 01 external address (2.1.1.1)
		n.WriteUDPPacketNoNAT(UDPPacket{
			Src:     req.Dst,
			Dst:     req.Src,
			Payload: res,
		})
		return
	}

	n.logf("TODO: handle PCP packet % 02x", req.Payload)
}

type PortMapping struct {
	dst     netip.AddrPort // LAN IP:port
	expiry  time.Time
	Service NetworkService
}

func (n *network) portMappings() map[netip.AddrPort]PortMapping {
	n.natMu.Lock()
	defer n.natMu.Unlock()
	now := time.Now()
	ret := maps.Clone(n.portMap)
	maps.DeleteFunc(ret, func(_ netip.AddrPort, pm PortMapping) bool {
		return now.After(pm.expiry)
	})
	return ret
}

func (n *network) doPortMap(src netip.Addr, dstLANPort, wantExtPort uint16, sec int, service NetworkService) (gotPort uint16, ok bool) {
	n.natMu.Lock()
	defer n.natMu.Unlock()

	if !n.svcs.Contains(service) {
		return 0, false
	}

	wanAP := netip.AddrPortFrom(n.wanIP4, wantExtPort)
	dst := netip.AddrPortFrom(src, dstLANPort)

	if sec == 0 {
		lanAP, ok := n.portMap[wanAP]
		if ok && lanAP.dst.Addr() == src {
			n.logf("vnet: released %v mapping from %v to %v", service, wanAP, dst)
			delete(n.portMap, wanAP)
		}
		return 0, false
	}

	// See if they already have a mapping and extend expiry if so.
	// TODO(fmarier): renewing with a different protocol overwrites the
	// service that created the mapping, so PortMappings only reports the
	// most recent one.
	for k, v := range n.portMap {
		if v.dst == dst {
			n.portMap[k] = PortMapping{
				dst:     dst,
				expiry:  time.Now().Add(time.Duration(sec) * time.Second),
				Service: service,
			}
			n.logf("vnet: renewed %v mapping from %v to %v", service, wanAP, dst)
			return k.Port(), true
		}
	}

	for range 20_000 {
		if wanAP.Port() > 0 && !n.natTable.IsPublicPortUsed(wanAP) {
			mak.Set(&n.portMap, wanAP, PortMapping{
				dst:     dst,
				expiry:  time.Now().Add(time.Duration(sec) * time.Second),
				Service: service,
			})
			n.logf("vnet: allocated %v mapping from %v to %v", service, wanAP, dst)
			return wanAP.Port(), true
		}
		wantExtPort = rand.N(uint16(32<<10)) + 32<<10
		wanAP = netip.AddrPortFrom(n.wanIP4, wantExtPort)
	}
	return 0, false
}
