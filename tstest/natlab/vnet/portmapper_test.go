// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// These unit tests exist to catch regression in the natlab portmapping server
// implementations. See tstest/natlab/vmtest/portmapper_test.go for the VM
// tests which verify that the tailscale client works.

package vnet

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"tailscale.com/util/must"
)

func newPortmapNetwork(t *testing.T, svc NetworkService) (*Server, *network) {
	t.Helper()
	var c Config
	nw := c.AddNetwork("2.1.1.1", "192.168.0.1/24", svc)
	c.AddNode(nw)
	s, err := New(&c)
	if err != nil {
		t.Fatal(err)
	}
	s.StopUnsolicitedRAsForTest()
	t.Cleanup(s.Close)
	return s, nw.network
}

// sendToRouter sends payload from node 1 to the router's LAN IP on dstPort
// and returns the UDP payload of the router's reply.
func sendToRouter(t *testing.T, s *Server, dstPort uint16, payload []byte) []byte {
	t.Helper()
	se := newSideEffects(s)
	routerIP := netip.MustParseAddr("192.168.0.1")
	eth := &layers.Ethernet{SrcMAC: nodeMac(1).HWAddr(), DstMAC: routerMac(1).HWAddr()}
	ip := mkIPLayer(layers.IPProtocolUDP, clientIPv4(1), routerIP)
	udp := &layers.UDP{SrcPort: 40000, DstPort: layers.UDPPort(dstPort)}
	if err := s.handleEthernetFrameFromVM(mustPacket(eth, ip, udp, gopacket.Payload(payload))); err != nil {
		t.Fatal(err)
	}
	if len(se.got) != 1 {
		t.Fatalf("got %d reply packets, want 1; logs:\n%s", len(se.got), strings.Join(se.logs, "\n"))
	}
	pkt := gopacket.NewPacket(se.got[0].eth, layers.LayerTypeEthernet, gopacket.Default)
	ip4, _ := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	res, _ := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if ip4 == nil || res == nil {
		t.Fatalf("reply is not IPv4/UDP:\n%v", pkt)
	}
	// The client drops replies that don't come from the gateway's port.
	if src, _ := netip.AddrFromSlice(ip4.SrcIP); src != routerIP || uint16(res.SrcPort) != dstPort {
		t.Errorf("reply from %v:%d, want %v:%d", src, res.SrcPort, routerIP, dstPort)
	}
	if res.DstPort != udp.SrcPort {
		t.Errorf("reply to port %d, want %d", res.DstPort, udp.SrcPort)
	}
	return res.Payload
}

func mustHex(s string) []byte {
	return must.Get(hex.DecodeString(strings.ReplaceAll(s, " ", "")))
}

// checkReply checks that got equals want, which is in "% x" format.
// zero holds [start, end) index pairs of bytes that vary between runs
// (epoch, allocated port); they are cleared in got before comparing.
func checkReply(t *testing.T, got []byte, want string, zero ...int) {
	t.Helper()
	if len(got) != len(mustHex(want)) {
		t.Fatalf("got  % x\nwant %s", got, want)
	}
	got = bytes.Clone(got)
	for i := 0; i+1 < len(zero); i += 2 {
		clear(got[zero[i]:zero[i+1]])
	}
	if got := fmt.Sprintf("% x", got); got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func checkMapping(t *testing.T, n *network, extPort uint16, want netip.AddrPort) {
	t.Helper()
	n.natMu.Lock()
	defer n.natMu.Unlock()
	if m := n.portMap[netip.AddrPortFrom(n.wanIP4, extPort)]; m.dst != want {
		t.Errorf("mapping for external port %d is to %v, want %v", extPort, m.dst, want)
	}
}

type soapResponse struct {
	ExternalIP   netip.Addr `xml:"NewExternalIPAddress"`
	ReservedPort uint16     `xml:"NewReservedPort"`
}

func soapRequest(t *testing.T, n *network, action, args string) soapResponse {
	t.Helper()
	body := `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">` +
		`<s:Body><u:` + action + ` xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:2">` + args +
		`</u:` + action + `></s:Body></s:Envelope>`
	rec := httptest.NewRecorder()
	n.upnpHandler().ServeHTTP(rec, httptest.NewRequest("POST", "/ctl/IPConn", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: status %d; body:\n%s", action, rec.Code, rec.Body)
	}
	// Namespaces as required by the client's SOAP decoder (github.com/huin/goupnp/soap).
	var env struct {
		XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
		Body    struct {
			Response soapResponse `xml:",any"`
		} `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
	}
	if err := xml.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("%s: parsing response: %v\n%s", action, err, rec.Body)
	}
	return env.Body.Response
}

var (
	pcpAnnounceReq = mustHex("02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff ff c0 a8 00 65") // PCP ANNOUNCE from 192.168.0.101
	natpmpAddrReq  = []byte{0, 0}                                                                       // NAT-PMP external address request
)

func TestNATPMP(t *testing.T) {
	s, n := newPortmapNetwork(t, NATPMP)
	t.Run("external-address", func(t *testing.T) {
		got := sendToRouter(t, s, pxpPort, natpmpAddrReq)
		// success, external address 2.1.1.1
		checkReply(t, got, "00 80 00 00 00 00 00 00 02 01 01 01", 4, 8)
	})
	t.Run("map-udp", func(t *testing.T) {
		// MAP UDP of int port 60736 to any ext port for 7200s
		got := sendToRouter(t, s, pxpPort, mustHex("00 01 00 00 ed 40 00 00 00 00 1c 20"))
		// success, MAP UDP of int port 60736 for 7200s
		checkReply(t, got, "00 81 00 00 00 00 00 00 ed 40 00 00 00 00 1c 20", 4, 8, 10, 12)
		checkMapping(t, n, binary.BigEndian.Uint16(got[10:12]), netip.AddrPortFrom(clientIPv4(1), 60736))
	})
	t.Run("request-unsupported", func(t *testing.T) {
		got := sendToRouter(t, s, pxpPort, pcpAnnounceReq)
		// NAT-PMP unsupported version
		checkReply(t, got, "00 00 00 01 00 00 00 00", 4, 8)
	})
}

func TestPCP(t *testing.T) {
	s, n := newPortmapNetwork(t, PCP)
	t.Run("announce", func(t *testing.T) {
		got := sendToRouter(t, s, pxpPort, pcpAnnounceReq)
		// ANNOUNCE success
		checkReply(t, got, "02 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00", 8, 12)
	})
	t.Run("map-udp", func(t *testing.T) {
		// MAP UDP of int 192.168.0.101:40768 to any ext IP and port for 7200s, with nonce 95bcb5d93d07ecbbc8b3bd4f
		got := sendToRouter(t, s, pxpPort, mustHex("02 01 00 00 00 00 1c 20 00 00 00 00 00 00 00 00 00 00 ff ff c0 a8 00 65 "+
			"95 bc b5 d9 3d 07 ec bb c8 b3 bd 4f 11 00 00 00 9f 40 00 00 00 00 00 00 00 00 00 00 00 00 ff ff 00 00 00 00"))
		// success, MAP UDP of int port 40768 to ext IP 2.1.1.1 for 7200s, same nonce
		checkReply(t, got, "02 81 00 00 00 00 1c 20 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "+
			"95 bc b5 d9 3d 07 ec bb c8 b3 bd 4f 11 00 00 00 9f 40 00 00 00 00 00 00 00 00 00 00 00 00 ff ff 02 01 01 01", 8, 12, 42, 44)
		checkMapping(t, n, binary.BigEndian.Uint16(got[42:44]), netip.AddrPortFrom(clientIPv4(1), 40768))
	})
	t.Run("request-unsupported", func(t *testing.T) {
		got := sendToRouter(t, s, pxpPort, natpmpAddrReq)
		// PCP unsupported version, error lifetime 1800s
		checkReply(t, got, "02 80 00 01 00 00 07 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00", 8, 12)
	})
}

func TestUPnP(t *testing.T) {
	s, n := newPortmapNetwork(t, UPnP)
	t.Run("ssdp-msearch", func(t *testing.T) {
		got := sendToRouter(t, s, ssdpPort, []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nST: ssdp:all\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\n\r\n"))
		res, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(got)), nil)
		if err != nil {
			t.Fatalf("parsing SSDP reply: %v\n%s", err, got)
		}
		if loc, want := res.Header.Get("Location"), "http://192.168.0.1:5000/rootDesc.xml"; loc != want {
			t.Errorf("Location = %q, want %q", loc, want)
		}
		if st := res.Header.Get("St"); !strings.Contains(st, ":InternetGatewayDevice:") {
			t.Errorf("ST = %q, want an InternetGatewayDevice", st)
		}
	})
	t.Run("root-desc", func(t *testing.T) {
		rec := httptest.NewRecorder()
		n.upnpHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/rootDesc.xml", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d; body:\n%s", rec.Code, rec.Body)
		}
		if mt, _, err := mime.ParseMediaType(rec.Header().Get("Content-Type")); err != nil || mt != "text/xml" {
			t.Errorf("Content-Type = %q, want text/xml", rec.Header().Get("Content-Type"))
		}
		if rec.Body.Len() == 0 {
			t.Error("empty body")
		}
	})
	t.Run("get-external-ip", func(t *testing.T) {
		res := soapRequest(t, n, "GetExternalIPAddress", "")
		if want := netip.MustParseAddr("2.1.1.1"); res.ExternalIP != want {
			t.Errorf("NewExternalIPAddress = %v, want %v", res.ExternalIP, want)
		}
	})
	t.Run("add-any-port-mapping", func(t *testing.T) {
		res := soapRequest(t, n, "AddAnyPortMapping",
			"<NewExternalPort>40768</NewExternalPort><NewInternalPort>40768</NewInternalPort>"+
				"<NewInternalClient>192.168.0.101</NewInternalClient><NewLeaseDuration>7200</NewLeaseDuration>")
		checkMapping(t, n, res.ReservedPort, netip.AddrPortFrom(clientIPv4(1), 40768))
	})
}
