// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// These unit tests exist to catch regressions in the natlab portmapping server
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
	"maps"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
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

func mustHex(s string) []byte {
	return must.Get(hex.DecodeString(strings.ReplaceAll(s, " ", "")))
}

// checkReply checks that got matches want, which is in "% x" format.
// Bytes written as "??" in want vary between runs (e.g. epoch, allocated
// port) and aren't compared.
func checkReply(t *testing.T, got []byte, want string) {
	t.Helper()
	gotHex, wantHex := strings.Fields(fmt.Sprintf("% x", got)), strings.Fields(want)
	if len(gotHex) != len(wantHex) {
		t.Fatalf("got  % x\nwant %s", got, want)
	}
	for i, w := range wantHex {
		if w != "??" && w != gotHex[i] {
			t.Errorf("got  % x\nwant %s", got, want)
			return
		}
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

func mappingExpiry(n *network, extPort uint16) time.Time {
	n.natMu.Lock()
	defer n.natMu.Unlock()
	return n.portMap[netip.AddrPortFrom(n.wanIP4, extPort)].ExpiresAt
}

// checkRenewed checks that the mapping for extPort is the only one to dst
// and that its expiry was pushed more than an hour past oldExpiry.
func checkRenewed(t *testing.T, n *network, extPort uint16, dst netip.AddrPort, oldExpiry time.Time) {
	t.Helper()
	checkMapping(t, n, extPort, dst)
	if exp := mappingExpiry(n, extPort); exp.Sub(oldExpiry) < time.Hour {
		t.Errorf("renewed expiry %v, want more than an hour after %v", exp, oldExpiry)
	}
	n.natMu.Lock()
	defer n.natMu.Unlock()
	for k, v := range n.portMap {
		if v.dst == dst && k.Port() != extPort {
			t.Errorf("extra mapping from %v to %v", k, dst)
		}
	}
}

func checkExpiresWithin(t *testing.T, n *network, extPort uint16, d time.Duration) {
	t.Helper()
	if exp := mappingExpiry(n, extPort); time.Until(exp) <= 0 || time.Until(exp) > d {
		t.Errorf("mapping expires at %v, want within %v", exp, d)
	}
}

func checkPortMap(t *testing.T, n *network, want map[netip.AddrPort]PortMapping) {
	t.Helper()
	if diff := cmp.Diff(n.portMappings(), want, cmpopts.EquateComparable(PortMapping{}), cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("got port mappings (-got, +want):\n%s", diff)
	}
}

// checkDeleted checks that the mapping for extPort is gone and that all other
// mappings in before are the same.
func checkDeleted(t *testing.T, n *network, extPort uint16, before map[netip.AddrPort]PortMapping) {
	t.Helper()
	want := maps.Clone(before)
	delete(want, netip.AddrPortFrom(n.wanIP4, extPort))
	checkPortMap(t, n, want)
}

type soapResponse struct {
	ExternalIP   netip.Addr `xml:"NewExternalIPAddress"`
	ReservedPort uint16     `xml:"NewReservedPort"`
}

func soapRequest(t *testing.T, n *network, action, args string) soapResponse {
	t.Helper()
	body := fmt.Sprintf(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:%[1]s xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:2">%[2]s</u:%[1]s>
  </s:Body>
</s:Envelope>`, action, args)
	rec := httptest.NewRecorder()
	n.upnpHandler().ServeHTTP(rec, httptest.NewRequest("POST", "/ctl/IPConn", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: status %d; body:\n%s", action, rec.Code, rec.Body)
	}

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
	natpmpAddrReq  = mustHex("00 00")                                                                   // NAT-PMP external address request
)

func TestNATPMP(t *testing.T) {
	s, n := newPortmapNetwork(t, NATPMP)
	t.Run("external-address", func(t *testing.T) {
		got := sendUDPToRouter(t, s, pxpPort, natpmpAddrReq)
		// success, external address 2.1.1.1
		checkReply(t, got, "00 80 00 00 ?? ?? ?? ?? 02 01 01 01")
	})
	t.Run("map-udp", func(t *testing.T) {
		n.portMapLifetime = time.Minute
		t.Cleanup(func() { n.portMapLifetime = 0 })
		// MAP UDP of int port 60736 to any ext port for 7200s
		got := sendUDPToRouter(t, s, pxpPort, mustHex("00 01 00 00 ed 40 00 00 00 00 1c 20"))
		// success, MAP UDP of int port 60736 for 60s
		checkReply(t, got, "00 81 00 00 ?? ?? ?? ?? ed 40 ?? ?? 00 00 00 3c")
		extPort := binary.BigEndian.Uint16(got[10:12])
		checkMapping(t, n, extPort, netip.AddrPortFrom(clientIPv4(1), 60736))
		checkExpiresWithin(t, n, extPort, time.Minute)
	})
	t.Run("renew-udp", func(t *testing.T) {
		// MAP UDP of int port 60737 to ext port 20000 for 60s
		got := sendUDPToRouter(t, s, pxpPort, mustHex("00 01 00 00 ed 41 4e 20 00 00 00 3c"))
		// success, MAP UDP of int port 60737 to ext port 20000 for 60s
		checkReply(t, got, "00 81 00 00 ?? ?? ?? ?? ed 41 4e 20 00 00 00 3c")
		extPort := uint16(20000) // 4e 20 in hex
		checkMapping(t, n, extPort, netip.AddrPortFrom(clientIPv4(1), 60737))
		expiry := mappingExpiry(n, extPort)

		// MAP UDP of int port 60737 to any ext port for 7200s
		got = sendUDPToRouter(t, s, pxpPort, mustHex("00 01 00 00 ed 41 00 00 00 00 1c 20"))
		// success, MAP UDP of int port 60737 to the same ext port for 7200s
		checkReply(t, got, "00 81 00 00 ?? ?? ?? ?? ed 41 4e 20 00 00 1c 20")
		checkRenewed(t, n, extPort, netip.AddrPortFrom(clientIPv4(1), 60737), expiry)
	})
	t.Run("delete-udp", func(t *testing.T) {
		// MAP UDP of int port 60738 (ed 42 in hex) to ext port 20003 for 7200s
		got := sendUDPToRouter(t, s, pxpPort, mustHex("00 01 00 00 ed 42 4e 23 00 00 1c 20"))
		// success, MAP UDP of int port 60738 to ext port 20003 for 7200s
		checkReply(t, got, "00 81 00 00 ?? ?? ?? ?? ed 42 4e 23 00 00 1c 20")
		extPort := uint16(20003) // 4e 23 in hex
		checkMapping(t, n, extPort, netip.AddrPortFrom(clientIPv4(1), 60738))
		before := n.portMappings()

		// MAP UDP of int port 60738 to bogus ext port 22222 (56 ce in hex) for 0s (delete)
		const deleteReq = "00 01 00 00 ed 42 56 ce 00 00 00 00"
		// success, int port 60738, ext port 0, lifetime 0
		const deleteReply = "00 81 00 00 ?? ?? ?? ?? ed 42 00 00 00 00 00 00"

		got = sendUDPToRouter(t, s, pxpPort, mustHex(deleteReq))
		checkReply(t, got, deleteReply)
		checkDeleted(t, n, extPort, before)
		after := n.portMappings()

		// Same delete again, now for a mapping that no longer exists
		got = sendUDPToRouter(t, s, pxpPort, mustHex(deleteReq))
		checkReply(t, got, deleteReply)
		checkPortMap(t, n, after)
	})
	t.Run("request-unsupported", func(t *testing.T) {
		got := sendUDPToRouter(t, s, pxpPort, pcpAnnounceReq)
		// NAT-PMP unsupported version
		checkReply(t, got, "00 00 00 01 ?? ?? ?? ??")
	})
}

func TestPCP(t *testing.T) {
	s, n := newPortmapNetwork(t, PCP)
	t.Run("announce", func(t *testing.T) {
		got := sendUDPToRouter(t, s, pxpPort, pcpAnnounceReq)
		// ANNOUNCE success
		checkReply(t, got, "02 80 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00")
	})
	t.Run("map-udp", func(t *testing.T) {
		n.portMapLifetime = time.Minute
		t.Cleanup(func() { n.portMapLifetime = 0 })
		// MAP UDP of int 192.168.0.101:40768 to any ext IP and port for 7200s, with nonce 95bcb5d93d07ecbbc8b3bd4f
		got := sendUDPToRouter(t, s, pxpPort, mustHex("02 01 00 00 00 00 1c 20 00 00 00 00 00 00 00 00 00 00 ff ff c0 a8 00 65 "+
			"95 bc b5 d9 3d 07 ec bb c8 b3 bd 4f 11 00 00 00 9f 40 00 00 00 00 00 00 00 00 00 00 00 00 ff ff 00 00 00 00"))
		// success, MAP UDP of int port 40768 to ext IP 2.1.1.1 for 60s, same nonce
		checkReply(t, got, "02 81 00 00 00 00 00 3c ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 "+
			"95 bc b5 d9 3d 07 ec bb c8 b3 bd 4f 11 00 00 00 9f 40 ?? ?? 00 00 00 00 00 00 00 00 00 00 ff ff 02 01 01 01")
		extPort := binary.BigEndian.Uint16(got[42:44])
		checkMapping(t, n, extPort, netip.AddrPortFrom(clientIPv4(1), 40768))
		checkExpiresWithin(t, n, extPort, time.Minute)
	})
	t.Run("renew-udp", func(t *testing.T) {
		// MAP UDP of int 192.168.0.101:40769 to any ext IP and port 20001 for 60s, with nonce 95bcb5d93d07ecbbc8b3bd4f
		got := sendUDPToRouter(t, s, pxpPort, mustHex("02 01 00 00 00 00 00 3c 00 00 00 00 00 00 00 00 00 00 ff ff c0 a8 00 65 "+
			"95 bc b5 d9 3d 07 ec bb c8 b3 bd 4f 11 00 00 00 9f 41 4e 21 00 00 00 00 00 00 00 00 00 00 ff ff 00 00 00 00"))
		// success, MAP UDP of int port 40769 to ext 2.1.1.1:20001 for 60s, same nonce
		checkReply(t, got, "02 81 00 00 00 00 00 3c ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 "+
			"95 bc b5 d9 3d 07 ec bb c8 b3 bd 4f 11 00 00 00 9f 41 4e 21 00 00 00 00 00 00 00 00 00 00 ff ff 02 01 01 01")
		extPort := uint16(20001) // 4e 21 in hex
		checkMapping(t, n, extPort, netip.AddrPortFrom(clientIPv4(1), 40769))
		expiry := mappingExpiry(n, extPort)

		// MAP UDP of int 192.168.0.101:40769 to any ext IP and port for 7200s, same nonce
		got = sendUDPToRouter(t, s, pxpPort, mustHex("02 01 00 00 00 00 1c 20 00 00 00 00 00 00 00 00 00 00 ff ff c0 a8 00 65 "+
			"95 bc b5 d9 3d 07 ec bb c8 b3 bd 4f 11 00 00 00 9f 41 00 00 00 00 00 00 00 00 00 00 00 00 ff ff 00 00 00 00"))
		// success, MAP UDP of int port 40769 to the same ext IP and port for 7200s, same nonce
		checkReply(t, got, "02 81 00 00 00 00 1c 20 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 "+
			"95 bc b5 d9 3d 07 ec bb c8 b3 bd 4f 11 00 00 00 9f 41 4e 21 00 00 00 00 00 00 00 00 00 00 ff ff 02 01 01 01")
		checkRenewed(t, n, extPort, netip.AddrPortFrom(clientIPv4(1), 40769), expiry)
	})
	t.Run("delete-udp", func(t *testing.T) {
		// MAP UDP of int 192.168.0.101:40770 (9f 42 in hex) to any ext IP and port 20005 for 7200s, with nonce 95bcb5d93d07ecbbc8b3bd4f
		got := sendUDPToRouter(t, s, pxpPort, mustHex("02 01 00 00 00 00 1c 20 00 00 00 00 00 00 00 00 00 00 ff ff c0 a8 00 65 "+
			"95 bc b5 d9 3d 07 ec bb c8 b3 bd 4f 11 00 00 00 9f 42 4e 25 00 00 00 00 00 00 00 00 00 00 ff ff 00 00 00 00"))
		// success, MAP UDP of int port 40770 to ext 2.1.1.1:20005 for 7200s, same nonce
		checkReply(t, got, "02 81 00 00 00 00 1c 20 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 "+
			"95 bc b5 d9 3d 07 ec bb c8 b3 bd 4f 11 00 00 00 9f 42 4e 25 00 00 00 00 00 00 00 00 00 00 ff ff 02 01 01 01")
		extPort := uint16(20005) // 4e 25 in hex
		checkMapping(t, n, extPort, netip.AddrPortFrom(clientIPv4(1), 40770))
		before := n.portMappings()

		// MAP UDP of int 192.168.0.101:40770 for 0s (delete), ext IP and port 0 as per https://www.rfc-editor.org/rfc/rfc6887#section-15.1, same nonce
		const deleteReq = "02 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff ff c0 a8 00 65 " +
			"95 bc b5 d9 3d 07 ec bb c8 b3 bd 4f 11 00 00 00 9f 42 00 00 00 00 00 00 00 00 00 00 00 00 ff ff 00 00 00 00"
		// success, int port 40770, ext IP and port copied from request, lifetime 0, same nonce
		const deleteReply = "02 81 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 " +
			"95 bc b5 d9 3d 07 ec bb c8 b3 bd 4f 11 00 00 00 9f 42 00 00 00 00 00 00 00 00 00 00 00 00 ff ff 00 00 00 00"

		got = sendUDPToRouter(t, s, pxpPort, mustHex(deleteReq))
		checkReply(t, got, deleteReply)
		checkDeleted(t, n, extPort, before)
		after := n.portMappings()

		// Same delete again, now for a mapping that no longer exists
		got = sendUDPToRouter(t, s, pxpPort, mustHex(deleteReq))
		checkReply(t, got, deleteReply)
		checkPortMap(t, n, after)
	})
	t.Run("request-unsupported", func(t *testing.T) {
		got := sendUDPToRouter(t, s, pxpPort, natpmpAddrReq)
		// PCP unsupported version, error lifetime 1800s
		checkReply(t, got, "02 80 00 01 00 00 07 08 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00")
	})
}

func TestUPnP(t *testing.T) {
	s, n := newPortmapNetwork(t, UPnP)
	t.Run("ssdp-msearch", func(t *testing.T) {
		// Same as uPnPPacket in net/portmapper.
		ssdpSearchReq := []byte("M-SEARCH * HTTP/1.1\r\n" +
			"HOST: 239.255.255.250:1900\r\n" +
			"ST: ssdp:all\r\n" +
			"MAN: \"ssdp:discover\"\r\n" +
			"MX: 2\r\n\r\n")
		got := sendUDPToRouter(t, s, ssdpPort, ssdpSearchReq)
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
		want := netip.MustParseAddr("2.1.1.1")
		if res.ExternalIP != want {
			t.Errorf("NewExternalIPAddress = %v, want %v", res.ExternalIP, want)
		}
	})
	t.Run("add-any-port-mapping", func(t *testing.T) {
		res := soapRequest(t, n, "AddAnyPortMapping", `
      <NewExternalPort>40768</NewExternalPort>
      <NewInternalPort>40768</NewInternalPort>
      <NewInternalClient>192.168.0.101</NewInternalClient>
      <NewLeaseDuration>7200</NewLeaseDuration>`)
		checkMapping(t, n, res.ReservedPort, netip.AddrPortFrom(clientIPv4(1), 40768))
	})
	t.Run("renew-any-port-mapping", func(t *testing.T) {
		res := soapRequest(t, n, "AddAnyPortMapping", `
      <NewExternalPort>20002</NewExternalPort>
      <NewInternalPort>40769</NewInternalPort>
      <NewInternalClient>192.168.0.101</NewInternalClient>
      <NewLeaseDuration>60</NewLeaseDuration>`)
		extPort := uint16(20002)
		if res.ReservedPort != extPort {
			t.Errorf("NewReservedPort = %d, want %d", res.ReservedPort, extPort)
		}
		checkMapping(t, n, extPort, netip.AddrPortFrom(clientIPv4(1), 40769))
		expiry := mappingExpiry(n, extPort)

		res = soapRequest(t, n, "AddAnyPortMapping", `
      <NewExternalPort>20002</NewExternalPort>
      <NewInternalPort>40769</NewInternalPort>
      <NewInternalClient>192.168.0.101</NewInternalClient>
      <NewLeaseDuration>7200</NewLeaseDuration>`)
		if res.ReservedPort != extPort {
			t.Errorf("renewed NewReservedPort = %d, want %d", res.ReservedPort, extPort)
		}
		checkRenewed(t, n, extPort, netip.AddrPortFrom(clientIPv4(1), 40769), expiry)
	})
	t.Run("delete-port-mapping", func(t *testing.T) {
		extPort := uint16(20006)
		intPort := uint16(40772)

		res := soapRequest(t, n, "AddAnyPortMapping", fmt.Sprintf(`
      <NewExternalPort>%d</NewExternalPort>
      <NewInternalPort>%d</NewInternalPort>
      <NewInternalClient>192.168.0.101</NewInternalClient>
      <NewLeaseDuration>7200</NewLeaseDuration>`, extPort, intPort))
		if res.ReservedPort != extPort {
			t.Errorf("NewReservedPort = %d, want %d", res.ReservedPort, extPort)
		}
		checkMapping(t, n, extPort, netip.AddrPortFrom(clientIPv4(1), intPort))
		before := n.portMappings()

		soapRequest(t, n, "DeletePortMapping", fmt.Sprintf(`
      <NewRemoteHost></NewRemoteHost>
      <NewExternalPort>%d</NewExternalPort>
      <NewProtocol>UDP</NewProtocol>`, extPort))
		checkDeleted(t, n, extPort, before)
	})
}
