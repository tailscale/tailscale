// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vnet

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/netip"
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
