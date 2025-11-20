// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package portmapper

import (
	"context"
	"encoding/xml"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/tailscale/goupnp"
	"github.com/tailscale/goupnp/dcps/internetgateway2"
)

// NOTE: this is in a distinct file because the various string constants are
// pretty verbose.

func TestSelectBestService(t *testing.T) {
	mustParseURL := func(ss string) *url.URL {
		u, err := url.Parse(ss)
		if err != nil {
			t.Fatalf("error parsing URL %q: %v", ss, err)
		}
		return u
	}

	// Run a fake IGD server to respond to UPnP requests.
	igd, err := NewTestIGD(t, TestIGDOptions{UPnP: true})
	if err != nil {
		t.Fatal(err)
	}
	defer igd.Close()

	testCases := []struct {
		name     string
		rootDesc string
		control  map[string]map[string]any
		want     string // controlURL field
	}{
		{
			name:     "single_device",
			rootDesc: testRootDesc,
			control: map[string]map[string]any{
				// Service that's up and should be selected.
				"/ctl/IPConn": {
					"GetExternalIPAddress": testGetExternalIPAddressResponse,
					"GetStatusInfo":        testGetStatusInfoResponse,
				},
			},
			want: "/ctl/IPConn",
		},
		{
			name:     "first_device_disconnected",
			rootDesc: testSelectRootDesc,
			control: map[string]map[string]any{
				// Service that's down; it's important that this is the
				// one that's down since it's ordered first in the XML
				// and we want to verify that our code properly queries
				// and then skips it.
				"/upnp/control/yomkmsnooi/wanipconn-1": {
					"GetStatusInfo": testGetStatusInfoResponseDisconnected,
					// NOTE: nothing else should be called
					// if GetStatusInfo returns a
					// disconnected result
				},
				// Service that's up and should be selected.
				"/upnp/control/xstnsgeuyh/wanipconn-7": {
					"GetExternalIPAddress": testGetExternalIPAddressResponse,
					"GetStatusInfo":        testGetStatusInfoResponse,
				},
			},
			want: "/upnp/control/xstnsgeuyh/wanipconn-7",
		},
		{
			name:     "prefer_public_external_IP",
			rootDesc: testSelectRootDesc,
			control: map[string]map[string]any{
				// Service with a private external IP; order matters as above.
				"/upnp/control/yomkmsnooi/wanipconn-1": {
					"GetStatusInfo":        testGetStatusInfoResponse,
					"GetExternalIPAddress": testGetExternalIPAddressResponsePrivate,
				},
				// Service that's up and should be selected.
				"/upnp/control/xstnsgeuyh/wanipconn-7": {
					"GetExternalIPAddress": testGetExternalIPAddressResponse,
					"GetStatusInfo":        testGetStatusInfoResponse,
				},
			},
			want: "/upnp/control/xstnsgeuyh/wanipconn-7",
		},
		{
			name:     "all_private_external_IPs",
			rootDesc: testSelectRootDesc,
			control: map[string]map[string]any{
				"/upnp/control/yomkmsnooi/wanipconn-1": {
					"GetStatusInfo":        testGetStatusInfoResponse,
					"GetExternalIPAddress": testGetExternalIPAddressResponsePrivate,
				},
				"/upnp/control/xstnsgeuyh/wanipconn-7": {
					"GetStatusInfo":        testGetStatusInfoResponse,
					"GetExternalIPAddress": testGetExternalIPAddressResponsePrivate,
				},
			},
			want: "/upnp/control/yomkmsnooi/wanipconn-1", // since this is first in the XML
		},
		{
			name:     "nothing_connected",
			rootDesc: testSelectRootDesc,
			control: map[string]map[string]any{
				"/upnp/control/yomkmsnooi/wanipconn-1": {
					"GetStatusInfo": testGetStatusInfoResponseDisconnected,
				},
				"/upnp/control/xstnsgeuyh/wanipconn-7": {
					"GetStatusInfo": testGetStatusInfoResponseDisconnected,
				},
			},
			want: "/upnp/control/yomkmsnooi/wanipconn-1", // since this is first in the XML
		},
		{
			name:     "GetStatusInfo_errors",
			rootDesc: testSelectRootDesc,
			control: map[string]map[string]any{
				"/upnp/control/yomkmsnooi/wanipconn-1": {
					"GetStatusInfo": func(_ string) (int, string) {
						return http.StatusInternalServerError, "internal error"
					},
				},
				"/upnp/control/xstnsgeuyh/wanipconn-7": {
					"GetStatusInfo": func(_ string) (int, string) {
						return http.StatusNotFound, "not found"
					},
				},
			},
			want: "/upnp/control/yomkmsnooi/wanipconn-1", // since this is first in the XML
		},
		{
			name:     "GetExternalIPAddress_bad_ip",
			rootDesc: testSelectRootDesc,
			control: map[string]map[string]any{
				"/upnp/control/yomkmsnooi/wanipconn-1": {
					"GetStatusInfo":        testGetStatusInfoResponse,
					"GetExternalIPAddress": testGetExternalIPAddressResponseInvalid,
				},
				"/upnp/control/xstnsgeuyh/wanipconn-7": {
					"GetStatusInfo":        testGetStatusInfoResponse,
					"GetExternalIPAddress": testGetExternalIPAddressResponse,
				},
			},
			want: "/upnp/control/xstnsgeuyh/wanipconn-7",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			// Ensure that we're using our test IGD server for all requests.
			rootDesc := strings.ReplaceAll(tt.rootDesc, "@SERVERURL@", igd.ts.URL)

			igd.SetUPnPHandler(&upnpServer{
				t:       t,
				Desc:    rootDesc,
				Control: tt.control,
			})
			c := newTestClient(t, igd, nil)
			t.Logf("Listening on upnp=%v", c.testUPnPPort)

			// Ensure that we're using the HTTP client that talks to our test IGD server
			ctx := context.Background()
			ctx = goupnp.WithHTTPClient(ctx, c.upnpHTTPClientLocked())

			loc := mustParseURL(igd.ts.URL)
			rootDev := mustParseRootDev(t, rootDesc, loc)

			svc, err := selectBestService(ctx, t.Logf, rootDev, loc)
			if err != nil {
				t.Fatal(err)
			}

			var controlURL string
			switch v := svc.(type) {
			case *internetgateway2.WANIPConnection2:
				controlURL = v.ServiceClient.Service.ControlURL.Str
			case *internetgateway2.WANIPConnection1:
				controlURL = v.ServiceClient.Service.ControlURL.Str
			case *internetgateway2.WANPPPConnection1:
				controlURL = v.ServiceClient.Service.ControlURL.Str
			default:
				t.Fatalf("unknown client type: %T", v)
			}

			if controlURL != tt.want {
				t.Errorf("mismatched controlURL: got=%q want=%q", controlURL, tt.want)
			}
		})
	}
}

func mustParseRootDev(t *testing.T, devXML string, loc *url.URL) *goupnp.RootDevice {
	decoder := xml.NewDecoder(strings.NewReader(devXML))
	decoder.DefaultSpace = goupnp.DeviceXMLNamespace
	decoder.CharsetReader = goupnp.CharsetReaderDefault

	root := new(goupnp.RootDevice)
	if err := decoder.Decode(root); err != nil {
		t.Fatalf("error decoding device XML: %v", err)
	}

	// Ensure the URLBase is set properly; this is how DeviceByURL does it.
	var urlBaseStr string
	if root.URLBaseStr != "" {
		urlBaseStr = root.URLBaseStr
	} else {
		urlBaseStr = loc.String()
	}
	urlBase, err := url.Parse(urlBaseStr)
	if err != nil {
		t.Fatalf("error parsing URL %q: %v", urlBaseStr, err)
	}
	root.SetURLBase(urlBase)

	return root
}

// Note: adapted from mikrotikRootDescXML with addresses replaced with
// localhost, and unnecessary fields removed.
const testSelectRootDesc = `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion>
    <major>1</major>
    <minor>0</minor>
  </specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>MikroTik Router</friendlyName>
    <manufacturer>MikroTik</manufacturer>
    <manufacturerURL>https://www.mikrotik.com/</manufacturerURL>
    <modelName>Router OS</modelName>
    <UDN>uuid:UUID-MIKROTIK-INTERNET-GATEWAY-DEVICE-</UDN>
    <serviceList>
      <service>
        <serviceType>urn:schemas-microsoft-com:service:OSInfo:1</serviceType>
        <serviceId>urn:microsoft-com:serviceId:OSInfo1</serviceId>
        <SCPDURL>/osinfo.xml</SCPDURL>
        <controlURL>/upnp/control/oqjsxqshhz/osinfo</controlURL>
        <eventSubURL>/upnp/event/cwzcyndrjf/osinfo</eventSubURL>
      </service>
    </serviceList>
    <deviceList>
      <device>
        <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
        <friendlyName>WAN Device</friendlyName>
        <manufacturer>MikroTik</manufacturer>
        <manufacturerURL>https://www.mikrotik.com/</manufacturerURL>
        <modelName>Router OS</modelName>
        <UDN>uuid:UUID-MIKROTIK-WAN-DEVICE--1</UDN>
        <serviceList>
          <service>
            <serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>
            <serviceId>urn:upnp-org:serviceId:WANCommonIFC1</serviceId>
            <SCPDURL>/wancommonifc-1.xml</SCPDURL>
            <controlURL>/upnp/control/ivvmxhunyq/wancommonifc-1</controlURL>
            <eventSubURL>/upnp/event/mkjzdqvryf/wancommonifc-1</eventSubURL>
          </service>
        </serviceList>
        <deviceList>
          <device>
            <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
            <friendlyName>WAN Connection Device</friendlyName>
            <manufacturer>MikroTik</manufacturer>
            <manufacturerURL>https://www.mikrotik.com/</manufacturerURL>
            <modelName>Router OS</modelName>
            <UDN>uuid:UUID-MIKROTIK-WAN-CONNECTION-DEVICE--1</UDN>
            <serviceList>
              <service>
                <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
                <SCPDURL>/wanipconn-1.xml</SCPDURL>
                <controlURL>/upnp/control/yomkmsnooi/wanipconn-1</controlURL>
                <eventSubURL>/upnp/event/veeabhzzva/wanipconn-1</eventSubURL>
              </service>
            </serviceList>
          </device>
        </deviceList>
      </device>
      <device>
        <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
        <friendlyName>WAN Device</friendlyName>
        <manufacturer>MikroTik</manufacturer>
        <manufacturerURL>https://www.mikrotik.com/</manufacturerURL>
        <modelName>Router OS</modelName>
        <UDN>uuid:UUID-MIKROTIK-WAN-DEVICE--7</UDN>
        <serviceList>
          <service>
            <serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>
            <serviceId>urn:upnp-org:serviceId:WANCommonIFC1</serviceId>
            <SCPDURL>/wancommonifc-7.xml</SCPDURL>
            <controlURL>/upnp/control/vzcyyzzttz/wancommonifc-7</controlURL>
            <eventSubURL>/upnp/event/womwbqtbkq/wancommonifc-7</eventSubURL>
          </service>
        </serviceList>
        <deviceList>
          <device>
            <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
            <friendlyName>WAN Connection Device</friendlyName>
            <manufacturer>MikroTik</manufacturer>
            <manufacturerURL>https://www.mikrotik.com/</manufacturerURL>
            <modelName>Router OS</modelName>
            <UDN>uuid:UUID-MIKROTIK-WAN-CONNECTION-DEVICE--7</UDN>
            <serviceList>
              <service>
                <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
                <SCPDURL>/wanipconn-7.xml</SCPDURL>
                <controlURL>/upnp/control/xstnsgeuyh/wanipconn-7</controlURL>
                <eventSubURL>/upnp/event/rscixkusbs/wanipconn-7</eventSubURL>
              </service>
            </serviceList>
          </device>
        </deviceList>
      </device>
    </deviceList>
    <presentationURL>@SERVERURL@</presentationURL>
  </device>
  <URLBase>@SERVERURL@</URLBase>
</root>`

const testGetStatusInfoResponseDisconnected = `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:GetStatusInfoResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewConnectionStatus>Disconnected</NewConnectionStatus>
      <NewLastConnectionError>ERROR_NONE</NewLastConnectionError>
      <NewUptime>0</NewUptime>
    </u:GetStatusInfoResponse>
  </s:Body>
</s:Envelope>
`

const testGetExternalIPAddressResponsePrivate = `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewExternalIPAddress>10.9.8.7</NewExternalIPAddress>
    </u:GetExternalIPAddressResponse>
  </s:Body>
</s:Envelope>
`

const testGetExternalIPAddressResponseInvalid = `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewExternalIPAddress>not-an-ip-addr</NewExternalIPAddress>
    </u:GetExternalIPAddressResponse>
  </s:Body>
</s:Envelope>
`
