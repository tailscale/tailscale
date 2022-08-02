// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package portmapper

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"regexp"
	"testing"

	"tailscale.com/tstest"
)

// Google Wifi
const (
	googleWifiUPnPDisco = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:2\r\nUSN: uuid:a9708184-a6c0-413a-bbac-11bcf7e30ece::urn:schemas-upnp-org:device:InternetGatewayDevice:2\r\nEXT:\r\nSERVER: Linux/5.4.0-1034-gcp UPnP/1.1 MiniUPnPd/1.9\r\nLOCATION: http://192.168.86.1:5000/rootDesc.xml\r\nOPT: \"http://schemas.upnp.org/upnp/1/0/\"; ns=01\r\n01-NLS: 1\r\nBOOTID.UPNP.ORG: 1\r\nCONFIGID.UPNP.ORG: 1337\r\n\r\n"

	googleWifiRootDescXML = `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><specVersion><major>1</major><minor>0</minor></specVersion><device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:2</deviceType><friendlyName>OnHub</friendlyName><manufacturer>Google</manufacturer><manufacturerURL>http://google.com/</manufacturerURL><modelDescription>Wireless Router</modelDescription><modelName>OnHub</modelName><modelNumber>1</modelNumber><modelURL>https://on.google.com/hub/</modelURL><serialNumber>00000000</serialNumber><UDN>uuid:a9708184-a6c0-413a-bbac-11bcf7e30ece</UDN><serviceList><service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType><serviceId>urn:upnp-org:serviceId:Layer3Forwarding1</serviceId><controlURL>/ctl/L3F</controlURL><eventSubURL>/evt/L3F</eventSubURL><SCPDURL>/L3F.xml</SCPDURL></service><service><serviceType>urn:schemas-upnp-org:service:DeviceProtection:1</serviceType><serviceId>urn:upnp-org:serviceId:DeviceProtection1</serviceId><controlURL>/ctl/DP</controlURL><eventSubURL>/evt/DP</eventSubURL><SCPDURL>/DP.xml</SCPDURL></service></serviceList><deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:2</deviceType><friendlyName>WANDevice</friendlyName><manufacturer>MiniUPnP</manufacturer><manufacturerURL>http://miniupnp.free.fr/</manufacturerURL><modelDescription>WAN Device</modelDescription><modelName>WAN Device</modelName><modelNumber>20210414</modelNumber><modelURL>http://miniupnp.free.fr/</modelURL><serialNumber>00000000</serialNumber><UDN>uuid:a9708184-a6c0-413a-bbac-11bcf7e30ecf</UDN><UPC>000000000000</UPC><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType><serviceId>urn:upnp-org:serviceId:WANCommonIFC1</serviceId><controlURL>/ctl/CmnIfCfg</controlURL><eventSubURL>/evt/CmnIfCfg</eventSubURL><SCPDURL>/WANCfg.xml</SCPDURL></service></serviceList><deviceList><device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:2</deviceType><friendlyName>WANConnectionDevice</friendlyName><manufacturer>MiniUPnP</manufacturer><manufacturerURL>http://miniupnp.free.fr/</manufacturerURL><modelDescription>MiniUPnP daemon</modelDescription><modelName>MiniUPnPd</modelName><modelNumber>20210414</modelNumber><modelURL>http://miniupnp.free.fr/</modelURL><serialNumber>00000000</serialNumber><UDN>uuid:a9708184-a6c0-413a-bbac-11bcf7e30ec0</UDN><UPC>000000000000</UPC><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:2</serviceType><serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId><controlURL>/ctl/IPConn</controlURL><eventSubURL>/evt/IPConn</eventSubURL><SCPDURL>/WANIPCn.xml</SCPDURL></service></serviceList></device></deviceList></device></deviceList><presentationURL>http://testwifi.here/</presentationURL></device></root>`
)

// pfSense 2.5.0-RELEASE / FreeBSD 12.2-STABLE
const (
	pfSenseUPnPDisco = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nUSN: uuid:bee7052b-49e8-3597-b545-55a1e38ac11::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nEXT:\r\nSERVER: FreeBSD/12.2-STABLE UPnP/1.1 MiniUPnPd/2.2.1\r\nLOCATION: http://192.168.1.1:2189/rootDesc.xml\r\nOPT: \"http://schemas.upnp.org/upnp/1/0/\"; ns=01\r\n01-NLS: 1627958564\r\nBOOTID.UPNP.ORG: 1627958564\r\nCONFIGID.UPNP.ORG: 1337\r\n\r\n"

	pfSenseRootDescXML = `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0" configId="1337"><specVersion><major>1</major><minor>1</minor></specVersion><device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType><friendlyName>FreeBSD router</friendlyName><manufacturer>FreeBSD</manufacturer><manufacturerURL>http://www.freebsd.org/</manufacturerURL><modelDescription>FreeBSD router</modelDescription><modelName>FreeBSD router</modelName><modelNumber>2.5.0-RELEASE</modelNumber><modelURL>http://www.freebsd.org/</modelURL><serialNumber>BEE7052B</serialNumber><UDN>uuid:bee7052b-49e8-3597-b545-55a1e38ac11</UDN><serviceList><service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType><serviceId>urn:upnp-org:serviceId:L3Forwarding1</serviceId><SCPDURL>/L3F.xml</SCPDURL><controlURL>/ctl/L3F</controlURL><eventSubURL>/evt/L3F</eventSubURL></service></serviceList><deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType><friendlyName>WANDevice</friendlyName><manufacturer>MiniUPnP</manufacturer><manufacturerURL>http://miniupnp.free.fr/</manufacturerURL><modelDescription>WAN Device</modelDescription><modelName>WAN Device</modelName><modelNumber>20210205</modelNumber><modelURL>http://miniupnp.free.fr/</modelURL><serialNumber>BEE7052B</serialNumber><UDN>uuid:bee7052b-49e8-3597-b545-55a1e38ac12</UDN><UPC>000000000000</UPC><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType><serviceId>urn:upnp-org:serviceId:WANCommonIFC1</serviceId><SCPDURL>/WANCfg.xml</SCPDURL><controlURL>/ctl/CmnIfCfg</controlURL><eventSubURL>/evt/CmnIfCfg</eventSubURL></service></serviceList><deviceList><device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType><friendlyName>WANConnectionDevice</friendlyName><manufacturer>MiniUPnP</manufacturer><manufacturerURL>http://miniupnp.free.fr/</manufacturerURL><modelDescription>MiniUPnP daemon</modelDescription><modelName>MiniUPnPd</modelName><modelNumber>20210205</modelNumber><modelURL>http://miniupnp.free.fr/</modelURL><serialNumber>BEE7052B</serialNumber><UDN>uuid:bee7052b-49e8-3597-b545-55a1e38ac13</UDN><UPC>000000000000</UPC><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId><SCPDURL>/WANIPCn.xml</SCPDURL><controlURL>/ctl/IPConn</controlURL><eventSubURL>/evt/IPConn</eventSubURL></service></serviceList></device></deviceList></device></deviceList><presentationURL>https://192.168.1.1/</presentationURL></device></root>`
)

// Sagemcom FAST3890V3, https://github.com/tailscale/tailscale/issues/3557
const (
	sagemcomUPnPDisco = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nDATE: Tue, 14 Dec 2021 07:51:29 GMT\r\nEXT:\r\nLOCATION: http://192.168.0.1:49153/69692b70/gatedesc0b.xml\r\nOPT: \"http://schemas.upnp.org/upnp/1/0/\"; ns=01\r\n01-NLS: cabd6488-1dd1-11b2-9e52-a7461e1f098e\r\nSERVER: \r\nUser-Agent: redsonic\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nUSN: uuid:75802409-bccb-40e7-8e6c-fa095ecce13e::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
)

func TestParseUPnPDiscoResponse(t *testing.T) {
	tests := []struct {
		name    string
		headers string
		want    uPnPDiscoResponse
	}{
		{"google", googleWifiUPnPDisco, uPnPDiscoResponse{
			Location: "http://192.168.86.1:5000/rootDesc.xml",
			Server:   "Linux/5.4.0-1034-gcp UPnP/1.1 MiniUPnPd/1.9",
			USN:      "uuid:a9708184-a6c0-413a-bbac-11bcf7e30ece::urn:schemas-upnp-org:device:InternetGatewayDevice:2",
		}},
		{"pfsense", pfSenseUPnPDisco, uPnPDiscoResponse{
			Location: "http://192.168.1.1:2189/rootDesc.xml",
			Server:   "FreeBSD/12.2-STABLE UPnP/1.1 MiniUPnPd/2.2.1",
			USN:      "uuid:bee7052b-49e8-3597-b545-55a1e38ac11::urn:schemas-upnp-org:device:InternetGatewayDevice:1",
		}},
		{"sagemcom", sagemcomUPnPDisco, uPnPDiscoResponse{
			Location: "http://192.168.0.1:49153/69692b70/gatedesc0b.xml",
			Server:   "",
			USN:      "uuid:75802409-bccb-40e7-8e6c-fa095ecce13e::urn:schemas-upnp-org:device:InternetGatewayDevice:1",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseUPnPDiscoResponse([]byte(tt.headers))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("unexpected result:\n got: %+v\nwant: %+v\n", got, tt.want)
			}
		})
	}
}

func TestGetUPnPClient(t *testing.T) {
	tests := []struct {
		name    string
		xmlBody string
		want    string
		wantLog string
	}{
		{
			"google",
			googleWifiRootDescXML,
			"*internetgateway2.WANIPConnection2",
			"saw UPnP type WANIPConnection2 at http://127.0.0.1:NNN/rootDesc.xml; OnHub (Google)\n",
		},
		{
			"pfsense",
			pfSenseRootDescXML,
			"*internetgateway2.WANIPConnection1",
			"saw UPnP type WANIPConnection1 at http://127.0.0.1:NNN/rootDesc.xml; FreeBSD router (FreeBSD)\n",
		},
		// TODO(bradfitz): find a PPP one in the wild
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.RequestURI == "/rootDesc.xml" {
					io.WriteString(w, tt.xmlBody)
					return
				}
				http.NotFound(w, r)
			}))
			defer ts.Close()
			gw, _ := netip.AddrFromSlice(ts.Listener.Addr().(*net.TCPAddr).IP)
			gw = gw.Unmap()
			var logBuf tstest.MemLogger
			c, err := getUPnPClient(context.Background(), logBuf.Logf, gw, uPnPDiscoResponse{
				Location: ts.URL + "/rootDesc.xml",
			})
			if err != nil {
				t.Fatal(err)
			}
			got := fmt.Sprintf("%T", c)
			if got != tt.want {
				t.Errorf("got %v; want %v", got, tt.want)
			}
			gotLog := regexp.MustCompile(`127\.0\.0\.1:\d+`).ReplaceAllString(logBuf.String(), "127.0.0.1:NNN")
			if gotLog != tt.wantLog {
				t.Errorf("logged %q; want %q", gotLog, tt.wantLog)
			}
		})
	}
}
