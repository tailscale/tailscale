// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package portmapper

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"regexp"
	"slices"
	"sync/atomic"
	"testing"

	"tailscale.com/tstest"
)

// Google Wifi
const (
	googleWifiUPnPDisco = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:2\r\nUSN: uuid:a9708184-a6c0-413a-bbac-11bcf7e30ece::urn:schemas-upnp-org:device:InternetGatewayDevice:2\r\nEXT:\r\nSERVER: Linux/5.4.0-1034-gcp UPnP/1.1 MiniUPnPd/1.9\r\nLOCATION: http://192.168.86.1:5000/rootDesc.xml\r\nOPT: \"http://schemas.upnp.org/upnp/1/0/\"; ns=01\r\n01-NLS: 1\r\nBOOTID.UPNP.ORG: 1\r\nCONFIGID.UPNP.ORG: 1337\r\n\r\n"

	googleWifiRootDescXML = `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><specVersion><major>1</major><minor>0</minor></specVersion><device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:2</deviceType><friendlyName>OnHub</friendlyName><manufacturer>Google</manufacturer><manufacturerURL>http://google.com/</manufacturerURL><modelDescription>Wireless Router</modelDescription><modelName>OnHub</modelName><modelNumber>1</modelNumber><modelURL>https://on.google.com/hub/</modelURL><serialNumber>00000000</serialNumber><UDN>uuid:a9708184-a6c0-413a-bbac-11bcf7e30ece</UDN><serviceList><service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType><serviceId>urn:upnp-org:serviceId:Layer3Forwarding1</serviceId><controlURL>/ctl/L3F</controlURL><eventSubURL>/evt/L3F</eventSubURL><SCPDURL>/L3F.xml</SCPDURL></service><service><serviceType>urn:schemas-upnp-org:service:DeviceProtection:1</serviceType><serviceId>urn:upnp-org:serviceId:DeviceProtection1</serviceId><controlURL>/ctl/DP</controlURL><eventSubURL>/evt/DP</eventSubURL><SCPDURL>/DP.xml</SCPDURL></service></serviceList><deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:2</deviceType><friendlyName>WANDevice</friendlyName><manufacturer>MiniUPnP</manufacturer><manufacturerURL>http://miniupnp.free.fr/</manufacturerURL><modelDescription>WAN Device</modelDescription><modelName>WAN Device</modelName><modelNumber>20210414</modelNumber><modelURL>http://miniupnp.free.fr/</modelURL><serialNumber>00000000</serialNumber><UDN>uuid:a9708184-a6c0-413a-bbac-11bcf7e30ecf</UDN><UPC>000000000000</UPC><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType><serviceId>urn:upnp-org:serviceId:WANCommonIFC1</serviceId><controlURL>/ctl/CmnIfCfg</controlURL><eventSubURL>/evt/CmnIfCfg</eventSubURL><SCPDURL>/WANCfg.xml</SCPDURL></service></serviceList><deviceList><device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:2</deviceType><friendlyName>WANConnectionDevice</friendlyName><manufacturer>MiniUPnP</manufacturer><manufacturerURL>http://miniupnp.free.fr/</manufacturerURL><modelDescription>MiniUPnP daemon</modelDescription><modelName>MiniUPnPd</modelName><modelNumber>20210414</modelNumber><modelURL>http://miniupnp.free.fr/</modelURL><serialNumber>00000000</serialNumber><UDN>uuid:a9708184-a6c0-413a-bbac-11bcf7e30ec0</UDN><UPC>000000000000</UPC><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:2</serviceType><serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId><controlURL>/ctl/IPConn</controlURL><eventSubURL>/evt/IPConn</eventSubURL><SCPDURL>/WANIPCn.xml</SCPDURL></service></serviceList></device></deviceList></device></deviceList><presentationURL>http://testwifi.here/</presentationURL></device></root>`

	// pfSense 2.5.0-RELEASE / FreeBSD 12.2-STABLE
	pfSenseUPnPDisco = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nUSN: uuid:bee7052b-49e8-3597-b545-55a1e38ac11::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nEXT:\r\nSERVER: FreeBSD/12.2-STABLE UPnP/1.1 MiniUPnPd/2.2.1\r\nLOCATION: http://192.168.1.1:2189/rootDesc.xml\r\nOPT: \"http://schemas.upnp.org/upnp/1/0/\"; ns=01\r\n01-NLS: 1627958564\r\nBOOTID.UPNP.ORG: 1627958564\r\nCONFIGID.UPNP.ORG: 1337\r\n\r\n"

	pfSenseRootDescXML = `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0" configId="1337"><specVersion><major>1</major><minor>1</minor></specVersion><device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType><friendlyName>FreeBSD router</friendlyName><manufacturer>FreeBSD</manufacturer><manufacturerURL>http://www.freebsd.org/</manufacturerURL><modelDescription>FreeBSD router</modelDescription><modelName>FreeBSD router</modelName><modelNumber>2.5.0-RELEASE</modelNumber><modelURL>http://www.freebsd.org/</modelURL><serialNumber>BEE7052B</serialNumber><UDN>uuid:bee7052b-49e8-3597-b545-55a1e38ac11</UDN><serviceList><service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType><serviceId>urn:upnp-org:serviceId:L3Forwarding1</serviceId><SCPDURL>/L3F.xml</SCPDURL><controlURL>/ctl/L3F</controlURL><eventSubURL>/evt/L3F</eventSubURL></service></serviceList><deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType><friendlyName>WANDevice</friendlyName><manufacturer>MiniUPnP</manufacturer><manufacturerURL>http://miniupnp.free.fr/</manufacturerURL><modelDescription>WAN Device</modelDescription><modelName>WAN Device</modelName><modelNumber>20210205</modelNumber><modelURL>http://miniupnp.free.fr/</modelURL><serialNumber>BEE7052B</serialNumber><UDN>uuid:bee7052b-49e8-3597-b545-55a1e38ac12</UDN><UPC>000000000000</UPC><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType><serviceId>urn:upnp-org:serviceId:WANCommonIFC1</serviceId><SCPDURL>/WANCfg.xml</SCPDURL><controlURL>/ctl/CmnIfCfg</controlURL><eventSubURL>/evt/CmnIfCfg</eventSubURL></service></serviceList><deviceList><device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType><friendlyName>WANConnectionDevice</friendlyName><manufacturer>MiniUPnP</manufacturer><manufacturerURL>http://miniupnp.free.fr/</manufacturerURL><modelDescription>MiniUPnP daemon</modelDescription><modelName>MiniUPnPd</modelName><modelNumber>20210205</modelNumber><modelURL>http://miniupnp.free.fr/</modelURL><serialNumber>BEE7052B</serialNumber><UDN>uuid:bee7052b-49e8-3597-b545-55a1e38ac13</UDN><UPC>000000000000</UPC><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId><SCPDURL>/WANIPCn.xml</SCPDURL><controlURL>/ctl/IPConn</controlURL><eventSubURL>/evt/IPConn</eventSubURL></service></serviceList></device></deviceList></device></deviceList><presentationURL>https://192.168.1.1/</presentationURL></device></root>`

	// Sagemcom FAST3890V3, https://github.com/tailscale/tailscale/issues/3557
	sagemcomUPnPDisco = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nDATE: Tue, 14 Dec 2021 07:51:29 GMT\r\nEXT:\r\nLOCATION: http://192.168.0.1:49153/69692b70/gatedesc0b.xml\r\nOPT: \"http://schemas.upnp.org/upnp/1/0/\"; ns=01\r\n01-NLS: cabd6488-1dd1-11b2-9e52-a7461e1f098e\r\nSERVER: \r\nUser-Agent: redsonic\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nUSN: uuid:75802409-bccb-40e7-8e6c-fa095ecce13e::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"

	// Huawei, https://github.com/tailscale/tailscale/issues/6320
	huaweiUPnPDisco = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nDATE: Fri, 25 Nov 2022 07:04:37 GMT\r\nEXT:\r\nLOCATION: http://192.168.1.1:49652/49652gatedesc.xml\r\nOPT: \"http://schemas.upnp.org/upnp/1/0/\"; ns=01\r\n01-NLS: ce8dd8b0-732d-11be-a4a1-a2b26c8915fb\r\nSERVER: Linux/4.4.240, UPnP/1.0, Portable SDK for UPnP devices/1.12.1\r\nX-User-Agent: UPnP/1.0 DLNADOC/1.50\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nUSN: uuid:00e0fc37-2525-2828-2500-0C31DCD93368::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"

	// Mikrotik CHR v7.10, https://github.com/tailscale/tailscale/issues/8364
	mikrotikRootDescXML = `<?xml version="1.0"?>
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
    <iconList>
      <icon>
        <mimetype>image/gif</mimetype>
        <width>16</width>
        <height>16</height>
        <depth>8</depth>
        <url>/logo16.gif</url>
      </icon>
      <icon>
        <mimetype>image/gif</mimetype>
        <width>32</width>
        <height>32</height>
        <depth>8</depth>
        <url>/logo32.gif</url>
      </icon>
      <icon>
        <mimetype>image/gif</mimetype>
        <width>48</width>
        <height>48</height>
        <depth>8</depth>
        <url>/logo48.gif</url>
      </icon>
    </iconList>
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
    <disabledForTestPresentationURL>http://10.0.0.1/</disabledForTestPresentationURL>
    <presentationURL>http://127.0.0.1/</presentationURL>
  </device>
  <disabledForTestURLBase>http://10.0.0.1:2828</disabledForTestURLBase>
</root>
`

	// Huawei, https://github.com/tailscale/tailscale/issues/10911
	huaweiRootDescXML = `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion>
    <major>1</major>
    <minor>0</minor>
  </specVersion>
  <device>
    <deviceType>urn:dslforum-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>HG531 V1</friendlyName>
    <manufacturer>Huawei Technologies Co., Ltd.</manufacturer>
    <manufacturerURL>http://www.huawei.com</manufacturerURL>
    <modelDescription>Huawei Home Gateway</modelDescription>
    <modelName>HG531 V1</modelName>
    <modelNumber>Huawei Model</modelNumber>
    <modelURL>http://www.huawei.com</modelURL>
    <serialNumber>G6J8W15326003974</serialNumber>
    <UDN>uuid:00e0fc37-2626-2828-2600-587f668bdd9a</UDN>
    <UPC>000000000001</UPC>
    <serviceList>
      <service>
        <serviceType>urn:www-huawei-com:service:DeviceConfig:1</serviceType>
        <serviceId>urn:www-huawei-com:serviceId:DeviceConfig1</serviceId>
        <SCPDURL>/desc/DevCfg.xml</SCPDURL>
        <controlURL>/ctrlt/DeviceConfig_1</controlURL>
        <eventSubURL>/evt/DeviceConfig_1</eventSubURL>
      </service>
      <service>
        <serviceType>urn:dslforum-org:service:LANConfigSecurity:1</serviceType>
        <serviceId>urn:dslforum-org:serviceId:LANConfigSecurity1</serviceId>
        <SCPDURL>/desc/LANSec.xml</SCPDURL>
        <controlURL>/ctrlt/LANConfigSecurity_1</controlURL>
        <eventSubURL>/evt/LANConfigSecurity_1</eventSubURL>
      </service>
      <service>
        <serviceType>urn:dslforum-org:service:Layer3Forwarding:1</serviceType>
        <serviceId>urn:dslforum-org:serviceId:Layer3Forwarding1</serviceId>
        <SCPDURL>/desc/L3Fwd.xml</SCPDURL>
        <controlURL>/ctrlt/Layer3Forwarding_1</controlURL>
        <eventSubURL>/evt/Layer3Forwarding_1</eventSubURL>
      </service>
    </serviceList>
    <deviceList>
      <device>
        <deviceType>urn:dslforum-org:device:WANDevice:1</deviceType>
        <friendlyName>WANDevice</friendlyName>
        <manufacturer>Huawei Technologies Co., Ltd.</manufacturer>
        <manufacturerURL>http://www.huawei.com</manufacturerURL>
        <modelDescription>Huawei Home Gateway</modelDescription>
        <modelName>HG531 V1</modelName>
        <modelNumber>Huawei Model</modelNumber>
        <modelURL>http://www.huawei.com</modelURL>
        <serialNumber>G6J8W15326003974</serialNumber>
        <UDN>uuid:00e0fc37-2626-2828-2601-587f668bdd9a</UDN>
        <UPC>000000000001</UPC>
        <serviceList>
          <service>
            <serviceType>urn:dslforum-org:service:WANDSLInterfaceConfig:1</serviceType>
            <serviceId>urn:dslforum-org:serviceId:WANDSLInterfaceConfig1</serviceId>
            <SCPDURL>/desc/WanDslIfCfg.xml</SCPDURL>
            <controlURL>/ctrlt/WANDSLInterfaceConfig_1</controlURL>
            <eventSubURL>/evt/WANDSLInterfaceConfig_1</eventSubURL>
          </service>
          <service>
            <serviceType>urn:dslforum-org:service:WANCommonInterfaceConfig:1</serviceType>
            <serviceId>urn:dslforum-org:serviceId:WANCommonInterfaceConfig1</serviceId>
            <SCPDURL>/desc/WanCommonIfc1.xml</SCPDURL>
            <controlURL>/ctrlt/WANCommonInterfaceConfig_1</controlURL>
            <eventSubURL>/evt/WANCommonInterfaceConfig_1</eventSubURL>
          </service>
        </serviceList>
        <deviceList>
          <device>
            <deviceType>urn:dslforum-org:device:WANConnectionDevice:1</deviceType>
            <friendlyName>WANConnectionDevice</friendlyName>
            <manufacturer>Huawei Technologies Co., Ltd.</manufacturer>
            <manufacturerURL>http://www.huawei.com</manufacturerURL>
            <modelDescription>Huawei Home Gateway</modelDescription>
            <modelName>HG531 V1</modelName>
            <modelNumber>Huawei Model</modelNumber>
            <modelURL>http://www.huawei.com</modelURL>
            <serialNumber>G6J8W15326003974</serialNumber>
            <UDN>uuid:00e0fc37-2626-2828-2603-587f668bdd9a</UDN>
            <UPC>000000000001</UPC>
            <serviceList>
              <service>
                <serviceType>urn:dslforum-org:service:WANPPPConnection:1</serviceType>
                <serviceId>urn:dslforum-org:serviceId:WANPPPConnection1</serviceId>
                <SCPDURL>/desc/WanPppConn.xml</SCPDURL>
                <controlURL>/ctrlt/WANPPPConnection_1</controlURL>
                <eventSubURL>/evt/WANPPPConnection_1</eventSubURL>
              </service>
              <service>
                <serviceType>urn:dslforum-org:service:WANEthernetConnectionManagement:1</serviceType>
                <serviceId>urn:dslforum-org:serviceId:WANEthernetConnectionManagement1</serviceId>
                <SCPDURL>/desc/WanEthConnMgt.xml</SCPDURL>
                <controlURL>/ctrlt/WANEthernetConnectionManagement_1</controlURL>
                <eventSubURL>/evt/WANEthernetConnectionManagement_1</eventSubURL>
              </service>
              <service>
                <serviceType>urn:dslforum-org:service:WANDSLLinkConfig:1</serviceType>
                <serviceId>urn:dslforum-org:serviceId:WANDSLLinkConfig1</serviceId>
                <SCPDURL>/desc/WanDslLink.xml</SCPDURL>
                <controlURL>/ctrlt/WANDSLLinkConfig_1</controlURL>
                <eventSubURL>/evt/WANDSLLinkConfig_1</eventSubURL>
              </service>
            </serviceList>
          </device>
        </deviceList>
      </device>
      <device>
        <deviceType>urn:dslforum-org:device:LANDevice:1</deviceType>
        <friendlyName>LANDevice</friendlyName>
        <manufacturer>Huawei Technologies Co., Ltd.</manufacturer>
        <manufacturerURL>http://www.huawei.com</manufacturerURL>
        <modelDescription>Huawei Home Gateway</modelDescription>
        <modelName>HG531 V1</modelName>
        <modelNumber>Huawei Model</modelNumber>
        <modelURL>http://www.huawei.com</modelURL>
        <serialNumber>G6J8W15326003974</serialNumber>
        <UDN>uuid:00e0fc37-2626-2828-2602-587f668bdd9a</UDN>
        <UPC>000000000001</UPC>
        <serviceList>
          <service>
            <serviceType>urn:dslforum-org:service:WLANConfiguration:1</serviceType>
            <serviceId>urn:dslforum-org:serviceId:WLANConfiguration4</serviceId>
            <SCPDURL>/desc/WLANCfg.xml</SCPDURL>
            <controlURL>/ctrlt/WLANConfiguration_4</controlURL>
            <eventSubURL>/evt/WLANConfiguration_4</eventSubURL>
          </service>
          <service>
            <serviceType>urn:dslforum-org:service:WLANConfiguration:1</serviceType>
            <serviceId>urn:dslforum-org:serviceId:WLANConfiguration3</serviceId>
            <SCPDURL>/desc/WLANCfg.xml</SCPDURL>
            <controlURL>/ctrlt/WLANConfiguration_3</controlURL>
            <eventSubURL>/evt/WLANConfiguration_3</eventSubURL>
          </service>
          <service>
            <serviceType>urn:dslforum-org:service:WLANConfiguration:1</serviceType>
            <serviceId>urn:dslforum-org:serviceId:WLANConfiguration2</serviceId>
            <SCPDURL>/desc/WLANCfg.xml</SCPDURL>
            <controlURL>/ctrlt/WLANConfiguration_2</controlURL>
            <eventSubURL>/evt/WLANConfiguration_2</eventSubURL>
          </service>
          <service>
            <serviceType>urn:dslforum-org:service:WLANConfiguration:1</serviceType>
            <serviceId>urn:dslforum-org:serviceId:WLANConfiguration1</serviceId>
            <SCPDURL>/desc/WLANCfg.xml</SCPDURL>
            <controlURL>/ctrlt/WLANConfiguration_1</controlURL>
            <eventSubURL>/evt/WLANConfiguration_1</eventSubURL>
          </service>
          <service>
            <serviceType>urn:dslforum-org:service:LANHostConfigManagement:1</serviceType>
            <serviceId>urn:dslforum-org:serviceId:LANHostConfigManagement1</serviceId>
            <SCPDURL>/desc/LanHostCfgMgmt.xml</SCPDURL>
            <controlURL>/ctrlt/LANHostConfigManagement_1</controlURL>
            <eventSubURL>/evt/LANHostConfigManagement_1</eventSubURL>
          </service>
        </serviceList>
      </device>
    </deviceList>
    <presentationURL>http://127.0.0.1</presentationURL>
  </device>
</root>
`

	noSupportedServicesRootDesc = `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion>
    <major>1</major>
    <minor>0</minor>
  </specVersion>
  <device>
    <deviceType>urn:dslforum-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>Fake Router</friendlyName>
    <manufacturer>Tailscale, Inc</manufacturer>
    <manufacturerURL>http://www.tailscale.com</manufacturerURL>
    <modelDescription>Fake Router</modelDescription>
    <modelName>Test Model</modelName>
    <modelNumber>v1</modelNumber>
    <modelURL>http://www.tailscale.com</modelURL>
    <serialNumber>123456789</serialNumber>
    <UDN>uuid:11111111-2222-3333-4444-555555555555</UDN>
    <UPC>000000000001</UPC>
    <serviceList>
      <service>
        <serviceType>urn:schemas-microsoft-com:service:OSInfo:1</serviceType>
        <serviceId>urn:microsoft-com:serviceId:OSInfo1</serviceId>
        <SCPDURL>/osinfo.xml</SCPDURL>
        <controlURL>/upnp/control/aaaaaaaaaa/osinfo</controlURL>
        <eventSubURL>/upnp/event/aaaaaaaaaa/osinfo</eventSubURL>
      </service>
    </serviceList>
    <deviceList>
      <device>
	<deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
        <friendlyName>WANDevice</friendlyName>
        <manufacturer>Tailscale, Inc</manufacturer>
	<manufacturerURL>http://www.tailscale.com</manufacturerURL>
	<modelDescription>Tailscale Test Router</modelDescription>
	<modelName>Test Model</modelName>
	<modelNumber>v1</modelNumber>
	<modelURL>http://www.tailscale.com</modelURL>
	<serialNumber>123456789</serialNumber>
	<UDN>uuid:11111111-2222-3333-4444-555555555555</UDN>
        <UPC>000000000001</UPC>
        <serviceList>
          <service>
            <serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>
            <serviceId>urn:upnp-org:serviceId:WANCommonIFC1</serviceId>
            <controlURL>/ctl/bbbbbbbb</controlURL>
            <eventSubURL>/evt/bbbbbbbb</eventSubURL>
            <SCPDURL>/WANCfg.xml</SCPDURL>
          </service>
        </serviceList>
        <deviceList>
          <device>
	    <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
            <friendlyName>WANConnectionDevice</friendlyName>
	    <manufacturer>Tailscale, Inc</manufacturer>
	    <manufacturerURL>http://www.tailscale.com</manufacturerURL>
	    <modelDescription>Tailscale Test Router</modelDescription>
	    <modelName>Test Model</modelName>
	    <modelNumber>v1</modelNumber>
	    <modelURL>http://www.tailscale.com</modelURL>
	    <serialNumber>123456789</serialNumber>
	    <UDN>uuid:11111111-2222-3333-4444-555555555555</UDN>
            <UPC>000000000001</UPC>
            <serviceList>
              <service>
		<serviceType>urn:tailscale:service:SomethingElse:1</serviceType>
		<serviceId>urn:upnp-org:serviceId:TailscaleSomethingElse</serviceId>
                <SCPDURL>/desc/SomethingElse.xml</SCPDURL>
                <controlURL>/ctrlt/SomethingElse_1</controlURL>
                <eventSubURL>/evt/SomethingElse_1</eventSubURL>
              </service>
            </serviceList>
          </device>
        </deviceList>
      </device>
    </deviceList>
    <presentationURL>http://127.0.0.1</presentationURL>
  </device>
</root>
`
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
		{"huawei", huaweiUPnPDisco, uPnPDiscoResponse{
			Location: "http://192.168.1.1:49652/49652gatedesc.xml",
			Server:   "Linux/4.4.240, UPnP/1.0, Portable SDK for UPnP devices/1.12.1",
			USN:      "uuid:00e0fc37-2525-2828-2500-0C31DCD93368::urn:schemas-upnp-org:device:InternetGatewayDevice:1",
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
			"saw UPnP type WANIPConnection2 at http://127.0.0.1:NNN/rootDesc.xml; OnHub (Google), method=single\n",
		},
		{
			"pfsense",
			pfSenseRootDescXML,
			"*internetgateway2.WANIPConnection1",
			"saw UPnP type WANIPConnection1 at http://127.0.0.1:NNN/rootDesc.xml; FreeBSD router (FreeBSD), method=single\n",
		},
		{
			"mikrotik",
			mikrotikRootDescXML,
			"*internetgateway2.WANIPConnection1",
			"saw UPnP type WANIPConnection1 at http://127.0.0.1:NNN/rootDesc.xml; MikroTik Router (MikroTik), method=none\n",
		},
		{
			"huawei",
			huaweiRootDescXML,
			"*portmapper.legacyWANPPPConnection1",
			"saw UPnP type *portmapper.legacyWANPPPConnection1 at http://127.0.0.1:NNN/rootDesc.xml; HG531 V1 (Huawei Technologies Co., Ltd.), method=single\n",
		},
		{
			"not_supported",
			noSupportedServicesRootDesc,
			"<nil>",
			"",
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

			ctx := context.Background()

			var logBuf tstest.MemLogger
			dev, loc, err := getUPnPRootDevice(ctx, logBuf.Logf, DebugKnobs{}, gw, uPnPDiscoResponse{
				Location: ts.URL + "/rootDesc.xml",
			})
			if err != nil {
				t.Fatal(err)
			}
			c, err := selectBestService(ctx, logBuf.Logf, dev, loc)
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

func TestGetUPnPPortMapping(t *testing.T) {
	igd, err := NewTestIGD(t.Logf, TestIGDOptions{UPnP: true})
	if err != nil {
		t.Fatal(err)
	}
	defer igd.Close()

	// This is a very basic fake UPnP server handler.
	var sawRequestWithLease atomic.Bool
	handlers := map[string]any{
		"AddPortMapping": func(body []byte) (int, string) {
			// Decode a minimal body to determine whether we skip the request or not.
			var req struct {
				Protocol       string `xml:"NewProtocol"`
				InternalPort   string `xml:"NewInternalPort"`
				ExternalPort   string `xml:"NewExternalPort"`
				InternalClient string `xml:"NewInternalClient"`
				LeaseDuration  string `xml:"NewLeaseDuration"`
			}
			if err := xml.Unmarshal(body, &req); err != nil {
				t.Errorf("bad request: %v", err)
				return http.StatusBadRequest, "bad request"
			}

			if req.Protocol != "UDP" {
				t.Errorf(`got Protocol=%q, want "UDP"`, req.Protocol)
			}
			if req.LeaseDuration != "0" {
				// Return a fake error to ensure that we fall back to a permanent lease.
				sawRequestWithLease.Store(true)
				return http.StatusOK, testAddPortMappingPermanentLease
			}

			// Success!
			return http.StatusOK, testAddPortMappingResponse
		},
		"GetExternalIPAddress": testGetExternalIPAddressResponse,
		"GetStatusInfo":        testGetStatusInfoResponse,
		"DeletePortMapping":    "", // Do nothing for test
	}

	ctx := context.Background()

	rootDescsToTest := []string{testRootDesc, mikrotikRootDescXML}
	for _, rootDesc := range rootDescsToTest {
		igd.SetUPnPHandler(&upnpServer{
			t:    t,
			Desc: rootDesc,
			Control: map[string]map[string]any{
				"/ctl/IPConn":                          handlers,
				"/upnp/control/yomkmsnooi/wanipconn-1": handlers,
			},
		})

		c := newTestClient(t, igd)
		t.Logf("Listening on upnp=%v", c.testUPnPPort)
		defer c.Close()

		c.debug.VerboseLogs = true

		// Try twice to test the "cache previous mapping" logic.
		var (
			firstResponse netip.AddrPort
			prevPort      uint16
		)
		for i := range 2 {
			sawRequestWithLease.Store(false)
			mustProbeUPnP(t, ctx, c)

			gw, myIP, ok := c.gatewayAndSelfIP()
			if !ok {
				t.Fatalf("could not get gateway and self IP")
			}
			t.Logf("gw=%v myIP=%v", gw, myIP)

			ext, ok := c.getUPnPPortMapping(ctx, gw, netip.AddrPortFrom(myIP, 12345), prevPort)
			if !ok {
				t.Fatal("could not get UPnP port mapping")
			}
			if got, want := ext.Addr(), netip.MustParseAddr("123.123.123.123"); got != want {
				t.Errorf("bad external address; got %v want %v", got, want)
			}
			if !sawRequestWithLease.Load() {
				t.Errorf("wanted request with lease, but didn't see one")
			}
			if i == 0 {
				firstResponse = ext
				prevPort = ext.Port()
			} else if firstResponse != ext {
				t.Errorf("got different response on second attempt: (got) %v != %v (want)", ext, firstResponse)
			}
			t.Logf("external IP: %v", ext)
		}
	}
}

// TestGetUPnPPortMapping_NoValidServices tests that getUPnPPortMapping doesn't
// crash when a valid UPnP response with no supported services is discovered
// and parsed.
//
// See https://github.com/tailscale/tailscale/issues/10911
func TestGetUPnPPortMapping_NoValidServices(t *testing.T) {
	igd, err := NewTestIGD(t.Logf, TestIGDOptions{UPnP: true})
	if err != nil {
		t.Fatal(err)
	}
	defer igd.Close()

	igd.SetUPnPHandler(&upnpServer{
		t:    t,
		Desc: noSupportedServicesRootDesc,
	})

	c := newTestClient(t, igd)
	defer c.Close()
	c.debug.VerboseLogs = true

	ctx := context.Background()
	mustProbeUPnP(t, ctx, c)

	gw, myIP, ok := c.gatewayAndSelfIP()
	if !ok {
		t.Fatalf("could not get gateway and self IP")
	}

	// This shouldn't panic
	_, ok = c.getUPnPPortMapping(ctx, gw, netip.AddrPortFrom(myIP, 12345), 0)
	if ok {
		t.Fatal("did not expect to get UPnP port mapping")
	}
}

// Tests the legacy behaviour with the pre-UPnP standard portmapping service.
func TestGetUPnPPortMapping_Legacy(t *testing.T) {
	igd, err := NewTestIGD(t.Logf, TestIGDOptions{UPnP: true})
	if err != nil {
		t.Fatal(err)
	}
	defer igd.Close()

	// This is a very basic fake UPnP server handler.
	handlers := map[string]any{
		"AddPortMapping":       testLegacyAddPortMappingResponse,
		"GetExternalIPAddress": testLegacyGetExternalIPAddressResponse,
		"GetStatusInfo":        testLegacyGetStatusInfoResponse,
		"DeletePortMapping":    "", // Do nothing for test
	}

	igd.SetUPnPHandler(&upnpServer{
		t:    t,
		Desc: huaweiRootDescXML,
		Control: map[string]map[string]any{
			"/ctrlt/WANPPPConnection_1": handlers,
		},
	})

	c := newTestClient(t, igd)
	defer c.Close()
	c.debug.VerboseLogs = true

	ctx := context.Background()
	mustProbeUPnP(t, ctx, c)

	gw, myIP, ok := c.gatewayAndSelfIP()
	if !ok {
		t.Fatalf("could not get gateway and self IP")
	}

	ext, ok := c.getUPnPPortMapping(ctx, gw, netip.AddrPortFrom(myIP, 12345), 0)
	if !ok {
		t.Fatal("could not get UPnP port mapping")
	}
	if got, want := ext.Addr(), netip.MustParseAddr("123.123.123.123"); got != want {
		t.Errorf("bad external address; got %v want %v", got, want)
	}
}

func TestGetUPnPPortMappingNoResponses(t *testing.T) {
	igd, err := NewTestIGD(t.Logf, TestIGDOptions{UPnP: true})
	if err != nil {
		t.Fatal(err)
	}
	defer igd.Close()

	c := newTestClient(t, igd)
	t.Logf("Listening on upnp=%v", c.testUPnPPort)
	defer c.Close()

	c.debug.VerboseLogs = true

	// Do this before setting uPnPMetas since it invalidates those mappings
	// if gw/myIP change.
	gw, myIP, _ := c.gatewayAndSelfIP()

	t.Run("ErrorContactingUPnP", func(t *testing.T) {
		c.mu.Lock()
		c.uPnPMetas = []uPnPDiscoResponse{{
			Location: "http://127.0.0.1:1/does-not-exist.xml",
			Server:   "Tailscale-Test/1.0 UPnP/1.1 MiniUPnPd/2.2.1",
			USN:      "uuid:bee7052b-49e8-3597-b545-55a1e38ac11::urn:schemas-upnp-org:device:InternetGatewayDevice:2",
		}}
		c.mu.Unlock()

		_, ok := c.getUPnPPortMapping(context.Background(), gw, netip.AddrPortFrom(myIP, 12345), 0)
		if ok {
			t.Errorf("expected no mapping when there are no responses")
		}
	})
}

func TestProcessUPnPResponses(t *testing.T) {
	testCases := []struct {
		name      string
		responses []uPnPDiscoResponse
		want      []uPnPDiscoResponse
	}{
		{
			name: "single",
			responses: []uPnPDiscoResponse{{
				Location: "http://192.168.1.1:2828/control.xml",
				Server:   "Tailscale-Test/1.0 UPnP/1.1 MiniUPnPd/2.2.1",
				USN:      "uuid:bee7052b-49e8-3597-b545-55a1e38ac11::urn:schemas-upnp-org:device:InternetGatewayDevice:1",
			}},
			want: []uPnPDiscoResponse{{
				Location: "http://192.168.1.1:2828/control.xml",
				Server:   "Tailscale-Test/1.0 UPnP/1.1 MiniUPnPd/2.2.1",
				USN:      "uuid:bee7052b-49e8-3597-b545-55a1e38ac11::urn:schemas-upnp-org:device:InternetGatewayDevice:1",
			}},
		},
		{
			name: "multiple_with_same_location",
			responses: []uPnPDiscoResponse{
				{
					Location: "http://192.168.1.1:2828/control.xml",
					Server:   "Tailscale-Test/1.0 UPnP/1.1 MiniUPnPd/2.2.1",
					USN:      "uuid:bee7052b-49e8-3597-b545-55a1e38ac11::urn:schemas-upnp-org:device:InternetGatewayDevice:1",
				},
				{
					Location: "http://192.168.1.1:2828/control.xml",
					Server:   "Tailscale-Test/1.0 UPnP/1.1 MiniUPnPd/2.2.1",
					USN:      "uuid:bee7052b-49e8-3597-b545-55a1e38ac11::urn:schemas-upnp-org:device:InternetGatewayDevice:2",
				},
			},
			want: []uPnPDiscoResponse{{
				Location: "http://192.168.1.1:2828/control.xml",
				Server:   "Tailscale-Test/1.0 UPnP/1.1 MiniUPnPd/2.2.1",
				USN:      "uuid:bee7052b-49e8-3597-b545-55a1e38ac11::urn:schemas-upnp-org:device:InternetGatewayDevice:2",
			}},
		},
		{
			name: "multiple_with_different_location",
			responses: []uPnPDiscoResponse{
				{
					Location: "http://192.168.1.1:2828/control.xml",
					Server:   "Tailscale-Test/1.0 UPnP/1.1 MiniUPnPd/2.2.1",
					USN:      "uuid:bee7052b-49e8-3597-b545-55a1e38ac11::urn:schemas-upnp-org:device:InternetGatewayDevice:1",
				},
				{
					Location: "http://192.168.100.1:2828/control.xml",
					Server:   "Tailscale-Test/1.0 UPnP/1.1 MiniUPnPd/2.2.1",
					USN:      "uuid:bee7052b-49e8-3597-b545-55a1e38ac11::urn:schemas-upnp-org:device:InternetGatewayDevice:2",
				},
			},
			want: []uPnPDiscoResponse{
				// note: this sorts first because we prefer "InternetGatewayDevice:2"
				{
					Location: "http://192.168.100.1:2828/control.xml",
					Server:   "Tailscale-Test/1.0 UPnP/1.1 MiniUPnPd/2.2.1",
					USN:      "uuid:bee7052b-49e8-3597-b545-55a1e38ac11::urn:schemas-upnp-org:device:InternetGatewayDevice:2",
				},
				{
					Location: "http://192.168.1.1:2828/control.xml",
					Server:   "Tailscale-Test/1.0 UPnP/1.1 MiniUPnPd/2.2.1",
					USN:      "uuid:bee7052b-49e8-3597-b545-55a1e38ac11::urn:schemas-upnp-org:device:InternetGatewayDevice:1",
				},
			},
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			got := processUPnPResponses(slices.Clone(tt.responses))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("unexpected result:\n got: %+v\nwant: %+v\n", got, tt.want)
			}
		})
	}
}

// See: https://github.com/tailscale/corp/issues/23538
func TestGetUPnPPortMapping_Invalid(t *testing.T) {
	for _, responseAddr := range []string{
		"0.0.0.0",
		"127.0.0.1",
	} {
		t.Run(responseAddr, func(t *testing.T) {
			igd, err := NewTestIGD(t.Logf, TestIGDOptions{UPnP: true})
			if err != nil {
				t.Fatal(err)
			}
			defer igd.Close()

			// This is a very basic fake UPnP server handler.
			handlers := map[string]any{
				"AddPortMapping":       testAddPortMappingResponse,
				"GetExternalIPAddress": makeGetExternalIPAddressResponse(responseAddr),
				"GetStatusInfo":        testGetStatusInfoResponse,
				"DeletePortMapping":    "", // Do nothing for test
			}

			igd.SetUPnPHandler(&upnpServer{
				t:    t,
				Desc: huaweiRootDescXML,
				Control: map[string]map[string]any{
					"/ctrlt/WANPPPConnection_1": handlers,
				},
			})

			c := newTestClient(t, igd)
			defer c.Close()
			c.debug.VerboseLogs = true

			ctx := context.Background()
			mustProbeUPnP(t, ctx, c)

			gw, myIP, ok := c.gatewayAndSelfIP()
			if !ok {
				t.Fatalf("could not get gateway and self IP")
			}

			ext, ok := c.getUPnPPortMapping(ctx, gw, netip.AddrPortFrom(myIP, 12345), 0)
			if ok {
				t.Fatal("did not expect to get UPnP port mapping")
			}
			if ext.IsValid() {
				t.Fatalf("expected no external address; got %v", ext)
			}
		})
	}
}

type upnpServer struct {
	t       *testing.T
	Desc    string                    // root device XML
	Control map[string]map[string]any // map["/url"]map["UPnPService"]response
}

func (u *upnpServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.t.Logf("got UPnP request %s %s", r.Method, r.URL.Path)
	if r.URL.Path == "/rootDesc.xml" {
		io.WriteString(w, u.Desc)
		return
	}
	if control, ok := u.Control[r.URL.Path]; ok {
		u.handleControl(w, r, control)
		return
	}

	u.t.Logf("ignoring request")
	http.NotFound(w, r)
}

func (u *upnpServer) handleControl(w http.ResponseWriter, r *http.Request, handlers map[string]any) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		u.t.Errorf("error reading request body: %v", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Decode the request type.
	var outerRequest struct {
		Body struct {
			Request struct {
				XMLName xml.Name
			} `xml:",any"`
			Inner string `xml:",innerxml"`
		} `xml:"Body"`
	}
	if err := xml.Unmarshal(body, &outerRequest); err != nil {
		u.t.Errorf("bad request: %v", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	requestType := outerRequest.Body.Request.XMLName.Local
	upnpRequest := outerRequest.Body.Inner
	u.t.Logf("UPnP request: %s", requestType)

	handler, ok := handlers[requestType]
	if !ok {
		u.t.Errorf("unhandled UPnP request type %q", requestType)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	switch v := handler.(type) {
	case string:
		io.WriteString(w, v)
	case []byte:
		w.Write(v)

	// Function handlers
	case func(string) string:
		io.WriteString(w, v(upnpRequest))
	case func([]byte) string:
		io.WriteString(w, v([]byte(upnpRequest)))

	case func(string) (int, string):
		code, body := v(upnpRequest)
		w.WriteHeader(code)
		io.WriteString(w, body)
	case func([]byte) (int, string):
		code, body := v([]byte(upnpRequest))
		w.WriteHeader(code)
		io.WriteString(w, body)

	default:
		u.t.Fatalf("invalid handler type: %T", v)
		http.Error(w, "invalid handler type", http.StatusInternalServerError)
		return
	}
}

func mustProbeUPnP(tb testing.TB, ctx context.Context, c *Client) ProbeResult {
	tb.Helper()
	res, err := c.Probe(ctx)
	if err != nil {
		tb.Fatalf("Probe: %v", err)
	}
	if !res.UPnP {
		tb.Fatalf("didn't detect UPnP")
	}
	return res
}

const testRootDesc = `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0" configId="1337">
  <specVersion>
    <major>1</major>
    <minor>1</minor>
  </specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>Tailscale Test Router</friendlyName>
    <manufacturer>Tailscale</manufacturer>
    <manufacturerURL>https://tailscale.com</manufacturerURL>
    <modelDescription>Tailscale Test Router</modelDescription>
    <modelName>Tailscale Test Router</modelName>
    <modelNumber>2.5.0-RELEASE</modelNumber>
    <modelURL>https://tailscale.com</modelURL>
    <serialNumber>1234</serialNumber>
    <UDN>uuid:1974e83b-6dc7-4635-92b3-6a85a4037294</UDN>
    <deviceList>
      <device>
	<deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
	<friendlyName>WANDevice</friendlyName>
	<manufacturer>MiniUPnP</manufacturer>
	<manufacturerURL>http://miniupnp.free.fr/</manufacturerURL>
	<modelDescription>WAN Device</modelDescription>
	<modelName>WAN Device</modelName>
	<modelNumber>20990102</modelNumber>
	<modelURL>http://miniupnp.free.fr/</modelURL>
	<serialNumber>1234</serialNumber>
	<UDN>uuid:1974e83b-6dc7-4635-92b3-6a85a4037294</UDN>
	<UPC>000000000000</UPC>
	<deviceList>
	  <device>
	    <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
	    <friendlyName>WANConnectionDevice</friendlyName>
	    <manufacturer>MiniUPnP</manufacturer>
	    <manufacturerURL>http://miniupnp.free.fr/</manufacturerURL>
	    <modelDescription>MiniUPnP daemon</modelDescription>
	    <modelName>MiniUPnPd</modelName>
	    <modelNumber>20210205</modelNumber>
	    <modelURL>http://miniupnp.free.fr/</modelURL>
	    <serialNumber>1234</serialNumber>
	    <UDN>uuid:1974e83b-6dc7-4635-92b3-6a85a4037294</UDN>
	    <UPC>000000000000</UPC>
	    <serviceList>
	      <service>
		<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
		<serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
		<SCPDURL>/WANIPCn.xml</SCPDURL>
		<controlURL>/ctl/IPConn</controlURL>
		<eventSubURL>/evt/IPConn</eventSubURL>
	      </service>
	    </serviceList>
	  </device>
	</deviceList>
      </device>
    </deviceList>
    <presentationURL>https://127.0.0.1/</presentationURL>
  </device>
</root>
`

const testAddPortMappingPermanentLease = `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <s:Fault>
      <faultCode>s:Client</faultCode>
      <faultString>UPnPError</faultString>
      <detail>
        <UPnPError xmlns="urn:schemas-upnp-org:control-1-0">
          <errorCode>725</errorCode>
          <errorDescription>OnlyPermanentLeasesSupported</errorDescription>
        </UPnPError>
      </detail>
    </s:Fault>
  </s:Body>
</s:Envelope>
`

const testAddPortMappingResponse = `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:AddPortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"/>
  </s:Body>
</s:Envelope>
`

const testGetExternalIPAddressResponse = `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewExternalIPAddress>123.123.123.123</NewExternalIPAddress>
    </u:GetExternalIPAddressResponse>
  </s:Body>
</s:Envelope>
`

const testGetStatusInfoResponse = `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:GetStatusInfoResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewConnectionStatus>Connected</NewConnectionStatus>
      <NewLastConnectionError>ERROR_NONE</NewLastConnectionError>
      <NewUptime>9999</NewUptime>
    </u:GetStatusInfoResponse>
  </s:Body>
</s:Envelope>
`

const testLegacyAddPortMappingResponse = `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:AddPortMappingResponse xmlns:u="urn:dslforum-org:service:WANPPPConnection:1"/>
  </s:Body>
</s:Envelope>
`

const testLegacyGetExternalIPAddressResponse = `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:GetExternalIPAddressResponse xmlns:u="urn:dslforum-org:service:WANPPPConnection:1">
      <NewExternalIPAddress>123.123.123.123</NewExternalIPAddress>
    </u:GetExternalIPAddressResponse>
  </s:Body>
</s:Envelope>
`

const testLegacyGetStatusInfoResponse = `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:GetStatusInfoResponse xmlns:u="urn:dslforum-org:service:WANPPPConnection:1">
      <NewConnectionStatus>Connected</NewConnectionStatus>
      <NewLastConnectionError>ERROR_NONE</NewLastConnectionError>
      <NewUpTime>9999</NewUpTime>
    </u:GetStatusInfoResponse>
  </s:Body>
</s:Envelope>
`

func makeGetExternalIPAddressResponse(ip string) string {
	return fmt.Sprintf(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewExternalIPAddress>%s</NewExternalIPAddress>
    </u:GetExternalIPAddressResponse>
  </s:Body>
</s:Envelope>
`, ip)
}
