package main

// DCP contains extra metadata to use when generating DCP source files.
type DCPMetadata struct {
	Name         string // What to name the Go DCP package.
	OfficialName string // Official name for the DCP.
	DocURL       string // Optional - URL for further documentation about the DCP.
	XMLSpecURL   string // Where to download the XML spec from.
	// Any special-case functions to run against the DCP before writing it out.
	Hacks []DCPHackFn
}

var dcpMetadata = []DCPMetadata{
	{
		Name:         "internetgateway1",
		OfficialName: "Internet Gateway Device v1",
		DocURL:       "http://upnp.org/specs/gw/UPnP-gw-InternetGatewayDevice-v1-Device.pdf",
		XMLSpecURL:   "http://upnp.org/specs/gw/UPnP-gw-IGD-TestFiles-20010921.zip",
		Hacks:        []DCPHackFn{totalBytesHack},
	},
	{
		Name:         "internetgateway2",
		OfficialName: "Internet Gateway Device v2",
		DocURL:       "http://upnp.org/specs/gw/UPnP-gw-InternetGatewayDevice-v2-Device.pdf",
		XMLSpecURL:   "http://upnp.org/specs/gw/UPnP-gw-IGD-Testfiles-20110224.zip",
		Hacks: []DCPHackFn{
			func(dcp *DCP) error {
				missingURN := "urn:schemas-upnp-org:service:WANIPv6FirewallControl:1"
				if _, ok := dcp.ServiceTypes[missingURN]; ok {
					return nil
				}
				urnParts, err := extractURNParts(missingURN, serviceURNPrefix)
				if err != nil {
					return err
				}
				dcp.ServiceTypes[missingURN] = urnParts
				return nil
			}, totalBytesHack,
		},
	},
	{
		Name:         "av1",
		OfficialName: "MediaServer v1 and MediaRenderer v1",
		DocURL:       "http://upnp.org/specs/av/av1/",
		XMLSpecURL:   "http://upnp.org/specs/av/UPnP-av-TestFiles-20070927.zip",
	},
}

func totalBytesHack(dcp *DCP) error {
	for _, service := range dcp.Services {
		if service.URN == "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1" {
			variables := service.SCPD.StateVariables
			for key, variable := range variables {
				varName := variable.Name
				if varName == "TotalBytesSent" || varName == "TotalBytesReceived" {
					// Fix size of total bytes which is by default ui4 or maximum 4 GiB.
					variable.DataType.Name = "ui8"
					variables[key] = variable
				}
			}

			break
		}
	}

	return nil
}

type DCPHackFn func(*DCP) error
