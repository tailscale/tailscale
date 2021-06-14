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
			func(dcp *DCP) error {
				// omit certain device types that we do not need
				var allowedServices = map[string]bool{
					"urn:schemas-upnp-org:service:WANIPConnection:1":  true,
					"urn:schemas-upnp-org:service:WANIPConnection:2":  true,
					"urn:schemas-upnp-org:service:WANPPPConnection:1": true,
				}
				var allowedParts = map[string]bool{
					"WANIPConnection":  true,
					"WANPPPConnection": true,
				}
				for service := range dcp.ServiceTypes {
					if _, ok := allowedServices[service]; ok {
						continue
					}
					delete(dcp.ServiceTypes, service)
				}
				var permitted []SCPDWithURN
				for _, v := range dcp.Services {
					if _, ok := allowedParts[v.URNParts.Name]; ok {
						permitted = append(permitted, v)
						continue
					}
				}
				dcp.Services = permitted
				return nil
			},
		},
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
