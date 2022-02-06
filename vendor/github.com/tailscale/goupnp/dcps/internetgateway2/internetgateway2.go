// Client for UPnP Device Control Protocol Internet Gateway Device v2.
//
// This DCP is documented in detail at: http://upnp.org/specs/gw/UPnP-gw-InternetGatewayDevice-v2-Device.pdf
//
// Typically, use one of the New* functions to create clients for services.
package internetgateway2

// ***********************************************************
// GENERATED FILE - DO NOT EDIT BY HAND. See README.md
// ***********************************************************

import (
	"context"
	"net/url"
	"time"

	"github.com/tailscale/goupnp"
	"github.com/tailscale/goupnp/soap"
)

// Hack to avoid Go complaining if time isn't used.
var _ time.Time

// Device URNs:
const (
	URN_LANDevice_1           = "urn:schemas-upnp-org:device:LANDevice:1"
	URN_WANConnectionDevice_1 = "urn:schemas-upnp-org:device:WANConnectionDevice:1"
	URN_WANConnectionDevice_2 = "urn:schemas-upnp-org:device:WANConnectionDevice:2"
	URN_WANDevice_1           = "urn:schemas-upnp-org:device:WANDevice:1"
	URN_WANDevice_2           = "urn:schemas-upnp-org:device:WANDevice:2"
)

// Service URNs:
const (
	URN_WANIPConnection_1  = "urn:schemas-upnp-org:service:WANIPConnection:1"
	URN_WANIPConnection_2  = "urn:schemas-upnp-org:service:WANIPConnection:2"
	URN_WANPPPConnection_1 = "urn:schemas-upnp-org:service:WANPPPConnection:1"
)

// WANIPConnection1 is a client for UPnP SOAP service with URN "urn:schemas-upnp-org:service:WANIPConnection:1". See
// goupnp.ServiceClient, which contains RootDevice and Service attributes which
// are provided for informational value.
type WANIPConnection1 struct {
	goupnp.ServiceClient
}

// NewWANIPConnection1Clients discovers instances of the service on the network,
// and returns clients to any that are found. errors will contain an error for
// any devices that replied but which could not be queried, and err will be set
// if the discovery process failed outright.
//
// This is a typical entry calling point into this package.
func NewWANIPConnection1Clients(ctx context.Context) (clients []*WANIPConnection1, errors []error, err error) {
	var genericClients []goupnp.ServiceClient
	if genericClients, errors, err = goupnp.NewServiceClients(ctx, URN_WANIPConnection_1); err != nil {
		return
	}
	clients = newWANIPConnection1ClientsFromGenericClients(genericClients)
	return
}

// NewWANIPConnection1ClientsByURL discovers instances of the service at the given
// URL, and returns clients to any that are found. An error is returned if
// there was an error probing the service.
//
// This is a typical entry calling point into this package when reusing an
// previously discovered service URL.
func NewWANIPConnection1ClientsByURL(ctx context.Context, loc *url.URL) ([]*WANIPConnection1, error) {
	genericClients, err := goupnp.NewServiceClientsByURL(ctx, loc, URN_WANIPConnection_1)
	if err != nil {
		return nil, err
	}
	return newWANIPConnection1ClientsFromGenericClients(genericClients), nil
}

// NewWANIPConnection1ClientsFromRootDevice discovers instances of the service in
// a given root device, and returns clients to any that are found. An error is
// returned if there was not at least one instance of the service within the
// device. The location parameter is simply assigned to the Location attribute
// of the wrapped ServiceClient(s).
//
// This is a typical entry calling point into this package when reusing an
// previously discovered root device.
func NewWANIPConnection1ClientsFromRootDevice(ctx context.Context, rootDevice *goupnp.RootDevice, loc *url.URL) ([]*WANIPConnection1, error) {
	genericClients, err := goupnp.NewServiceClientsFromRootDevice(ctx, rootDevice, loc, URN_WANIPConnection_1)
	if err != nil {
		return nil, err
	}
	return newWANIPConnection1ClientsFromGenericClients(genericClients), nil
}

func newWANIPConnection1ClientsFromGenericClients(genericClients []goupnp.ServiceClient) []*WANIPConnection1 {
	clients := make([]*WANIPConnection1, len(genericClients))
	for i := range genericClients {
		clients[i] = &WANIPConnection1{genericClients[i]}
	}
	return clients
}

func (client *WANIPConnection1) SetConnectionType(ctx context.Context, NewConnectionType string) (err error) {
	// Request structure.
	request := &struct {
		NewConnectionType string
	}{}
	// BEGIN Marshal arguments into request.

	if request.NewConnectionType, err = soap.MarshalString(NewConnectionType); err != nil {
		return
	}
	// END Marshal arguments into request.

	// Response structure.
	response := interface{}(nil)

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_1, "SetConnectionType", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	// END Unmarshal arguments from response.
	return
}

//
// Return values:
//
// * NewPossibleConnectionTypes: allowed values: Unconfigured, IP_Routed, IP_Bridged
func (client *WANIPConnection1) GetConnectionTypeInfo(ctx context.Context) (NewConnectionType string, NewPossibleConnectionTypes string, err error) {
	// Request structure.
	request := interface{}(nil)
	// BEGIN Marshal arguments into request.

	// END Marshal arguments into request.

	// Response structure.
	response := &struct {
		NewConnectionType          string
		NewPossibleConnectionTypes string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_1, "GetConnectionTypeInfo", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	if NewConnectionType, err = soap.UnmarshalString(response.NewConnectionType); err != nil {
		return
	}
	if NewPossibleConnectionTypes, err = soap.UnmarshalString(response.NewPossibleConnectionTypes); err != nil {
		return
	}
	// END Unmarshal arguments from response.
	return
}

func (client *WANIPConnection1) RequestConnection(ctx context.Context) (err error) {
	// Request structure.
	request := interface{}(nil)
	// BEGIN Marshal arguments into request.

	// END Marshal arguments into request.

	// Response structure.
	response := interface{}(nil)

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_1, "RequestConnection", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	// END Unmarshal arguments from response.
	return
}

func (client *WANIPConnection1) RequestTermination(ctx context.Context) (err error) {
	// Request structure.
	request := interface{}(nil)
	// BEGIN Marshal arguments into request.

	// END Marshal arguments into request.

	// Response structure.
	response := interface{}(nil)

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_1, "RequestTermination", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	// END Unmarshal arguments from response.
	return
}

func (client *WANIPConnection1) ForceTermination(ctx context.Context) (err error) {
	// Request structure.
	request := interface{}(nil)
	// BEGIN Marshal arguments into request.

	// END Marshal arguments into request.

	// Response structure.
	response := interface{}(nil)

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_1, "ForceTermination", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	// END Unmarshal arguments from response.
	return
}

func (client *WANIPConnection1) SetAutoDisconnectTime(ctx context.Context, NewAutoDisconnectTime uint32) (err error) {
	// Request structure.
	request := &struct {
		NewAutoDisconnectTime string
	}{}
	// BEGIN Marshal arguments into request.

	if request.NewAutoDisconnectTime, err = soap.MarshalUi4(NewAutoDisconnectTime); err != nil {
		return
	}
	// END Marshal arguments into request.

	// Response structure.
	response := interface{}(nil)

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_1, "SetAutoDisconnectTime", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	// END Unmarshal arguments from response.
	return
}

func (client *WANIPConnection1) SetIdleDisconnectTime(ctx context.Context, NewIdleDisconnectTime uint32) (err error) {
	// Request structure.
	request := &struct {
		NewIdleDisconnectTime string
	}{}
	// BEGIN Marshal arguments into request.

	if request.NewIdleDisconnectTime, err = soap.MarshalUi4(NewIdleDisconnectTime); err != nil {
		return
	}
	// END Marshal arguments into request.

	// Response structure.
	response := interface{}(nil)

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_1, "SetIdleDisconnectTime", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	// END Unmarshal arguments from response.
	return
}

func (client *WANIPConnection1) SetWarnDisconnectDelay(ctx context.Context, NewWarnDisconnectDelay uint32) (err error) {
	// Request structure.
	request := &struct {
		NewWarnDisconnectDelay string
	}{}
	// BEGIN Marshal arguments into request.

	if request.NewWarnDisconnectDelay, err = soap.MarshalUi4(NewWarnDisconnectDelay); err != nil {
		return
	}
	// END Marshal arguments into request.

	// Response structure.
	response := interface{}(nil)

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_1, "SetWarnDisconnectDelay", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	// END Unmarshal arguments from response.
	return
}

//
// Return values:
//
// * NewConnectionStatus: allowed values: Unconfigured, Connected, Disconnected
//
// * NewLastConnectionError: allowed values: ERROR_NONE
func (client *WANIPConnection1) GetStatusInfo(ctx context.Context) (NewConnectionStatus string, NewLastConnectionError string, NewUptime uint32, err error) {
	// Request structure.
	request := interface{}(nil)
	// BEGIN Marshal arguments into request.

	// END Marshal arguments into request.

	// Response structure.
	response := &struct {
		NewConnectionStatus    string
		NewLastConnectionError string
		NewUptime              string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_1, "GetStatusInfo", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	if NewConnectionStatus, err = soap.UnmarshalString(response.NewConnectionStatus); err != nil {
		return
	}
	if NewLastConnectionError, err = soap.UnmarshalString(response.NewLastConnectionError); err != nil {
		return
	}
	if NewUptime, err = soap.UnmarshalUi4(response.NewUptime); err != nil {
		return
	}
	// END Unmarshal arguments from response.
	return
}

func (client *WANIPConnection1) GetAutoDisconnectTime(ctx context.Context) (NewAutoDisconnectTime uint32, err error) {
	// Request structure.
	request := interface{}(nil)
	// BEGIN Marshal arguments into request.

	// END Marshal arguments into request.

	// Response structure.
	response := &struct {
		NewAutoDisconnectTime string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_1, "GetAutoDisconnectTime", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	if NewAutoDisconnectTime, err = soap.UnmarshalUi4(response.NewAutoDisconnectTime); err != nil {
		return
	}
	// END Unmarshal arguments from response.
	return
}

func (client *WANIPConnection1) GetIdleDisconnectTime(ctx context.Context) (NewIdleDisconnectTime uint32, err error) {
	// Request structure.
	request := interface{}(nil)
	// BEGIN Marshal arguments into request.

	// END Marshal arguments into request.

	// Response structure.
	response := &struct {
		NewIdleDisconnectTime string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_1, "GetIdleDisconnectTime", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	if NewIdleDisconnectTime, err = soap.UnmarshalUi4(response.NewIdleDisconnectTime); err != nil {
		return
	}
	// END Unmarshal arguments from response.
	return
}

func (client *WANIPConnection1) GetWarnDisconnectDelay(ctx context.Context) (NewWarnDisconnectDelay uint32, err error) {
	// Request structure.
	request := interface{}(nil)
	// BEGIN Marshal arguments into request.

	// END Marshal arguments into request.

	// Response structure.
	response := &struct {
		NewWarnDisconnectDelay string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_1, "GetWarnDisconnectDelay", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	if NewWarnDisconnectDelay, err = soap.UnmarshalUi4(response.NewWarnDisconnectDelay); err != nil {
		return
	}
	// END Unmarshal arguments from response.
	return
}

func (client *WANIPConnection1) GetNATRSIPStatus(ctx context.Context) (NewRSIPAvailable bool, NewNATEnabled bool, err error) {
	// Request structure.
	request := interface{}(nil)
	// BEGIN Marshal arguments into request.

	// END Marshal arguments into request.

	// Response structure.
	response := &struct {
		NewRSIPAvailable string
		NewNATEnabled    string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_1, "GetNATRSIPStatus", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	if NewRSIPAvailable, err = soap.UnmarshalBoolean(response.NewRSIPAvailable); err != nil {
		return
	}
	if NewNATEnabled, err = soap.UnmarshalBoolean(response.NewNATEnabled); err != nil {
		return
	}
	// END Unmarshal arguments from response.
	return
}

//
// Return values:
//
// * NewProtocol: allowed values: TCP, UDP
func (client *WANIPConnection1) GetGenericPortMappingEntry(ctx context.Context, NewPortMappingIndex uint16) (NewRemoteHost string, NewExternalPort uint16, NewProtocol string, NewInternalPort uint16, NewInternalClient string, NewEnabled bool, NewPortMappingDescription string, NewLeaseDuration uint32, err error) {
	// Request structure.
	request := &struct {
		NewPortMappingIndex string
	}{}
	// BEGIN Marshal arguments into request.

	if request.NewPortMappingIndex, err = soap.MarshalUi2(NewPortMappingIndex); err != nil {
		return
	}
	// END Marshal arguments into request.

	// Response structure.
	response := &struct {
		NewRemoteHost             string
		NewExternalPort           string
		NewProtocol               string
		NewInternalPort           string
		NewInternalClient         string
		NewEnabled                string
		NewPortMappingDescription string
		NewLeaseDuration          string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_1, "GetGenericPortMappingEntry", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	if NewRemoteHost, err = soap.UnmarshalString(response.NewRemoteHost); err != nil {
		return
	}
	if NewExternalPort, err = soap.UnmarshalUi2(response.NewExternalPort); err != nil {
		return
	}
	if NewProtocol, err = soap.UnmarshalString(response.NewProtocol); err != nil {
		return
	}
	if NewInternalPort, err = soap.UnmarshalUi2(response.NewInternalPort); err != nil {
		return
	}
	if NewInternalClient, err = soap.UnmarshalString(response.NewInternalClient); err != nil {
		return
	}
	if NewEnabled, err = soap.UnmarshalBoolean(response.NewEnabled); err != nil {
		return
	}
	if NewPortMappingDescription, err = soap.UnmarshalString(response.NewPortMappingDescription); err != nil {
		return
	}
	if NewLeaseDuration, err = soap.UnmarshalUi4(response.NewLeaseDuration); err != nil {
		return
	}
	// END Unmarshal arguments from response.
	return
}

//
// Arguments:
//
// * NewProtocol: allowed values: TCP, UDP

func (client *WANIPConnection1) GetSpecificPortMappingEntry(ctx context.Context, NewRemoteHost string, NewExternalPort uint16, NewProtocol string) (NewInternalPort uint16, NewInternalClient string, NewEnabled bool, NewPortMappingDescription string, NewLeaseDuration uint32, err error) {
	// Request structure.
	request := &struct {
		NewRemoteHost   string
		NewExternalPort string
		NewProtocol     string
	}{}
	// BEGIN Marshal arguments into request.

	if request.NewRemoteHost, err = soap.MarshalString(NewRemoteHost); err != nil {
		return
	}
	if request.NewExternalPort, err = soap.MarshalUi2(NewExternalPort); err != nil {
		return
	}
	if request.NewProtocol, err = soap.MarshalString(NewProtocol); err != nil {
		return
	}
	// END Marshal arguments into request.

	// Response structure.
	response := &struct {
		NewInternalPort           string
		NewInternalClient         string
		NewEnabled                string
		NewPortMappingDescription string
		NewLeaseDuration          string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_1, "GetSpecificPortMappingEntry", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	if NewInternalPort, err = soap.UnmarshalUi2(response.NewInternalPort); err != nil {
		return
	}
	if NewInternalClient, err = soap.UnmarshalString(response.NewInternalClient); err != nil {
		return
	}
	if NewEnabled, err = soap.UnmarshalBoolean(response.NewEnabled); err != nil {
		return
	}
	if NewPortMappingDescription, err = soap.UnmarshalString(response.NewPortMappingDescription); err != nil {
		return
	}
	if NewLeaseDuration, err = soap.UnmarshalUi4(response.NewLeaseDuration); err != nil {
		return
	}
	// END Unmarshal arguments from response.
	return
}

//
// Arguments:
//
// * NewProtocol: allowed values: TCP, UDP

func (client *WANIPConnection1) AddPortMapping(ctx context.Context, NewRemoteHost string, NewExternalPort uint16, NewProtocol string, NewInternalPort uint16, NewInternalClient string, NewEnabled bool, NewPortMappingDescription string, NewLeaseDuration uint32) (err error) {
	// Request structure.
	request := &struct {
		NewRemoteHost             string
		NewExternalPort           string
		NewProtocol               string
		NewInternalPort           string
		NewInternalClient         string
		NewEnabled                string
		NewPortMappingDescription string
		NewLeaseDuration          string
	}{}
	// BEGIN Marshal arguments into request.

	if request.NewRemoteHost, err = soap.MarshalString(NewRemoteHost); err != nil {
		return
	}
	if request.NewExternalPort, err = soap.MarshalUi2(NewExternalPort); err != nil {
		return
	}
	if request.NewProtocol, err = soap.MarshalString(NewProtocol); err != nil {
		return
	}
	if request.NewInternalPort, err = soap.MarshalUi2(NewInternalPort); err != nil {
		return
	}
	if request.NewInternalClient, err = soap.MarshalString(NewInternalClient); err != nil {
		return
	}
	if request.NewEnabled, err = soap.MarshalBoolean(NewEnabled); err != nil {
		return
	}
	if request.NewPortMappingDescription, err = soap.MarshalString(NewPortMappingDescription); err != nil {
		return
	}
	if request.NewLeaseDuration, err = soap.MarshalUi4(NewLeaseDuration); err != nil {
		return
	}
	// END Marshal arguments into request.

	// Response structure.
	response := interface{}(nil)

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_1, "AddPortMapping", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	// END Unmarshal arguments from response.
	return
}

//
// Arguments:
//
// * NewProtocol: allowed values: TCP, UDP

func (client *WANIPConnection1) DeletePortMapping(ctx context.Context, NewRemoteHost string, NewExternalPort uint16, NewProtocol string) (err error) {
	// Request structure.
	request := &struct {
		NewRemoteHost   string
		NewExternalPort string
		NewProtocol     string
	}{}
	// BEGIN Marshal arguments into request.

	if request.NewRemoteHost, err = soap.MarshalString(NewRemoteHost); err != nil {
		return
	}
	if request.NewExternalPort, err = soap.MarshalUi2(NewExternalPort); err != nil {
		return
	}
	if request.NewProtocol, err = soap.MarshalString(NewProtocol); err != nil {
		return
	}
	// END Marshal arguments into request.

	// Response structure.
	response := interface{}(nil)

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_1, "DeletePortMapping", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	// END Unmarshal arguments from response.
	return
}

func (client *WANIPConnection1) GetExternalIPAddress(ctx context.Context) (NewExternalIPAddress string, err error) {
	// Request structure.
	request := interface{}(nil)
	// BEGIN Marshal arguments into request.

	// END Marshal arguments into request.

	// Response structure.
	response := &struct {
		NewExternalIPAddress string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_1, "GetExternalIPAddress", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	if NewExternalIPAddress, err = soap.UnmarshalString(response.NewExternalIPAddress); err != nil {
		return
	}
	// END Unmarshal arguments from response.
	return
}

// WANIPConnection2 is a client for UPnP SOAP service with URN "urn:schemas-upnp-org:service:WANIPConnection:2". See
// goupnp.ServiceClient, which contains RootDevice and Service attributes which
// are provided for informational value.
type WANIPConnection2 struct {
	goupnp.ServiceClient
}

// NewWANIPConnection2Clients discovers instances of the service on the network,
// and returns clients to any that are found. errors will contain an error for
// any devices that replied but which could not be queried, and err will be set
// if the discovery process failed outright.
//
// This is a typical entry calling point into this package.
func NewWANIPConnection2Clients(ctx context.Context) (clients []*WANIPConnection2, errors []error, err error) {
	var genericClients []goupnp.ServiceClient
	if genericClients, errors, err = goupnp.NewServiceClients(ctx, URN_WANIPConnection_2); err != nil {
		return
	}
	clients = newWANIPConnection2ClientsFromGenericClients(genericClients)
	return
}

// NewWANIPConnection2ClientsByURL discovers instances of the service at the given
// URL, and returns clients to any that are found. An error is returned if
// there was an error probing the service.
//
// This is a typical entry calling point into this package when reusing an
// previously discovered service URL.
func NewWANIPConnection2ClientsByURL(ctx context.Context, loc *url.URL) ([]*WANIPConnection2, error) {
	genericClients, err := goupnp.NewServiceClientsByURL(ctx, loc, URN_WANIPConnection_2)
	if err != nil {
		return nil, err
	}
	return newWANIPConnection2ClientsFromGenericClients(genericClients), nil
}

// NewWANIPConnection2ClientsFromRootDevice discovers instances of the service in
// a given root device, and returns clients to any that are found. An error is
// returned if there was not at least one instance of the service within the
// device. The location parameter is simply assigned to the Location attribute
// of the wrapped ServiceClient(s).
//
// This is a typical entry calling point into this package when reusing an
// previously discovered root device.
func NewWANIPConnection2ClientsFromRootDevice(ctx context.Context, rootDevice *goupnp.RootDevice, loc *url.URL) ([]*WANIPConnection2, error) {
	genericClients, err := goupnp.NewServiceClientsFromRootDevice(ctx, rootDevice, loc, URN_WANIPConnection_2)
	if err != nil {
		return nil, err
	}
	return newWANIPConnection2ClientsFromGenericClients(genericClients), nil
}

func newWANIPConnection2ClientsFromGenericClients(genericClients []goupnp.ServiceClient) []*WANIPConnection2 {
	clients := make([]*WANIPConnection2, len(genericClients))
	for i := range genericClients {
		clients[i] = &WANIPConnection2{genericClients[i]}
	}
	return clients
}

func (client *WANIPConnection2) SetConnectionType(ctx context.Context, NewConnectionType string) (err error) {
	// Request structure.
	request := &struct {
		NewConnectionType string
	}{}
	// BEGIN Marshal arguments into request.

	if request.NewConnectionType, err = soap.MarshalString(NewConnectionType); err != nil {
		return
	}
	// END Marshal arguments into request.

	// Response structure.
	response := interface{}(nil)

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_2, "SetConnectionType", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	// END Unmarshal arguments from response.
	return
}

func (client *WANIPConnection2) GetConnectionTypeInfo(ctx context.Context) (NewConnectionType string, NewPossibleConnectionTypes string, err error) {
	// Request structure.
	request := interface{}(nil)
	// BEGIN Marshal arguments into request.

	// END Marshal arguments into request.

	// Response structure.
	response := &struct {
		NewConnectionType          string
		NewPossibleConnectionTypes string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_2, "GetConnectionTypeInfo", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	if NewConnectionType, err = soap.UnmarshalString(response.NewConnectionType); err != nil {
		return
	}
	if NewPossibleConnectionTypes, err = soap.UnmarshalString(response.NewPossibleConnectionTypes); err != nil {
		return
	}
	// END Unmarshal arguments from response.
	return
}

func (client *WANIPConnection2) RequestConnection(ctx context.Context) (err error) {
	// Request structure.
	request := interface{}(nil)
	// BEGIN Marshal arguments into request.

	// END Marshal arguments into request.

	// Response structure.
	response := interface{}(nil)

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_2, "RequestConnection", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	// END Unmarshal arguments from response.
	return
}

func (client *WANIPConnection2) RequestTermination(ctx context.Context) (err error) {
	// Request structure.
	request := interface{}(nil)
	// BEGIN Marshal arguments into request.

	// END Marshal arguments into request.

	// Response structure.
	response := interface{}(nil)

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_2, "RequestTermination", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	// END Unmarshal arguments from response.
	return
}

func (client *WANIPConnection2) ForceTermination(ctx context.Context) (err error) {
	// Request structure.
	request := interface{}(nil)
	// BEGIN Marshal arguments into request.

	// END Marshal arguments into request.

	// Response structure.
	response := interface{}(nil)

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_2, "ForceTermination", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	// END Unmarshal arguments from response.
	return
}

func (client *WANIPConnection2) SetAutoDisconnectTime(ctx context.Context, NewAutoDisconnectTime uint32) (err error) {
	// Request structure.
	request := &struct {
		NewAutoDisconnectTime string
	}{}
	// BEGIN Marshal arguments into request.

	if request.NewAutoDisconnectTime, err = soap.MarshalUi4(NewAutoDisconnectTime); err != nil {
		return
	}
	// END Marshal arguments into request.

	// Response structure.
	response := interface{}(nil)

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_2, "SetAutoDisconnectTime", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	// END Unmarshal arguments from response.
	return
}

func (client *WANIPConnection2) SetIdleDisconnectTime(ctx context.Context, NewIdleDisconnectTime uint32) (err error) {
	// Request structure.
	request := &struct {
		NewIdleDisconnectTime string
	}{}
	// BEGIN Marshal arguments into request.

	if request.NewIdleDisconnectTime, err = soap.MarshalUi4(NewIdleDisconnectTime); err != nil {
		return
	}
	// END Marshal arguments into request.

	// Response structure.
	response := interface{}(nil)

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_2, "SetIdleDisconnectTime", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	// END Unmarshal arguments from response.
	return
}

func (client *WANIPConnection2) SetWarnDisconnectDelay(ctx context.Context, NewWarnDisconnectDelay uint32) (err error) {
	// Request structure.
	request := &struct {
		NewWarnDisconnectDelay string
	}{}
	// BEGIN Marshal arguments into request.

	if request.NewWarnDisconnectDelay, err = soap.MarshalUi4(NewWarnDisconnectDelay); err != nil {
		return
	}
	// END Marshal arguments into request.

	// Response structure.
	response := interface{}(nil)

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_2, "SetWarnDisconnectDelay", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	// END Unmarshal arguments from response.
	return
}

//
// Return values:
//
// * NewConnectionStatus: allowed values: Unconfigured, Connecting, Connected, PendingDisconnect, Disconnecting, Disconnected
//
// * NewLastConnectionError: allowed values: ERROR_NONE, ERROR_COMMAND_ABORTED, ERROR_NOT_ENABLED_FOR_INTERNET, ERROR_USER_DISCONNECT, ERROR_ISP_DISCONNECT, ERROR_IDLE_DISCONNECT, ERROR_FORCED_DISCONNECT, ERROR_NO_CARRIER, ERROR_IP_CONFIGURATION, ERROR_UNKNOWN
func (client *WANIPConnection2) GetStatusInfo(ctx context.Context) (NewConnectionStatus string, NewLastConnectionError string, NewUptime uint32, err error) {
	// Request structure.
	request := interface{}(nil)
	// BEGIN Marshal arguments into request.

	// END Marshal arguments into request.

	// Response structure.
	response := &struct {
		NewConnectionStatus    string
		NewLastConnectionError string
		NewUptime              string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_2, "GetStatusInfo", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	if NewConnectionStatus, err = soap.UnmarshalString(response.NewConnectionStatus); err != nil {
		return
	}
	if NewLastConnectionError, err = soap.UnmarshalString(response.NewLastConnectionError); err != nil {
		return
	}
	if NewUptime, err = soap.UnmarshalUi4(response.NewUptime); err != nil {
		return
	}
	// END Unmarshal arguments from response.
	return
}

func (client *WANIPConnection2) GetAutoDisconnectTime(ctx context.Context) (NewAutoDisconnectTime uint32, err error) {
	// Request structure.
	request := interface{}(nil)
	// BEGIN Marshal arguments into request.

	// END Marshal arguments into request.

	// Response structure.
	response := &struct {
		NewAutoDisconnectTime string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_2, "GetAutoDisconnectTime", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	if NewAutoDisconnectTime, err = soap.UnmarshalUi4(response.NewAutoDisconnectTime); err != nil {
		return
	}
	// END Unmarshal arguments from response.
	return
}

func (client *WANIPConnection2) GetIdleDisconnectTime(ctx context.Context) (NewIdleDisconnectTime uint32, err error) {
	// Request structure.
	request := interface{}(nil)
	// BEGIN Marshal arguments into request.

	// END Marshal arguments into request.

	// Response structure.
	response := &struct {
		NewIdleDisconnectTime string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_2, "GetIdleDisconnectTime", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	if NewIdleDisconnectTime, err = soap.UnmarshalUi4(response.NewIdleDisconnectTime); err != nil {
		return
	}
	// END Unmarshal arguments from response.
	return
}

func (client *WANIPConnection2) GetWarnDisconnectDelay(ctx context.Context) (NewWarnDisconnectDelay uint32, err error) {
	// Request structure.
	request := interface{}(nil)
	// BEGIN Marshal arguments into request.

	// END Marshal arguments into request.

	// Response structure.
	response := &struct {
		NewWarnDisconnectDelay string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_2, "GetWarnDisconnectDelay", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	if NewWarnDisconnectDelay, err = soap.UnmarshalUi4(response.NewWarnDisconnectDelay); err != nil {
		return
	}
	// END Unmarshal arguments from response.
	return
}

func (client *WANIPConnection2) GetNATRSIPStatus(ctx context.Context) (NewRSIPAvailable bool, NewNATEnabled bool, err error) {
	// Request structure.
	request := interface{}(nil)
	// BEGIN Marshal arguments into request.

	// END Marshal arguments into request.

	// Response structure.
	response := &struct {
		NewRSIPAvailable string
		NewNATEnabled    string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_2, "GetNATRSIPStatus", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	if NewRSIPAvailable, err = soap.UnmarshalBoolean(response.NewRSIPAvailable); err != nil {
		return
	}
	if NewNATEnabled, err = soap.UnmarshalBoolean(response.NewNATEnabled); err != nil {
		return
	}
	// END Unmarshal arguments from response.
	return
}

//
// Return values:
//
// * NewProtocol: allowed values: TCP, UDP
func (client *WANIPConnection2) GetGenericPortMappingEntry(ctx context.Context, NewPortMappingIndex uint16) (NewRemoteHost string, NewExternalPort uint16, NewProtocol string, NewInternalPort uint16, NewInternalClient string, NewEnabled bool, NewPortMappingDescription string, NewLeaseDuration uint32, err error) {
	// Request structure.
	request := &struct {
		NewPortMappingIndex string
	}{}
	// BEGIN Marshal arguments into request.

	if request.NewPortMappingIndex, err = soap.MarshalUi2(NewPortMappingIndex); err != nil {
		return
	}
	// END Marshal arguments into request.

	// Response structure.
	response := &struct {
		NewRemoteHost             string
		NewExternalPort           string
		NewProtocol               string
		NewInternalPort           string
		NewInternalClient         string
		NewEnabled                string
		NewPortMappingDescription string
		NewLeaseDuration          string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_2, "GetGenericPortMappingEntry", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	if NewRemoteHost, err = soap.UnmarshalString(response.NewRemoteHost); err != nil {
		return
	}
	if NewExternalPort, err = soap.UnmarshalUi2(response.NewExternalPort); err != nil {
		return
	}
	if NewProtocol, err = soap.UnmarshalString(response.NewProtocol); err != nil {
		return
	}
	if NewInternalPort, err = soap.UnmarshalUi2(response.NewInternalPort); err != nil {
		return
	}
	if NewInternalClient, err = soap.UnmarshalString(response.NewInternalClient); err != nil {
		return
	}
	if NewEnabled, err = soap.UnmarshalBoolean(response.NewEnabled); err != nil {
		return
	}
	if NewPortMappingDescription, err = soap.UnmarshalString(response.NewPortMappingDescription); err != nil {
		return
	}
	if NewLeaseDuration, err = soap.UnmarshalUi4(response.NewLeaseDuration); err != nil {
		return
	}
	// END Unmarshal arguments from response.
	return
}

//
// Arguments:
//
// * NewProtocol: allowed values: TCP, UDP

func (client *WANIPConnection2) GetSpecificPortMappingEntry(ctx context.Context, NewRemoteHost string, NewExternalPort uint16, NewProtocol string) (NewInternalPort uint16, NewInternalClient string, NewEnabled bool, NewPortMappingDescription string, NewLeaseDuration uint32, err error) {
	// Request structure.
	request := &struct {
		NewRemoteHost   string
		NewExternalPort string
		NewProtocol     string
	}{}
	// BEGIN Marshal arguments into request.

	if request.NewRemoteHost, err = soap.MarshalString(NewRemoteHost); err != nil {
		return
	}
	if request.NewExternalPort, err = soap.MarshalUi2(NewExternalPort); err != nil {
		return
	}
	if request.NewProtocol, err = soap.MarshalString(NewProtocol); err != nil {
		return
	}
	// END Marshal arguments into request.

	// Response structure.
	response := &struct {
		NewInternalPort           string
		NewInternalClient         string
		NewEnabled                string
		NewPortMappingDescription string
		NewLeaseDuration          string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_2, "GetSpecificPortMappingEntry", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	if NewInternalPort, err = soap.UnmarshalUi2(response.NewInternalPort); err != nil {
		return
	}
	if NewInternalClient, err = soap.UnmarshalString(response.NewInternalClient); err != nil {
		return
	}
	if NewEnabled, err = soap.UnmarshalBoolean(response.NewEnabled); err != nil {
		return
	}
	if NewPortMappingDescription, err = soap.UnmarshalString(response.NewPortMappingDescription); err != nil {
		return
	}
	if NewLeaseDuration, err = soap.UnmarshalUi4(response.NewLeaseDuration); err != nil {
		return
	}
	// END Unmarshal arguments from response.
	return
}

//
// Arguments:
//
// * NewProtocol: allowed values: TCP, UDP

func (client *WANIPConnection2) AddPortMapping(ctx context.Context, NewRemoteHost string, NewExternalPort uint16, NewProtocol string, NewInternalPort uint16, NewInternalClient string, NewEnabled bool, NewPortMappingDescription string, NewLeaseDuration uint32) (err error) {
	// Request structure.
	request := &struct {
		NewRemoteHost             string
		NewExternalPort           string
		NewProtocol               string
		NewInternalPort           string
		NewInternalClient         string
		NewEnabled                string
		NewPortMappingDescription string
		NewLeaseDuration          string
	}{}
	// BEGIN Marshal arguments into request.

	if request.NewRemoteHost, err = soap.MarshalString(NewRemoteHost); err != nil {
		return
	}
	if request.NewExternalPort, err = soap.MarshalUi2(NewExternalPort); err != nil {
		return
	}
	if request.NewProtocol, err = soap.MarshalString(NewProtocol); err != nil {
		return
	}
	if request.NewInternalPort, err = soap.MarshalUi2(NewInternalPort); err != nil {
		return
	}
	if request.NewInternalClient, err = soap.MarshalString(NewInternalClient); err != nil {
		return
	}
	if request.NewEnabled, err = soap.MarshalBoolean(NewEnabled); err != nil {
		return
	}
	if request.NewPortMappingDescription, err = soap.MarshalString(NewPortMappingDescription); err != nil {
		return
	}
	if request.NewLeaseDuration, err = soap.MarshalUi4(NewLeaseDuration); err != nil {
		return
	}
	// END Marshal arguments into request.

	// Response structure.
	response := interface{}(nil)

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_2, "AddPortMapping", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	// END Unmarshal arguments from response.
	return
}

//
// Arguments:
//
// * NewProtocol: allowed values: TCP, UDP

func (client *WANIPConnection2) DeletePortMapping(ctx context.Context, NewRemoteHost string, NewExternalPort uint16, NewProtocol string) (err error) {
	// Request structure.
	request := &struct {
		NewRemoteHost   string
		NewExternalPort string
		NewProtocol     string
	}{}
	// BEGIN Marshal arguments into request.

	if request.NewRemoteHost, err = soap.MarshalString(NewRemoteHost); err != nil {
		return
	}
	if request.NewExternalPort, err = soap.MarshalUi2(NewExternalPort); err != nil {
		return
	}
	if request.NewProtocol, err = soap.MarshalString(NewProtocol); err != nil {
		return
	}
	// END Marshal arguments into request.

	// Response structure.
	response := interface{}(nil)

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_2, "DeletePortMapping", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	// END Unmarshal arguments from response.
	return
}

//
// Arguments:
//
// * NewProtocol: allowed values: TCP, UDP

func (client *WANIPConnection2) DeletePortMappingRange(ctx context.Context, NewStartPort uint16, NewEndPort uint16, NewProtocol string, NewManage bool) (err error) {
	// Request structure.
	request := &struct {
		NewStartPort string
		NewEndPort   string
		NewProtocol  string
		NewManage    string
	}{}
	// BEGIN Marshal arguments into request.

	if request.NewStartPort, err = soap.MarshalUi2(NewStartPort); err != nil {
		return
	}
	if request.NewEndPort, err = soap.MarshalUi2(NewEndPort); err != nil {
		return
	}
	if request.NewProtocol, err = soap.MarshalString(NewProtocol); err != nil {
		return
	}
	if request.NewManage, err = soap.MarshalBoolean(NewManage); err != nil {
		return
	}
	// END Marshal arguments into request.

	// Response structure.
	response := interface{}(nil)

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_2, "DeletePortMappingRange", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	// END Unmarshal arguments from response.
	return
}

func (client *WANIPConnection2) GetExternalIPAddress(ctx context.Context) (NewExternalIPAddress string, err error) {
	// Request structure.
	request := interface{}(nil)
	// BEGIN Marshal arguments into request.

	// END Marshal arguments into request.

	// Response structure.
	response := &struct {
		NewExternalIPAddress string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_2, "GetExternalIPAddress", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	if NewExternalIPAddress, err = soap.UnmarshalString(response.NewExternalIPAddress); err != nil {
		return
	}
	// END Unmarshal arguments from response.
	return
}

//
// Arguments:
//
// * NewProtocol: allowed values: TCP, UDP

func (client *WANIPConnection2) GetListOfPortMappings(ctx context.Context, NewStartPort uint16, NewEndPort uint16, NewProtocol string, NewManage bool, NewNumberOfPorts uint16) (NewPortListing string, err error) {
	// Request structure.
	request := &struct {
		NewStartPort     string
		NewEndPort       string
		NewProtocol      string
		NewManage        string
		NewNumberOfPorts string
	}{}
	// BEGIN Marshal arguments into request.

	if request.NewStartPort, err = soap.MarshalUi2(NewStartPort); err != nil {
		return
	}
	if request.NewEndPort, err = soap.MarshalUi2(NewEndPort); err != nil {
		return
	}
	if request.NewProtocol, err = soap.MarshalString(NewProtocol); err != nil {
		return
	}
	if request.NewManage, err = soap.MarshalBoolean(NewManage); err != nil {
		return
	}
	if request.NewNumberOfPorts, err = soap.MarshalUi2(NewNumberOfPorts); err != nil {
		return
	}
	// END Marshal arguments into request.

	// Response structure.
	response := &struct {
		NewPortListing string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_2, "GetListOfPortMappings", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	if NewPortListing, err = soap.UnmarshalString(response.NewPortListing); err != nil {
		return
	}
	// END Unmarshal arguments from response.
	return
}

//
// Arguments:
//
// * NewProtocol: allowed values: TCP, UDP

func (client *WANIPConnection2) AddAnyPortMapping(ctx context.Context, NewRemoteHost string, NewExternalPort uint16, NewProtocol string, NewInternalPort uint16, NewInternalClient string, NewEnabled bool, NewPortMappingDescription string, NewLeaseDuration uint32) (NewReservedPort uint16, err error) {
	// Request structure.
	request := &struct {
		NewRemoteHost             string
		NewExternalPort           string
		NewProtocol               string
		NewInternalPort           string
		NewInternalClient         string
		NewEnabled                string
		NewPortMappingDescription string
		NewLeaseDuration          string
	}{}
	// BEGIN Marshal arguments into request.

	if request.NewRemoteHost, err = soap.MarshalString(NewRemoteHost); err != nil {
		return
	}
	if request.NewExternalPort, err = soap.MarshalUi2(NewExternalPort); err != nil {
		return
	}
	if request.NewProtocol, err = soap.MarshalString(NewProtocol); err != nil {
		return
	}
	if request.NewInternalPort, err = soap.MarshalUi2(NewInternalPort); err != nil {
		return
	}
	if request.NewInternalClient, err = soap.MarshalString(NewInternalClient); err != nil {
		return
	}
	if request.NewEnabled, err = soap.MarshalBoolean(NewEnabled); err != nil {
		return
	}
	if request.NewPortMappingDescription, err = soap.MarshalString(NewPortMappingDescription); err != nil {
		return
	}
	if request.NewLeaseDuration, err = soap.MarshalUi4(NewLeaseDuration); err != nil {
		return
	}
	// END Marshal arguments into request.

	// Response structure.
	response := &struct {
		NewReservedPort string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANIPConnection_2, "AddAnyPortMapping", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	if NewReservedPort, err = soap.UnmarshalUi2(response.NewReservedPort); err != nil {
		return
	}
	// END Unmarshal arguments from response.
	return
}

// WANPPPConnection1 is a client for UPnP SOAP service with URN "urn:schemas-upnp-org:service:WANPPPConnection:1". See
// goupnp.ServiceClient, which contains RootDevice and Service attributes which
// are provided for informational value.
type WANPPPConnection1 struct {
	goupnp.ServiceClient
}

// NewWANPPPConnection1Clients discovers instances of the service on the network,
// and returns clients to any that are found. errors will contain an error for
// any devices that replied but which could not be queried, and err will be set
// if the discovery process failed outright.
//
// This is a typical entry calling point into this package.
func NewWANPPPConnection1Clients(ctx context.Context) (clients []*WANPPPConnection1, errors []error, err error) {
	var genericClients []goupnp.ServiceClient
	if genericClients, errors, err = goupnp.NewServiceClients(ctx, URN_WANPPPConnection_1); err != nil {
		return
	}
	clients = newWANPPPConnection1ClientsFromGenericClients(genericClients)
	return
}

// NewWANPPPConnection1ClientsByURL discovers instances of the service at the given
// URL, and returns clients to any that are found. An error is returned if
// there was an error probing the service.
//
// This is a typical entry calling point into this package when reusing an
// previously discovered service URL.
func NewWANPPPConnection1ClientsByURL(ctx context.Context, loc *url.URL) ([]*WANPPPConnection1, error) {
	genericClients, err := goupnp.NewServiceClientsByURL(ctx, loc, URN_WANPPPConnection_1)
	if err != nil {
		return nil, err
	}
	return newWANPPPConnection1ClientsFromGenericClients(genericClients), nil
}

// NewWANPPPConnection1ClientsFromRootDevice discovers instances of the service in
// a given root device, and returns clients to any that are found. An error is
// returned if there was not at least one instance of the service within the
// device. The location parameter is simply assigned to the Location attribute
// of the wrapped ServiceClient(s).
//
// This is a typical entry calling point into this package when reusing an
// previously discovered root device.
func NewWANPPPConnection1ClientsFromRootDevice(ctx context.Context, rootDevice *goupnp.RootDevice, loc *url.URL) ([]*WANPPPConnection1, error) {
	genericClients, err := goupnp.NewServiceClientsFromRootDevice(ctx, rootDevice, loc, URN_WANPPPConnection_1)
	if err != nil {
		return nil, err
	}
	return newWANPPPConnection1ClientsFromGenericClients(genericClients), nil
}

func newWANPPPConnection1ClientsFromGenericClients(genericClients []goupnp.ServiceClient) []*WANPPPConnection1 {
	clients := make([]*WANPPPConnection1, len(genericClients))
	for i := range genericClients {
		clients[i] = &WANPPPConnection1{genericClients[i]}
	}
	return clients
}

func (client *WANPPPConnection1) SetConnectionType(ctx context.Context, NewConnectionType string) (err error) {
	// Request structure.
	request := &struct {
		NewConnectionType string
	}{}
	// BEGIN Marshal arguments into request.

	if request.NewConnectionType, err = soap.MarshalString(NewConnectionType); err != nil {
		return
	}
	// END Marshal arguments into request.

	// Response structure.
	response := interface{}(nil)

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANPPPConnection_1, "SetConnectionType", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	// END Unmarshal arguments from response.
	return
}

//
// Return values:
//
// * NewPossibleConnectionTypes: allowed values: Unconfigured, IP_Routed, DHCP_Spoofed, PPPoE_Bridged, PPTP_Relay, L2TP_Relay, PPPoE_Relay
func (client *WANPPPConnection1) GetConnectionTypeInfo(ctx context.Context) (NewConnectionType string, NewPossibleConnectionTypes string, err error) {
	// Request structure.
	request := interface{}(nil)
	// BEGIN Marshal arguments into request.

	// END Marshal arguments into request.

	// Response structure.
	response := &struct {
		NewConnectionType          string
		NewPossibleConnectionTypes string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANPPPConnection_1, "GetConnectionTypeInfo", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	if NewConnectionType, err = soap.UnmarshalString(response.NewConnectionType); err != nil {
		return
	}
	if NewPossibleConnectionTypes, err = soap.UnmarshalString(response.NewPossibleConnectionTypes); err != nil {
		return
	}
	// END Unmarshal arguments from response.
	return
}

func (client *WANPPPConnection1) ConfigureConnection(ctx context.Context, NewUserName string, NewPassword string) (err error) {
	// Request structure.
	request := &struct {
		NewUserName string
		NewPassword string
	}{}
	// BEGIN Marshal arguments into request.

	if request.NewUserName, err = soap.MarshalString(NewUserName); err != nil {
		return
	}
	if request.NewPassword, err = soap.MarshalString(NewPassword); err != nil {
		return
	}
	// END Marshal arguments into request.

	// Response structure.
	response := interface{}(nil)

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANPPPConnection_1, "ConfigureConnection", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	// END Unmarshal arguments from response.
	return
}

func (client *WANPPPConnection1) RequestConnection(ctx context.Context) (err error) {
	// Request structure.
	request := interface{}(nil)
	// BEGIN Marshal arguments into request.

	// END Marshal arguments into request.

	// Response structure.
	response := interface{}(nil)

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANPPPConnection_1, "RequestConnection", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	// END Unmarshal arguments from response.
	return
}

func (client *WANPPPConnection1) RequestTermination(ctx context.Context) (err error) {
	// Request structure.
	request := interface{}(nil)
	// BEGIN Marshal arguments into request.

	// END Marshal arguments into request.

	// Response structure.
	response := interface{}(nil)

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANPPPConnection_1, "RequestTermination", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	// END Unmarshal arguments from response.
	return
}

func (client *WANPPPConnection1) ForceTermination(ctx context.Context) (err error) {
	// Request structure.
	request := interface{}(nil)
	// BEGIN Marshal arguments into request.

	// END Marshal arguments into request.

	// Response structure.
	response := interface{}(nil)

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANPPPConnection_1, "ForceTermination", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	// END Unmarshal arguments from response.
	return
}

func (client *WANPPPConnection1) SetAutoDisconnectTime(ctx context.Context, NewAutoDisconnectTime uint32) (err error) {
	// Request structure.
	request := &struct {
		NewAutoDisconnectTime string
	}{}
	// BEGIN Marshal arguments into request.

	if request.NewAutoDisconnectTime, err = soap.MarshalUi4(NewAutoDisconnectTime); err != nil {
		return
	}
	// END Marshal arguments into request.

	// Response structure.
	response := interface{}(nil)

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANPPPConnection_1, "SetAutoDisconnectTime", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	// END Unmarshal arguments from response.
	return
}

func (client *WANPPPConnection1) SetIdleDisconnectTime(ctx context.Context, NewIdleDisconnectTime uint32) (err error) {
	// Request structure.
	request := &struct {
		NewIdleDisconnectTime string
	}{}
	// BEGIN Marshal arguments into request.

	if request.NewIdleDisconnectTime, err = soap.MarshalUi4(NewIdleDisconnectTime); err != nil {
		return
	}
	// END Marshal arguments into request.

	// Response structure.
	response := interface{}(nil)

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANPPPConnection_1, "SetIdleDisconnectTime", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	// END Unmarshal arguments from response.
	return
}

func (client *WANPPPConnection1) SetWarnDisconnectDelay(ctx context.Context, NewWarnDisconnectDelay uint32) (err error) {
	// Request structure.
	request := &struct {
		NewWarnDisconnectDelay string
	}{}
	// BEGIN Marshal arguments into request.

	if request.NewWarnDisconnectDelay, err = soap.MarshalUi4(NewWarnDisconnectDelay); err != nil {
		return
	}
	// END Marshal arguments into request.

	// Response structure.
	response := interface{}(nil)

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANPPPConnection_1, "SetWarnDisconnectDelay", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	// END Unmarshal arguments from response.
	return
}

//
// Return values:
//
// * NewConnectionStatus: allowed values: Unconfigured, Connected, Disconnected
//
// * NewLastConnectionError: allowed values: ERROR_NONE
func (client *WANPPPConnection1) GetStatusInfo(ctx context.Context) (NewConnectionStatus string, NewLastConnectionError string, NewUptime uint32, err error) {
	// Request structure.
	request := interface{}(nil)
	// BEGIN Marshal arguments into request.

	// END Marshal arguments into request.

	// Response structure.
	response := &struct {
		NewConnectionStatus    string
		NewLastConnectionError string
		NewUptime              string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANPPPConnection_1, "GetStatusInfo", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	if NewConnectionStatus, err = soap.UnmarshalString(response.NewConnectionStatus); err != nil {
		return
	}
	if NewLastConnectionError, err = soap.UnmarshalString(response.NewLastConnectionError); err != nil {
		return
	}
	if NewUptime, err = soap.UnmarshalUi4(response.NewUptime); err != nil {
		return
	}
	// END Unmarshal arguments from response.
	return
}

func (client *WANPPPConnection1) GetLinkLayerMaxBitRates(ctx context.Context) (NewUpstreamMaxBitRate uint32, NewDownstreamMaxBitRate uint32, err error) {
	// Request structure.
	request := interface{}(nil)
	// BEGIN Marshal arguments into request.

	// END Marshal arguments into request.

	// Response structure.
	response := &struct {
		NewUpstreamMaxBitRate   string
		NewDownstreamMaxBitRate string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANPPPConnection_1, "GetLinkLayerMaxBitRates", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	if NewUpstreamMaxBitRate, err = soap.UnmarshalUi4(response.NewUpstreamMaxBitRate); err != nil {
		return
	}
	if NewDownstreamMaxBitRate, err = soap.UnmarshalUi4(response.NewDownstreamMaxBitRate); err != nil {
		return
	}
	// END Unmarshal arguments from response.
	return
}

func (client *WANPPPConnection1) GetPPPEncryptionProtocol(ctx context.Context) (NewPPPEncryptionProtocol string, err error) {
	// Request structure.
	request := interface{}(nil)
	// BEGIN Marshal arguments into request.

	// END Marshal arguments into request.

	// Response structure.
	response := &struct {
		NewPPPEncryptionProtocol string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANPPPConnection_1, "GetPPPEncryptionProtocol", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	if NewPPPEncryptionProtocol, err = soap.UnmarshalString(response.NewPPPEncryptionProtocol); err != nil {
		return
	}
	// END Unmarshal arguments from response.
	return
}

func (client *WANPPPConnection1) GetPPPCompressionProtocol(ctx context.Context) (NewPPPCompressionProtocol string, err error) {
	// Request structure.
	request := interface{}(nil)
	// BEGIN Marshal arguments into request.

	// END Marshal arguments into request.

	// Response structure.
	response := &struct {
		NewPPPCompressionProtocol string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANPPPConnection_1, "GetPPPCompressionProtocol", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	if NewPPPCompressionProtocol, err = soap.UnmarshalString(response.NewPPPCompressionProtocol); err != nil {
		return
	}
	// END Unmarshal arguments from response.
	return
}

func (client *WANPPPConnection1) GetPPPAuthenticationProtocol(ctx context.Context) (NewPPPAuthenticationProtocol string, err error) {
	// Request structure.
	request := interface{}(nil)
	// BEGIN Marshal arguments into request.

	// END Marshal arguments into request.

	// Response structure.
	response := &struct {
		NewPPPAuthenticationProtocol string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANPPPConnection_1, "GetPPPAuthenticationProtocol", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	if NewPPPAuthenticationProtocol, err = soap.UnmarshalString(response.NewPPPAuthenticationProtocol); err != nil {
		return
	}
	// END Unmarshal arguments from response.
	return
}

func (client *WANPPPConnection1) GetUserName(ctx context.Context) (NewUserName string, err error) {
	// Request structure.
	request := interface{}(nil)
	// BEGIN Marshal arguments into request.

	// END Marshal arguments into request.

	// Response structure.
	response := &struct {
		NewUserName string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANPPPConnection_1, "GetUserName", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	if NewUserName, err = soap.UnmarshalString(response.NewUserName); err != nil {
		return
	}
	// END Unmarshal arguments from response.
	return
}

func (client *WANPPPConnection1) GetPassword(ctx context.Context) (NewPassword string, err error) {
	// Request structure.
	request := interface{}(nil)
	// BEGIN Marshal arguments into request.

	// END Marshal arguments into request.

	// Response structure.
	response := &struct {
		NewPassword string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANPPPConnection_1, "GetPassword", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	if NewPassword, err = soap.UnmarshalString(response.NewPassword); err != nil {
		return
	}
	// END Unmarshal arguments from response.
	return
}

func (client *WANPPPConnection1) GetAutoDisconnectTime(ctx context.Context) (NewAutoDisconnectTime uint32, err error) {
	// Request structure.
	request := interface{}(nil)
	// BEGIN Marshal arguments into request.

	// END Marshal arguments into request.

	// Response structure.
	response := &struct {
		NewAutoDisconnectTime string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANPPPConnection_1, "GetAutoDisconnectTime", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	if NewAutoDisconnectTime, err = soap.UnmarshalUi4(response.NewAutoDisconnectTime); err != nil {
		return
	}
	// END Unmarshal arguments from response.
	return
}

func (client *WANPPPConnection1) GetIdleDisconnectTime(ctx context.Context) (NewIdleDisconnectTime uint32, err error) {
	// Request structure.
	request := interface{}(nil)
	// BEGIN Marshal arguments into request.

	// END Marshal arguments into request.

	// Response structure.
	response := &struct {
		NewIdleDisconnectTime string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANPPPConnection_1, "GetIdleDisconnectTime", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	if NewIdleDisconnectTime, err = soap.UnmarshalUi4(response.NewIdleDisconnectTime); err != nil {
		return
	}
	// END Unmarshal arguments from response.
	return
}

func (client *WANPPPConnection1) GetWarnDisconnectDelay(ctx context.Context) (NewWarnDisconnectDelay uint32, err error) {
	// Request structure.
	request := interface{}(nil)
	// BEGIN Marshal arguments into request.

	// END Marshal arguments into request.

	// Response structure.
	response := &struct {
		NewWarnDisconnectDelay string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANPPPConnection_1, "GetWarnDisconnectDelay", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	if NewWarnDisconnectDelay, err = soap.UnmarshalUi4(response.NewWarnDisconnectDelay); err != nil {
		return
	}
	// END Unmarshal arguments from response.
	return
}

func (client *WANPPPConnection1) GetNATRSIPStatus(ctx context.Context) (NewRSIPAvailable bool, NewNATEnabled bool, err error) {
	// Request structure.
	request := interface{}(nil)
	// BEGIN Marshal arguments into request.

	// END Marshal arguments into request.

	// Response structure.
	response := &struct {
		NewRSIPAvailable string
		NewNATEnabled    string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANPPPConnection_1, "GetNATRSIPStatus", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	if NewRSIPAvailable, err = soap.UnmarshalBoolean(response.NewRSIPAvailable); err != nil {
		return
	}
	if NewNATEnabled, err = soap.UnmarshalBoolean(response.NewNATEnabled); err != nil {
		return
	}
	// END Unmarshal arguments from response.
	return
}

//
// Return values:
//
// * NewProtocol: allowed values: TCP, UDP
func (client *WANPPPConnection1) GetGenericPortMappingEntry(ctx context.Context, NewPortMappingIndex uint16) (NewRemoteHost string, NewExternalPort uint16, NewProtocol string, NewInternalPort uint16, NewInternalClient string, NewEnabled bool, NewPortMappingDescription string, NewLeaseDuration uint32, err error) {
	// Request structure.
	request := &struct {
		NewPortMappingIndex string
	}{}
	// BEGIN Marshal arguments into request.

	if request.NewPortMappingIndex, err = soap.MarshalUi2(NewPortMappingIndex); err != nil {
		return
	}
	// END Marshal arguments into request.

	// Response structure.
	response := &struct {
		NewRemoteHost             string
		NewExternalPort           string
		NewProtocol               string
		NewInternalPort           string
		NewInternalClient         string
		NewEnabled                string
		NewPortMappingDescription string
		NewLeaseDuration          string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANPPPConnection_1, "GetGenericPortMappingEntry", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	if NewRemoteHost, err = soap.UnmarshalString(response.NewRemoteHost); err != nil {
		return
	}
	if NewExternalPort, err = soap.UnmarshalUi2(response.NewExternalPort); err != nil {
		return
	}
	if NewProtocol, err = soap.UnmarshalString(response.NewProtocol); err != nil {
		return
	}
	if NewInternalPort, err = soap.UnmarshalUi2(response.NewInternalPort); err != nil {
		return
	}
	if NewInternalClient, err = soap.UnmarshalString(response.NewInternalClient); err != nil {
		return
	}
	if NewEnabled, err = soap.UnmarshalBoolean(response.NewEnabled); err != nil {
		return
	}
	if NewPortMappingDescription, err = soap.UnmarshalString(response.NewPortMappingDescription); err != nil {
		return
	}
	if NewLeaseDuration, err = soap.UnmarshalUi4(response.NewLeaseDuration); err != nil {
		return
	}
	// END Unmarshal arguments from response.
	return
}

//
// Arguments:
//
// * NewProtocol: allowed values: TCP, UDP

func (client *WANPPPConnection1) GetSpecificPortMappingEntry(ctx context.Context, NewRemoteHost string, NewExternalPort uint16, NewProtocol string) (NewInternalPort uint16, NewInternalClient string, NewEnabled bool, NewPortMappingDescription string, NewLeaseDuration uint32, err error) {
	// Request structure.
	request := &struct {
		NewRemoteHost   string
		NewExternalPort string
		NewProtocol     string
	}{}
	// BEGIN Marshal arguments into request.

	if request.NewRemoteHost, err = soap.MarshalString(NewRemoteHost); err != nil {
		return
	}
	if request.NewExternalPort, err = soap.MarshalUi2(NewExternalPort); err != nil {
		return
	}
	if request.NewProtocol, err = soap.MarshalString(NewProtocol); err != nil {
		return
	}
	// END Marshal arguments into request.

	// Response structure.
	response := &struct {
		NewInternalPort           string
		NewInternalClient         string
		NewEnabled                string
		NewPortMappingDescription string
		NewLeaseDuration          string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANPPPConnection_1, "GetSpecificPortMappingEntry", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	if NewInternalPort, err = soap.UnmarshalUi2(response.NewInternalPort); err != nil {
		return
	}
	if NewInternalClient, err = soap.UnmarshalString(response.NewInternalClient); err != nil {
		return
	}
	if NewEnabled, err = soap.UnmarshalBoolean(response.NewEnabled); err != nil {
		return
	}
	if NewPortMappingDescription, err = soap.UnmarshalString(response.NewPortMappingDescription); err != nil {
		return
	}
	if NewLeaseDuration, err = soap.UnmarshalUi4(response.NewLeaseDuration); err != nil {
		return
	}
	// END Unmarshal arguments from response.
	return
}

//
// Arguments:
//
// * NewProtocol: allowed values: TCP, UDP

func (client *WANPPPConnection1) AddPortMapping(ctx context.Context, NewRemoteHost string, NewExternalPort uint16, NewProtocol string, NewInternalPort uint16, NewInternalClient string, NewEnabled bool, NewPortMappingDescription string, NewLeaseDuration uint32) (err error) {
	// Request structure.
	request := &struct {
		NewRemoteHost             string
		NewExternalPort           string
		NewProtocol               string
		NewInternalPort           string
		NewInternalClient         string
		NewEnabled                string
		NewPortMappingDescription string
		NewLeaseDuration          string
	}{}
	// BEGIN Marshal arguments into request.

	if request.NewRemoteHost, err = soap.MarshalString(NewRemoteHost); err != nil {
		return
	}
	if request.NewExternalPort, err = soap.MarshalUi2(NewExternalPort); err != nil {
		return
	}
	if request.NewProtocol, err = soap.MarshalString(NewProtocol); err != nil {
		return
	}
	if request.NewInternalPort, err = soap.MarshalUi2(NewInternalPort); err != nil {
		return
	}
	if request.NewInternalClient, err = soap.MarshalString(NewInternalClient); err != nil {
		return
	}
	if request.NewEnabled, err = soap.MarshalBoolean(NewEnabled); err != nil {
		return
	}
	if request.NewPortMappingDescription, err = soap.MarshalString(NewPortMappingDescription); err != nil {
		return
	}
	if request.NewLeaseDuration, err = soap.MarshalUi4(NewLeaseDuration); err != nil {
		return
	}
	// END Marshal arguments into request.

	// Response structure.
	response := interface{}(nil)

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANPPPConnection_1, "AddPortMapping", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	// END Unmarshal arguments from response.
	return
}

//
// Arguments:
//
// * NewProtocol: allowed values: TCP, UDP

func (client *WANPPPConnection1) DeletePortMapping(ctx context.Context, NewRemoteHost string, NewExternalPort uint16, NewProtocol string) (err error) {
	// Request structure.
	request := &struct {
		NewRemoteHost   string
		NewExternalPort string
		NewProtocol     string
	}{}
	// BEGIN Marshal arguments into request.

	if request.NewRemoteHost, err = soap.MarshalString(NewRemoteHost); err != nil {
		return
	}
	if request.NewExternalPort, err = soap.MarshalUi2(NewExternalPort); err != nil {
		return
	}
	if request.NewProtocol, err = soap.MarshalString(NewProtocol); err != nil {
		return
	}
	// END Marshal arguments into request.

	// Response structure.
	response := interface{}(nil)

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANPPPConnection_1, "DeletePortMapping", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	// END Unmarshal arguments from response.
	return
}

func (client *WANPPPConnection1) GetExternalIPAddress(ctx context.Context) (NewExternalIPAddress string, err error) {
	// Request structure.
	request := interface{}(nil)
	// BEGIN Marshal arguments into request.

	// END Marshal arguments into request.

	// Response structure.
	response := &struct {
		NewExternalIPAddress string
	}{}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, URN_WANPPPConnection_1, "GetExternalIPAddress", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.

	if NewExternalIPAddress, err = soap.UnmarshalString(response.NewExternalIPAddress); err != nil {
		return
	}
	// END Unmarshal arguments from response.
	return
}
