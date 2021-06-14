package main

import (
	"html/template"
)

var packageTmpl = template.Must(template.New("package").Parse(`{{$name := .Metadata.Name}}
// Client for UPnP Device Control Protocol {{.Metadata.OfficialName}}.
// {{if .Metadata.DocURL}}
// This DCP is documented in detail at: {{.Metadata.DocURL}}{{end}}
//
// Typically, use one of the New* functions to create clients for services.
package {{$name}}

// ***********************************************************
// GENERATED FILE - DO NOT EDIT BY HAND. See README.md
// ***********************************************************

import (
  "context"
	"net/url"
	"time"

	"tailscale.com/tempfork/upnp"
	"tailscale.com/tempfork/upnp/soap"
)

// Hack to avoid Go complaining if time isn't used.
var _ time.Time

// Device URNs:
const ({{range .DeviceTypes}}
	{{.Const}} = "{{.URN}}"{{end}}
)

// Service URNs:
const ({{range .ServiceTypes}}
	{{.Const}} = "{{.URN}}"{{end}}
)

{{range .Services}}
{{$srv := .}}
{{$srvIdent := printf "%s%s" .Name .Version}}

// {{$srvIdent}} is a client for UPnP SOAP service with URN "{{.URN}}". See
// goupnp.ServiceClient, which contains RootDevice and Service attributes which
// are provided for informational value.
type {{$srvIdent}} struct {
	goupnp.ServiceClient
}

// New{{$srvIdent}}Clients discovers instances of the service on the network,
// and returns clients to any that are found. errors will contain an error for
// any devices that replied but which could not be queried, and err will be set
// if the discovery process failed outright.
//
// This is a typical entry calling point into this package.
func New{{$srvIdent}}Clients() (clients []*{{$srvIdent}}, errors []error, err error) {
	var genericClients []goupnp.ServiceClient
	if genericClients, errors, err = goupnp.NewServiceClients({{$srv.Const}}); err != nil {
		return
	}
	clients = new{{$srvIdent}}ClientsFromGenericClients(genericClients)
	return
}

// New{{$srvIdent}}ClientsByURL discovers instances of the service at the given
// URL, and returns clients to any that are found. An error is returned if
// there was an error probing the service.
//
// This is a typical entry calling point into this package when reusing an
// previously discovered service URL.
func New{{$srvIdent}}ClientsByURL(loc *url.URL) ([]*{{$srvIdent}}, error) {
	genericClients, err := goupnp.NewServiceClientsByURL(loc, {{$srv.Const}})
	if err != nil {
		return nil, err
	}
	return new{{$srvIdent}}ClientsFromGenericClients(genericClients), nil
}

// New{{$srvIdent}}ClientsFromRootDevice discovers instances of the service in
// a given root device, and returns clients to any that are found. An error is
// returned if there was not at least one instance of the service within the
// device. The location parameter is simply assigned to the Location attribute
// of the wrapped ServiceClient(s).
//
// This is a typical entry calling point into this package when reusing an
// previously discovered root device.
func New{{$srvIdent}}ClientsFromRootDevice(rootDevice *goupnp.RootDevice, loc *url.URL) ([]*{{$srvIdent}}, error) {
	genericClients, err := goupnp.NewServiceClientsFromRootDevice(rootDevice, loc, {{$srv.Const}})
	if err != nil {
		return nil, err
	}
	return new{{$srvIdent}}ClientsFromGenericClients(genericClients), nil
}

func new{{$srvIdent}}ClientsFromGenericClients(genericClients []goupnp.ServiceClient) []*{{$srvIdent}} {
	clients := make([]*{{$srvIdent}}, len(genericClients))
	for i := range genericClients {
		clients[i] = &{{$srvIdent}}{genericClients[i]}
	}
	return clients
}

{{range .SCPD.Actions}}{{/* loops over *SCPDWithURN values */}}

{{$winargs := $srv.WrapArguments .InputArguments}}
{{$woutargs := $srv.WrapArguments .OutputArguments}}
{{if $winargs.HasDoc}}
//
// Arguments:{{range $winargs}}{{if .HasDoc}}
//
// * {{.Name}}: {{.Document}}{{end}}{{end}}{{end}}
{{if $woutargs.HasDoc}}
//
// Return values:{{range $woutargs}}{{if .HasDoc}}
//
// * {{.Name}}: {{.Document}}{{end}}{{end}}{{end}}
func (client *{{$srvIdent}}) {{.Name}}(ctx context.Context, {{range $winargs -}}
{{.AsParameter}}, {{end -}}
) ({{range $woutargs -}}
{{.AsParameter}}, {{end}} err error) {
	// Request structure.
	request := {{if $winargs}}&{{template "argstruct" $winargs}}{{"{}"}}{{else}}{{"interface{}(nil)"}}{{end}}
	// BEGIN Marshal arguments into request.
{{range $winargs}}
	if request.{{.Name}}, err = {{.Marshal}}; err != nil {
		return
	}{{end}}
	// END Marshal arguments into request.

	// Response structure.
	response := {{if $woutargs}}&{{template "argstruct" $woutargs}}{{"{}"}}{{else}}{{"interface{}(nil)"}}{{end}}

	// Perform the SOAP call.
	if err = client.SOAPClient.PerformAction(ctx, {{$srv.URNParts.Const}}, "{{.Name}}", request, response); err != nil {
		return
	}

	// BEGIN Unmarshal arguments from response.
{{range $woutargs}}
	if {{.Name}}, err = {{.Unmarshal "response"}}; err != nil {
		return
	}{{end}}
	// END Unmarshal arguments from response.
	return
}
{{end}}
{{end}}

{{define "argstruct"}}struct {{"{"}}
{{range .}}{{.Name}} string
{{end}}{{"}"}}{{end}}
`))
