// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailperf

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
)

type LayerStatus string

const (
	LayerPass     LayerStatus = "pass"
	LayerFail     LayerStatus = "fail"
	LayerDegraded LayerStatus = "degraded"
	LayerUnknown  LayerStatus = "unknown"
	LayerSkipped  LayerStatus = "skipped"
)

type DiagnosisCode string

const (
	DiagnosisDNSLikely               DiagnosisCode = "dns-likely"
	DiagnosisDNSPassed               DiagnosisCode = "dns-passed"
	DiagnosisRouteInterfaceLikely    DiagnosisCode = "route-interface-likely"
	DiagnosisTailscaleDisconnected   DiagnosisCode = "tailscale-not-connected"
	DiagnosisTailscaleExpectedNoPath DiagnosisCode = "tailscale-expected-but-not-in-path"
	DiagnosisTailscalePathDegraded   DiagnosisCode = "tailscale-path-degraded"
	DiagnosisTailperfPermission      DiagnosisCode = "tailperf-permission-grant-issue"
	DiagnosisTransportLikely         DiagnosisCode = "transport-likely"
	DiagnosisTLSLikely               DiagnosisCode = "tls-likely"
	DiagnosisApplicationLikely       DiagnosisCode = "application-likely"
	DiagnosisRemoteServiceLikely     DiagnosisCode = "remote-service-likely"
	DiagnosisLocalNetworkLikely      DiagnosisCode = "local-network-likely"
	DiagnosisUnknown                 DiagnosisCode = "unknown-insufficient-evidence"
)

type AddressClass string

const (
	AddressTailscale    AddressClass = "tailscale"
	AddressPrivate      AddressClass = "private"
	AddressPublic       AddressClass = "public"
	AddressSubnetRouted AddressClass = "subnet-routed"
	AddressConnector    AddressClass = "connector-routed"
	AddressUnknown      AddressClass = "unknown"
)

type DiagnosisLayer struct {
	Name    string      `json:"name"`
	Status  LayerStatus `json:"status"`
	Summary string      `json:"summary,omitempty"`
	Error   string      `json:"error,omitempty"`
}

type DiagnosticSignals struct {
	Destination              string
	TailscaleConnected       LayerStatus
	DestinationRecognized    LayerStatus
	DNS                      LayerStatus
	DNSAnswers               []netip.Addr
	DNSAnswerClasses         []AddressClass
	ExpectedTailscalePath    bool
	Route                    LayerStatus
	RouteUsesTailscale       bool
	TailscalePath            PathMetadata
	TailscalePathStatus      LayerStatus
	TCP                      LayerStatus
	TLS                      LayerStatus
	HTTP                     LayerStatus
	HTTPStatus               int
	Tailperf                 LayerStatus
	TailperfPermissionDenied bool
	TailperfResult           *Result
	LocalNetwork             LayerStatus
}

type Diagnosis struct {
	Destination string           `json:"destination"`
	Code        DiagnosisCode    `json:"code"`
	Summary     string           `json:"summary"`
	Layers      []DiagnosisLayer `json:"layers"`
}

func EvaluateDiagnosis(s DiagnosticSignals) Diagnosis {
	d := Diagnosis{
		Destination: s.Destination,
		Code:        DiagnosisUnknown,
		Summary:     "Unknown / insufficient evidence.",
		Layers: []DiagnosisLayer{
			layer("Local Tailscale state", s.TailscaleConnected, ""),
			layer("Destination recognition", s.DestinationRecognized, ""),
			layer("DNS", s.DNS, dnsSummary(s)),
			layer("Route/interface", s.Route, routeSummary(s)),
			layer("Tailscale path", s.TailscalePathStatus, s.TailscalePath.String()),
			layer("TCP connect", s.TCP, ""),
			layer("TLS handshake", s.TLS, ""),
			layer("HTTP/application response", s.HTTP, httpSummary(s.HTTPStatus)),
			layer("Performance result", s.Tailperf, tailperfSummary(s)),
		},
	}

	switch {
	case s.TailscaleConnected == LayerFail:
		d.Code, d.Summary = DiagnosisTailscaleDisconnected, "Tailscale is not connected."
	case s.DNS == LayerFail:
		d.Code, d.Summary = DiagnosisDNSLikely, "DNS likely: the destination did not resolve."
	case s.ExpectedTailscalePath && hasPublicAnswer(s):
		d.Code, d.Summary = DiagnosisDNSLikely, "DNS may be involved: the hostname resolved outside the expected Tailscale path."
	case s.ExpectedTailscalePath && s.Route != LayerUnknown && !s.RouteUsesTailscale:
		d.Code, d.Summary = DiagnosisTailscaleExpectedNoPath, "Tailscale was expected but the selected route does not use Tailscale."
	case s.Route == LayerFail:
		d.Code, d.Summary = DiagnosisRouteInterfaceLikely, "Route/interface likely: the local route check failed."
	case s.TailperfPermissionDenied:
		d.Code, d.Summary = DiagnosisTailperfPermission, "Tailperf permission/grant issue."
	case s.TailscalePathStatus == LayerDegraded || s.TailscalePath.Normalized().Type == PathDERP:
		d.Code, d.Summary = DiagnosisTailscalePathDegraded, "Tailscale path degraded or relayed."
	case s.TCP == LayerFail:
		d.Code, d.Summary = DiagnosisTransportLikely, "Transport likely: DNS passed but TCP failed."
	case s.TLS == LayerFail:
		d.Code, d.Summary = DiagnosisTLSLikely, "TLS likely: TCP passed but TLS failed."
	case s.HTTP == LayerFail && s.HTTPStatus >= 500:
		d.Code, d.Summary = DiagnosisRemoteServiceLikely, "Remote service likely: the server returned an error."
	case s.HTTP == LayerFail:
		d.Code, d.Summary = DiagnosisApplicationLikely, "Application likely: HTTP/application response failed."
	case s.LocalNetwork == LayerFail:
		d.Code, d.Summary = DiagnosisLocalNetworkLikely, "Local network likely."
	case s.DNS == LayerPass:
		d.Code, d.Summary = DiagnosisDNSPassed, "DNS passed."
	}
	return d
}

func ClassifyAddr(ip netip.Addr) AddressClass {
	if ip.Is4() {
		a := ip.As4()
		if a[0] == 100 && a[1] >= 64 && a[1] <= 127 {
			return AddressTailscale
		}
	}
	if ip.Is6() && strings.HasPrefix(ip.String(), "fd7a:115c:a1e0:") {
		return AddressTailscale
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return AddressPrivate
	}
	if ip.IsValid() {
		return AddressPublic
	}
	return AddressUnknown
}

func layer(name string, st LayerStatus, summary string) DiagnosisLayer {
	if st == "" {
		st = LayerUnknown
	}
	return DiagnosisLayer{Name: name, Status: st, Summary: summary}
}

func dnsSummary(s DiagnosticSignals) string {
	if s.DNS == LayerPass {
		return "DNS passed. The hostname resolved successfully."
	}
	if s.DNS == LayerFail {
		return "DNS may be involved. The hostname did not resolve."
	}
	if s.ExpectedTailscalePath && hasPublicAnswer(s) {
		return "DNS may be involved. The hostname resolved to a public IP, but this destination appears expected to use a Tailscale-routed private path."
	}
	return ""
}

func routeSummary(s DiagnosticSignals) string {
	if s.RouteUsesTailscale {
		return "Selected route uses Tailscale."
	}
	if s.ExpectedTailscalePath && s.Route != LayerUnknown {
		return "Selected route does not use Tailscale."
	}
	return ""
}

func httpSummary(code int) string {
	if code == 0 {
		return ""
	}
	return fmt.Sprintf("HTTP status %d (%s)", code, http.StatusText(code))
}

func tailperfSummary(s DiagnosticSignals) string {
	if s.TailperfResult == nil {
		return ""
	}
	return fmt.Sprintf("%s, %s", formatBytes(s.TailperfResult.TransferBytes), formatBitrate(s.TailperfResult.BitrateBitsPerSecond))
}

func hasPublicAnswer(s DiagnosticSignals) bool {
	for _, c := range s.DNSAnswerClasses {
		if c == AddressPublic {
			return true
		}
	}
	for _, ip := range s.DNSAnswers {
		if ClassifyAddr(ip) == AddressPublic {
			return true
		}
	}
	return false
}
