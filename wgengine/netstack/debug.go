// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netstack

import (
	"html/template"
	"net/http"
	"net/netip"
	"slices"
	"time"

	xmaps "golang.org/x/exp/maps"
	"gvisor.dev/gvisor/pkg/tcpip"
)

var tcpForwarderTemplate = template.Must(template.New("").Parse(`
<html>
	<head>
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<style>
		body { font-family: monospace; font-size: 12; }
		td { padding: 0.3em; }
		</style>
	</head>
	<body>
	<h1>TCP Forwarder</h1>

	<h2>TCP Statistics</h2>
	<table border=1>
		<tr>
			<th>Metric</th>
			<th>Value</th>
		</tr>
		{{ range .Stats }}
		<tr><td>{{ .Key }}</td><td>{{ .Value }}</td></tr>
		{{ end }}
	</table>

	<h2>In-Flight Outbound Connections</h2>
	<table border=1>
		<tr>
			<th>Start Time</th>
			<th>Client IP</th>
			<th>Remote IP</th>
		</tr>
		{{ range .InFlightDials }}
		<tr>
			<td>{{ .Start.Format "2006-01-02T15:04:05Z07:00" }} ({{ printf "%.2f" .DurationSecs }} seconds ago)</td>
			<td>{{ .ClientIP }}</td>
			<td>{{ .RemoteAddr }}</td>
		</tr>
		{{ end }}
	</table>
</body>
</html>
`))

// DebugTCPForwarder writes debug information about this netstack
// implementation's current TCP forwarder in HTML format.
func (ns *Impl) DebugTCPForwarder(w http.ResponseWriter, r *http.Request) {
	// Grab data while holding the mutex
	ns.tcpDebugMu.Lock()
	tcpDials := xmaps.Values(ns.inFlightDials)
	ns.tcpDebugMu.Unlock()

	slices.SortFunc(tcpDials, func(a, b tcpDialInfo) int {
		return a.start.Compare(b.start)
	})

	type templateDataStats struct {
		Key   string
		Value uint64
	}
	type templateDataDial struct {
		Start        time.Time
		DurationSecs float64
		ClientIP     netip.Addr
		RemoteAddr   netip.AddrPort
	}
	type templateData struct {
		Stats         []templateDataStats
		InFlightDials []templateDataDial
	}

	var data templateData

	// Statistics from gVisor
	tcpStats := ns.ipstack.Stats().TCP
	tcpMetrics := []struct {
		name  string
		field *tcpip.StatCounter
	}{
		{"Active Connection Openings", tcpStats.ActiveConnectionOpenings},
		{"Passive Connection Openings", tcpStats.PassiveConnectionOpenings},
		{"Established Connections", tcpStats.CurrentEstablished},
		{"Connected Connections", tcpStats.CurrentConnected},
		{"Dropped In-Flight Forwarder Connections", tcpStats.ForwardMaxInFlightDrop},
		{"Established Resets", tcpStats.EstablishedResets},
		{"Established Timeout", tcpStats.EstablishedTimedout},
		{"Failed Connection Attempts", tcpStats.FailedConnectionAttempts},
		{"Retransmits", tcpStats.Retransmits},
		{"Timeouts", tcpStats.Timeouts},
		{"Checksum Errors", tcpStats.ChecksumErrors},
		{"Failed Port Reservations", tcpStats.FailedPortReservations},
	}
	for _, metric := range tcpMetrics {
		data.Stats = append(data.Stats, templateDataStats{
			Key:   metric.name,
			Value: metric.field.Value(),
		})
	}

	// Any in-flight DialContext calls in the TCP forwarding path.
	now := time.Now()
	for _, dial := range tcpDials {
		elapsed := now.Sub(dial.start)
		data.InFlightDials = append(data.InFlightDials, templateDataDial{
			Start:        dial.start,
			DurationSecs: elapsed.Seconds(),
			ClientIP:     dial.clientRemoteIP,
			RemoteAddr:   dial.dialAddr,
		})
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	tcpForwarderTemplate.Execute(w, &data)
}
