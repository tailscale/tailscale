// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailperf

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseBandwidthAndDuration(t *testing.T) {
	tests := []struct {
		in   string
		want int64
	}{
		{"", 0},
		{"0", 0},
		{"100mbit", 100_000_000},
		{"1.5gbit", 1_500_000_000},
		{"42k", 42_000},
	}
	for _, tt := range tests {
		got, err := ParseBandwidth(tt.in)
		if err != nil {
			t.Fatalf("ParseBandwidth(%q): %v", tt.in, err)
		}
		if got != tt.want {
			t.Fatalf("ParseBandwidth(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
	if _, err := ParseDuration("-1s"); err == nil {
		t.Fatal("ParseDuration(-1s) succeeded")
	}
	if _, err := ParseBandwidth("-1mbit"); err == nil {
		t.Fatal("ParseBandwidth(-1mbit) succeeded")
	}
}

func TestTCPClientServerLoopback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port := freePort(t, "tcp")
	errc := make(chan error, 1)
	go func() {
		errc <- RunServer(ctx, ServerConfig{Addr: "127.0.0.1", Port: port, Protocol: ProtoTCP})
	}()
	waitForTCP(t, port)
	r, err := RunClient(ctx, ClientConfig{
		Host:             "127.0.0.1",
		Port:             port,
		Protocol:         ProtoTCP,
		Duration:         150 * time.Millisecond,
		Interval:         50 * time.Millisecond,
		CapBitsPerSecond: 10_000_000,
		PathProvider:     staticPath(PathDirect),
	})
	if err != nil {
		t.Fatalf("RunClient: %v", err)
	}
	if r.TransferBytes == 0 {
		t.Fatal("TransferBytes = 0")
	}
	if r.BitrateBitsPerSecond == 0 {
		t.Fatal("BitrateBitsPerSecond = 0")
	}
	if len(r.Intervals) == 0 {
		t.Fatal("no intervals")
	}
	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("RunServer returned error after cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop after cancel")
	}
}

func TestTCPReverseLoopback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port := freePort(t, "tcp")
	go func() {
		_ = RunServer(ctx, ServerConfig{Addr: "127.0.0.1", Port: port, Protocol: ProtoTCP})
	}()
	waitForTCP(t, port)
	r, err := RunClient(ctx, ClientConfig{
		Host:             "127.0.0.1",
		Port:             port,
		Protocol:         ProtoTCP,
		Duration:         120 * time.Millisecond,
		Interval:         50 * time.Millisecond,
		CapBitsPerSecond: 10_000_000,
		Direction:        DirectionReverse,
	})
	if err != nil {
		t.Fatalf("RunClient reverse: %v", err)
	}
	if r.Direction != DirectionReverse {
		t.Fatalf("Direction = %q, want reverse", r.Direction)
	}
	if r.TransferBytes == 0 {
		t.Fatal("TransferBytes = 0")
	}
}

func TestUDPClientServerLoopback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port := freePort(t, "udp")
	go func() {
		_ = RunServer(ctx, ServerConfig{Addr: "127.0.0.1", Port: port, Protocol: ProtoUDP})
	}()
	time.Sleep(50 * time.Millisecond)
	r, err := RunClient(ctx, ClientConfig{
		Host:             "127.0.0.1",
		Port:             port,
		Protocol:         ProtoUDP,
		Duration:         100 * time.Millisecond,
		Interval:         50 * time.Millisecond,
		CapBitsPerSecond: 1_000_000,
	})
	if err != nil {
		t.Fatalf("RunClient udp: %v", err)
	}
	if r.TransferBytes == 0 {
		t.Fatal("TransferBytes = 0")
	}
}

func TestFormatPathMetadata(t *testing.T) {
	tests := []struct {
		p    PathMetadata
		want string
	}{
		{PathMetadata{Type: PathDirect}, "direct"},
		{PathMetadata{Type: PathDERP, DERPRegionCode: "FRA"}, "DERP (FRA)"},
		{PathMetadata{Type: PathPeerRelay, PeerRelay: "1.2.3.4:1234:vni:99"}, "peer relay (1.2.3.4:1234) vni:99"},
		{PathMetadata{Type: PathUnknown}, "unknown"},
	}
	for _, tt := range tests {
		if got := tt.p.String(); got != tt.want {
			t.Fatalf("%+v String = %q, want %q", tt.p, got, tt.want)
		}
	}
}

func TestWriteTextReportIncludesPathAndSummary(t *testing.T) {
	r := Result{
		SchemaVersion:        SchemaVersion,
		SourceNode:           "node-b",
		DestinationNode:      "node-a",
		Direction:            DirectionForward,
		Protocol:             ProtoTCP,
		DurationMillis:       1000,
		TransferBytes:        1024,
		BitrateBitsPerSecond: 8192,
		Path:                 PathMetadata{Type: PathDERP, DERPRegionCode: "FRA"},
		LoggingDisabled:      true,
		Intervals: []IntervalResult{{
			StartSeconds:         0,
			EndSeconds:           1,
			TransferBytes:        1024,
			BitrateBitsPerSecond: 8192,
			Path:                 PathMetadata{Type: PathDERP, DERPRegionCode: "FRA"},
		}},
	}
	var b bytes.Buffer
	if err := WriteTextReport(&b, "node-a", r); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"Connecting to host node-a", "Path", "DERP (FRA)", "Tailperf result logging disabled"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

func TestNoLogSuppressesLogSink(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port := freePort(t, "tcp")
	go func() {
		_ = RunServer(ctx, ServerConfig{Addr: "127.0.0.1", Port: port, Protocol: ProtoTCP})
	}()
	waitForTCP(t, port)
	var logged atomic.Bool
	_, err := RunClient(ctx, ClientConfig{
		Host:     "127.0.0.1",
		Port:     port,
		Protocol: ProtoTCP,
		Duration: 80 * time.Millisecond,
		Interval: 40 * time.Millisecond,
		NoLog:    true,
		LogSink: LogSinkFunc(func(context.Context, Result) error {
			logged.Store(true)
			return nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if logged.Load() {
		t.Fatal("log sink called with NoLog")
	}
}

func TestResultSchemaSerializationAndRedaction(t *testing.T) {
	r := Result{
		SchemaVersion:        SchemaVersion,
		SourceNode:           "alice-laptop",
		DestinationNode:      "db",
		Direction:            DirectionForward,
		Protocol:             ProtoTCP,
		DurationMillis:       1000,
		TransferBytes:        100,
		BitrateBitsPerSecond: 800,
		Path:                 PathMetadata{Type: PathDirect, Endpoint: "192.0.2.1:1234"},
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var round Result
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatal(err)
	}
	if round.SchemaVersion != SchemaVersion {
		t.Fatalf("schemaVersion = %d", round.SchemaVersion)
	}
	redacted := RedactResult(r, RedactionOptions{HideNodeNames: true, HidePublicIPs: true})
	if redacted.SourceNode == "alice-laptop" || redacted.Path.Endpoint == "192.0.2.1:1234" {
		t.Fatalf("redaction failed: %+v", redacted)
	}
}

func TestHistoryRetentionAndExport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.jsonl")
	s := HistoryStore{Path: path, RetentionRecords: 2}
	for i := 0; i < 3; i++ {
		if err := s.Append(context.Background(), Result{SchemaVersion: SchemaVersion, SourceNode: "src", DestinationNode: "dst", TransferBytes: int64(i)}); err != nil {
			t.Fatal(err)
		}
	}
	rs, err := s.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 2 {
		t.Fatalf("len(history) = %d, want 2", len(rs))
	}
	exported, err := s.ExportSupport(context.Background(), RedactionOptions{HideNodeNames: true})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(exported, []byte(`"src"`)) {
		t.Fatalf("export was not redacted: %s", exported)
	}
}

func TestCompareBaseline(t *testing.T) {
	base := Result{
		SourceNode:           "a",
		DestinationNode:      "b",
		Direction:            DirectionForward,
		Protocol:             ProtoTCP,
		BitrateBitsPerSecond: 100,
		Path:                 PathMetadata{Type: PathDirect},
	}
	prior := []Result{base, base, base}
	degraded := base
	degraded.BitrateBitsPerSecond = 40
	s := CompareBaseline(degraded, prior, BaselineOptions{})
	if !s.Available || !s.Degraded {
		t.Fatalf("summary = %+v, want degraded baseline", s)
	}
	changed := degraded
	changed.BitrateBitsPerSecond = 100
	changed.Path = PathMetadata{Type: PathDERP, DERPRegionCode: "NYC"}
	s = CompareBaseline(changed, append(prior, base), BaselineOptions{MinSamples: 1})
	if !s.PathChanged {
		t.Fatalf("summary = %+v, want path changed", s)
	}
}

func TestScheduleValidate(t *testing.T) {
	err := ScheduleConfig{
		Enabled:      true,
		Frequency:    DurationJSON{Duration: time.Minute},
		TestDuration: DurationJSON{Duration: time.Second},
	}.Validate()
	if err == nil {
		t.Fatal("short frequency accepted")
	}
	if err := (ScheduleConfig{
		Enabled:       true,
		Frequency:     DurationJSON{Duration: 15 * time.Minute},
		TestDuration:  DurationJSON{Duration: time.Second},
		MaxConcurrent: 1,
	}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestDiagnosisTaxonomy(t *testing.T) {
	tests := []struct {
		name string
		in   DiagnosticSignals
		want DiagnosisCode
	}{
		{"dns failure", DiagnosticSignals{DNS: LayerFail}, DiagnosisDNSLikely},
		{"dns success tcp failure", DiagnosticSignals{DNS: LayerPass, TCP: LayerFail}, DiagnosisTransportLikely},
		{"public answer expected tailscale", DiagnosticSignals{DNS: LayerPass, ExpectedTailscalePath: true, DNSAnswerClasses: []AddressClass{AddressPublic}}, DiagnosisDNSLikely},
		{"route mismatch", DiagnosticSignals{ExpectedTailscalePath: true, Route: LayerPass, RouteUsesTailscale: false}, DiagnosisTailscaleExpectedNoPath},
		{"tailscale disconnected", DiagnosticSignals{TailscaleConnected: LayerFail}, DiagnosisTailscaleDisconnected},
		{"derp degraded", DiagnosticSignals{TailscalePathStatus: LayerDegraded, TailscalePath: PathMetadata{Type: PathDERP}}, DiagnosisTailscalePathDegraded},
		{"peer relay path", DiagnosticSignals{TailscalePathStatus: LayerDegraded, TailscalePath: PathMetadata{Type: PathPeerRelay}}, DiagnosisTailscalePathDegraded},
		{"http 503", DiagnosticSignals{DNS: LayerPass, TCP: LayerPass, TLS: LayerPass, HTTP: LayerFail, HTTPStatus: 503}, DiagnosisRemoteServiceLikely},
		{"tls failure", DiagnosticSignals{DNS: LayerPass, TCP: LayerPass, TLS: LayerFail}, DiagnosisTLSLikely},
		{"unknown", DiagnosticSignals{}, DiagnosisUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EvaluateDiagnosis(tt.in)
			if got.Code != tt.want {
				t.Fatalf("Code = %q, want %q (%+v)", got.Code, tt.want, got)
			}
		})
	}
}

func staticPath(pt PathType) PathProvider {
	return func(context.Context) PathMetadata {
		return PathMetadata{Type: pt}
	}
}

func freePort(t *testing.T, network string) uint16 {
	t.Helper()
	switch network {
	case "tcp":
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		return uint16(ln.Addr().(*net.TCPAddr).Port)
	case "udp":
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
		return uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	default:
		t.Fatalf("unknown network %q", network)
		return 0
	}
}

func waitForTCP(t *testing.T, port uint16) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))), 50*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("tcp server on port %d did not start", port)
}
