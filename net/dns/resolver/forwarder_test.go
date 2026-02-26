// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package resolver

import (
	"bytes"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dns "golang.org/x/net/dns/dnsmessage"
	"tailscale.com/control/controlknobs"
	"tailscale.com/health"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tstest"
	"tailscale.com/types/dnstype"
	"tailscale.com/util/eventbus/eventbustest"
)

func (rr resolverAndDelay) String() string {
	return fmt.Sprintf("%v+%v", rr.name, rr.startDelay)
}

// setTCFlagInPacket sets the TC flag in a DNS packet (for testing).
func setTCFlagInPacket(packet []byte) {
	if len(packet) < headerBytes {
		return
	}
	flags := binary.BigEndian.Uint16(packet[2:4])
	flags |= dnsFlagTruncated
	binary.BigEndian.PutUint16(packet[2:4], flags)
}

// clearTCFlagInPacket clears the TC flag in a DNS packet (for testing).
func clearTCFlagInPacket(packet []byte) {
	if len(packet) < headerBytes {
		return
	}
	flags := binary.BigEndian.Uint16(packet[2:4])
	flags &^= dnsFlagTruncated
	binary.BigEndian.PutUint16(packet[2:4], flags)
}

// verifyEDNSBufferSize verifies a request has the expected EDNS buffer size.
func verifyEDNSBufferSize(t *testing.T, request []byte, expectedSize uint16) {
	t.Helper()
	ednsSize, hasEDNS := getEDNSBufferSize(request)
	if !hasEDNS {
		t.Fatalf("request should have EDNS OPT record")
	}
	if ednsSize != expectedSize {
		t.Fatalf("request EDNS size = %d, want %d", ednsSize, expectedSize)
	}
}

// setupForwarderWithTCPRetriesDisabled returns a forwarder modifier that disables TCP retries.
func setupForwarderWithTCPRetriesDisabled() func(*forwarder) {
	return func(fwd *forwarder) {
		fwd.controlKnobs = &controlknobs.Knobs{}
		fwd.controlKnobs.DisableDNSForwarderTCPRetries.Store(true)
	}
}

func TestResolversWithDelays(t *testing.T) {
	// query
	q := func(ss ...string) (ipps []*dnstype.Resolver) {
		for _, host := range ss {
			ipps = append(ipps, &dnstype.Resolver{Addr: host})
		}
		return
	}
	// output
	o := func(ss ...string) (rr []resolverAndDelay) {
		for _, s := range ss {
			var d time.Duration
			s, durStr, hasPlus := strings.Cut(s, "+")
			if hasPlus {
				var err error
				d, err = time.ParseDuration(durStr)
				if err != nil {
					panic(fmt.Sprintf("parsing duration in %q: %v", s, err))
				}
			}
			rr = append(rr, resolverAndDelay{
				name:       &dnstype.Resolver{Addr: s},
				startDelay: d,
			})
		}
		return
	}

	tests := []struct {
		name string
		in   []*dnstype.Resolver
		want []resolverAndDelay
	}{
		{
			name: "unknown-no-delays",
			in:   q("1.2.3.4", "2.3.4.5"),
			want: o("1.2.3.4", "2.3.4.5"),
		},
		{
			name: "google-all-ipv4",
			in:   q("8.8.8.8", "8.8.4.4"),
			want: o("https://dns.google/dns-query", "8.8.8.8+0.5s", "8.8.4.4+0.7s"),
		},
		{
			name: "google-only-ipv6",
			in:   q("2001:4860:4860::8888", "2001:4860:4860::8844"),
			want: o("https://dns.google/dns-query", "2001:4860:4860::8888+0.5s", "2001:4860:4860::8844+0.7s"),
		},
		{
			name: "google-all-four",
			in:   q("8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"),
			want: o("https://dns.google/dns-query", "8.8.8.8+0.5s", "8.8.4.4+0.7s", "2001:4860:4860::8888+0.5s", "2001:4860:4860::8844+0.7s"),
		},
		{
			name: "quad9-one-v4-one-v6",
			in:   q("9.9.9.9", "2620:fe::fe"),
			want: o("https://dns.quad9.net/dns-query", "9.9.9.9+0.5s", "2620:fe::fe+0.5s"),
		},
		{
			name: "nextdns-ipv6-expand",
			in:   q("2a07:a8c0::c3:a884"),
			want: o("https://dns.nextdns.io/c3a884"),
		},
		{
			name: "nextdns-doh-input",
			in:   q("https://dns.nextdns.io/c3a884"),
			want: o("https://dns.nextdns.io/c3a884"),
		},
		{
			name: "controld-ipv6-expand",
			in:   q("2606:1a40:0:6:7b5b:5949:35ad:0"),
			want: o("https://dns.controld.com/hyq3ipr2ct"),
		},
		{
			name: "controld-doh-input",
			in:   q("https://dns.controld.com/hyq3ipr2ct"),
			want: o("https://dns.controld.com/hyq3ipr2ct"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolversWithDelays(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v; want %v", got, tt.want)
			}
		})
	}
}

func TestGetRCode(t *testing.T) {
	tests := []struct {
		name   string
		packet []byte
		want   dns.RCode
	}{
		{
			name:   "empty",
			packet: []byte{},
			want:   dns.RCode(5),
		},
		{
			name:   "too-short",
			packet: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			want:   dns.RCode(5),
		},
		{
			name:   "noerror",
			packet: []byte{0xC4, 0xFE, 0x81, 0xA0, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01},
			want:   dns.RCode(0),
		},
		{
			name:   "refused",
			packet: []byte{0xee, 0xa1, 0x81, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			want:   dns.RCode(5),
		},
		{
			name:   "nxdomain",
			packet: []byte{0x34, 0xf4, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01},
			want:   dns.RCode(3),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getRCode(tt.packet)
			if got != tt.want {
				t.Errorf("got %d; want %d", got, tt.want)
			}
		})
	}
}

var testDNS = flag.Bool("test-dns", false, "run tests that require a working DNS server")

func TestGetKnownDoHClientForProvider(t *testing.T) {
	var fwd forwarder
	c, ok := fwd.getKnownDoHClientForProvider("https://dns.google/dns-query")
	if !ok {
		t.Fatal("not found")
	}
	if !*testDNS {
		t.Skip("skipping without --test-dns")
	}
	res, err := c.Head("https://dns.google/")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	t.Logf("Got: %+v", res)
}

func BenchmarkNameFromQuery(b *testing.B) {
	builder := dns.NewBuilder(nil, dns.Header{})
	builder.StartQuestions()
	builder.Question(dns.Question{
		Name:  dns.MustNewName("foo.example."),
		Type:  dns.TypeA,
		Class: dns.ClassINET,
	})
	msg, err := builder.Finish()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		_, _, err := nameFromQuery(msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Reproduces https://github.com/tailscale/tailscale/issues/2533
// Fixed by https://github.com/tailscale/tailscale/commit/f414a9cc01f3264912513d07c0244ff4f3e4ba54
//
// NOTE: fuzz tests act like unit tests when run without `-fuzz`
func FuzzClampEDNSSize(f *testing.F) {
	// Empty DNS packet
	f.Add([]byte{
		// query id
		0x12, 0x34,
		// flags: standard query, recurse
		0x01, 0x20,
		// num questions
		0x00, 0x00,
		// num answers
		0x00, 0x00,
		// num authority RRs
		0x00, 0x00,
		// num additional RRs
		0x00, 0x00,
	})

	// Empty OPT
	f.Add([]byte{
		// header
		0xaf, 0x66, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		// query
		0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f,
		0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
		// OPT
		0x00,       // name: <root>
		0x00, 0x29, // type: OPT
		0x10, 0x00, // UDP payload size
		0x00,       // higher bits in extended RCODE
		0x00,       // EDNS0 version
		0x80, 0x00, // "Z" field
		0x00, 0x00, // data length
	})

	// Query for "google.com"
	f.Add([]byte{
		// header
		0xaf, 0x66, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		// query
		0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f,
		0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
		// OPT
		0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00,
		0x0c, 0x00, 0x0a, 0x00, 0x08, 0x62, 0x18, 0x1a, 0xcb, 0x19,
		0xd7, 0xee, 0x23,
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		clampEDNSSize(data, maxResponseBytes)
	})
}

type testDNSServerOptions struct {
	SkipUDP bool
	SkipTCP bool
}

func runDNSServer(tb testing.TB, opts *testDNSServerOptions, response []byte, onRequest func(bool, []byte)) (port uint16) {
	if opts != nil && opts.SkipUDP && opts.SkipTCP {
		tb.Fatal("cannot skip both UDP and TCP servers")
	}

	logf := tstest.WhileTestRunningLogger(tb)

	tcpResponse := make([]byte, len(response)+2)
	binary.BigEndian.PutUint16(tcpResponse, uint16(len(response)))
	copy(tcpResponse[2:], response)

	// Repeatedly listen until we can get the same port.
	const tries = 25
	var (
		tcpLn *net.TCPListener
		udpLn *net.UDPConn
		err   error
	)
	for try := 0; try < tries; try++ {
		if tcpLn != nil {
			tcpLn.Close()
			tcpLn = nil
		}

		tcpLn, err = net.ListenTCP("tcp4", &net.TCPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 0, // Choose one
		})
		if err != nil {
			tb.Fatal(err)
		}
		udpLn, err = net.ListenUDP("udp4", &net.UDPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: tcpLn.Addr().(*net.TCPAddr).Port,
		})
		if err == nil {
			break
		}
	}
	if tcpLn == nil || udpLn == nil {
		if tcpLn != nil {
			tcpLn.Close()
		}
		if udpLn != nil {
			udpLn.Close()
		}

		// Skip instead of being fatal to avoid flaking on extremely
		// heavily-loaded CI systems.
		tb.Skipf("failed to listen on same port for TCP/UDP after %d tries", tries)
	}

	port = uint16(tcpLn.Addr().(*net.TCPAddr).Port)

	handleConn := func(conn net.Conn) {
		defer conn.Close()

		// Read the length header, then the buffer
		var length uint16
		if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
			logf("error reading length header: %v", err)
			return
		}
		req := make([]byte, length)
		n, err := io.ReadFull(conn, req)
		if err != nil {
			logf("error reading query: %v", err)
			return
		}
		req = req[:n]
		onRequest(true, req)

		// Write response
		if _, err := conn.Write(tcpResponse); err != nil {
			logf("error writing response: %v", err)
			return
		}
	}

	var wg sync.WaitGroup

	if opts == nil || !opts.SkipTCP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				conn, err := tcpLn.Accept()
				if err != nil {
					return
				}
				go handleConn(conn)
			}
		}()
	}

	handleUDP := func(addr netip.AddrPort, req []byte) {
		onRequest(false, req)
		if _, err := udpLn.WriteToUDPAddrPort(response, addr); err != nil {
			logf("error writing response: %v", err)
		}
	}

	if opts == nil || !opts.SkipUDP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				buf := make([]byte, 65535)
				n, addr, err := udpLn.ReadFromUDPAddrPort(buf)
				if err != nil {
					return
				}
				buf = buf[:n]
				go handleUDP(addr, buf)
			}
		}()
	}

	tb.Cleanup(func() {
		tcpLn.Close()
		udpLn.Close()
		logf("waiting for listeners to finish...")
		wg.Wait()
	})
	return
}

func makeLargeResponse(tb testing.TB, domain string) (request, response []byte) {
	name := dns.MustNewName(domain)

	builder := dns.NewBuilder(nil, dns.Header{Response: true})
	builder.StartQuestions()
	builder.Question(dns.Question{
		Name:  name,
		Type:  dns.TypeA,
		Class: dns.ClassINET,
	})
	builder.StartAnswers()
	for i := range 120 {
		builder.AResource(dns.ResourceHeader{
			Name:  name,
			Class: dns.ClassINET,
			TTL:   300,
		}, dns.AResource{
			A: [4]byte{127, 0, 0, byte(i)},
		})
	}

	var err error
	response, err = builder.Finish()
	if err != nil {
		tb.Fatal(err)
	}
	if len(response) <= maxResponseBytes {
		tb.Fatalf("got len(largeResponse)=%d, want > %d", len(response), maxResponseBytes)
	}

	// Our request is a single A query for the domain in the answer, above.
	request = makeTestRequest(tb, domain, dns.TypeA, 0)

	return
}

func runTestQuery(tb testing.TB, request []byte, modify func(*forwarder), ports ...uint16) ([]byte, error) {
	return runTestQueryWithFamily(tb, request, "udp", modify, ports...)
}

func runTestQueryWithFamily(tb testing.TB, request []byte, family string, modify func(*forwarder), ports ...uint16) ([]byte, error) {
	logf := tstest.WhileTestRunningLogger(tb)
	bus := eventbustest.NewBus(tb)
	netMon, err := netmon.New(bus, logf)
	if err != nil {
		tb.Fatal(err)
	}

	var dialer tsdial.Dialer
	dialer.SetNetMon(netMon)
	dialer.SetBus(bus)

	fwd := newForwarder(logf, netMon, nil, &dialer, health.NewTracker(bus), nil)
	if modify != nil {
		modify(fwd)
	}

	resolvers := make([]resolverAndDelay, len(ports))
	for i, port := range ports {
		resolvers[i].name = &dnstype.Resolver{Addr: fmt.Sprintf("127.0.0.1:%d", port)}
	}

	rpkt := packet{
		bs:     request,
		family: family,
		addr:   netip.MustParseAddrPort("127.0.0.1:12345"),
	}

	rchan := make(chan packet, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	tb.Cleanup(cancel)
	err = fwd.forwardWithDestChan(ctx, rpkt, rchan, resolvers...)
	select {
	case res := <-rchan:
		return res.bs, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// makeTestRequest returns a new DNS request for the given domain.
// If queryType is 0, it defaults to TypeA. If ednsSize > 0, it adds an EDNS OPT record.
func makeTestRequest(tb testing.TB, domain string, queryType dns.Type, ednsSize uint16) []byte {
	tb.Helper()
	if queryType == 0 {
		queryType = dns.TypeA
	}
	name := dns.MustNewName(domain)
	builder := dns.NewBuilder(nil, dns.Header{})
	builder.StartQuestions()
	builder.Question(dns.Question{
		Name:  name,
		Type:  queryType,
		Class: dns.ClassINET,
	})
	if ednsSize > 0 {
		builder.StartAdditionals()
		builder.OPTResource(dns.ResourceHeader{
			Name:  dns.MustNewName("."),
			Type:  dns.TypeOPT,
			Class: dns.Class(ednsSize),
		}, dns.OPTResource{})
	}
	request, err := builder.Finish()
	if err != nil {
		tb.Fatal(err)
	}
	return request
}

// makeTestResponse returns a new Type A response for the given domain,
// with the specified status code and zero or more addresses.
func makeTestResponse(tb testing.TB, domain string, code dns.RCode, addrs ...netip.Addr) []byte {
	tb.Helper()
	name := dns.MustNewName(domain)
	builder := dns.NewBuilder(nil, dns.Header{
		Response:      true,
		Authoritative: true,
		RCode:         code,
	})
	builder.StartQuestions()
	q := dns.Question{
		Name:  name,
		Type:  dns.TypeA,
		Class: dns.ClassINET,
	}
	builder.Question(q)
	if len(addrs) > 0 {
		builder.StartAnswers()
		for _, addr := range addrs {
			builder.AResource(dns.ResourceHeader{
				Name:  q.Name,
				Class: q.Class,
				TTL:   120,
			}, dns.AResource{
				A: addr.As4(),
			})
		}
	}
	response, err := builder.Finish()
	if err != nil {
		tb.Fatal(err)
	}
	return response
}

func mustRunTestQuery(tb testing.TB, request []byte, modify func(*forwarder), ports ...uint16) []byte {
	resp, err := runTestQuery(tb, request, modify, ports...)
	if err != nil {
		tb.Fatalf("error making request: %v", err)
	}
	return resp
}

func beVerbose(f *forwarder) {
	f.verboseFwd = true
}

// makeEDNSResponse creates a DNS response of approximately the specified size
// with TXT records and an OPT record. The response will NOT have the TC flag set
// (simulating a non-compliant server that doesn't set TC when response exceeds EDNS buffer).
// The actual size may vary significantly due to DNS packet structure constraints.
func makeEDNSResponse(tb testing.TB, domain string, targetSize int) []byte {
	tb.Helper()
	// Use makeResponseOfSize with includeOPT=true
	// Allow significant variance since DNS packet sizes are hard to predict exactly
	// Use a combination of fixed tolerance (200 bytes) and percentage (25%) for larger targets
	response := makeResponseOfSize(tb, domain, targetSize, true)
	actualSize := len(response)
	maxVariance := 200
	if targetSize > 400 {
		// For larger targets, allow 25% variance
		maxVariance = targetSize * 25 / 100
	}
	if actualSize < targetSize-maxVariance || actualSize > targetSize+maxVariance {
		tb.Fatalf("response size = %d, want approximately %d (variance: %d, allowed: ±%d)",
			actualSize, targetSize, actualSize-targetSize, maxVariance)
	}
	return response
}

func TestEDNSBufferSizeTruncation(t *testing.T) {
	const domain = "edns-test.example.com."
	const ednsBufferSize = 500 // Small EDNS buffer
	const responseSize = 800   // Response exceeds EDNS but < maxResponseBytes

	// Create a response that exceeds EDNS buffer size but doesn't have TC flag set
	response := makeEDNSResponse(t, domain, responseSize)

	// Create a request with EDNS buffer size
	request := makeTestRequest(t, domain, dns.TypeTXT, ednsBufferSize)
	verifyEDNSBufferSize(t, request, ednsBufferSize)

	// Verify response doesn't have TC flag set initially
	if truncatedFlagSet(response) {
		t.Fatal("test response should not have TC flag set initially")
	}

	// Set up test DNS server
	port := runDNSServer(t, nil, response, func(isTCP bool, gotRequest []byte) {
		verifyEDNSBufferSize(t, gotRequest, ednsBufferSize)
	})

	// Disable TCP retries to ensure we test UDP path
	resp := mustRunTestQuery(t, request, setupForwarderWithTCPRetriesDisabled(), port)

	// Verify the response has TC flag set by forwarder
	if !truncatedFlagSet(resp) {
		t.Errorf("TC flag not set in response (response size=%d, EDNS=%d)", len(resp), ednsBufferSize)
	}

	// Verify response size is preserved (not truncated by buffer)
	if len(resp) != len(response) {
		t.Errorf("response size = %d, want %d (response should not be truncated by buffer)", len(resp), len(response))
	}

	// Verify response size exceeds EDNS buffer
	if len(resp) <= int(ednsBufferSize) {
		t.Errorf("response size = %d, should exceed EDNS buffer size %d", len(resp), ednsBufferSize)
	}
}

// makeResponseOfSize creates a DNS response of approximately the specified size
// with TXT records. The response will NOT have the TC flag set initially.
// If includeOPT is true, an OPT record is added to the response.
func makeResponseOfSize(tb testing.TB, domain string, targetSize int, includeOPT bool) []byte {
	tb.Helper()
	name := dns.MustNewName(domain)

	// Estimate how many TXT records we need
	// Each TXT record with ~200 bytes of data adds roughly 220-230 bytes to the packet
	// (including DNS headers, name compression, etc.)
	bytesPerRecord := 220
	baseSize := 50 // Approximate base packet size (header + question)
	if includeOPT {
		baseSize += 11 // OPT record adds ~11 bytes
	}
	estimatedRecords := (targetSize - baseSize) / bytesPerRecord
	if estimatedRecords < 1 {
		estimatedRecords = 1
	}

	// Start with estimated records and adjust
	txtLen := 200
	var response []byte
	var err error

	for attempt := 0; attempt < 10; attempt++ {
		testBuilder := dns.NewBuilder(nil, dns.Header{
			Response:      true,
			Authoritative: true,
			RCode:         dns.RCodeSuccess,
		})
		testBuilder.StartQuestions()
		testBuilder.Question(dns.Question{
			Name:  name,
			Type:  dns.TypeTXT,
			Class: dns.ClassINET,
		})
		testBuilder.StartAnswers()

		for i := 0; i < estimatedRecords; i++ {
			txtValue := strings.Repeat("x", txtLen)
			testBuilder.TXTResource(dns.ResourceHeader{
				Name:  name,
				Type:  dns.TypeTXT,
				Class: dns.ClassINET,
				TTL:   300,
			}, dns.TXTResource{
				TXT: []string{txtValue},
			})
		}

		// Optionally add OPT record
		if includeOPT {
			testBuilder.StartAdditionals()
			testBuilder.OPTResource(dns.ResourceHeader{
				Name:  dns.MustNewName("."),
				Type:  dns.TypeOPT,
				Class: dns.Class(4096),
			}, dns.OPTResource{})
		}

		response, err = testBuilder.Finish()
		if err != nil {
			tb.Fatal(err)
		}

		actualSize := len(response)
		// Stop if we've reached or slightly exceeded the target
		// Allow up to 20% overshoot to avoid excessive iterations
		if actualSize >= targetSize && actualSize <= targetSize*120/100 {
			break
		}
		// If we've overshot significantly, we're done (better than undershooting)
		if actualSize > targetSize*120/100 {
			break
		}

		// Adjust for next attempt
		needed := targetSize - actualSize
		additionalRecords := (needed / bytesPerRecord) + 1
		estimatedRecords += additionalRecords
		if estimatedRecords > 200 {
			// If we need too many records, increase TXT length instead
			txtLen = 255         // Max single TXT string length
			bytesPerRecord = 280 // Adjusted estimate
			estimatedRecords = (targetSize - baseSize) / bytesPerRecord
			if estimatedRecords < 1 {
				estimatedRecords = 1
			}
		}
	}

	// Ensure TC flag is NOT set initially
	clearTCFlagInPacket(response)

	return response
}

func TestCheckResponseSizeAndSetTC(t *testing.T) {
	const domain = "test.example.com."
	logf := func(format string, args ...any) {
		// Silent logger for tests
	}

	tests := []struct {
		name           string
		responseSize   int
		requestHasEDNS bool
		ednsSize       uint16
		family         string
		responseTCSet  bool // Whether response has TC flag set initially
		wantTCSet      bool // Whether TC flag should be set after function call
		skipIfNotExact bool // Skip test if we can't hit exact size (for edge cases)
	}{
		// Default UDP size (512 bytes) without EDNS
		{
			name:           "UDP_noEDNS_small_should_not_set_TC",
			responseSize:   400,
			requestHasEDNS: false,
			family:         "udp",
			wantTCSet:      false,
		},
		{
			name:           "UDP_noEDNS_512bytes_should_not_set_TC",
			responseSize:   512,
			requestHasEDNS: false,
			family:         "udp",
			wantTCSet:      false,
			skipIfNotExact: true,
		},
		{
			name:           "UDP_noEDNS_513bytes_should_set_TC",
			responseSize:   513,
			requestHasEDNS: false,
			family:         "udp",
			wantTCSet:      true,
			skipIfNotExact: true,
		},
		{
			name:           "UDP_noEDNS_large_should_set_TC",
			responseSize:   600,
			requestHasEDNS: false,
			family:         "udp",
			wantTCSet:      true,
		},

		// EDNS edge cases
		{
			name:           "UDP_EDNS_small_under_limit_should_not_set_TC",
			responseSize:   450,
			requestHasEDNS: true,
			ednsSize:       500,
			family:         "udp",
			wantTCSet:      false,
		},
		{
			name:           "UDP_EDNS_at_limit_should_not_set_TC",
			responseSize:   500,
			requestHasEDNS: true,
			ednsSize:       500,
			family:         "udp",
			wantTCSet:      false,
		},
		{
			name:           "UDP_EDNS_over_limit_should_set_TC",
			responseSize:   550,
			requestHasEDNS: true,
			ednsSize:       500,
			family:         "udp",
			wantTCSet:      true,
		},
		{
			name:           "UDP_EDNS_large_over_limit_should_set_TC",
			responseSize:   1500,
			requestHasEDNS: true,
			ednsSize:       1200,
			family:         "udp",
			wantTCSet:      true,
		},

		// Early return paths
		{
			name:         "TCP_query_should_skip",
			responseSize: 1000,
			family:       "tcp",
			wantTCSet:    false,
		},
		{
			name:         "response_too_small_should_skip",
			responseSize: headerBytes - 1,
			family:       "udp",
			wantTCSet:    false,
		},
		{
			name:         "response_exactly_headerBytes_should_not_set_TC",
			responseSize: headerBytes,
			family:       "udp",
			wantTCSet:    false,
		},
		{
			name:          "response_TC_already_set_should_skip",
			responseSize:  600,
			family:        "udp",
			responseTCSet: true,
			wantTCSet:     true, // Should remain set
		},
		{
			name:           "UDP_noEDNS_large_TC_already_set_should_skip",
			responseSize:   600,
			requestHasEDNS: false,
			family:         "udp",
			responseTCSet:  true,
			wantTCSet:      true, // Should remain set
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var response []byte

			// Create response of specified size
			if tt.responseSize < headerBytes {
				// For too-small test, create minimal invalid packet
				response = make([]byte, tt.responseSize)
				// Don't set any flags, just make it too small
			} else {
				response = makeResponseOfSize(t, domain, tt.responseSize, false)
				actualSize := len(response)

				// Only adjust expectations for UDP queries that go through size checking
				// TCP queries and other early-return cases should keep their original expectations
				if tt.family == "udp" && !tt.responseTCSet && actualSize >= headerBytes {
					// Determine the maximum allowed size based on request
					var maxSize int
					if tt.requestHasEDNS {
						maxSize = int(tt.ednsSize)
					} else {
						maxSize = 512 // default UDP size per RFC 1035
					}

					// For edge cases where exact size matters, verify we're close enough
					if tt.skipIfNotExact {
						// For 512/513 byte tests, we need to be very close
						if actualSize < tt.responseSize-10 || actualSize > tt.responseSize+10 {
							t.Skipf("skipping: could not create response close to target size %d (got %d)", tt.responseSize, actualSize)
						}
						// Function sets TC if response > maxSize, so adjust expectation based on actual size
						tt.wantTCSet = actualSize > maxSize
					} else {
						// For non-exact tests, adjust expectation based on actual response size
						// The function sets TC if actualSize > maxSize
						tt.wantTCSet = actualSize > maxSize
					}
				}
			}

			// Set TC flag initially if requested
			if tt.responseTCSet {
				setTCFlagInPacket(response)
			}

			// Create request with or without EDNS
			var ednsSize uint16
			if tt.requestHasEDNS {
				ednsSize = tt.ednsSize
			}
			request := makeTestRequest(t, domain, dns.TypeTXT, ednsSize)

			// Call the function
			result := checkResponseSizeAndSetTC(response, request, tt.family, logf)

			// Verify response size is preserved (function should not truncate, only set flag)
			if len(result) != len(response) {
				t.Errorf("response size changed: got %d, want %d", len(result), len(response))
			}

			// Verify TC flag state
			if len(result) >= headerBytes {
				hasTC := truncatedFlagSet(result)
				if hasTC != tt.wantTCSet {
					t.Errorf("TC flag: got %v, want %v (response size=%d)", hasTC, tt.wantTCSet, len(result))
				}
			} else if tt.responseSize >= headerBytes {
				// If we expected a valid response but got too small, that's unexpected
				t.Errorf("response too small (%d bytes) but expected valid response", len(result))
			}

			// Verify response pointer is same (should be in-place modification)
			if &result[0] != &response[0] {
				t.Errorf("function should modify response in place, but got new slice")
			}
		})
	}
}

func TestForwarderTCPFallback(t *testing.T) {
	const domain = "large-dns-response.tailscale.com."

	// Make a response that's very large, containing a bunch of localhost addresses.
	request, largeResponse := makeLargeResponse(t, domain)

	var sawTCPRequest atomic.Bool
	port := runDNSServer(t, nil, largeResponse, func(isTCP bool, gotRequest []byte) {
		if isTCP {
			t.Logf("saw TCP request")
			sawTCPRequest.Store(true)
		} else {
			t.Logf("saw UDP request")
		}

		if !bytes.Equal(request, gotRequest) {
			t.Errorf("invalid request\ngot: %+v\nwant: %+v", gotRequest, request)
		}
	})

	resp, err := runTestQueryWithFamily(t, request, "tcp", beVerbose, port)
	if err != nil {
		t.Fatalf("error making request: %v", err)
	}
	if !bytes.Equal(resp, largeResponse) {
		t.Errorf("invalid response\ngot: %+v\nwant: %+v", resp, largeResponse)
	}
	if !sawTCPRequest.Load() {
		t.Errorf("DNS server never saw TCP request")
	}

	// NOTE: can't assert that we see a UDP request here since we might
	// race and run the TCP query first. We test the UDP codepath in
	// TestForwarderTCPFallbackDisabled below, though.
}

// Test to ensure that if the UDP listener is unresponsive, we always make a
// TCP request even if we never get a response.
func TestForwarderTCPFallbackTimeout(t *testing.T) {
	const domain = "large-dns-response.tailscale.com."

	// Make a response that's very large, containing a bunch of localhost addresses.
	request, largeResponse := makeLargeResponse(t, domain)

	var sawTCPRequest atomic.Bool
	opts := &testDNSServerOptions{SkipUDP: true}
	port := runDNSServer(t, opts, largeResponse, func(isTCP bool, gotRequest []byte) {
		if isTCP {
			t.Logf("saw TCP request")
			sawTCPRequest.Store(true)
		} else {
			t.Error("saw unexpected UDP request")
		}

		if !bytes.Equal(request, gotRequest) {
			t.Errorf("invalid request\ngot: %+v\nwant: %+v", gotRequest, request)
		}
	})

	resp := mustRunTestQuery(t, request, beVerbose, port)
	if !bytes.Equal(resp, largeResponse) {
		t.Errorf("invalid response\ngot: %+v\nwant: %+v", resp, largeResponse)
	}
	if !sawTCPRequest.Load() {
		t.Errorf("DNS server never saw TCP request")
	}
}

func TestForwarderTCPFallbackDisabled(t *testing.T) {
	const domain = "large-dns-response.tailscale.com."

	// Make a response that's very large, containing a bunch of localhost addresses.
	request, largeResponse := makeLargeResponse(t, domain)

	var sawUDPRequest atomic.Bool
	port := runDNSServer(t, nil, largeResponse, func(isTCP bool, gotRequest []byte) {
		if isTCP {
			t.Error("saw unexpected TCP request")
		} else {
			t.Logf("saw UDP request")
			sawUDPRequest.Store(true)
		}

		if !bytes.Equal(request, gotRequest) {
			t.Errorf("invalid request\ngot: %+v\nwant: %+v", gotRequest, request)
		}
	})

	resp := mustRunTestQuery(t, request, func(fwd *forwarder) {
		fwd.verboseFwd = true
		setupForwarderWithTCPRetriesDisabled()(fwd)
	}, port)

	wantResp := append([]byte(nil), largeResponse[:maxResponseBytes]...)

	// Set the truncated flag on the expected response, since that's what we expect.
	setTCFlagInPacket(wantResp)

	if !bytes.Equal(resp, wantResp) {
		t.Errorf("invalid response\ngot (%d): %+v\nwant (%d): %+v", len(resp), resp, len(wantResp), wantResp)
	}
	if !sawUDPRequest.Load() {
		t.Errorf("DNS server never saw UDP request")
	}
}

// Test to ensure that we propagate DNS errors
func TestForwarderTCPFallbackError(t *testing.T) {
	const domain = "error-response.tailscale.com."

	// Our response is a SERVFAIL
	response := makeTestResponse(t, domain, dns.RCodeServerFailure)

	// Our request is a single A query for the domain in the answer, above.
	request := makeTestRequest(t, domain, dns.TypeA, 0)

	var sawRequest atomic.Bool
	port := runDNSServer(t, nil, response, func(isTCP bool, gotRequest []byte) {
		sawRequest.Store(true)
		if !bytes.Equal(request, gotRequest) {
			t.Errorf("invalid request\ngot: %+v\nwant: %+v", gotRequest, request)
		}
	})

	resp, err := runTestQuery(t, request, beVerbose, port)
	if !sawRequest.Load() {
		t.Error("did not see DNS request")
	}
	if err != nil {
		t.Fatalf("wanted nil, got %v", err)
	}
	var parser dns.Parser
	respHeader, err := parser.Start(resp)
	if err != nil {
		t.Fatalf("parser.Start() failed: %v", err)
	}
	if got, want := respHeader.RCode, dns.RCodeServerFailure; got != want {
		t.Errorf("wanted %v, got %v", want, got)
	}
}

// Test to ensure that if we have more than one resolver, and at least one of them
// returns a successful response, we propagate it.
func TestForwarderWithManyResolvers(t *testing.T) {
	const domain = "example.com."
	request := makeTestRequest(t, domain, dns.TypeA, 0)

	tests := []struct {
		name          string
		responses     [][]byte // upstream responses
		wantResponses [][]byte // we should receive one of these from the forwarder
	}{
		{
			name: "Success",
			responses: [][]byte{ // All upstream servers returned successful, but different, response.
				makeTestResponse(t, domain, dns.RCodeSuccess, netip.MustParseAddr("127.0.0.1")),
				makeTestResponse(t, domain, dns.RCodeSuccess, netip.MustParseAddr("127.0.0.2")),
				makeTestResponse(t, domain, dns.RCodeSuccess, netip.MustParseAddr("127.0.0.3")),
			},
			wantResponses: [][]byte{ // We may forward whichever response is received first.
				makeTestResponse(t, domain, dns.RCodeSuccess, netip.MustParseAddr("127.0.0.1")),
				makeTestResponse(t, domain, dns.RCodeSuccess, netip.MustParseAddr("127.0.0.2")),
				makeTestResponse(t, domain, dns.RCodeSuccess, netip.MustParseAddr("127.0.0.3")),
			},
		},
		{
			name: "ServFail",
			responses: [][]byte{ // All upstream servers returned a SERVFAIL.
				makeTestResponse(t, domain, dns.RCodeServerFailure),
				makeTestResponse(t, domain, dns.RCodeServerFailure),
				makeTestResponse(t, domain, dns.RCodeServerFailure),
			},
			wantResponses: [][]byte{
				makeTestResponse(t, domain, dns.RCodeServerFailure),
			},
		},
		{
			name: "ServFail+Success",
			responses: [][]byte{ // All upstream servers fail except for one.
				makeTestResponse(t, domain, dns.RCodeServerFailure),
				makeTestResponse(t, domain, dns.RCodeServerFailure),
				makeTestResponse(t, domain, dns.RCodeSuccess, netip.MustParseAddr("127.0.0.1")),
				makeTestResponse(t, domain, dns.RCodeServerFailure),
			},
			wantResponses: [][]byte{ // We should forward the successful response.
				makeTestResponse(t, domain, dns.RCodeSuccess, netip.MustParseAddr("127.0.0.1")),
			},
		},
		{
			name: "NXDomain",
			responses: [][]byte{ // All upstream servers returned NXDOMAIN.
				makeTestResponse(t, domain, dns.RCodeNameError),
				makeTestResponse(t, domain, dns.RCodeNameError),
				makeTestResponse(t, domain, dns.RCodeNameError),
			},
			wantResponses: [][]byte{
				makeTestResponse(t, domain, dns.RCodeNameError),
			},
		},
		{
			name: "NXDomain+Success",
			responses: [][]byte{ // All upstream servers returned NXDOMAIN except for one.
				makeTestResponse(t, domain, dns.RCodeNameError),
				makeTestResponse(t, domain, dns.RCodeNameError),
				makeTestResponse(t, domain, dns.RCodeSuccess, netip.MustParseAddr("127.0.0.1")),
			},
			wantResponses: [][]byte{ // However, only SERVFAIL are considered to be errors. Therefore, we may forward any response.
				makeTestResponse(t, domain, dns.RCodeNameError),
				makeTestResponse(t, domain, dns.RCodeSuccess, netip.MustParseAddr("127.0.0.1")),
			},
		},
		{
			name: "Refused",
			responses: [][]byte{ // All upstream servers return different failures.
				makeTestResponse(t, domain, dns.RCodeRefused),
				makeTestResponse(t, domain, dns.RCodeRefused),
				makeTestResponse(t, domain, dns.RCodeRefused),
				makeTestResponse(t, domain, dns.RCodeRefused),
				makeTestResponse(t, domain, dns.RCodeRefused),
				makeTestResponse(t, domain, dns.RCodeSuccess, netip.MustParseAddr("127.0.0.1")),
			},
			wantResponses: [][]byte{ // Refused is not considered to be an error and can be forwarded.
				makeTestResponse(t, domain, dns.RCodeRefused),
				makeTestResponse(t, domain, dns.RCodeSuccess, netip.MustParseAddr("127.0.0.1")),
			},
		},
		{
			name: "MixFail",
			responses: [][]byte{ // All upstream servers return different failures.
				makeTestResponse(t, domain, dns.RCodeServerFailure),
				makeTestResponse(t, domain, dns.RCodeNameError),
				makeTestResponse(t, domain, dns.RCodeRefused),
			},
			wantResponses: [][]byte{ // Both NXDomain and Refused can be forwarded.
				makeTestResponse(t, domain, dns.RCodeNameError),
				makeTestResponse(t, domain, dns.RCodeRefused),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ports := make([]uint16, len(tt.responses))
			for i := range tt.responses {
				ports[i] = runDNSServer(t, nil, tt.responses[i], func(isTCP bool, gotRequest []byte) {})
			}
			gotResponse, err := runTestQuery(t, request, beVerbose, ports...)
			if err != nil {
				t.Fatalf("wanted nil, got %v", err)
			}
			responseOk := slices.ContainsFunc(tt.wantResponses, func(wantResponse []byte) bool {
				return slices.Equal(gotResponse, wantResponse)
			})
			if !responseOk {
				t.Errorf("invalid response\ngot: %+v\nwant: %+v", gotResponse, tt.wantResponses[0])
			}
		})
	}
}

// mdnsResponder at minimum has an expectation that NXDOMAIN must include the
// question, otherwise it will penalize our server (#13511).
func TestNXDOMAINIncludesQuestion(t *testing.T) {
	var domain = "lb._dns-sd._udp.example.org."

	// Our response is a NXDOMAIN
	response := func() []byte {
		name := dns.MustNewName(domain)

		builder := dns.NewBuilder(nil, dns.Header{
			Response: true,
			RCode:    dns.RCodeNameError,
		})
		builder.StartQuestions()
		builder.Question(dns.Question{
			Name:  name,
			Type:  dns.TypePTR,
			Class: dns.ClassINET,
		})
		response, err := builder.Finish()
		if err != nil {
			t.Fatal(err)
		}
		return response
	}()

	// Our request is a single PTR query for the domain in the answer, above.
	request := makeTestRequest(t, domain, dns.TypePTR, 0)

	port := runDNSServer(t, nil, response, func(isTCP bool, gotRequest []byte) {
	})

	res, err := runTestQuery(t, request, beVerbose, port)
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(res, response) {
		t.Errorf("invalid response\ngot: %+v\nwant: %+v", res, response)
	}
}

func TestForwarderVerboseLogs(t *testing.T) {
	const domain = "test.tailscale.com."
	response := makeTestResponse(t, domain, dns.RCodeServerFailure)
	request := makeTestRequest(t, domain, dns.TypeA, 0)

	port := runDNSServer(t, nil, response, func(isTCP bool, gotRequest []byte) {
		if !bytes.Equal(request, gotRequest) {
			t.Errorf("invalid request\ngot: %+v\nwant: %+v", gotRequest, request)
		}
	})

	var (
		mu     sync.Mutex // protects following
		done   bool
		logBuf bytes.Buffer
	)
	fwdLogf := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		if done {
			return // no logging after test is done
		}

		t.Logf("[forwarder] "+format, args...)
		fmt.Fprintf(&logBuf, format+"\n", args...)
	}
	t.Cleanup(func() {
		mu.Lock()
		done = true
		mu.Unlock()
	})

	_, err := runTestQuery(t, request, func(f *forwarder) {
		f.logf = fwdLogf
		f.verboseFwd = true
	}, port)
	if err != nil {
		t.Fatal(err)
	}

	logStr := logBuf.String()
	if !strings.Contains(logStr, "forwarder.send(") {
		t.Errorf("expected forwarding log, got:\n%s", logStr)
	}
}
