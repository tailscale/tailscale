// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package resolver

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/envknob"
	"tailscale.com/health"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tstest"
	"tailscale.com/types/dnstype"
	"tailscale.com/util/eventbus/eventbustest"
)

const testNextDNSProfile = "https://dns.nextdns.io/c3a884"

var (
	steeredV4 = netip.MustParseAddr("203.0.113.7")
	steeredV6 = netip.MustParseAddr("2001:db8::7")
	otherV4   = netip.MustParseAddr("198.51.100.9")
	anycastV4 = netip.MustParseAddr("45.90.28.0")
	anycastV6 = netip.MustParseAddr("2a07:a8c0::c3:a884")
	privateV4 = netip.MustParseAddr("10.0.0.1")
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// fakeDoH is a DoH server that echoes queries back and answers NextDNS
// steering lookups for nextDNSSteeringName with steer.
type fakeDoH struct {
	mu         sync.Mutex
	err        error         // if non-nil, every request fails with it
	lookupGate chan struct{} // if non-nil, steering lookups wait for it to close
	queryGate  chan struct{} // if non-nil, other requests wait for it to close
	steer      []netip.Addr  // steering answers
	ttl        time.Duration // TTL of steering answers, or steerTTL if zero
	queries    int           // requests other than steering lookups
	lookups    int           // steering lookups
}

const steerTTL = 30 * time.Minute

func (d *fakeDoH) client() *http.Client {
	return &http.Client{Transport: roundTripFunc(d.roundTrip)}
}

func (d *fakeDoH) setSteer(ips ...netip.Addr) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.steer = ips
}

func (d *fakeDoH) counts() (queries, lookups int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.queries, d.lookups
}

func (d *fakeDoH) roundTrip(r *http.Request) (*http.Response, error) {
	if err := r.Context().Err(); err != nil {
		return nil, err
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	if r.URL.String() == nextDNSSteeringURL {
		if d.lookupGate != nil {
			<-d.lookupGate
		}
	} else if d.queryGate != nil {
		<-d.queryGate
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	res := body
	if r.URL.String() == nextDNSSteeringURL {
		d.lookups++
		ttl := cmp.Or(d.ttl, steerTTL)
		if res, err = steeringAnswer(body, d.steer, ttl); err != nil {
			return nil, err
		}
	} else {
		d.queries++
	}
	if d.err != nil {
		return nil, d.err
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {dohType}},
		Body:       io.NopCloser(bytes.NewReader(res)),
		Request:    r,
	}, nil
}

// steeringAnswer answers query the way NextDNS does: a CNAME to
// steering.nextdns.io followed by the ips of the queried family.
func steeringAnswer(query []byte, ips []netip.Addr, ttl time.Duration) ([]byte, error) {
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil {
		return nil, err
	}
	q, err := p.Question()
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true})
	b.StartQuestions()
	b.Question(q)
	b.StartAnswers()
	rh := func(typ dnsmessage.Type) dnsmessage.ResourceHeader {
		return dnsmessage.ResourceHeader{Name: q.Name, Type: typ, Class: dnsmessage.ClassINET, TTL: uint32(ttl / time.Second)}
	}
	b.CNAMEResource(rh(dnsmessage.TypeCNAME), dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("steering.nextdns.io.")})
	for _, ip := range ips {
		switch {
		case q.Type == dnsmessage.TypeA && ip.Is4():
			b.AResource(rh(dnsmessage.TypeA), dnsmessage.AResource{A: ip.As4()})
		case q.Type == dnsmessage.TypeAAAA && ip.Is6():
			b.AAAAResource(rh(dnsmessage.TypeAAAA), dnsmessage.AAAAResource{AAAA: ip.As16()})
		}
	}
	return b.Finish()
}

// newSteeringTestForwarder returns a forwarder whose DoH clients for each
// upstream URL base are the given fakes.
func newSteeringTestForwarder(t *testing.T, upstreams map[string]*fakeDoH) *forwarder {
	f := &forwarder{logf: t.Logf, dialer: new(tsdial.Dialer)}
	f.ctx, f.ctxCancel = context.WithCancel(context.Background())
	t.Cleanup(f.ctxCancel)
	f.dohClient = map[string]*http.Client{}
	for urlBase, d := range upstreams {
		f.dohClient[urlBase] = d.client()
	}
	return f
}

func sendTestQuery(ctx context.Context, t *testing.T, f *forwarder, urlBase string) error {
	fq := &forwardQuery{txid: someDNSID, packet: someDNSQuestion(t), family: "udp"}
	_, err := f.send(ctx, fq, resolverAndDelay{name: &dnstype.Resolver{Addr: urlBase}})
	return err
}

func mustSend(t *testing.T, f *forwarder, urlBase string) {
	t.Helper()
	if err := sendTestQuery(context.Background(), t, f, urlBase); err != nil {
		t.Fatalf("send: %v", err)
	}
}

func steeredNow(f *forwarder) *steeredClient {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.nextDNS.cur
}

func setSteered(f *forwarder, sc *steeredClient) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextDNS = nextDNSSteering{cur: sc, nextRefresh: time.Now().Add(time.Hour)}
}

func checkSteeredIPs(t *testing.T, f *forwarder, want ...netip.Addr) *steeredClient {
	t.Helper()
	sc := steeredNow(f)
	if sc == nil {
		t.Fatalf("no steered client; want one for %v", want)
	}
	if !slices.Equal(sc.ips, want) {
		t.Fatalf("steered IPs = %v; want %v", sc.ips, want)
	}
	return sc
}

func checkCounts(t *testing.T, name string, d *fakeDoH, wantQueries, wantLookups int) {
	t.Helper()
	if queries, lookups := d.counts(); queries != wantQueries || lookups != wantLookups {
		t.Fatalf("%s: got %d queries, %d steering lookups; want %d, %d", name, queries, lookups, wantQueries, wantLookups)
	}
}

func TestNextDNSSteers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		anycast := &fakeDoH{steer: []netip.Addr{steeredV6, anycastV4, anycastV6, privateV4, steeredV4}}
		f := newSteeringTestForwarder(t, map[string]*fakeDoH{testNextDNSProfile: anycast})

		mustSend(t, f, testNextDNSProfile)
		synctest.Wait()
		checkCounts(t, "anycast", anycast, 1, 2)
		sc := checkSteeredIPs(t, f, steeredV4, steeredV6)

		steered := &fakeDoH{}
		setSteered(f, &steeredClient{client: steered.client(), ips: sc.ips})
		mustSend(t, f, testNextDNSProfile)
		checkCounts(t, "steered", steered, 1, 0)
		checkCounts(t, "anycast", anycast, 1, 2)
	})
}

func TestNextDNSLookupWaitsForQuery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		anycast := &fakeDoH{steer: []netip.Addr{steeredV4}, queryGate: make(chan struct{})}
		f := newSteeringTestForwarder(t, map[string]*fakeDoH{testNextDNSProfile: anycast})

		done := make(chan error)
		go func() { done <- sendTestQuery(context.Background(), t, f, testNextDNSProfile) }()
		synctest.Wait()
		checkCounts(t, "anycast", anycast, 0, 0)

		close(anycast.queryGate)
		if err := <-done; err != nil {
			t.Fatalf("send: %v", err)
		}
		synctest.Wait()
		checkCounts(t, "anycast", anycast, 1, 2)
		checkSteeredIPs(t, f, steeredV4)
	})
}

func TestNextDNSOneRefreshAtATime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		anycast := &fakeDoH{steer: []netip.Addr{steeredV4}, lookupGate: make(chan struct{})}
		f := newSteeringTestForwarder(t, map[string]*fakeDoH{testNextDNSProfile: anycast})

		for range 3 {
			mustSend(t, f, testNextDNSProfile)
		}
		close(anycast.lookupGate)
		synctest.Wait()
		checkCounts(t, "anycast", anycast, 3, 2)
	})
}

func TestNextDNSSteeredFailureFallsBack(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		anycast := &fakeDoH{steer: []netip.Addr{steeredV4}}
		steered := &fakeDoH{err: errors.New("connection refused")}
		f := newSteeringTestForwarder(t, map[string]*fakeDoH{testNextDNSProfile: anycast})
		setSteered(f, &steeredClient{client: steered.client(), ips: []netip.Addr{steeredV4}})

		mustSend(t, f, testNextDNSProfile)
		checkCounts(t, "steered", steered, 1, 0)
		checkCounts(t, "anycast", anycast, 1, 0)
		if sc := steeredNow(f); sc != nil {
			t.Fatalf("steered client %v kept after failure", sc.ips)
		}

		mustSend(t, f, testNextDNSProfile)
		synctest.Wait()
		checkCounts(t, "steered", steered, 1, 0)
		checkCounts(t, "anycast", anycast, 2, 0)

		time.Sleep(nextDNSRetryInterval - time.Second)
		mustSend(t, f, testNextDNSProfile)
		synctest.Wait()
		checkCounts(t, "anycast", anycast, 3, 0)

		time.Sleep(time.Second)
		mustSend(t, f, testNextDNSProfile)
		synctest.Wait()
		checkCounts(t, "anycast", anycast, 4, 2)
		checkSteeredIPs(t, f, steeredV4)
	})
}

func TestNextDNSUnreachableSteeredIPsFallBack(t *testing.T) {
	tests := []struct {
		name string
		dial func(ctx context.Context, peers chan<- net.Conn) (net.Conn, error)
	}{
		{
			name: "dial-hangs",
			dial: func(ctx context.Context, _ chan<- net.Conn) (net.Conn, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			},
		},
		{
			name: "tls-hangs",
			dial: func(_ context.Context, peers chan<- net.Conn) (net.Conn, error) {
				c, peer := net.Pipe()
				peers <- peer
				return c, nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envknob.SetenvForTest(t, "TS_DEBUG_DNS_FORWARD_USE_ROUTES", "false")
			synctest.Test(t, func(t *testing.T) {
				anycast := &fakeDoH{steer: []netip.Addr{steeredV4}}
				f := newSteeringTestForwarder(t, map[string]*fakeDoH{testNextDNSProfile: anycast})
				peers := make(chan net.Conn, 1)
				f.dialer.SetSystemDialer(func(ctx context.Context, _, _ string) (net.Conn, error) {
					return tt.dial(ctx, peers)
				})
				mustSend(t, f, testNextDNSProfile)
				synctest.Wait()
				checkSteeredIPs(t, f, steeredV4)

				ctx, cancel := context.WithTimeout(context.Background(), dnsQueryTimeout)
				defer cancel()
				if err := sendTestQuery(ctx, t, f, testNextDNSProfile); err != nil {
					t.Fatalf("send: %v", err)
				}
				checkCounts(t, "anycast", anycast, 2, 2)
				if sc := steeredNow(f); sc != nil {
					t.Fatalf("steered client %v kept after timing out", sc.ips)
				}
				close(peers)
				for p := range peers {
					p.Close()
				}
			})
		})
	}
}

func TestNextDNSFailedLookupWaits(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		anycast := &fakeDoH{}
		f := newSteeringTestForwarder(t, map[string]*fakeDoH{testNextDNSProfile: anycast})

		mustSend(t, f, testNextDNSProfile)
		synctest.Wait()
		checkCounts(t, "anycast", anycast, 1, 2)

		time.Sleep(nextDNSRetryInterval - time.Second)
		mustSend(t, f, testNextDNSProfile)
		synctest.Wait()
		checkCounts(t, "anycast", anycast, 2, 2)

		anycast.setSteer(steeredV4)
		time.Sleep(time.Second)
		mustSend(t, f, testNextDNSProfile)
		synctest.Wait()
		checkCounts(t, "anycast", anycast, 3, 4)
		checkSteeredIPs(t, f, steeredV4)
	})
}

func TestNextDNSStaleFailureKeepsNewSteering(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		anycast := &fakeDoH{steer: []netip.Addr{steeredV4}}
		f := newSteeringTestForwarder(t, map[string]*fakeDoH{testNextDNSProfile: anycast})
		fresh := &steeredClient{client: (&fakeDoH{}).client(), ips: []netip.Addr{otherV4}}
		stale := &steeredClient{ips: []netip.Addr{steeredV4}}
		stale.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			setSteered(f, fresh)
			return nil, errors.New("connection refused")
		})}
		setSteered(f, stale)

		mustSend(t, f, testNextDNSProfile)
		if steeredNow(f) != fresh {
			t.Fatal("failure on a replaced steered client dropped its replacement")
		}
	})
}

func TestNextDNSFailureDuringRefreshBacksOff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		anycast := &fakeDoH{steer: []netip.Addr{otherV4}, lookupGate: make(chan struct{})}
		steered := &fakeDoH{}
		f := newSteeringTestForwarder(t, map[string]*fakeDoH{testNextDNSProfile: anycast})
		f.nextDNS.cur = &steeredClient{client: steered.client(), ips: []netip.Addr{steeredV4}}

		mustSend(t, f, testNextDNSProfile)
		synctest.Wait()
		steered.mu.Lock()
		steered.err = errors.New("connection refused")
		steered.mu.Unlock()
		mustSend(t, f, testNextDNSProfile)
		close(anycast.lookupGate)
		synctest.Wait()
		checkCounts(t, "anycast", anycast, 1, 2)
		if sc := steeredNow(f); sc != nil {
			t.Fatalf("refresh in flight re-steered to %v right after a failure", sc.ips)
		}
		f.mu.Lock()
		wait := time.Until(f.nextDNS.nextRefresh)
		f.mu.Unlock()
		if wait != nextDNSRetryInterval {
			t.Fatalf("next refresh in %v after a failure; want %v", wait, nextDNSRetryInterval)
		}
	})
}

func TestNextDNSSteeringFollowsTTL(t *testing.T) {
	tests := []struct {
		name     string
		ttl      time.Duration
		wantWait time.Duration
	}{
		{"ttl", 30 * time.Minute, 30 * time.Minute},
		{"short-ttl", time.Minute, nextDNSRetryInterval},
		{"long-ttl", 2 * time.Hour, nextDNSMaxTTL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				anycast := &fakeDoH{steer: []netip.Addr{steeredV4}, ttl: tt.ttl}
				steered := &fakeDoH{}
				f := newSteeringTestForwarder(t, map[string]*fakeDoH{testNextDNSProfile: anycast})
				first := &steeredClient{client: steered.client(), ips: []netip.Addr{steeredV4}}
				f.nextDNS.cur = first

				mustSend(t, f, testNextDNSProfile)
				synctest.Wait()
				checkCounts(t, "anycast", anycast, 0, 2)
				if sc := checkSteeredIPs(t, f, steeredV4); sc != first {
					t.Fatal("same steered IPs replaced the client")
				}

				time.Sleep(tt.wantWait - time.Second)
				mustSend(t, f, testNextDNSProfile)
				synctest.Wait()
				checkCounts(t, "anycast", anycast, 0, 2)

				time.Sleep(time.Second)
				mustSend(t, f, testNextDNSProfile)
				synctest.Wait()
				checkCounts(t, "anycast", anycast, 0, 4)
				checkCounts(t, "steered", steered, 3, 0)

				anycast.setSteer(otherV4)
				time.Sleep(tt.wantWait)
				mustSend(t, f, testNextDNSProfile)
				synctest.Wait()
				checkCounts(t, "anycast", anycast, 0, 6)
				if sc := checkSteeredIPs(t, f, otherV4); sc == first {
					t.Fatal("new steered IPs kept the old client")
				}
			})
		})
	}
}

func TestNextDNSSteeringSurvivesCanceledQuery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		anycast := &fakeDoH{steer: []netip.Addr{steeredV4}}
		f := newSteeringTestForwarder(t, map[string]*fakeDoH{testNextDNSProfile: anycast})
		sc := &steeredClient{client: (&fakeDoH{}).client(), ips: []netip.Addr{steeredV4}}
		setSteered(f, sc)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := sendTestQuery(ctx, t, f, testNextDNSProfile); err == nil {
			t.Fatal("send succeeded with a canceled context")
		}
		if steeredNow(f) != sc {
			t.Fatal("steered client dropped for a canceled query")
		}
	})
}

func TestNextDNSStalledSteeredIPsDropOnDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		anycast := &fakeDoH{steer: []netip.Addr{steeredV4}}
		f := newSteeringTestForwarder(t, map[string]*fakeDoH{testNextDNSProfile: anycast})
		stalled := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			<-r.Context().Done()
			return nil, r.Context().Err()
		})}
		setSteered(f, &steeredClient{client: stalled, ips: []netip.Addr{steeredV4}})

		ctx, cancel := context.WithTimeout(context.Background(), dnsQueryTimeout)
		defer cancel()
		if err := sendTestQuery(ctx, t, f, testNextDNSProfile); err == nil {
			t.Fatal("send succeeded on a stalled steered client")
		}
		if sc := steeredNow(f); sc != nil {
			t.Fatalf("steered client %v kept after the query ran out of time", sc.ips)
		}
		mustSend(t, f, testNextDNSProfile)
		checkCounts(t, "anycast", anycast, 1, 0)
	})
}

func TestNextDNSSteeringOnlyForNextDNS(t *testing.T) {
	const google = "https://dns.google/dns-query"
	t.Run("other-provider", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			d := &fakeDoH{steer: []netip.Addr{steeredV4}}
			f := newSteeringTestForwarder(t, map[string]*fakeDoH{google: d})
			mustSend(t, f, google)
			synctest.Wait()
			checkCounts(t, google, d, 1, 0)
			if sc := steeredNow(f); sc != nil {
				t.Fatalf("steered to %v for %s", sc.ips, google)
			}
		})
	})
	t.Run("envknob", func(t *testing.T) {
		envknob.SetenvForTest(t, "TS_DEBUG_DNS_NEXTDNS_ANYCAST_ONLY", "true")
		synctest.Test(t, func(t *testing.T) {
			anycast := &fakeDoH{steer: []netip.Addr{steeredV4}}
			f := newSteeringTestForwarder(t, map[string]*fakeDoH{testNextDNSProfile: anycast})
			mustSend(t, f, testNextDNSProfile)
			synctest.Wait()
			checkCounts(t, "anycast", anycast, 1, 0)
			if sc := steeredNow(f); sc != nil {
				t.Fatalf("steered to %v with steering disabled", sc.ips)
			}
		})
	})
}

func TestNextDNSSteeringLive(t *testing.T) {
	if !*testDoH {
		t.Skip("skipping manual test without --test-doh flag")
	}
	logf := tstest.WhileTestRunningLogger(t)
	bus := eventbustest.NewBus(t)
	netMon, err := netmon.New(bus, logf)
	if err != nil {
		t.Fatal(err)
	}
	var dialer tsdial.Dialer
	dialer.SetNetMon(netMon)
	dialer.SetBus(bus)
	f := newForwarder(logf, netMon, nil, &dialer, health.NewTracker(bus), nil)
	defer f.Close()

	anycast, ok := f.getKnownDoHClientForProvider(testNextDNSProfile)
	if !ok {
		t.Fatal("no anycast client")
	}
	f.refreshNextDNSSteering(anycast, nil)
	sc := steeredNow(f)
	if sc == nil {
		t.Fatal("no steered client")
	}
	t.Logf("steered to %v; refresh in %v", sc.ips, time.Until(f.nextDNS.nextRefresh).Round(time.Second))
	for _, ip := range sc.ips {
		if ip == anycastV4 || ip == netip.MustParseAddr("45.90.30.0") {
			t.Errorf("steered IPs include anycast %v", ip)
		}
	}

	res, err := f.sendDoH(context.Background(), nextDNSSteeringURL, sc.client, someDNSQuestion(t))
	if err != nil {
		t.Fatal(err)
	}
	var p dnsmessage.Parser
	if _, err := p.Start(res.Bs); err != nil {
		t.Fatal(err)
	}
	p.SkipAllQuestions()
	answers, err := p.AllAnswers()
	if err != nil {
		t.Fatal(err)
	}
	if len(answers) == 0 {
		t.Fatal("no answers via steered client")
	}
	for _, a := range answers {
		t.Logf("got: %v", a.GoString())
	}
}
