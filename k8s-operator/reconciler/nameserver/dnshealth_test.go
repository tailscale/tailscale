// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package nameserver

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/tstest"
)

func addresses(ips ...string) []netip.Addr {
	var ret []netip.Addr
	for _, ip := range ips {
		ret = append(ret, netip.MustParseAddr(ip))
	}
	return ret
}

func TestSelectProbeRecord(t *testing.T) {
	for _, tt := range []struct {
		name, data, want string
		wantErr          bool
	}{
		{"empty", "", "/[]/[]", false},
		{"no-addresses", `{"version":"v1alpha1","ip4":{"empty.ts.net":[]}}`, "/[]/[]", false},
		{"stable-dual-stack", `{"version":"v1alpha1","ip4":{"z.ts.net":["192.0.2.9"],"a.ts.net":["192.0.2.2","192.0.2.1","192.0.2.1"]},"ip6":{"a.ts.net":["2001:db8::1"]}}`, "a.ts.net./[192.0.2.1 192.0.2.2]/[2001:db8::1]", false},
		{"v6-only", `{"version":"v1alpha1","ip6":{"a.ts.net":["2001:db8::1"]}}`, "a.ts.net./[]/[2001:db8::1]", false},
		{"absolute-name", `{"version":"v1alpha1","ip4":{"A.ts.net.":["192.0.2.1"]}}`, "a.ts.net./[192.0.2.1]/[]", false},
		{"invalid-json", `{`, "", true},
		{"unknown-version", `{"version":"v2"}`, "", true},
		{"other-domain", `{"version":"v1alpha1","ip4":{"a.example.com":["192.0.2.1"]}}`, "", true},
		{"invalid-address", `{"version":"v1alpha1","ip4":{"a.ts.net":["bad"]}}`, "", true},
		{"wrong-family", `{"version":"v1alpha1","ip4":{"a.ts.net":["2001:db8::1"]}}`, "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := selectProbeRecord(tt.data)
			if (err != nil) != tt.wantErr || (!tt.wantErr && got.key() != tt.want) {
				t.Fatalf("got %q, %v; want %q, error=%v", got.key(), err, tt.want, tt.wantErr)
			}
		})
	}
}

func TestResolutionObservation(t *testing.T) {
	for _, tt := range []struct {
		name, network, reason string
		cluster, direct       []netip.Addr
		clusterErr, directErr error
	}{
		{"healthy-v4", "ip4", "DNSResolutionSucceeded", addresses("192.0.2.1"), nil, nil, errors.New("direct access blocked")},
		{"healthy-v6", "ip6", "DNSResolutionSucceeded", addresses("2001:db8::1"), nil, nil, nil},
		{"missing-forwarding", "ip4", "DNSForwardingFailed", nil, addresses("192.0.2.1"), &net.DNSError{IsNotFound: true}, nil},
		{"wrong-forwarding", "ip4", "DNSForwardingFailed", addresses("192.0.2.99"), addresses("192.0.2.1"), nil, nil},
		{"empty-answer", "ip4", "DNSForwardingFailed", nil, addresses("192.0.2.1"), nil, nil},
		{"both-time-out", "ip4", "NameserverUnavailable", nil, nil, context.DeadlineExceeded, context.DeadlineExceeded},
		{"stale-nameserver", "ip4", "NameserverUnavailable", addresses("192.0.2.99"), addresses("192.0.2.99"), nil, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			p := newResolutionProbe(tstest.NewClock(tstest.ClockOpts{}), func(ctx context.Context, network, host, server string) ([]netip.Addr, error) {
				calls++
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > dnsLookupTimeout {
					t.Fatal("lookup has no bounded deadline")
				}
				if network != tt.network || host != "a.ts.net." {
					t.Fatalf("unexpected lookup %q %q", network, host)
				}
				if server == "" {
					return tt.cluster, tt.clusterErr
				}
				return tt.direct, tt.directErr
			})
			rec := probeRecord{name: "a.ts.net."}
			if tt.network == "ip4" {
				rec.ip4 = addresses("192.0.2.1")
			} else {
				rec.ip6 = addresses("2001:db8::1")
			}
			got := p.observe(context.Background(), "192.0.2.53", rec)
			wantStatus := metav1.ConditionFalse
			if tt.reason == "DNSResolutionSucceeded" {
				wantStatus = metav1.ConditionTrue
			} else if tt.reason == "NameserverUnavailable" {
				wantStatus = metav1.ConditionUnknown
			}
			if got.reason != tt.reason || got.status != wantStatus {
				t.Fatalf("got %+v; want reason %s", got, tt.reason)
			}
			if got.status == metav1.ConditionTrue && calls != 1 {
				t.Fatal("healthy cluster resolution must not require direct Service access")
			}
		})
	}
}

func TestDualStackAndAddressOrder(t *testing.T) {
	var networks []string
	p := newResolutionProbe(tstest.NewClock(tstest.ClockOpts{}), func(_ context.Context, network, _, _ string) ([]netip.Addr, error) {
		networks = append(networks, network)
		if network == "ip4" {
			return addresses("192.0.2.2", "192.0.2.1", "192.0.2.1"), nil
		}
		return addresses("2001:db8::1"), nil
	})
	got := p.observe(context.Background(), "192.0.2.53", probeRecord{"a.ts.net.", addresses("192.0.2.1", "192.0.2.2"), addresses("2001:db8::1")})
	if got.status != metav1.ConditionTrue || strings.Join(networks, ",") != "ip4,ip6" {
		t.Fatalf("got %+v; lookups %v", got, networks)
	}
}

type healthFixture struct {
	t          *testing.T
	r          *Reconciler
	client     client.Client
	clock      *tstest.Clock
	events     *record.FakeRecorder
	updates    int
	failUpdate bool
	lookups    int
	healthy    bool
}

func newHealthFixture(t *testing.T) *healthFixture {
	t.Helper()
	f := &healthFixture{t: t, clock: tstest.NewClock(tstest.ClockOpts{}), events: record.NewFakeRecorder(20)}
	cfg := &tsapi.DNSConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test", UID: "test-uid", Generation: 1},
		Spec:       tsapi.DNSConfigSpec{Nameserver: &tsapi.Nameserver{Service: &tsapi.NameserverService{ClusterIP: "192.0.2.53"}}},
	}
	f.client = fake.NewClientBuilder().WithScheme(tsapi.GlobalScheme).WithObjects(cfg).
		WithStatusSubresource(cfg).WithInterceptorFuncs(interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			if f.failUpdate {
				return errors.New("injected status update failure")
			}
			f.updates++
			return c.SubResource(sub).Update(ctx, obj, opts...)
		},
	}).Build()
	f.r = NewReconciler(ReconcilerOptions{Client: f.client, Logger: zap.NewNop().Sugar(), Clock: f.clock, Recorder: f.events, TailscaleNamespace: "tailscale",
		LookupIP: func(_ context.Context, _, _, server string) ([]netip.Addr, error) {
			f.lookups++
			if f.healthy || server != "" {
				return addresses("192.0.2.1"), nil
			}
			return nil, &net.DNSError{IsNotFound: true}
		},
	})
	f.reconcile("NoProbeRecord", metav1.ConditionUnknown)
	return f
}

func (f *healthFixture) records(data string) {
	f.t.Helper()
	var cm corev1.ConfigMap
	key := client.ObjectKey{Namespace: "tailscale", Name: tsoperator.DNSRecordsCMName}
	if err := f.client.Get(context.Background(), key, &cm); err != nil {
		f.t.Fatal(err)
	}
	cm.Data = map[string]string{tsoperator.DNSRecordsCMKey: data}
	if err := f.client.Update(context.Background(), &cm); err != nil {
		f.t.Fatal(err)
	}
}

func (f *healthFixture) get() *tsapi.DNSConfig {
	f.t.Helper()
	cfg := new(tsapi.DNSConfig)
	if err := f.client.Get(context.Background(), client.ObjectKey{Name: "test"}, cfg); err != nil {
		f.t.Fatal(err)
	}
	return cfg
}

func (f *healthFixture) reconcile(reason string, status metav1.ConditionStatus) {
	f.t.Helper()
	res, err := f.r.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test"}})
	if err != nil || res.RequeueAfter <= 0 || res.RequeueAfter > dnsProbeInterval {
		f.t.Fatalf("reconcile result %+v, %v", res, err)
	}
	cfg := f.get()
	if !tsoperator.DNSCfgIsReady(cfg) {
		f.t.Fatal("DNS diagnosis must not block provisioning readiness / record creation")
	}
	got := meta.FindStatusCondition(cfg.Status.Conditions, string(tsapi.DNSResolutionReady))
	if got == nil || got.Reason != reason || got.Status != status || got.ObservedGeneration != cfg.Generation {
		f.t.Fatalf("got condition %+v; want %s/%s", got, status, reason)
	}
}

func (f *healthFixture) event(want string) {
	f.t.Helper()
	select {
	case got := <-f.events.Events:
		if want == "" || !strings.HasPrefix(got, want+" ") {
			f.t.Fatalf("event %q; want %q", got, want)
		}
	default:
		if want != "" {
			f.t.Fatalf("missing event %q", want)
		}
	}
}

const testRecords = `{"version":"v1alpha1","ip4":{"a.ts.net":["192.0.2.1"]}}`

func TestDNSFailureRecoveryAndDeduplication(t *testing.T) {
	f := newHealthFixture(t)
	f.records(testRecords)
	f.reconcile("DNSResolutionPending", metav1.ConditionUnknown)
	updates, lookups := f.updates, f.lookups
	f.reconcile("DNSResolutionPending", metav1.ConditionUnknown)
	if f.updates != updates || f.lookups != lookups {
		t.Fatal("watch events must not cause repeated probes or status writes")
	}
	f.clock.Advance(dnsFailureGracePeriod - dnsProbeInterval)
	f.reconcile("DNSResolutionPending", metav1.ConditionUnknown)
	f.event("")
	f.clock.Advance(dnsProbeInterval)
	f.reconcile("DNSForwardingFailed", metav1.ConditionFalse)
	f.event("Warning DNSForwardingFailed")
	failed := meta.FindStatusCondition(f.get().Status.Conditions, string(tsapi.DNSResolutionReady)).DeepCopy()
	updates = f.updates
	f.clock.Advance(dnsProbeInterval)
	f.reconcile("DNSForwardingFailed", metav1.ConditionFalse)
	if f.updates != updates {
		t.Fatal("identical failure should not write status")
	}
	f.event("")
	f.healthy = true
	f.clock.Advance(dnsProbeInterval)
	f.reconcile("DNSResolutionSucceeded", metav1.ConditionTrue)
	f.event("Normal DNSResolutionRecovered")
	healthy := meta.FindStatusCondition(f.get().Status.Conditions, string(tsapi.DNSResolutionReady))
	if !healthy.LastTransitionTime.After(failed.LastTransitionTime.Time) {
		t.Fatal("recovery did not update transition time")
	}
	updates = f.updates
	f.clock.Advance(dnsProbeInterval)
	f.reconcile("DNSResolutionSucceeded", metav1.ConditionTrue)
	if f.updates != updates {
		t.Fatal("identical success should not write status")
	}
	f.event("")
}

func TestDNSStatusWriteFailureDoesNotLoseEvent(t *testing.T) {
	f := newHealthFixture(t)
	f.records(testRecords)
	f.reconcile("DNSResolutionPending", metav1.ConditionUnknown)
	f.clock.Advance(dnsFailureGracePeriod)
	f.failUpdate = true
	_, err := f.r.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test"}})
	if err == nil {
		t.Fatal("expected failed status update")
	}
	f.event("")
	f.failUpdate = false
	f.reconcile("DNSForwardingFailed", metav1.ConditionFalse)
	f.event("Warning DNSForwardingFailed")
	f.reconcile("DNSForwardingFailed", metav1.ConditionFalse)
	f.event("")
}

func TestDNSUnavailableAndChangedRecords(t *testing.T) {
	f := newHealthFixture(t)
	f.records("{")
	f.reconcile("InvalidDNSRecords", metav1.ConditionUnknown)
	if f.lookups != 0 {
		t.Fatal("invalid configuration must not trigger DNS queries")
	}
	f.records(testRecords)
	cfg := f.get()
	cfg.Spec.Nameserver.Replicas = new(int32(0))
	cfg.Generation++
	if err := f.client.Update(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	f.reconcile("NameserverDisabled", metav1.ConditionUnknown)
	if f.lookups != 0 {
		t.Fatal("disabled nameserver must not trigger DNS queries")
	}
	cfg = f.get()
	cfg.Spec.Nameserver.Replicas = new(int32(1))
	cfg.Generation++
	if err := f.client.Update(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	f.r.dnsProbe.lookupIP = func(context.Context, string, string, string) ([]netip.Addr, error) {
		f.records(strings.ReplaceAll(testRecords, "192.0.2.1", "192.0.2.2"))
		return addresses("192.0.2.1"), nil
	}
	f.reconcile("DNSRecordsChanged", metav1.ConditionUnknown)
	f.event("")
	f.r.dnsProbe.lookupIP = func(context.Context, string, string, string) ([]netip.Addr, error) {
		return addresses("192.0.2.2"), nil
	}
	f.reconcile("DNSResolutionSucceeded", metav1.ConditionTrue)
}

func TestDNSRecordChangeResetsFailureGrace(t *testing.T) {
	f := newHealthFixture(t)
	f.records(testRecords)
	f.reconcile("DNSResolutionPending", metav1.ConditionUnknown)
	f.clock.Advance(dnsFailureGracePeriod)
	f.reconcile("DNSForwardingFailed", metav1.ConditionFalse)
	f.event("Warning DNSForwardingFailed")
	f.records(strings.ReplaceAll(testRecords, "a.ts.net", "b.ts.net"))
	f.reconcile("DNSResolutionPending", metav1.ConditionUnknown)
	f.event("")
}

func TestDNSCancelledReconcileDoesNotPublishFailure(t *testing.T) {
	f := newHealthFixture(t)
	f.records(testRecords)
	ctx, cancel := context.WithCancel(context.Background())
	f.r.dnsProbe.lookupIP = func(context.Context, string, string, string) ([]netip.Addr, error) {
		cancel()
		return nil, context.Canceled
	}
	before, _ := json.Marshal(f.get().Status)
	_, err := f.r.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKey{Name: "test"}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v; want cancellation", err)
	}
	after, _ := json.Marshal(f.get().Status)
	if string(before) != string(after) {
		t.Fatal("cancelled probe published a status update")
	}
	f.event("")
	// A cancelled observation must not be cached or delay the next real check.
	f.healthy = true
	f.r.dnsProbe.lookupIP = func(context.Context, string, string, string) ([]netip.Addr, error) {
		return addresses("192.0.2.1"), nil
	}
	f.reconcile("DNSResolutionSucceeded", metav1.ConditionTrue)
}

func TestNameserverDNSUDPAndTCP(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp4", pc.LocalAddr().String())
	if err != nil {
		pc.Close()
		t.Fatal(err)
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(q)
		switch q.Question[0].Name {
		case "missing.ts.net.":
			m.Rcode = dns.RcodeNameError
		case "silent.ts.net.":
			return // Deliberately never answer; the caller's deadline must win.
		default:
			if w.LocalAddr().Network() == "udp" {
				m.Truncated = true
			} else if q.Question[0].Qtype == dns.TypeA {
				m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("192.0.2.1")}}
			} else {
				m.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET}, AAAA: net.ParseIP("2001:db8::1")}}
			}
		}
		if err := w.WriteMsg(m); err != nil {
			t.Errorf("write DNS response: %v", err)
		}
	})
	for _, srv := range []*dns.Server{{PacketConn: pc, Handler: handler}, {Listener: ln, Handler: handler}} {
		started, done := make(chan struct{}), make(chan error, 1)
		srv.NotifyStartedFunc = func() { close(started) }
		go func() { done <- srv.ActivateAndServe() }()
		<-started
		t.Cleanup(func() {
			srv.Shutdown()
			if err := <-done; err != nil {
				t.Errorf("DNS server: %v", err)
			}
		})
	}
	for _, tt := range []struct {
		qtype uint16
		want  string
	}{{dns.TypeA, "192.0.2.1"}, {dns.TypeAAAA, "2001:db8::1"}} {
		ips, err := lookupNameserverIP(context.Background(), "a.ts.net.", tt.qtype, pc.LocalAddr().String())
		if err != nil || len(ips) != 1 || ips[0].String() != tt.want {
			t.Fatalf("UDP truncation/TCP fallback returned %v, %v; want %s", ips, err, tt.want)
		}
	}
	_, err = lookupNameserverIP(context.Background(), "missing.ts.net.", dns.TypeA, pc.LocalAddr().String())
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Fatalf("got %v; want not found", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = lookupNameserverIP(ctx, "silent.ts.net.", dns.TypeA, pc.LocalAddr().String())
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("DNS deadline not respected: %v after %v", err, time.Since(start))
	}
}

func TestMultipleDNSConfigsDoNotProbeOrReportReady(t *testing.T) {
	f := newHealthFixture(t)
	other := &tsapi.DNSConfig{ObjectMeta: metav1.ObjectMeta{Name: "other"}, Spec: tsapi.DNSConfigSpec{Nameserver: &tsapi.Nameserver{}}}
	if err := f.client.Create(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	_, err := f.r.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test"}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := f.get()
	if tsoperator.DNSCfgIsReady(cfg) || f.lookups != 0 {
		t.Fatal("invalid singleton configuration was probed or marked ready")
	}
	if c := meta.FindStatusCondition(cfg.Status.Conditions, string(tsapi.DNSResolutionReady)); c.Status != metav1.ConditionUnknown {
		t.Fatalf("resolution condition = %+v; want Unknown", c)
	}
	f.event("Warning " + reasonMultipleDNSConfigsPresent)
	f.clock.Advance(dnsProbeInterval)
	if _, err := f.r.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test"}}); err != nil {
		t.Fatal(err)
	}
	f.event("")
}

func TestDNSChecksRequeueAfterProvisioningConflict(t *testing.T) {
	f := newHealthFixture(t)
	f.r.Client = interceptor.NewClient(f.client.(client.WithWatch), interceptor.Funcs{
		Update: func(context.Context, client.WithWatch, client.Object, ...client.UpdateOption) error {
			return errors.New(optimisticLockErrorMsg)
		},
	})
	res, err := f.r.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test"}})
	if err != nil || res.RequeueAfter <= 0 {
		t.Fatalf("provisioning conflict stopped periodic DNS checks: %+v, %v", res, err)
	}
}

// The three resources with no update callback must not issue no-op API writes
// on every health poll. The Deployment still follows normal reconciliation.
func TestDNSPollingDoesNotRewriteUnchangedSupportingResources(t *testing.T) {
	f := newHealthFixture(t)
	f.r.Client = interceptor.NewClient(f.client.(client.WithWatch), interceptor.Funcs{
		Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			switch obj.(type) {
			case *corev1.Service, *corev1.ServiceAccount, *corev1.ConfigMap:
				t.Errorf("unnecessary update of %T", obj)
			}
			return c.Update(ctx, obj, opts...)
		},
	})
	f.reconcile("NoProbeRecord", metav1.ConditionUnknown)
}

func TestDNSReadErrorCannotPublishSuccess(t *testing.T) {
	f := newHealthFixture(t)
	f.records(testRecords)
	f.healthy = true
	f.reconcile("DNSResolutionSucceeded", metav1.ConditionTrue)
	f.event("Normal DNSResolutionSucceeded")
	readErr := errors.New("injected records read error")
	f.r.Client = interceptor.NewClient(f.client.(client.WithWatch), interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*corev1.ConfigMap); ok {
				return readErr
			}
			return c.Get(ctx, key, obj, opts...)
		},
	})
	cfg := f.get()
	got, _, err := f.r.checkDNSResolution(context.Background(), cfg, "192.0.2.53")
	if !errors.Is(err, readErr) || got.status != metav1.ConditionUnknown || got.reason != "DNSRecordsUnavailable" {
		t.Fatalf("got %+v, %v; want Unknown on read failure", got, err)
	}
}

func TestDNSBriefFailureDoesNotReportPersistentFailure(t *testing.T) {
	f := newHealthFixture(t)
	f.records(testRecords)
	f.healthy = true
	f.reconcile("DNSResolutionSucceeded", metav1.ConditionTrue)
	f.event("Normal DNSResolutionSucceeded")
	f.healthy = false
	f.clock.Advance(dnsProbeInterval)
	f.reconcile("DNSResolutionPending", metav1.ConditionUnknown)
	f.event("")
	f.healthy = true
	f.clock.Advance(dnsProbeInterval)
	f.reconcile("DNSResolutionSucceeded", metav1.ConditionTrue)
	f.event("Normal DNSResolutionSucceeded")
	// The next failure needs its own grace period.
	f.healthy = false
	f.clock.Advance(dnsFailureGracePeriod)
	f.reconcile("DNSResolutionPending", metav1.ConditionUnknown)
	f.event("")
}

func TestDNSHealthyRestartReportsRecovery(t *testing.T) {
	f := newHealthFixture(t)
	f.records(testRecords)
	f.reconcile("DNSResolutionPending", metav1.ConditionUnknown)
	f.clock.Advance(dnsFailureGracePeriod)
	f.reconcile("DNSForwardingFailed", metav1.ConditionFalse)
	f.event("Warning DNSForwardingFailed")
	f.healthy = true
	f.r.dnsProbe = newResolutionProbe(f.clock, f.r.dnsProbe.lookupIP)
	f.reconcile("DNSResolutionSucceeded", metav1.ConditionTrue)
	f.event("Normal DNSResolutionRecovered")
}

func TestDNSDirectSocketTimeoutIsReportedAsTimeout(t *testing.T) {
	p := newResolutionProbe(tstest.NewClock(tstest.ClockOpts{}), func(_ context.Context, _, _, server string) ([]netip.Addr, error) {
		if server == "" {
			return nil, &net.DNSError{IsNotFound: true}
		}
		return nil, &net.OpError{Op: "read", Net: "udp", Err: context.DeadlineExceeded}
	})
	got := p.observe(context.Background(), "192.0.2.53", probeRecord{name: "a.ts.net.", ip4: addresses("192.0.2.1")})
	if !strings.Contains(got.message, "also timed out") {
		t.Fatalf("socket timeout not identified: %+v", got)
	}
}

// Without an authoritative answer, an operator resolver failure does not
// establish a cluster DNS mismatch, even after the failure grace has elapsed.
func TestDNSNameserverUnavailableDoesNotReportForwardingFailure(t *testing.T) {
	for _, tt := range []struct {
		name string
		ips  []netip.Addr
		err  error
	}{
		{"timeout", nil, context.DeadlineExceeded},
		{"no-record", nil, &net.DNSError{IsNotFound: true}},
		{"server-failure", nil, errors.New("SERVFAIL")},
		{"empty-answer", nil, nil},
		{"stale-address", addresses("192.0.2.99"), nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newHealthFixture(t)
			f.records(testRecords)
			directAvailable := false
			f.r.dnsProbe.lookupIP = func(_ context.Context, _, _, server string) ([]netip.Addr, error) {
				if server == "" {
					return nil, &net.DNSError{IsNotFound: true}
				}
				if directAvailable {
					return addresses("192.0.2.1"), nil
				}
				return tt.ips, tt.err
			}
			f.reconcile("NameserverUnavailable", metav1.ConditionUnknown)
			updates := f.updates
			f.clock.Advance(2 * dnsFailureGracePeriod)
			f.reconcile("NameserverUnavailable", metav1.ConditionUnknown)
			if f.updates != updates {
				t.Fatal("unchanged unavailable nameserver rewrote status")
			}
			f.event("")
			// An unavailable nameserver must not consume the mismatch grace.
			directAvailable = true
			f.clock.Advance(dnsProbeInterval)
			f.reconcile("DNSResolutionPending", metav1.ConditionUnknown)
			f.event("")
			f.clock.Advance(dnsFailureGracePeriod)
			f.reconcile("DNSForwardingFailed", metav1.ConditionFalse)
			f.event("Warning DNSForwardingFailed")
			// Losing the direct answer invalidates a previously known mismatch.
			directAvailable = false
			f.clock.Advance(dnsProbeInterval)
			f.reconcile("NameserverUnavailable", metav1.ConditionUnknown)
			f.event("")
			directAvailable = true
			f.clock.Advance(dnsProbeInterval)
			f.reconcile("DNSResolutionPending", metav1.ConditionUnknown)
			f.event("")
		})
	}
}
