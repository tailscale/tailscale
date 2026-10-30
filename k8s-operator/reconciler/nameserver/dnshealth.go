// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package nameserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/tstime"
	"tailscale.com/util/dnsname"
)

const (
	dnsProbeInterval = 30 * time.Second
	// Allow ConfigMap projection and resolver reloads to converge before
	// reporting a persistent failure. Recovery is reported on the next success.
	dnsFailureGracePeriod = 2 * time.Minute
	dnsProbeTimeout       = 5 * time.Second
	dnsLookupTimeout      = 2 * time.Second
)

type resolutionObservation struct {
	status          metav1.ConditionStatus
	reason, message string
}

type probeRecord struct {
	name     string // absolute, normalized DNS name
	ip4, ip6 []netip.Addr
}

func (p probeRecord) key() string { return fmt.Sprintf("%s/%v/%v", p.name, p.ip4, p.ip6) }

// selectProbeRecord chooses a stable managed name with at least one address.
// Only the selected record is sampled; this is not a check of every record.
func selectProbeRecord(data string) (probeRecord, error) {
	if data == "" {
		return probeRecord{}, nil
	}
	var records tsoperator.Records
	if err := json.Unmarshal([]byte(data), &records); err != nil {
		return probeRecord{}, err
	}
	if records.Version != tsoperator.Alpha1Version {
		return probeRecord{}, fmt.Errorf("unsupported DNS records version %q", records.Version)
	}
	names := make(map[string]bool)
	for name, ips := range records.IP4 {
		if len(ips) != 0 {
			names[name] = true
		}
	}
	for name, ips := range records.IP6 {
		if len(ips) != 0 {
			names[name] = true
		}
	}
	for _, name := range slices.Sorted(maps.Keys(names)) {
		fqdn, err := dnsname.ToFQDN(strings.ToLower(name))
		if err != nil || !strings.HasSuffix(string(fqdn), ".ts.net.") {
			return probeRecord{}, fmt.Errorf("invalid managed DNS name %q", name)
		}
		p := probeRecord{name: string(fqdn)}
		for i, ips := range [][]string{records.IP4[name], records.IP6[name]} {
			for _, ip := range ips {
				addr, err := netip.ParseAddr(ip)
				if err != nil || addr.Zone() != "" || (i == 0) != addr.Is4() {
					return probeRecord{}, fmt.Errorf("invalid address %q for %q", ip, name)
				}
				if i == 0 {
					p.ip4 = append(p.ip4, addr)
				} else {
					p.ip6 = append(p.ip6, addr)
				}
			}
		}
		p.ip4 = sortedAddresses(p.ip4)
		p.ip6 = sortedAddresses(p.ip6)
		return p, nil
	}
	return probeRecord{}, nil
}

func sortedAddresses(ips []netip.Addr) []netip.Addr {
	ips = slices.Clone(ips)
	slices.SortFunc(ips, netip.Addr.Compare)
	return slices.Compact(ips)
}

// resolutionProbe caches observations between checks. DNSConfig is a singleton;
// switching identity, generation, Service IP or sampled record resets the cache.
// The mutex also protects against concurrent reconciles during invalid singleton
// configurations. The controller normally reconciles one resource at a time.
type resolutionProbe struct {
	mu       sync.Mutex
	clock    tstime.Clock
	lookupIP func(context.Context, string, string, string) ([]netip.Addr, error)
	key      string
	next     time.Time
	failing  bool
	since    time.Time
	last     resolutionObservation
}

func newResolutionProbe(clock tstime.Clock, lookup func(context.Context, string, string, string) ([]netip.Addr, error)) *resolutionProbe {
	if lookup == nil {
		lookup = lookupProbeIP
	}
	return &resolutionProbe{clock: clock, lookupIP: lookup}
}

func (p *resolutionProbe) reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.key, p.failing = "", false
	p.next = time.Time{}
}

func (p *resolutionProbe) check(ctx context.Context, key, server string, record probeRecord) (resolutionObservation, time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.clock.Now()
	if key == p.key && now.Before(p.next) {
		return p.last, p.next.Sub(now)
	}
	probeCtx, cancel := context.WithTimeout(ctx, dnsProbeTimeout)
	defer cancel()
	observation := p.observe(probeCtx, server, record)
	// A cancelled reconcile is not an observation of DNS health. In particular,
	// do not cache it or start the failure grace period for the next reconcile.
	if ctx.Err() != nil {
		return observation, dnsProbeInterval
	}
	if key != p.key {
		p.failing = false
		p.key = key
	}
	if observation.status == metav1.ConditionFalse {
		if !p.failing {
			p.failing, p.since = true, now
		}
		if now.Sub(p.since) < dnsFailureGracePeriod {
			observation = resolutionObservation{metav1.ConditionUnknown, "DNSResolutionPending", fmt.Sprintf("DNS resolution for %q from the operator Pod has not succeeded; waiting for DNS configuration to converge before reporting a persistent failure.", record.name)}
		}
	} else {
		p.failing = false
	}
	p.last, p.next = observation, now.Add(dnsProbeInterval)
	return observation, dnsProbeInterval
}

func (p *resolutionProbe) observe(ctx context.Context, server string, record probeRecord) resolutionObservation {
	for _, family := range []struct {
		network, rrtype string
		ips             []netip.Addr
	}{{"ip4", "A", record.ip4}, {"ip6", "AAAA", record.ip6}} {
		// An IPv4-only name legitimately has no AAAA answer, and vice versa.
		if len(family.ips) == 0 {
			continue
		}
		lookup := func(server string) string {
			queryCtx, cancel := context.WithTimeout(ctx, dnsLookupTimeout)
			defer cancel()
			ips, err := p.lookupIP(queryCtx, family.network, record.name, server)
			if err != nil {
				// Avoid volatile details (for example local UDP ports) in status.
				var dnsErr *net.DNSError
				var netErr net.Error
				switch {
				case errors.Is(err, context.DeadlineExceeded):
					return "timed out"
				case errors.As(err, &netErr) && netErr.Timeout():
					return "timed out"
				case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
					return "returned no record"
				default:
					return "failed"
				}
			}
			if !slices.Equal(sortedAddresses(ips), family.ips) {
				return "returned unexpected addresses"
			}
			return ""
		}
		if failure := lookup(""); failure != "" {
			message := fmt.Sprintf("%s lookup for %q through the operator Pod's configured resolver %s.", family.rrtype, record.name, failure)
			if directFailure := lookup(server); directFailure == "" {
				return resolutionObservation{metav1.ConditionFalse, "DNSForwardingFailed", fmt.Sprintf("%s The Tailscale nameserver returns the expected addresses. Check cluster DNS forwarding for ts.net to %s and the operator Pod's resolver/network configuration.", message, server)}
			} else {
				// Without the expected direct answer, we cannot establish a
				// mismatch in the cluster resolver path. In particular, a
				// nameserver that has not started must not trigger a warning.
				return resolutionObservation{metav1.ConditionUnknown, "NameserverUnavailable", fmt.Sprintf("%s A direct query to nameserver %s also %s. Unable to assess cluster DNS forwarding until the nameserver returns the expected addresses. Check nameserver availability and network access.", message, server, directFailure)}
			}
		}
	}
	return resolutionObservation{metav1.ConditionTrue, "DNSResolutionSucceeded", fmt.Sprintf("The sampled record %q resolves to its expected addresses through the operator Pod's configured resolver. Other workload DNS paths are not checked.", record.name)}
}

// lookupProbeIP uses the Pod's normal resolver for the application-facing query.
// The direct query bypasses hosts files and resolver configuration so that a
// successful result really is an answer from the nameserver Service.
func lookupProbeIP(ctx context.Context, network, host, server string) ([]netip.Addr, error) {
	if server == "" {
		return (&net.Resolver{PreferGo: true}).LookupNetIP(ctx, network, host)
	}
	qtype := uint16(dns.TypeA)
	if network == "ip6" {
		qtype = dns.TypeAAAA
	}
	return lookupNameserverIP(ctx, host, qtype, net.JoinHostPort(server, "53"))
}

func lookupNameserverIP(ctx context.Context, host string, qtype uint16, server string) ([]netip.Addr, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(host, qtype)
	c := &dns.Client{Net: "udp", Timeout: dnsLookupTimeout}
	answer, _, err := c.ExchangeContext(ctx, msg, server)
	if err == nil && answer.Truncated {
		c.Net = "tcp"
		answer, _, err = c.ExchangeContext(ctx, msg, server)
	}
	if err != nil {
		return nil, err
	}
	if answer.Rcode != dns.RcodeSuccess {
		return nil, &net.DNSError{Name: host, IsNotFound: answer.Rcode == dns.RcodeNameError, Err: dns.RcodeToString[answer.Rcode]}
	}
	var ips []netip.Addr
	for _, rr := range answer.Answer {
		if !strings.EqualFold(rr.Header().Name, host) {
			continue
		}
		switch rr := rr.(type) {
		case *dns.A:
			if addr, ok := netip.AddrFromSlice(rr.A); ok && qtype == dns.TypeA {
				ips = append(ips, addr.Unmap())
			}
		case *dns.AAAA:
			if addr, ok := netip.AddrFromSlice(rr.AAAA); ok && qtype == dns.TypeAAAA {
				ips = append(ips, addr)
			}
		}
	}
	return ips, nil
}

func (r *Reconciler) checkDNSResolution(ctx context.Context, cfg *tsapi.DNSConfig, server string) (resolutionObservation, time.Duration, error) {
	unknown := func(reason, message string, err error) (resolutionObservation, time.Duration, error) {
		r.dnsProbe.reset()
		return resolutionObservation{metav1.ConditionUnknown, reason, message}, dnsProbeInterval, err
	}
	if cfg.Spec.Nameserver.Replicas != nil && *cfg.Spec.Nameserver.Replicas == 0 {
		return unknown("NameserverDisabled", "DNS resolution is not checked while nameserver replicas are zero.", nil)
	}
	var cm corev1.ConfigMap
	key := client.ObjectKey{Namespace: r.tsNamespace, Name: tsoperator.DNSRecordsCMName}
	if err := r.Get(ctx, key, &cm); err != nil {
		return unknown("DNSRecordsUnavailable", "Unable to read the nameserver records for the DNS resolution check.", err)
	}
	probe, err := selectProbeRecord(cm.Data[tsoperator.DNSRecordsCMKey])
	if err != nil {
		r.logger.Warnf("cannot select a DNS probe record: %v", err)
		return unknown("InvalidDNSRecords", "Unable to select a valid probe record from the nameserver ConfigMap.", nil)
	}
	if probe.name == "" {
		return unknown("NoProbeRecord", "Waiting for an operator-managed DNS record to check resolution from the operator Pod.", nil)
	}
	cacheKey := fmt.Sprintf("%s/%s/%d/%s/%s", cfg.Name, cfg.UID, cfg.Generation, server, probe.key())
	observation, after := r.dnsProbe.check(ctx, cacheKey, server, probe)
	// Discard an observation if our cache saw the sampled record change while
	// queries were in flight. Like other reconciler reads, this is eventually
	// consistent; subsequent reconciles pick up later changes. Unrelated record
	// changes do not reset the probe.
	var latest corev1.ConfigMap
	if err := r.Get(ctx, key, &latest); err != nil {
		return unknown("DNSRecordsUnavailable", "Unable to read the nameserver records for the DNS resolution check.", err)
	}
	if latest.ResourceVersion != cm.ResourceVersion {
		current, err := selectProbeRecord(latest.Data[tsoperator.DNSRecordsCMKey])
		if err != nil || current.key() != probe.key() {
			return unknown("DNSRecordsChanged", "The sampled DNS record changed during the check; waiting to check the current record.", nil)
		}
	}
	return observation, after, nil
}

func (r *Reconciler) setResolutionCondition(cfg *tsapi.DNSConfig, observation resolutionObservation) {
	tsoperator.SetDNSConfigCondition(cfg, tsapi.DNSResolutionReady, observation.status, observation.reason, observation.message, cfg.Generation, r.clock, r.logger)
}

// Only emit transitions after the status update succeeds. Identical polling
// results neither update status nor generate repeated events.
func (r *Reconciler) reportResolutionTransition(old []metav1.Condition, cfg *tsapi.DNSConfig) {
	current := meta.FindStatusCondition(cfg.Status.Conditions, string(tsapi.DNSResolutionReady))
	previous := meta.FindStatusCondition(old, string(tsapi.DNSResolutionReady))
	if current == nil || (previous != nil && current.Status == previous.Status && current.Reason == previous.Reason) {
		return
	}
	if current.Status == metav1.ConditionFalse {
		r.recorder.Event(cfg, corev1.EventTypeWarning, current.Reason, current.Message)
	} else if current.Status == metav1.ConditionTrue {
		reason := current.Reason
		if previous != nil && previous.Status == metav1.ConditionFalse {
			reason = "DNSResolutionRecovered"
		}
		r.recorder.Event(cfg, corev1.EventTypeNormal, reason, current.Message)
	}
}
