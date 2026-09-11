// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package captivedetection

import (
	"fmt"
	"slices"

	"tailscale.com/types/opt"
	"tailscale.com/util/clientmetric"
)

// metricCleanConflict counts detection passes where one endpoint was provably
// reachable while another looked intercepted. [evidence.result] resolves those
// in favor of reporting no portal, so this is the one place where the bias
// against false positives could be costing us a real detection. If it turns out
// to be non-negligible in the field, the precedence rule deserves another look.
var metricCleanConflict = clientmetric.NewCounter("captiveportal_clean_conflict")

// Verdict is the outcome of a captive portal detection attempt.
//
// Detection is deliberately asymmetric: we only ever report [VerdictPortal]
// when we have positive evidence that something intercepted a request or a DNS
// answer on someone else's behalf. The mere absence of connectivity is never
// enough, because a network with no Internet at all looks identical to a
// captive portal that silently drops our probes. Such cases are
// [VerdictUnknown], which leaves any existing health warning alone and asks the
// caller to try again later.
type Verdict int

const (
	// VerdictUnknown means we found no usable evidence either way. The caller
	// should neither raise nor clear a captive portal warning, and should
	// retry later.
	VerdictUnknown Verdict = iota
	// VerdictNoPortal means we reached a Tailscale server and verified its
	// response was untampered with, which proves traffic is flowing
	// unimpeded.
	VerdictNoPortal
	// VerdictPortal means we have positive evidence of interception.
	VerdictPortal
)

func (v Verdict) String() string {
	switch v {
	case VerdictUnknown:
		return "unknown"
	case VerdictNoPortal:
		return "no-portal"
	case VerdictPortal:
		return "portal"
	default:
		return fmt.Sprintf("Verdict(%d)", int(v))
	}
}

// Signal is a single piece of evidence gathered by one probe.
type Signal int

const (
	// SignalNoResponse means the probe got no response at all: a timeout, a
	// connection reset, or an unreachable host. It is evidence of nothing, but
	// it tells us to escalate to a different kind of probe.
	SignalNoResponse Signal = iota

	// SignalNoEvidence means a probe got a response, but one that tells us
	// nothing either way. Unlike SignalNoResponse it shows traffic reached
	// something, so it does not on its own justify escalating.
	SignalNoEvidence

	// SignalClean means a probe reached a Tailscale-operated server and the
	// response was provably untampered with.
	SignalClean

	// Definitive signals. Any one of these is enough to report a portal.

	// SignalRedirect means a probe was answered with a redirect to a different
	// host, which is how the large majority of captive portals announce
	// themselves.
	SignalRedirect
	// SignalHTML means a probe that should have returned no content (or known
	// plain text) was answered with a web page.
	SignalHTML
	// SignalChallengeTampered means a probe was answered with the status code we
	// expected, but without the echoed X-Tailscale-Challenge value that only the
	// real server could have produced.
	SignalChallengeTampered
	// SignalHTTP511 means a probe was answered with 511 Network Authentication
	// Required, which RFC 6585 reserves for exactly this situation.
	SignalHTTP511
	// SignalDNSHijack means a Tailscale hostname resolved to an address on the
	// local network instead of its real address.
	SignalDNSHijack
	// SignalDNSWildcard means names that cannot exist resolved to an address on
	// the local network, i.e. the resolver answers everything.
	SignalDNSWildcard
	// SignalPlatformHint means the host OS told us it detected a portal.
	SignalPlatformHint

	// Weak signals. These are recorded as evidence and counted, but never
	// report a portal, no matter how many of them accumulate.
	//
	// The reason is that the networks which produce them in bulk are not
	// captive portals. A corporate HTTP proxy that answers every port-80
	// request to an unapproved destination with a plain "access denied" page
	// looks, signal for signal, exactly like a portal that answers with a bare
	// status code — except that there is no login page to send the user to, so
	// warning them to go find one is worse than saying nothing. Portals that
	// work at all must eventually get a browser to their login page, which
	// means redirecting, serving a page, or saying 511; those are the
	// definitive signals above.
	//
	// They are still worth recording. They prove something on the network
	// answered us, which stops us needlessly escalating to the third-party
	// probes, and their counters will show us in the field if there is a real
	// portal family we're missing here.

	// SignalUnexpectedStatus means a probe was answered with an unexpected
	// status code but no page body.
	SignalUnexpectedStatus
	// SignalProxyHeaders means a response carried headers that only an
	// intermediary would add.
	SignalProxyHeaders
)

func (s Signal) String() string {
	switch s {
	case SignalNoResponse:
		return "no-response"
	case SignalNoEvidence:
		return "no-evidence"
	case SignalClean:
		return "clean"
	case SignalRedirect:
		return "redirect"
	case SignalHTML:
		return "html"
	case SignalChallengeTampered:
		return "challenge-tampered"
	case SignalHTTP511:
		return "http-511"
	case SignalDNSHijack:
		return "dns-hijack"
	case SignalDNSWildcard:
		return "dns-wildcard"
	case SignalPlatformHint:
		return "platform-hint"
	case SignalUnexpectedStatus:
		return "unexpected-status"
	case SignalProxyHeaders:
		return "proxy-headers"
	default:
		return fmt.Sprintf("Signal(%d)", int(s))
	}
}

// isDefinitive reports whether a single instance of s is enough to conclude
// that a captive portal is present.
func (s Signal) isDefinitive() bool {
	switch s {
	case SignalRedirect, SignalHTML, SignalChallengeTampered, SignalHTTP511,
		SignalDNSHijack, SignalDNSWildcard, SignalPlatformHint:
		return true
	}
	return false
}

// Result is the outcome of a detection attempt, along with the evidence behind
// it.
type Result struct {
	// Verdict is the conclusion drawn from Signals.
	Verdict Verdict
	// PortalURL is a best-effort login URL for the portal, learned from the
	// response that gave us away (a redirect target, or a meta-refresh or
	// script location in an intercepted page). It is often empty even when
	// Verdict is VerdictPortal, since not every portal reveals a usable URL.
	PortalURL string
	// PortalURLIsLocal reports whether PortalURL's host is on the local
	// network, and so is reachable without the default route. It is unset when
	// PortalURL is empty, carries no host, or could not be resolved.
	//
	// Callers that route all traffic somewhere else — a client using an exit
	// node — use this to tell a login page they can still make reachable from
	// one they cannot. See [Detector.annotatePortalLocality].
	PortalURLIsLocal opt.Bool
	// Signals is every signal gathered during detection, in no particular
	// order. Callers use it for logging and metrics.
	Signals []Signal

	// ifIndex is the index of the interface whose probes reported the portal,
	// or zero if no single interface did. It is used to scope the lookup in
	// [Detector.annotatePortalLocality] to the network that intercepted us.
	ifIndex int
}

// evidence accumulates the signals gathered by the probes of one detection
// attempt and draws a [Verdict] from them.
//
// It is not safe for concurrent use; probes report into it under the caller's
// lock.
type evidence struct {
	signals   []Signal
	portalURL string
}

// add records a signal, along with an optional portal URL learned from the same
// response.
func (ev *evidence) add(s Signal, portalURL string) {
	ev.signals = append(ev.signals, s)
	if ev.portalURL == "" {
		ev.portalURL = portalURL
	}
}

// gotAnyResponse reports whether any probe got a response at all. When nothing
// did, the network is blackholing our probes and it's worth escalating to a
// different kind of probe rather than concluding anything.
func (ev *evidence) gotAnyResponse() bool {
	return slices.ContainsFunc(ev.signals, func(s Signal) bool {
		return s != SignalNoResponse
	})
}

// result draws a verdict from the accumulated signals.
//
// Precedence is:
//
//  1. Any clean response wins. Echoing our challenge back proves the response
//     came from a real Tailscale server, and a portal that let that through is
//     not blocking us. This deliberately outranks a conflicting definitive
//     signal from another probe: in a network that intercepts some destinations
//     but not others, we would rather stay quiet than warn about a portal the
//     user cannot log into. Callers can spot this case by looking for a
//     definitive signal alongside a VerdictNoPortal.
//  2. Any definitive signal reports a portal.
//  3. Otherwise we know nothing. In particular, any number of weak signals
//     still amounts to nothing; see their definitions for why.
func (ev *evidence) result() Result {
	r := Result{Signals: slices.Clone(ev.signals)}

	if slices.Contains(ev.signals, SignalClean) {
		r.Verdict = VerdictNoPortal
		return r
	}

	if slices.ContainsFunc(ev.signals, Signal.isDefinitive) {
		r.Verdict = VerdictPortal
		r.PortalURL = ev.portalURL
		return r
	}

	r.Verdict = VerdictUnknown
	return r
}

// hasConflict reports whether the evidence contains both a clean response and a
// definitive portal signal, meaning the network treats different destinations
// differently. [evidence.result] resolves this in favor of no portal; callers
// may want to log or count it.
func (ev *evidence) hasConflict() bool {
	return slices.Contains(ev.signals, SignalClean) &&
		slices.ContainsFunc(ev.signals, Signal.isDefinitive)
}
