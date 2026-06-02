// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_serve

package cli

import (
	"context"
	"maps"
	"net"
	"slices"
	"strconv"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

// isServeConfigEmpty reports whether sc has no user-visible configuration
// to render in the non-JSON status output.
func isServeConfigEmpty(sc *ipn.ServeConfig) bool {
	return sc == nil || (len(sc.TCP) == 0 && len(sc.Web) == 0 && len(sc.Services) == 0 && len(sc.AllowFunnel) == 0)
}

// printServeStatusTrees prints the tree-style human-readable status of sc,
// including any node-level TCP and Web serve entries and any configured
// services, to [Stdout]. It does not print the funnel-status header, the
// no-config message, or the trailing funnel warning — callers are expected
// to handle those.
//
// Ordering is deterministic: node TCP forwards (existing behavior), then
// node Web entries by HostPort, then services by name.
func printServeStatusTrees(sc *ipn.ServeConfig, st *ipnstate.Status) error {
	if sc == nil {
		return nil
	}
	if sc.IsTCPForwardingAny() {
		if err := printTCPStatusTree(context.Background(), sc, st); err != nil {
			return err
		}
		printf("\n")
	}
	for _, hp := range slices.Sorted(maps.Keys(sc.Web)) {
		_, portStr, _ := net.SplitHostPort(string(hp))
		port, err := parseServePort(portStr)
		if err != nil {
			return err
		}
		funnel := sc.AllowFunnel[hp]
		https := !sc.IsServingHTTP(port, noService)
		if err := printWebStatusTree(sc.Web[hp], hp, funnel, https, noService); err != nil {
			return err
		}
		printf("\n")
	}
	for _, name := range slices.Sorted(maps.Keys(sc.Services)) {
		if err := printServiceStatusTree(sc, st, name); err != nil {
			return err
		}
	}
	return nil
}

// printServiceStatusTree prints the tree-style status for a single
// configured service. Each rendered URL/forward line is prefixed with the
// service name in the URL annotation (e.g.
// "https://db.example.ts.net (tailnet only) (svc:db)") so service entries
// are visually distinct from node-level serves.
func printServiceStatusTree(sc *ipn.ServeConfig, st *ipnstate.Status, name tailcfg.ServiceName) error {
	svc, ok := sc.Services[name]
	if !ok || svc == nil {
		return nil
	}

	if svc.Tun {
		printf("tun (L3 forwarding) (%s)\n\n", name)
		return nil
	}

	suffix := ""
	if st != nil && st.CurrentTailnet != nil {
		suffix = st.CurrentTailnet.MagicDNSSuffix
	}
	host := name.WithoutPrefix()
	if suffix != "" {
		host = host + "." + suffix
	}

	// TCP forwards configured directly on the service.
	for _, p := range slices.Sorted(maps.Keys(svc.TCP)) {
		h := svc.TCP[p]
		if h == nil || h.TCPForward == "" {
			continue
		}
		hp := ipn.HostPort(net.JoinHostPort(host, strconv.Itoa(int(p))))
		if h.TerminateTLS != "" {
			printf("tcp://%s (TLS-terminated TCP, tailnet only) (%s)\n", hp, name)
		} else {
			printf("tcp://%s (tailnet only) (%s)\n", hp, name)
		}
		printf("|--> tcp://%s\n\n", h.TCPForward)
	}

	// Web entries (HTTP/HTTPS). Services have no Funnel concept.
	for _, hp := range slices.Sorted(maps.Keys(svc.Web)) {
		_, portStr, _ := net.SplitHostPort(string(hp))
		port, err := parseServePort(portStr)
		if err != nil {
			return err
		}
		https := !sc.IsServingHTTP(port, name)
		if err := printWebStatusTree(svc.Web[hp], hp, false, https, name); err != nil {
			return err
		}
		printf("\n")
	}

	return nil
}
