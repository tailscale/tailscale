// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_serve

package cli

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
)

func init() {
	maybeFunnelCmd = funnelCmd
}

var funnelCmd = func() *ffcli.Command {
	se := &serveEnv{lc: &localClient}
	return newServeV2Command(se, funnel)
}

// verifyFunnelEnabled verifies that the self node is allowed to use Funnel.
//
// If Funnel is not yet enabled by the current node capabilities,
// the user is sent through an interactive flow to enable the feature.
// Once enabled, verifyFunnelEnabled checks that the given port is allowed
// with Funnel.
//
// If an error is reported, the CLI should stop execution and return the error.
//
// verifyFunnelEnabled may refresh the local state and modify the st input.
func (e *serveEnv) verifyFunnelEnabled(ctx context.Context, port uint16) error {
	enableErr := e.enableFeatureInteractive(ctx, "funnel", tailcfg.CapabilityHTTPS, tailcfg.NodeAttrFunnel)
	st, statusErr := e.getLocalClientStatusWithoutPeers(ctx) // get updated status; interactive flow may block
	switch {
	case statusErr != nil:
		return fmt.Errorf("getting client status: %w", statusErr)
	case enableErr != nil:
		// enableFeatureInteractive is a new flow behind a control server
		// feature flag. If anything caused it to error, fallback to using
		// the old CheckFunnelAccess call. Likely this domain does not have
		// the feature flag on.
		// TODO(sonia,tailscale/corp#10577): Remove this fallback once the
		// control flag is turned on for all domains.
		if err := ipn.CheckFunnelAccess(port, st.Self); err != nil {
			return err
		}
	default:
		// Done with enablement, make sure the requested port is allowed.
		if err := ipn.CheckFunnelPort(port, st.Self); err != nil {
			return err
		}
	}
	return nil
}

// printFunnelWarning prints a warning if the Funnel is on but there is no serve
// config for its host:port.
func printFunnelWarning(sc *ipn.ServeConfig) {
	var warn bool
	for hp, a := range sc.AllowFunnel {
		if !a {
			continue
		}
		_, portStr, _ := net.SplitHostPort(string(hp))
		p, _ := strconv.ParseUint(portStr, 10, 16)
		if _, ok := sc.TCP[uint16(p)]; !ok {
			warn = true
			fmt.Fprintf(Stderr, "\nWarning: funnel=on for %s, but no serve config\n", hp)
		}
	}
	if warn {
		fmt.Fprintf(Stderr, "         run: `tailscale serve --help` to see how to configure handlers\n")
	}
}

func init() {
	hookPrintFunnelStatus.Set(printFunnelStatus)
}

// printFunnelStatus prints the status of the funnel, if it's running.
// It prints nothing if the funnel is not running.
func printFunnelStatus(ctx context.Context) {
	sc, err := localClient.GetServeConfig(ctx)
	if err != nil {
		outln()
		printf("# Funnel:\n")
		printf("#     - Unable to get Funnel status: %v\n", err)
		return
	}
	if !sc.IsFunnelOn() {
		return
	}
	outln()
	printf("# Funnel on:\n")
	for hp, on := range sc.AllowFunnel {
		if !on { // if present, should be on
			continue
		}
		sni, portStr, _ := net.SplitHostPort(string(hp))
		p, _ := strconv.ParseUint(portStr, 10, 16)
		isTCP := sc.IsTCPForwardingOnPort(uint16(p), noService)
		url := "https://"
		if isTCP {
			url = "tcp://"
		}
		url += sni
		if isTCP || p != 443 {
			url += ":" + portStr
		}
		printf("#     - %s\n", url)
	}
	outln()
}
