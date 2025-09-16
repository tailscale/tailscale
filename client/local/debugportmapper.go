// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_debugportmapper

package local

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"tailscale.com/client/tailscale/apitype"
)

// DebugPortmapOpts contains options for the [Client.DebugPortmap] command.
type DebugPortmapOpts struct {
	// Duration is how long the mapping should be created for. It defaults
	// to 5 seconds if not set.
	Duration time.Duration

	// Type is the kind of portmap to debug. The empty string instructs the
	// portmap client to perform all known types. Other valid options are
	// "pmp", "pcp", and "upnp".
	Type string

	// GatewayAddr specifies the gateway address used during portmapping.
	// If set, SelfAddr must also be set. If unset, it will be
	// autodetected.
	GatewayAddr netip.Addr

	// SelfAddr specifies the gateway address used during portmapping. If
	// set, GatewayAddr must also be set. If unset, it will be
	// autodetected.
	SelfAddr netip.Addr

	// LogHTTP instructs the debug-portmap endpoint to print all HTTP
	// requests and responses made to the logs.
	LogHTTP bool
}

// DebugPortmap invokes the debug-portmap endpoint, and returns an
// io.ReadCloser that can be used to read the logs that are printed during this
// process.
//
// opts can be nil; if so, default values will be used.
func (lc *Client) DebugPortmap(ctx context.Context, opts *DebugPortmapOpts) (io.ReadCloser, error) {
	vals := make(url.Values)
	if opts == nil {
		opts = &DebugPortmapOpts{}
	}

	vals.Set("duration", cmp.Or(opts.Duration, 5*time.Second).String())
	vals.Set("type", opts.Type)
	vals.Set("log_http", strconv.FormatBool(opts.LogHTTP))

	if opts.GatewayAddr.IsValid() != opts.SelfAddr.IsValid() {
		return nil, fmt.Errorf("both GatewayAddr and SelfAddr must be provided if one is")
	} else if opts.GatewayAddr.IsValid() {
		vals.Set("gateway_and_self", fmt.Sprintf("%s/%s", opts.GatewayAddr, opts.SelfAddr))
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+apitype.LocalAPIHost+"/localapi/v0/debug-portmap?"+vals.Encode(), nil)
	if err != nil {
		return nil, err
	}
	res, err := lc.doLocalRequestNiceError(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 200 {
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return nil, fmt.Errorf("HTTP %s: %s", res.Status, body)
	}

	return res.Body, nil
}
