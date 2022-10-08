// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnlocal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"

	"golang.org/x/exp/slices"
	"tailscale.com/ipn"
	"tailscale.com/net/netutil"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
)

// PipeDialPeerAPIURL ....
func (b *LocalBackend) PipeDialPeerAPIURL(ip netip.Addr) (peerAPIURL string, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	nm := b.netMap
	if b.state != ipn.Running || nm == nil {
		return "", errors.New("not connected to the tailnet")
	}
	ipa := netip.PrefixFrom(ip, ip.BitLen())
	for _, p := range nm.Peers {
		if slices.Contains(p.Addresses, ipa) {
			if p.User == nm.User ||
				len(p.Addresses) > 0 && b.peerHasCapLocked(p.Addresses[0].Addr(), tailcfg.CapabilityTailpipeTarget) {
				peerAPI := peerAPIBase(b.netMap, p)
				if peerAPI == "" {
					continue
				}
			}
			return "", errors.New("invalid target")
		}
	}
	return "", errors.New("target not found")
}

func (b *LocalBackend) DialTailpipe(ctx context.Context, tailscaleIPStr, portName string) (net.Conn, error) {
	ip, err := netip.ParseAddr(tailscaleIPStr)
	if err != nil || !tsaddr.IsTailscaleIP(ip) {
		return nil, fmt.Errorf("host must be a Tailscale IP for now, not %q", tailscaleIPStr)
	}

	hc := b.dialer.PeerAPIHTTPClient()

	peerAPIBase, err := b.PipeDialPeerAPIURL(ip)
	if err != nil {
		return nil, err
	}
	connCh := make(chan net.Conn, 1)
	trace := httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			connCh <- info.Conn
		},
	}
	ctx = httptrace.WithClientTrace(ctx, &trace)
	req, err := http.NewRequestWithContext(ctx, "POST", peerAPIBase+"/localapi/v0/connect-to-open-tailpipe", nil)
	if err != nil {
		return nil, err
	}
	req.Header = http.Header{
		"Upgrade":    []string{"tailpipe"},
		"Connection": []string{"upgrade"},
		"Port-Name":  []string{portName},
	}
	res, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return nil, fmt.Errorf("unexpected HTTP response: %s, %s", res.Status, body)
	}
	// From here on, the underlying net.Conn is ours to use, but there
	// is still a read buffer attached to it within resp.Body. So, we
	// must direct I/O through resp.Body, but we can still use the
	// underlying net.Conn for stuff like deadlines.
	var switchedConn net.Conn
	select {
	case switchedConn = <-connCh:
	default:
	}
	if switchedConn == nil {
		res.Body.Close()
		return nil, fmt.Errorf("httptrace didn't provide a connection")
	}
	rwc, ok := res.Body.(io.ReadWriteCloser)
	if !ok {
		res.Body.Close()
		return nil, errors.New("http Transport did not provide a writable body")
	}
	return netutil.NewAltReadWriteCloserConn(rwc, switchedConn), nil
}
