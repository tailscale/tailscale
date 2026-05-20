// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netx

import (
	"context"
	"net"
	"net/netip"
	"time"

	"tailscale.com/util/slicesx"
)

// RaceDial races TCP connect attempts across addrs using a
// happy-eyeballs-style staggered approach: a new dial is started every
// fallbackDelay, and the first successful connection wins. Losers are
// cancelled and their connections closed. If all dials fail, the first
// error is returned.
//
// Addresses are interleaved v6-first so that IPv6 is preferred but both
// families are tried promptly. The dial func is always called with
// network "tcp".
func RaceDial(ctx context.Context, addrs []netip.AddrPort, dial DialFunc, fallbackDelay time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var v4, v6 []netip.AddrPort
	for _, a := range addrs {
		if a.Addr().Is6() {
			v6 = append(v6, a)
		} else {
			v4 = append(v4, a)
		}
	}
	ordered := slicesx.Interleave(v6, v4)

	type result struct {
		c   net.Conn
		err error
	}
	resc := make(chan result)           // unbuffered: senders sync with collector
	failBoost := make(chan struct{}, 1) // wake the launcher when a dial fails fast

	go func() {
		for i, addr := range ordered {
			if i > 0 {
				t := time.NewTimer(fallbackDelay)
				select {
				case <-t.C:
				case <-failBoost:
					t.Stop()
				case <-ctx.Done():
					t.Stop()
					return
				}
			}
			go func() {
				c, err := dial(ctx, "tcp", addr.String())
				if err != nil {
					select {
					case failBoost <- struct{}{}:
					default:
					}
				}
				select {
				case resc <- result{c, err}:
				case <-ctx.Done():
					if c != nil {
						c.Close()
					}
				}
			}()
		}
	}()

	var firstErr error
	var nFailed int
	for {
		select {
		case r := <-resc:
			if r.err == nil {
				return r.c, nil
			}
			if firstErr == nil {
				firstErr = r.err
			}
			nFailed++
			if nFailed >= len(ordered) {
				return nil, firstErr
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}
