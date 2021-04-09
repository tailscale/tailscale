// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package portlist

import (
	"context"
	"errors"
	"time"

	"tailscale.com/version"
)

// Poller scans the systems for listening ports periodically and sends
// the results to C.
type Poller struct {
	// C received the list of ports periodically. It's closed when
	// Run completes, after which Err can be checked.
	C <-chan List

	c chan List

	// Err is the error from the final GetList call. It is only
	// valid to read once C has been closed. Err is nil if Close
	// is called or the context is canceled.
	Err error

	quitCh chan struct{} // close this to force exit
	prev   List          // most recent data
}

// NewPoller returns a new portlist Poller. It returns an error
// if the portlist couldn't be obtained.
func NewPoller() (*Poller, error) {
	if version.OS() == "iOS" {
		return nil, errors.New("not available on iOS")
	}
	p := &Poller{
		c:      make(chan List),
		quitCh: make(chan struct{}),
	}
	p.C = p.c

	// Do one initial poll synchronously so we can return an error
	// early.
	var err error
	p.prev, err = GetList(nil)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Poller) Close() error {
	select {
	case <-p.quitCh:
		return nil
	default:
	}
	close(p.quitCh)
	<-p.C
	return nil
}

// Run runs the Poller periodically until either the context
// is done, or the Close is called.
func (p *Poller) Run(ctx context.Context) error {
	defer close(p.c)
	tick := time.NewTicker(pollInterval)
	defer tick.Stop()

	// Send out the pre-generated initial value
	p.c <- p.prev

	for {
		select {
		case <-tick.C:
			pl, err := GetList(p.prev)
			if err != nil {
				p.Err = err
				return err
			}
			if pl.sameInodes(p.prev) {
				continue
			}
			p.prev = pl
			select {
			case p.c <- pl:
			case <-ctx.Done():
				return ctx.Err()
			case <-p.quitCh:
				return nil
			}
		case <-ctx.Done():
			return ctx.Err()
		case <-p.quitCh:
			return nil
		}
	}
}
