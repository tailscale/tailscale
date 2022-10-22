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
	c chan List // unbuffered

	// closeCtx is the context that's canceled on Close.
	closeCtx       context.Context
	closeCtxCancel context.CancelFunc

	runDone chan struct{} // closed when Run completes

	// scatch is memory for Poller.getList to reuse between calls.
	scratch []Port

	prev List // most recent data
}

// NewPoller returns a new portlist Poller. It returns an error
// if the portlist couldn't be obtained.
func NewPoller() (*Poller, error) {
	if version.OS() == "iOS" {
		return nil, errors.New("not available on iOS")
	}
	p := &Poller{
		c:       make(chan List),
		runDone: make(chan struct{}),
	}
	p.closeCtx, p.closeCtxCancel = context.WithCancel(context.Background())

	// Do one initial poll synchronously so we can return an error
	// early.
	var err error
	p.prev, err = p.getList()
	if err != nil {
		return nil, err
	}
	return p, nil
}

// Updates return the channel that receives port list updates.
//
// The channel is closed when the Poller is closed.
func (p *Poller) Updates() <-chan List { return p.c }

// Close closes the Poller.
// Run will return with a nil error.
func (p *Poller) Close() error {
	p.closeCtxCancel()
	<-p.runDone
	return nil
}

// send sends pl to p.c and returns whether it was successfully sent.
func (p *Poller) send(ctx context.Context, pl List) (sent bool, err error) {
	select {
	case p.c <- pl:
		return true, nil
	case <-ctx.Done():
		return false, ctx.Err()
	case <-p.closeCtx.Done():
		return false, nil
	}
}

// Run runs the Poller periodically until either the context
// is done, or the Close is called.
//
// Run may only be called once.
func (p *Poller) Run(ctx context.Context) error {
	defer close(p.runDone)
	defer close(p.c)

	tick := time.NewTicker(pollInterval)
	defer tick.Stop()

	// Send out the pre-generated initial value.
	if sent, err := p.send(ctx, p.prev); !sent {
		return err
	}

	for {
		select {
		case <-tick.C:
			pl, err := p.getList()
			if err != nil {
				return err
			}
			if pl.sameInodes(p.prev) {
				continue
			}
			p.prev = pl
			if sent, err := p.send(ctx, p.prev); !sent {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		case <-p.closeCtx.Done():
			return nil
		}
	}
}
