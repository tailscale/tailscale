// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package portlist

import (
	"time"
)

type Poller struct {
	C      chan List     // new data when it arrives; closed when done
	quitCh chan struct{} // close this to force exit
	Err    error         // last returned error code, if any
	prev   List          // most recent data
}

func NewPoller() (*Poller, error) {
	p := &Poller{
		C:      make(chan List),
		quitCh: make(chan struct{}),
	}
	// Do one initial poll synchronously, so the caller can react
	// to any obvious errors.
	p.prev, p.Err = GetList(nil)
	return p, p.Err
}

func (p *Poller) Close() {
	close(p.quitCh)
	<-p.C
}

// Poll periodically. Run this in a goroutine if you want.
func (p *Poller) Run() error {
	defer close(p.C)
	tick := time.NewTicker(POLL_SECONDS * time.Second)
	defer tick.Stop()

	// Send out the pre-generated initial value
	p.C <- p.prev

	for {
		select {
		case <-tick.C:
			pl, err := GetList(p.prev)
			if err != nil {
				p.Err = err
				return p.Err
			}
			if !pl.SameInodes(p.prev) {
				p.prev = pl
				p.C <- pl
			}
		case <-p.quitCh:
			return nil
		}
	}
}
