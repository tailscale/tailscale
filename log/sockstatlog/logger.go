// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package sockstatlog provides a logger for capturing and storing network socket stats.
package sockstatlog

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"time"

	"tailscale.com/logtail/filch"
	"tailscale.com/net/sockstats"
	"tailscale.com/types/logger"
	"tailscale.com/util/mak"
)

// pollPeriod specifies how often to poll for socket stats.
const pollPeriod = time.Second / 10

// Logger logs statistics about network sockets.
type Logger struct {
	ctx      context.Context
	cancelFn context.CancelFunc

	ticker    *time.Ticker
	logf      logger.Logf
	logbuffer *filch.Filch
}

// deltaStat represents the bytes transferred during a time period.
// The first element is transmitted bytes, the second element is received bytes.
type deltaStat [2]uint64

// event represents the socket stats on a specific interface during a time period.
type event struct {
	// Time is when the event started as a Unix timestamp in milliseconds.
	Time int64 `json:"t"`

	// Duration is the duration of this event in milliseconds.
	Duration int64 `json:"d"`

	// IsCellularInterface is set to 1 if the traffic was sent over a cellular interface.
	IsCellularInterface int `json:"c,omitempty"`

	// Stats records the stats for each Label during the time period.
	Stats map[sockstats.Label]deltaStat `json:"s"`
}

// NewLogger returns a new Logger that will store stats in logdir.
// On platforms that do not support sockstat logging, a nil Logger will be returned.
// The returned Logger must be shut down with Shutdown when it is no longer needed.
func NewLogger(logdir string, logf logger.Logf) (*Logger, error) {
	if !sockstats.IsAvailable {
		return nil, nil
	}

	if err := os.MkdirAll(logdir, 0755); err != nil && !os.IsExist(err) {
		return nil, err
	}
	filchPrefix := filepath.Join(logdir, "sockstats")
	filch, err := filch.New(filchPrefix, filch.Options{ReplaceStderr: false})
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	logger := &Logger{
		ctx:       ctx,
		cancelFn:  cancel,
		ticker:    time.NewTicker(pollPeriod),
		logf:      logf,
		logbuffer: filch,
	}

	go logger.poll()

	return logger, nil
}

// poll fetches the current socket stats at the configured time interval,
// calculates the delta since the last poll, and logs any non-zero values.
// This method does not return.
func (l *Logger) poll() {
	// last is the last set of socket stats we saw.
	var lastStats *sockstats.SockStats
	var lastTime time.Time

	enc := json.NewEncoder(l.logbuffer)
	for {
		select {
		case <-l.ctx.Done():
			return
		case t := <-l.ticker.C:
			stats := sockstats.Get()
			if lastStats != nil {
				diffstats := delta(lastStats, stats)
				if len(diffstats) > 0 {
					e := event{
						Time:     lastTime.UnixMilli(),
						Duration: t.Sub(lastTime).Milliseconds(),
						Stats:    diffstats,
					}
					if stats.CurrentInterfaceCellular {
						e.IsCellularInterface = 1
					}
					if err := enc.Encode(e); err != nil {
						l.logf("sockstatlog: error encoding log: %v", err)
					}
				}
			}
			lastTime = t
			lastStats = stats
		}
	}
}

func (l *Logger) Shutdown() {
	l.ticker.Stop()
	l.logbuffer.Close()
	l.cancelFn()
}

// WriteLogs reads local logs, combining logs into events, and writes them to w.
// Logs within eventWindow are combined into the same event.
func (l *Logger) WriteLogs(w io.Writer) {
	if l == nil || l.logbuffer == nil {
		return
	}
	for {
		b, err := l.logbuffer.TryReadLine()
		if err != nil {
			l.logf("sockstatlog: error reading log: %v", err)
			return
		}
		if b == nil {
			// no more log messages
			return
		}

		w.Write(b)
	}
}

// delta calculates the delta stats between two SockStats snapshots.
// b is assumed to have occurred after a.
// Zero values are omitted from the returned map, and an empty map is returned if no bytes were transferred.
func delta(a, b *sockstats.SockStats) (stats map[sockstats.Label]deltaStat) {
	if a == nil || b == nil {
		return nil
	}
	for label, bs := range b.Stats {
		as := a.Stats[label]
		if as.TxBytes == bs.TxBytes && as.RxBytes == bs.RxBytes {
			// fast path for unchanged stats
			continue
		}
		mak.Set(&stats, label, deltaStat{bs.TxBytes - as.TxBytes, bs.RxBytes - as.RxBytes})
	}
	return stats
}
