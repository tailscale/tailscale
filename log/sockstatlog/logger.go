// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package sockstatlog provides a logger for capturing and storing network socket stats.
package sockstatlog

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"tailscale.com/logpolicy"
	"tailscale.com/logtail"
	"tailscale.com/logtail/filch"
	"tailscale.com/net/sockstats"
	"tailscale.com/smallzstd"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/util/mak"
)

// pollPeriod specifies how often to poll for socket stats.
const pollPeriod = time.Second / 10

// Logger logs statistics about network sockets.
type Logger struct {
	ctx      context.Context
	cancelFn context.CancelFunc

	ticker *time.Ticker
	logf   logger.Logf

	logger *logtail.Logger
	filch  *filch.Filch
	tr     *http.Transport
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

// SockstatLogID reproducibly derives a new logid.PrivateID for sockstat logging from a node's public backend log ID.
// The returned PrivateID is the sha256 sum of logID + "sockstat".
// If a node's public log ID becomes known, it is trivial to spoof sockstat logs for that node.
// Given the this is just for debugging, we're not too concerned about that.
func SockstatLogID(logID logid.PublicID) logid.PrivateID {
	return logid.PrivateID(sha256.Sum256([]byte(logID.String() + "sockstat")))
}

// NewLogger returns a new Logger that will store stats in logdir.
// On platforms that do not support sockstat logging, a nil Logger will be returned.
// The returned Logger must be shut down with Shutdown when it is no longer needed.
func NewLogger(logdir string, logf logger.Logf, logID logid.PublicID) (*Logger, error) {
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
		ctx:      ctx,
		cancelFn: cancel,
		ticker:   time.NewTicker(pollPeriod),
		logf:     logf,
		filch:    filch,
		tr:       logpolicy.NewLogtailTransport(logtail.DefaultHost),
	}
	logger.logger = logtail.NewLogger(logtail.Config{
		BaseURL:    logpolicy.LogURL(),
		PrivateID:  SockstatLogID(logID),
		Collection: "sockstats.log.tailscale.io",
		Buffer:     filch,
		NewZstdEncoder: func() logtail.Encoder {
			w, err := smallzstd.NewEncoder(nil)
			if err != nil {
				panic(err)
			}
			return w
		},
		FlushDelayFn: func() time.Duration {
			// set flush delay to 100 years so it never flushes automatically
			return 100 * 365 * 24 * time.Hour
		},
		Stderr: io.Discard, // don't log to stderr

		HTTPC: &http.Client{Transport: logger.tr},
	}, logf)

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

	enc := json.NewEncoder(l.logger)
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

func (l *Logger) LogID() string {
	if l.logger == nil {
		return ""
	}
	return l.logger.PrivateID().Public().String()
}

// Flush sends pending logs to the log server and flushes them from the local buffer.
func (l *Logger) Flush() {
	l.logger.StartFlush()
}

func (l *Logger) Shutdown() {
	l.ticker.Stop()
	l.logger.Shutdown(l.ctx)
	l.cancelFn()
	l.filch.Close()
	l.tr.CloseIdleConnections()
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
