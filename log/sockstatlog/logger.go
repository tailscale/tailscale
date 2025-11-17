// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package sockstatlog provides a logger for capturing network socket stats for debugging.
// Stats are collected at a frequency of 10 Hz and logged to disk.
// Stats are only uploaded to the log server on demand.
package sockstatlog

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"tailscale.com/feature/buildfeatures"
	"tailscale.com/health"
	"tailscale.com/logpolicy"
	"tailscale.com/logtail"
	"tailscale.com/logtail/filch"
	"tailscale.com/net/netmon"
	"tailscale.com/net/sockstats"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/mak"
)

// pollInterval specifies how often to poll for socket stats.
const pollInterval = time.Second / 10

// logInterval specifies how often to log sockstat events to disk.
// This delay is added to prevent an infinite loop when logs are uploaded,
// which itself creates additional sockstat events.
const logInterval = 10 * time.Second

// maxLogFileSize specifies the maximum size of a log file before it is rotated.
// Our logs are fairly compact, and we are mostly only looking at a few hours of data.
// Combined with the fact that these are often uploaded over cellular connections,
// we keep this relatively small.
const maxLogFileSize = 5 << 20 // 5 MB

// Logger logs statistics about network sockets.
type Logger struct {
	// enabled identifies whether the logger is enabled.
	enabled atomic.Bool

	ctx      context.Context
	cancelFn context.CancelFunc

	// eventCh is used to pass events from the poller to the logger.
	eventCh chan event

	logf logger.Logf

	// logger is the underlying logtail logger than manages log files on disk
	// and uploading to the log server.
	logger *logtail.Logger
	filch  *filch.Filch
	tr     http.RoundTripper
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
// Given that this is just for debugging, we're not too concerned about that.
func SockstatLogID(logID logid.PublicID) logid.PrivateID {
	return logid.PrivateID(sha256.Sum256([]byte(logID.String() + "sockstat")))
}

// NewLogger returns a new Logger that will store stats in logdir.
// On platforms that do not support sockstat logging, a nil Logger will be returned.
// The returned Logger is not yet enabled, and must be shut down with Shutdown when it is no longer needed.
// Logs will be uploaded to the log server using a new log ID derived from the provided backend logID.
//
// The netMon parameter is optional. It should be specified in environments where
// Tailscaled is manipulating the routing table.
func NewLogger(logdir string, logf logger.Logf, logID logid.PublicID, netMon *netmon.Monitor, health *health.Tracker, bus *eventbus.Bus) (*Logger, error) {
	if !sockstats.IsAvailable || !buildfeatures.HasLogTail {
		return nil, nil
	}
	if netMon == nil {
		netMon = netmon.NewStatic()
	}

	if err := os.MkdirAll(logdir, 0755); err != nil && !os.IsExist(err) {
		return nil, err
	}
	filchPrefix := filepath.Join(logdir, "sockstats")
	filch, err := filch.New(filchPrefix, filch.Options{
		MaxFileSize:   maxLogFileSize,
		ReplaceStderr: false,
	})
	if err != nil {
		return nil, err
	}

	logger := &Logger{
		logf:  logf,
		filch: filch,
		tr:    logpolicy.NewLogtailTransport(logtail.DefaultHost, netMon, health, logf),
	}
	logger.logger = logtail.NewLogger(logtail.Config{
		BaseURL:      logpolicy.LogURL(),
		PrivateID:    SockstatLogID(logID),
		Collection:   "sockstats.log.tailscale.io",
		Buffer:       filch,
		Bus:          bus,
		CompressLogs: true,
		FlushDelayFn: func() time.Duration {
			// set flush delay to 100 years so it never flushes automatically
			return 100 * 365 * 24 * time.Hour
		},
		Stderr: io.Discard, // don't log to stderr

		HTTPC: &http.Client{Transport: logger.tr},
	}, logf)
	logger.logger.SetSockstatsLabel(sockstats.LabelSockstatlogLogger)

	return logger, nil
}

// SetLoggingEnabled enables or disables logging.
// When disabled, socket stats are not polled and no new logs are written to disk.
// Existing logs can still be fetched via the C2N API.
func (lg *Logger) SetLoggingEnabled(v bool) {
	old := lg.enabled.Load()
	if old != v && lg.enabled.CompareAndSwap(old, v) {
		if v {
			if lg.eventCh == nil {
				// eventCh should be large enough for the number of events that will occur within logInterval.
				// Add an extra second's worth of events to ensure we don't drop any.
				lg.eventCh = make(chan event, (logInterval+time.Second)/pollInterval)
			}
			lg.ctx, lg.cancelFn = context.WithCancel(context.Background())
			go lg.poll()
			go lg.logEvents()
		} else {
			lg.cancelFn()
		}
	}
}

func (lg *Logger) Write(p []byte) (int, error) {
	return lg.logger.Write(p)
}

// poll fetches the current socket stats at the configured time interval,
// calculates the delta since the last poll,
// and writes any non-zero values to the logger event channel.
// This method does not return.
func (lg *Logger) poll() {
	// last is the last set of socket stats we saw.
	var lastStats *sockstats.SockStats
	var lastTime time.Time

	ticker := time.NewTicker(pollInterval)
	for {
		select {
		case <-lg.ctx.Done():
			ticker.Stop()
			return
		case t := <-ticker.C:
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
					lg.eventCh <- e
				}
			}
			lastTime = t
			lastStats = stats
		}
	}
}

// logEvents reads events from the event channel at logInterval and logs them to disk.
// This method does not return.
func (lg *Logger) logEvents() {
	enc := json.NewEncoder(lg)
	flush := func() {
		for {
			select {
			case e := <-lg.eventCh:
				if err := enc.Encode(e); err != nil {
					lg.logf("sockstatlog: error encoding log: %v", err)
				}
			default:
				return
			}
		}
	}
	ticker := time.NewTicker(logInterval)
	for {
		select {
		case <-lg.ctx.Done():
			ticker.Stop()
			return
		case <-ticker.C:
			flush()
		}
	}
}

func (lg *Logger) LogID() string {
	if lg.logger == nil {
		return ""
	}
	return lg.logger.PrivateID().Public().String()
}

// Flush sends pending logs to the log server and flushes them from the local buffer.
func (lg *Logger) Flush() {
	lg.logger.StartFlush()
}

func (lg *Logger) Shutdown(ctx context.Context) {
	if lg.cancelFn != nil {
		lg.cancelFn()
	}
	lg.filch.Close()
	lg.logger.Shutdown(ctx)

	type closeIdler interface {
		CloseIdleConnections()
	}
	if tr, ok := lg.tr.(closeIdler); ok {
		tr.CloseIdleConnections()
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
