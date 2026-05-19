// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailperf

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	payloadSize       = 16 << 10
	maxControlLineLen = 4 << 10
)

type protocolRequest struct {
	Protocol         Protocol  `json:"protocol"`
	Direction        Direction `json:"direction"`
	DurationMillis   int64     `json:"durationMillis"`
	CapBitsPerSecond int64     `json:"capBitsPerSecond,omitempty"`
}

func RunServer(ctx context.Context, cfg ServerConfig) error {
	cfg, err := NormalizeServerConfig(cfg)
	if err != nil {
		return err
	}
	addr := fmt.Sprintf("%s:%d", cfg.Addr, cfg.Port)
	switch cfg.Protocol {
	case ProtoTCP:
		return runTCPServer(ctx, addr)
	case ProtoUDP:
		return runUDPServer(ctx, addr)
	default:
		return fmt.Errorf("unsupported tailperf protocol %q", cfg.Protocol)
	}
}

func RunClient(ctx context.Context, cfg ClientConfig) (Result, error) {
	cfg, err := NormalizeClientConfig(cfg)
	if err != nil {
		return Result{}, err
	}
	if cfg.Direction == DirectionBoth {
		subCfg := cfg
		subCfg.LogSink = nil
		fwd, err := runOneDirection(ctx, subCfg, DirectionForward)
		if err != nil {
			return fwd, err
		}
		rev, err := runOneDirection(ctx, subCfg, DirectionReverse)
		if err != nil {
			return rev, err
		}
		return combineBothDirections(ctx, cfg, fwd, rev)
	}
	return runOneDirection(ctx, cfg, cfg.Direction)
}

func runOneDirection(ctx context.Context, cfg ClientConfig, dir Direction) (Result, error) {
	switch cfg.Protocol {
	case ProtoTCP:
		return runTCPClient(ctx, cfg, dir)
	case ProtoUDP:
		if dir != DirectionForward {
			return Result{}, fmt.Errorf("tailperf UDP reverse and both-directions are not supported yet")
		}
		return runUDPClient(ctx, cfg)
	default:
		return Result{}, fmt.Errorf("unsupported tailperf protocol %q", cfg.Protocol)
	}
}

func combineBothDirections(ctx context.Context, cfg ClientConfig, fwd, rev Result) (Result, error) {
	out := fwd
	out.Direction = DirectionBoth
	out.Ended = rev.Ended
	out.DurationMillis = fwd.DurationMillis + rev.DurationMillis
	out.TransferBytes = fwd.TransferBytes + rev.TransferBytes
	if out.DurationMillis > 0 {
		out.BitrateBitsPerSecond = float64(out.TransferBytes) * 8 / (float64(out.DurationMillis) / 1000)
	}
	out.Intervals = append(append([]IntervalResult{}, fwd.Intervals...), rev.Intervals...)
	out.PathChanges = append(append([]PathChange{}, fwd.PathChanges...), rev.PathChanges...)
	if cfg.LogSink != nil && !cfg.NoLog {
		if err := cfg.LogSink.LogTailperfResult(ctx, out); err != nil {
			return out, err
		}
	}
	return out, nil
}

func runTCPServer(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go handleTCPServerConn(ctx, c)
	}
}

func handleTCPServerConn(ctx context.Context, c net.Conn) {
	defer c.Close()
	br := bufio.NewReaderSize(c, maxControlLineLen)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := br.ReadSlice('\n')
	if err != nil || len(line) > maxControlLineLen {
		return
	}
	var req protocolRequest
	if err := json.Unmarshal(line, &req); err != nil {
		return
	}
	if req.Protocol != ProtoTCP {
		return
	}
	duration := time.Duration(req.DurationMillis) * time.Millisecond
	if duration <= 0 || duration > MaxDuration {
		return
	}
	deadline := time.Now().Add(duration + 10*time.Second)
	_ = c.SetDeadline(deadline)
	switch req.Direction {
	case DirectionForward:
		_, _ = io.Copy(io.Discard, br)
	case DirectionReverse:
		_ = writeForDuration(ctx, c, duration, req.CapBitsPerSecond, nil)
	}
}

func runUDPServer(ctx context.Context, addr string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	defer pc.Close()
	go func() {
		<-ctx.Done()
		pc.Close()
	}()
	buf := make([]byte, payloadSize)
	for {
		if _, _, err := pc.ReadFrom(buf); err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}
	}
}

func runTCPClient(ctx context.Context, cfg ClientConfig, dir Direction) (Result, error) {
	dial := cfg.DialTCP
	if dial == nil {
		var nd net.Dialer
		dial = func(ctx context.Context, host string, port uint16) (net.Conn, error) {
			return nd.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
		}
	}
	c, err := dial(ctx, cfg.Host, cfg.Port)
	if err != nil {
		return resultWithError(cfg, dir, err), err
	}
	defer c.Close()
	stopCancelWatcher := cancelOnContext(ctx, c)
	defer stopCancelWatcher()

	req := protocolRequest{
		Protocol:         ProtoTCP,
		Direction:        dir,
		DurationMillis:   cfg.Duration.Milliseconds(),
		CapBitsPerSecond: cfg.CapBitsPerSecond,
	}
	if err := json.NewEncoder(c).Encode(req); err != nil {
		return resultWithError(cfg, dir, err), err
	}
	var r Result
	if dir == DirectionReverse {
		r, err = readForDuration(ctx, c, cfg, dir)
	} else {
		r, err = writeForDurationResult(ctx, c, cfg, dir)
		if cw, ok := c.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}
	if err != nil {
		return r, err
	}
	if cfg.LogSink != nil && !cfg.NoLog {
		if err := cfg.LogSink.LogTailperfResult(ctx, r); err != nil {
			return r, err
		}
	}
	return r, nil
}

func runUDPClient(ctx context.Context, cfg ClientConfig) (Result, error) {
	dial := cfg.DialUDP
	if dial == nil {
		var nd net.Dialer
		dial = func(ctx context.Context, host string, port uint16) (net.Conn, error) {
			return nd.DialContext(ctx, "udp", net.JoinHostPort(host, fmt.Sprint(port)))
		}
	}
	c, err := dial(ctx, cfg.Host, cfg.Port)
	if err != nil {
		return resultWithError(cfg, DirectionForward, err), err
	}
	defer c.Close()
	stopCancelWatcher := cancelOnContext(ctx, c)
	defer stopCancelWatcher()

	r, err := writeForDurationResult(ctx, c, cfg, DirectionForward)
	if err != nil {
		return r, err
	}
	if cfg.LogSink != nil && !cfg.NoLog {
		if err := cfg.LogSink.LogTailperfResult(ctx, r); err != nil {
			return r, err
		}
	}
	return r, nil
}

func writeForDurationResult(ctx context.Context, w io.Writer, cfg ClientConfig, dir Direction) (Result, error) {
	m := newMeter(cfg, dir)
	err := writeForDuration(ctx, w, cfg.Duration, cfg.CapBitsPerSecond, m.add)
	return m.finish(err), err
}

func writeForDuration(ctx context.Context, w io.Writer, duration time.Duration, capBitsPerSecond int64, add func(int)) error {
	buf := make([]byte, payloadSize)
	start := time.Now()
	var written int64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		elapsed := time.Since(start)
		if elapsed >= duration {
			return nil
		}
		if capBitsPerSecond > 0 {
			allowed := int64(float64(capBitsPerSecond) / 8 * elapsed.Seconds())
			if written > allowed {
				sleep := time.Duration(float64(written-allowed) / (float64(capBitsPerSecond) / 8) * float64(time.Second))
				timer := time.NewTimer(sleep)
				select {
				case <-ctx.Done():
					timer.Stop()
					return ctx.Err()
				case <-timer.C:
				}
			}
		}
		n, err := w.Write(buf)
		if n > 0 {
			written += int64(n)
			if add != nil {
				add(n)
			}
		}
		if err != nil {
			return err
		}
	}
}

func readForDuration(ctx context.Context, r io.Reader, cfg ClientConfig, dir Direction) (Result, error) {
	m := newMeter(cfg, dir)
	buf := make([]byte, payloadSize)
	deadline := time.Now().Add(cfg.Duration)
	if c, ok := r.(net.Conn); ok {
		_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	}
	for {
		if err := ctx.Err(); err != nil {
			return m.finish(err), err
		}
		if time.Now().After(deadline) {
			return m.finish(nil), nil
		}
		n, err := r.Read(buf)
		if n > 0 {
			m.add(n)
		}
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			return m.finish(nil), nil
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			if c, ok := r.(net.Conn); ok {
				_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			}
			continue
		}
		return m.finish(err), err
	}
}

func cancelOnContext(ctx context.Context, c net.Conn) func() {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = c.SetDeadline(time.Now())
		case <-done:
		}
	}()
	return func() { close(done) }
}

func resultWithError(cfg ClientConfig, dir Direction, err error) Result {
	r := newMeter(cfg, dir).finish(err)
	if err != nil {
		r.Error = err.Error()
	}
	return r
}

type meter struct {
	cfg         ClientConfig
	dir         Direction
	start       time.Time
	lastFlush   time.Time
	curBytes    int64
	totalBytes  int64
	intervals   []IntervalResult
	path        PathMetadata
	pathChanges []PathChange
}

func newMeter(cfg ClientConfig, dir Direction) *meter {
	now := time.Now()
	path := PathMetadata{Type: PathUnknown}
	if cfg.PathProvider != nil {
		path = cfg.PathProvider(context.Background()).Normalized()
	}
	return &meter{
		cfg:       cfg,
		dir:       dir,
		start:     now,
		lastFlush: now,
		path:      path,
	}
}

func (m *meter) add(n int) {
	now := time.Now()
	m.curBytes += int64(n)
	m.totalBytes += int64(n)
	for now.Sub(m.lastFlush) >= m.cfg.Interval {
		next := m.lastFlush.Add(m.cfg.Interval)
		m.flush(next)
		m.lastFlush = next
	}
}

func (m *meter) flush(end time.Time) {
	path := m.path
	if m.cfg.PathProvider != nil {
		path = m.cfg.PathProvider(context.Background()).Normalized()
	}
	if path != m.path {
		m.pathChanges = append(m.pathChanges, PathChange{
			AtSeconds: end.Sub(m.start).Seconds(),
			From:      m.path,
			To:        path,
		})
		m.path = path
	}
	startSeconds := m.lastFlush.Sub(m.start).Seconds()
	endSeconds := end.Sub(m.start).Seconds()
	dur := end.Sub(m.lastFlush).Seconds()
	var bps float64
	if dur > 0 {
		bps = float64(m.curBytes) * 8 / dur
	}
	m.intervals = append(m.intervals, IntervalResult{
		StartSeconds:         startSeconds,
		EndSeconds:           endSeconds,
		TransferBytes:        m.curBytes,
		BitrateBitsPerSecond: bps,
		Path:                 path,
	})
	m.curBytes = 0
}

func (m *meter) finish(err error) Result {
	end := time.Now()
	if end.After(m.lastFlush) && m.curBytes > 0 {
		m.flush(end)
	}
	duration := end.Sub(m.start)
	path := m.path.Normalized()
	r := Result{
		SchemaVersion:    SchemaVersion,
		Started:          m.start,
		Ended:            end,
		SourceNode:       m.cfg.SourceNode,
		DestinationNode:  m.cfg.DestinationNode,
		Direction:        m.dir,
		Protocol:         m.cfg.Protocol,
		DurationMillis:   duration.Milliseconds(),
		CapBitsPerSecond: m.cfg.CapBitsPerSecond,
		TUNMode:          m.cfg.TUNMode,
		TransferBytes:    m.totalBytes,
		Path:             path,
		PathChanges:      m.pathChanges,
		Intervals:        m.intervals,
		LoggingDisabled:  m.cfg.NoLog,
	}
	if duration > 0 {
		r.BitrateBitsPerSecond = float64(m.totalBytes) * 8 / duration.Seconds()
	}
	if err != nil {
		r.Error = err.Error()
	}
	return r
}
