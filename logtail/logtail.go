// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package logtail sends logs to log.tailscale.io.
package logtail

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"time"

	"tailscale.com/logtail/backoff"
	tslogger "tailscale.com/types/logger"
)

// DefaultHost is the default host name to upload logs to when
// Config.BaseURL isn't provided.
const DefaultHost = "log.tailscale.io"

type Logger interface {
	// Write logs an encoded JSON blob.
	//
	// If the []byte passed to Write is not an encoded JSON blob,
	// then contents is fit into a JSON blob and written.
	//
	// This is intended as an interface for the stdlib "log" package.
	Write([]byte) (int, error)

	// Flush uploads all logs to the server.
	// It blocks until complete or there is an unrecoverable error.
	Flush() error

	// Shutdown gracefully shuts down the logger while completing any
	// remaining uploads.
	//
	// It will block, continuing to try and upload unless the passed
	// context object interrupts it by being done.
	// If the shutdown is interrupted, an error is returned.
	Shutdown(context.Context) error

	// Close shuts down this logger object, the background log uploader
	// process, and any associated goroutines.
	//
	// DEPRECATED: use Shutdown
	Close()
}

type Encoder interface {
	EncodeAll(src, dst []byte) []byte
	Close() error
}

type Config struct {
	Collection     string           // collection name, a domain name
	PrivateID      PrivateID        // machine-specific private identifier
	BaseURL        string           // if empty defaults to "https://log.tailscale.io"
	HTTPC          *http.Client     // if empty defaults to http.DefaultClient
	SkipClientTime bool             // if true, client_time is not written to logs
	LowMemory      bool             // if true, logtail minimizes memory use
	TimeNow        func() time.Time // if set, subsitutes uses of time.Now
	Stderr         io.Writer        // if set, logs are sent here instead of os.Stderr
	Buffer         Buffer           // temp storage, if nil a MemoryBuffer
	NewZstdEncoder func() Encoder   // if set, used to compress logs for transmission

	// DrainLogs, if non-nil, disables automatic uploading of new logs,
	// so that logs are only uploaded when a token is sent to DrainLogs.
	DrainLogs <-chan struct{}
}

func Log(cfg Config, logf tslogger.Logf) Logger {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://" + DefaultHost
	}
	if cfg.HTTPC == nil {
		cfg.HTTPC = http.DefaultClient
	}
	if cfg.TimeNow == nil {
		cfg.TimeNow = time.Now
	}
	if cfg.Stderr == nil {
		cfg.Stderr = os.Stderr
	}
	if cfg.Buffer == nil {
		pendingSize := 256
		if cfg.LowMemory {
			pendingSize = 64
		}
		cfg.Buffer = NewMemoryBuffer(pendingSize)
	}
	l := &logger{
		stderr:         cfg.Stderr,
		httpc:          cfg.HTTPC,
		url:            cfg.BaseURL + "/c/" + cfg.Collection + "/" + cfg.PrivateID.String(),
		lowMem:         cfg.LowMemory,
		buffer:         cfg.Buffer,
		skipClientTime: cfg.SkipClientTime,
		sent:           make(chan struct{}, 1),
		sentinel:       make(chan int32, 16),
		drainLogs:      cfg.DrainLogs,
		timeNow:        cfg.TimeNow,
		bo:             backoff.NewBackoff("logtail", logf, 30*time.Second),

		shutdownStart: make(chan struct{}),
		shutdownDone:  make(chan struct{}),
	}
	if cfg.NewZstdEncoder != nil {
		l.zstdEncoder = cfg.NewZstdEncoder()
	}

	ctx, cancel := context.WithCancel(context.Background())
	l.uploadCancel = cancel

	go l.uploading(ctx)
	l.Write([]byte("logtail started"))
	return l
}

type logger struct {
	stderr         io.Writer
	httpc          *http.Client
	url            string
	lowMem         bool
	skipClientTime bool
	buffer         Buffer
	sent           chan struct{}   // signal to speed up drain
	drainLogs      <-chan struct{} // if non-nil, external signal to attempt a drain
	sentinel       chan int32
	timeNow        func() time.Time
	bo             *backoff.Backoff
	zstdEncoder    Encoder
	uploadCancel   func()

	shutdownStart chan struct{} // closed when shutdown begins
	shutdownDone  chan struct{} // closd when shutdown complete
}

func (l *logger) Shutdown(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			l.uploadCancel()
			<-l.shutdownDone
		case <-l.shutdownDone:
		}
		close(done)
	}()

	close(l.shutdownStart)
	io.WriteString(l, "logger closing down\n")
	<-done

	if l.zstdEncoder != nil {
		return l.zstdEncoder.Close()
	}
	return nil
}

func (l *logger) Close() {
	l.Shutdown(context.Background())
}

// drainBlock is called by drainPending when there are no logs to drain.
//
// In typical operation, every call to the Write method unblocks and triggers
// a buffer.TryReadline, so logs are written with very low latency.
//
// If the caller provides a DrainLogs channel, then unblock-drain-on-Write
// is disabled, and it is up to the caller to trigger unblock the drain.
func (l *logger) drainBlock() (shuttingDown bool) {
	if l.drainLogs == nil {
		select {
		case <-l.shutdownStart:
			return true
		case <-l.sent:
		}
	} else {
		select {
		case <-l.shutdownStart:
			return true
		case <-l.drainLogs:
		}
	}
	return false
}

// drainPending drains and encodes a batch of logs from the buffer for upload.
// If no logs are available, drainPending blocks until logs are available.
func (l *logger) drainPending() (res []byte) {
	buf := new(bytes.Buffer)
	entries := 0

	var batchDone bool
	const maxLen = 256 << 10
	for buf.Len() < maxLen && !batchDone {
		b, err := l.buffer.TryReadLine()
		if err == io.EOF {
			break
		} else if err != nil {
			b = []byte(fmt.Sprintf("reading ringbuffer: %v", err))
			batchDone = true
		} else if b == nil {
			if entries > 0 {
				break
			}

			batchDone = l.drainBlock()
			continue
		}

		if len(b) == 0 {
			continue
		}
		if b[0] != '{' || !json.Valid(b) {
			// This is probably a log added to stderr by filch
			// outside of the logtail logger. Encode it.
			// Do not add a client time, as it could have been
			// been written a long time ago.
			b = l.encodeText(b, true)
		}

		switch {
		case entries == 0:
			buf.Write(b)
		case entries == 1:
			buf2 := new(bytes.Buffer)
			buf2.WriteByte('[')
			buf2.Write(buf.Bytes())
			buf2.WriteByte(',')
			buf2.Write(b)
			buf.Reset()
			buf.Write(buf2.Bytes())
		default:
			buf.WriteByte(',')
			buf.Write(b)
		}
		entries++
	}

	if entries > 1 {
		buf.WriteByte(']')
	}
	if buf.Len() == 0 {
		return nil
	}
	return buf.Bytes()
}

// This is the goroutine that repeatedly uploads logs in the background.
func (l *logger) uploading(ctx context.Context) {
	defer close(l.shutdownDone)

	for {
		body := l.drainPending()
		origlen := -1 // sentinel value: uncompressed
		// Don't attempt to compress tiny bodies; not worth the CPU cycles.
		if l.zstdEncoder != nil && len(body) > 256 {
			zbody := l.zstdEncoder.EncodeAll(body, nil)
			// Only send it compressed if the bandwidth savings are sufficient.
			// Just the extra headers associated with enabling compression
			// are 50 bytes by themselves.
			if len(body)-len(zbody) > 64 {
				origlen = len(body)
				body = zbody
			}
		}

		for len(body) > 0 {
			select {
			case <-ctx.Done():
				return
			default:
			}
			uploaded, err := l.upload(ctx, body, origlen)
			if err != nil {
				fmt.Fprintf(l.stderr, "logtail: upload: %v\n", err)
			}
			l.bo.BackOff(ctx, err)
			if uploaded {
				break
			}
		}

		select {
		case <-l.shutdownStart:
			return
		default:
		}
	}
}

// upload uploads body to the log server.
// origlen indicates the pre-compression body length.
// origlen of -1 indicates that the body is not compressed.
func (l *logger) upload(ctx context.Context, body []byte, origlen int) (uploaded bool, err error) {
	req, err := http.NewRequest("POST", l.url, bytes.NewReader(body))
	if err != nil {
		// I know of no conditions under which this could fail.
		// Report it very loudly.
		// TODO record logs to disk
		panic("logtail: cannot build http request: " + err.Error())
	}
	if origlen != -1 {
		req.Header.Add("Content-Encoding", "zstd")
		req.Header.Add("Orig-Content-Length", strconv.Itoa(origlen))
	}
	req.Header["User-Agent"] = nil // not worth writing one; save some bytes

	maxUploadTime := 45 * time.Second
	ctx, cancel := context.WithTimeout(ctx, maxUploadTime)
	defer cancel()
	req = req.WithContext(ctx)

	compressedNote := "not-compressed"
	if origlen != -1 {
		compressedNote = "compressed"
	}

	resp, err := l.httpc.Do(req)
	if err != nil {
		return false, fmt.Errorf("log upload of %d bytes %s failed: %v", len(body), compressedNote, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		uploaded = resp.StatusCode == 400 // the server saved the logs anyway
		b, _ := ioutil.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return uploaded, fmt.Errorf("log upload of %d bytes %s failed %d: %q", len(body), compressedNote, resp.StatusCode, b)
	}

	// Try to read to EOF, in case server's response is
	// chunked. We want to reuse the TCP connection if it's
	// HTTP/1. On success, we expect 0 bytes.
	// TODO(bradfitz): can remove a few days after 2020-04-04 once
	// server is fixed.
	if resp.ContentLength == -1 {
		resp.Body.Read(make([]byte, 1))
	}
	return true, nil
}

func (l *logger) Flush() error {
	return nil
}

func (l *logger) send(jsonBlob []byte) (int, error) {
	n, err := l.buffer.Write(jsonBlob)
	if l.drainLogs == nil {
		select {
		case l.sent <- struct{}{}:
		default:
		}
	}
	return n, err
}

// TODO: instead of allocating, this should probably just append
// directly into the output log buffer.
func (l *logger) encodeText(buf []byte, skipClientTime bool) []byte {
	now := l.timeNow()

	// Factor in JSON encoding overhead to try to only do one alloc
	// in the make below (so appends don't resize the buffer).
	overhead := 13
	if !skipClientTime {
		overhead += 67
	}
	// TODO: do a pass over buf and count how many backslashes will be needed?
	// For now just factor in a dozen.
	overhead += 12

	b := make([]byte, 0, len(buf)+overhead)
	b = append(b, '{')

	if !skipClientTime {
		b = append(b, `"logtail": {"client_time": "`...)
		b = now.AppendFormat(b, time.RFC3339Nano)
		b = append(b, "\"}, "...)
	}

	b = append(b, "\"text\": \""...)
	for i, c := range buf {
		switch c {
		case '\b':
			b = append(b, '\\', 'b')
		case '\f':
			b = append(b, '\\', 'f')
		case '\n':
			b = append(b, '\\', 'n')
		case '\r':
			b = append(b, '\\', 'r')
		case '\t':
			b = append(b, '\\', 't')
		case '"':
			b = append(b, '\\', '"')
		case '\\':
			b = append(b, '\\', '\\')
		default:
			// TODO: what about binary gibberish or non UTF-8?
			b = append(b, c)
		}
		if l.lowMem && i > 254 {
			// TODO: this can break a UTF-8 character
			// mid-encoding.  We don't tend to log
			// non-ASCII stuff ourselves, but e.g. client
			// names might be.
			b = append(b, "…"...)
			break
		}
	}
	b = append(b, "\"}\n"...)
	return b
}

func (l *logger) encode(buf []byte) []byte {
	if buf[0] != '{' {
		return l.encodeText(buf, l.skipClientTime) // text fast-path
	}

	now := l.timeNow()

	obj := make(map[string]interface{})
	if err := json.Unmarshal(buf, &obj); err != nil {
		for k := range obj {
			delete(obj, k)
		}
		obj["text"] = string(buf)
	}
	if txt, isStr := obj["text"].(string); l.lowMem && isStr && len(txt) > 254 {
		// TODO(crawshaw): trim to unicode code point
		obj["text"] = txt[:254] + "…"
	}

	hasLogtail := obj["logtail"] != nil
	if hasLogtail {
		obj["error_has_logtail"] = obj["logtail"]
		obj["logtail"] = nil
	}
	if !l.skipClientTime {
		obj["logtail"] = map[string]string{
			"client_time": now.Format(time.RFC3339Nano),
		}
	}

	b, err := json.Marshal(obj)
	if err != nil {
		fmt.Fprintf(l.stderr, "logtail: re-encoding JSON failed: %v\n", err)
		// I know of no conditions under which this could fail.
		// Report it very loudly.
		panic("logtail: re-encoding JSON failed: " + err.Error())
	}
	b = append(b, '\n')
	return b
}

func (l *logger) Write(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if l.stderr != nil && l.stderr != ioutil.Discard {
		if buf[len(buf)-1] == '\n' {
			l.stderr.Write(buf)
		} else {
			// The log package always line-terminates logs,
			// so this is an uncommon path.
			withNL := append(buf[:len(buf):len(buf)], '\n')
			l.stderr.Write(withNL)
		}
	}
	b := l.encode(buf)
	_, err := l.send(b)
	return len(buf), err
}
