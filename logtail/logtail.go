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
	"time"

	"tailscale.com/logtail/backoff"
)

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
	CheckLogs      <-chan struct{}  // signals Logger to check for filched logs to upload
	NewZstdEncoder func() Encoder   // if set, used to compress logs for transmission
}

func Log(cfg Config) Logger {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://log.tailscale.io"
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
	if cfg.CheckLogs == nil {
		cfg.CheckLogs = make(chan struct{})
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
		checkLogs:      cfg.CheckLogs,
		timeNow:        cfg.TimeNow,
		bo: backoff.Backoff{
			Name: "logtail",
		},

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
	checkLogs      <-chan struct{} // external signal to attempt a drain
	sentinel       chan int32
	timeNow        func() time.Time
	bo             backoff.Backoff
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

			select {
			case <-l.shutdownStart:
				batchDone = true
			case <-l.checkLogs:
			case <-l.sent:
			}
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
		if l.zstdEncoder != nil {
			body = l.zstdEncoder.EncodeAll(body, nil)
		}

		for len(body) > 0 {
			select {
			case <-ctx.Done():
				return
			default:
			}
			uploaded, err := l.upload(ctx, body)
			if err != nil {
				fmt.Fprintf(l.stderr, "logtail: upload: %v\n", err)
			}
			if uploaded {
				break
			}
			l.bo.BackOff(ctx, err)
		}

		select {
		case <-l.shutdownStart:
			return
		default:
		}
	}
}

func (l *logger) upload(ctx context.Context, body []byte) (uploaded bool, err error) {
	req, err := http.NewRequest("POST", l.url, bytes.NewReader(body))
	if err != nil {
		// I know of no conditions under which this could fail.
		// Report it very loudly.
		// TODO record logs to disk
		panic("logtail: cannot build http request: " + err.Error())
	}
	if l.zstdEncoder != nil {
		req.Header.Add("Content-Encoding", "zstd")
	}

	maxUploadTime := 45 * time.Second
	ctx, cancel := context.WithTimeout(ctx, maxUploadTime)
	defer cancel()
	req = req.WithContext(ctx)

	compressedNote := "not-compressed"
	if l.zstdEncoder != nil {
		compressedNote = "compressed"
	}

	resp, err := l.httpc.Do(req)
	if err != nil {
		return false, fmt.Errorf("log upload of %d bytes %s failed: %v", len(body), compressedNote, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		uploaded = resp.StatusCode == 400 // the server saved the logs anyway
		b, _ := ioutil.ReadAll(resp.Body)
		return uploaded, fmt.Errorf("log upload of %d bytes %s failed %d: %q", len(body), compressedNote, resp.StatusCode, b)
	}
	return true, nil
}

func (l *logger) Flush() error {
	return nil
}

func (l *logger) send(jsonBlob []byte) (int, error) {
	n, err := l.buffer.Write(jsonBlob)
	select {
	case l.sent <- struct{}{}:
	default:
	}
	return n, err
}

func (l *logger) encodeText(buf []byte, skipClientTime bool) []byte {
	now := l.timeNow()

	b := make([]byte, 0, len(buf)+16)
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
			b = append(b, c)
		}
		if l.lowMem && i > 254 {
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
	return l.send(b)
}
