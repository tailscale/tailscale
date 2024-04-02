// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package logtail sends logs to log.tailscale.io.
package logtail

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/net/netmon"
	"tailscale.com/net/sockstats"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tstime"
	tslogger "tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/util/set"
	"tailscale.com/util/zstdframe"
)

// DefaultHost is the default host name to upload logs to when
// Config.BaseURL isn't provided.
const DefaultHost = "log.tailscale.io"

const defaultFlushDelay = 2 * time.Second

const (
	// CollectionNode is the name of a logtail Config.Collection
	// for tailscaled (or equivalent: IPNExtension, Android app).
	CollectionNode = "tailnode.log.tailscale.io"
)

type Config struct {
	Collection     string          // collection name, a domain name
	PrivateID      logid.PrivateID // private ID for the primary log stream
	CopyPrivateID  logid.PrivateID // private ID for a log stream that is a superset of this log stream
	BaseURL        string          // if empty defaults to "https://log.tailscale.io"
	HTTPC          *http.Client    // if empty defaults to http.DefaultClient
	SkipClientTime bool            // if true, client_time is not written to logs
	LowMemory      bool            // if true, logtail minimizes memory use
	Clock          tstime.Clock    // if set, Clock.Now substitutes uses of time.Now
	Stderr         io.Writer       // if set, logs are sent here instead of os.Stderr
	StderrLevel    int             // max verbosity level to write to stderr; 0 means the non-verbose messages only
	Buffer         Buffer          // temp storage, if nil a MemoryBuffer
	CompressLogs   bool            // whether to compress the log uploads

	// MetricsDelta, if non-nil, is a func that returns an encoding
	// delta in clientmetrics to upload alongside existing logs.
	// It can return either an empty string (for nothing) or a string
	// that's safe to embed in a JSON string literal without further escaping.
	MetricsDelta func() string

	// FlushDelayFn, if non-nil is a func that returns how long to wait to
	// accumulate logs before uploading them. 0 or negative means to upload
	// immediately.
	//
	// If nil, a default value is used. (currently 2 seconds)
	FlushDelayFn func() time.Duration

	// IncludeProcID, if true, results in an ephemeral process identifier being
	// included in logs. The ID is random and not guaranteed to be globally
	// unique, but it can be used to distinguish between different instances
	// running with same PrivateID.
	IncludeProcID bool

	// IncludeProcSequence, if true, results in an ephemeral sequence number
	// being included in the logs. The sequence number is incremented for each
	// log message sent, but is not persisted across process restarts.
	IncludeProcSequence bool
}

func NewLogger(cfg Config, logf tslogger.Logf) *Logger {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://" + DefaultHost
	}
	if cfg.HTTPC == nil {
		cfg.HTTPC = http.DefaultClient
	}
	if cfg.Clock == nil {
		cfg.Clock = tstime.StdClock{}
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
	var procID uint32
	if cfg.IncludeProcID {
		keyBytes := make([]byte, 4)
		rand.Read(keyBytes)
		procID = binary.LittleEndian.Uint32(keyBytes)
		if procID == 0 {
			// 0 is the empty/off value, assign a different (non-zero) value to
			// make sure we still include an ID (actual value does not matter).
			procID = 7
		}
	}
	if s := envknob.String("TS_DEBUG_LOGTAIL_FLUSHDELAY"); s != "" {
		if delay, err := time.ParseDuration(s); err == nil {
			cfg.FlushDelayFn = func() time.Duration { return delay }
		} else {
			log.Fatalf("invalid TS_DEBUG_LOGTAIL_FLUSHDELAY: %v", err)
		}
	} else if cfg.FlushDelayFn == nil && envknob.Bool("IN_TS_TEST") {
		cfg.FlushDelayFn = func() time.Duration { return 0 }
	}

	var urlSuffix string
	if !cfg.CopyPrivateID.IsZero() {
		urlSuffix = "?copyId=" + cfg.CopyPrivateID.String()
	}
	l := &Logger{
		privateID:      cfg.PrivateID,
		stderr:         cfg.Stderr,
		stderrLevel:    int64(cfg.StderrLevel),
		httpc:          cfg.HTTPC,
		url:            cfg.BaseURL + "/c/" + cfg.Collection + "/" + cfg.PrivateID.String() + urlSuffix,
		lowMem:         cfg.LowMemory,
		buffer:         cfg.Buffer,
		skipClientTime: cfg.SkipClientTime,
		drainWake:      make(chan struct{}, 1),
		sentinel:       make(chan int32, 16),
		flushDelayFn:   cfg.FlushDelayFn,
		clock:          cfg.Clock,
		metricsDelta:   cfg.MetricsDelta,

		procID:              procID,
		includeProcSequence: cfg.IncludeProcSequence,

		shutdownStart: make(chan struct{}),
		shutdownDone:  make(chan struct{}),
	}
	l.SetSockstatsLabel(sockstats.LabelLogtailLogger)
	l.compressLogs = cfg.CompressLogs

	ctx, cancel := context.WithCancel(context.Background())
	l.uploadCancel = cancel

	go l.uploading(ctx)
	l.Write([]byte("logtail started"))
	return l
}

// Logger writes logs, splitting them as configured between local
// logging facilities and uploading to a log server.
type Logger struct {
	stderr         io.Writer
	stderrLevel    int64 // accessed atomically
	httpc          *http.Client
	url            string
	lowMem         bool
	skipClientTime bool
	netMonitor     *netmon.Monitor
	buffer         Buffer
	drainWake      chan struct{}        // signal to speed up drain
	drainBuf       bytes.Buffer         // owned by drainPending for reuse
	flushDelayFn   func() time.Duration // negative or zero return value to upload aggressively, or >0 to batch at this delay
	flushPending   atomic.Bool
	sentinel       chan int32
	clock          tstime.Clock
	compressLogs   bool
	uploadCancel   func()
	explainedRaw   bool
	metricsDelta   func() string // or nil
	privateID      logid.PrivateID
	httpDoCalls    atomic.Int32
	sockstatsLabel atomicSocktatsLabel

	procID              uint32
	includeProcSequence bool

	writeLock    sync.Mutex // guards procSequence, flushTimer, buffer.Write calls
	procSequence uint64
	flushTimer   tstime.TimerController // used when flushDelay is >0

	shutdownStartMu sync.Mutex    // guards the closing of shutdownStart
	shutdownStart   chan struct{} // closed when shutdown begins
	shutdownDone    chan struct{} // closed when shutdown complete
}

type atomicSocktatsLabel struct{ p atomic.Uint32 }

func (p *atomicSocktatsLabel) Load() sockstats.Label       { return sockstats.Label(p.p.Load()) }
func (p *atomicSocktatsLabel) Store(label sockstats.Label) { p.p.Store(uint32(label)) }

// SetVerbosityLevel controls the verbosity level that should be
// written to stderr. 0 is the default (not verbose). Levels 1 or higher
// are increasingly verbose.
func (l *Logger) SetVerbosityLevel(level int) {
	atomic.StoreInt64(&l.stderrLevel, int64(level))
}

// SetNetMon sets the optional the network monitor.
//
// It should not be changed concurrently with log writes and should
// only be set once.
func (l *Logger) SetNetMon(lm *netmon.Monitor) {
	l.netMonitor = lm
}

// SetSockstatsLabel sets the label used in sockstat logs to identify network traffic from this logger.
func (l *Logger) SetSockstatsLabel(label sockstats.Label) {
	l.sockstatsLabel.Store(label)
}

// PrivateID returns the logger's private log ID.
//
// It exists for internal use only.
func (l *Logger) PrivateID() logid.PrivateID { return l.privateID }

// Shutdown gracefully shuts down the logger while completing any
// remaining uploads.
//
// It will block, continuing to try and upload unless the passed
// context object interrupts it by being done.
// If the shutdown is interrupted, an error is returned.
func (l *Logger) Shutdown(ctx context.Context) error {
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

	l.shutdownStartMu.Lock()
	select {
	case <-l.shutdownStart:
		l.shutdownStartMu.Unlock()
		return nil
	default:
	}
	close(l.shutdownStart)
	l.shutdownStartMu.Unlock()

	io.WriteString(l, "logger closing down\n")
	<-done

	return nil
}

// Close shuts down this logger object, the background log uploader
// process, and any associated goroutines.
//
// Deprecated: use Shutdown
func (l *Logger) Close() {
	l.Shutdown(context.Background())
}

// drainBlock is called by drainPending when there are no logs to drain.
//
// In typical operation, every call to the Write method unblocks and triggers a
// buffer.TryReadline, so logs are written with very low latency.
//
// If the caller specified FlushInterface, drainWake is only sent to
// periodically.
func (l *Logger) drainBlock() (shuttingDown bool) {
	select {
	case <-l.shutdownStart:
		return true
	case <-l.drainWake:
	}
	return false
}

// drainPending drains and encodes a batch of logs from the buffer for upload.
// If no logs are available, drainPending blocks until logs are available.
func (l *Logger) drainPending() (res []byte) {
	buf := &l.drainBuf
	buf.Reset()
	buf.WriteByte('[')
	entries := 0

	var batchDone bool
	const maxLen = 256 << 10
	for buf.Len() < maxLen && !batchDone {
		b, err := l.buffer.TryReadLine()
		if err == io.EOF {
			break
		} else if err != nil {
			b = fmt.Appendf(nil, "reading ringbuffer: %v", err)
			batchDone = true
		} else if b == nil {
			if entries > 0 {
				break
			}

			// We're about to block. If we're holding on to too much memory
			// in our buffer from a previous large write, let it go.
			if buf.Available() > 4<<10 {
				cur := buf.Bytes()
				l.drainBuf = bytes.Buffer{}
				buf.Write(cur)
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
			if !l.explainedRaw {
				fmt.Fprintf(l.stderr, "RAW-STDERR: ***\n")
				fmt.Fprintf(l.stderr, "RAW-STDERR: *** Lines prefixed with RAW-STDERR below bypassed logtail and probably come from a previous run of the program\n")
				fmt.Fprintf(l.stderr, "RAW-STDERR: ***\n")
				fmt.Fprintf(l.stderr, "RAW-STDERR:\n")
				l.explainedRaw = true
			}
			fmt.Fprintf(l.stderr, "RAW-STDERR: %s", b)
			// Do not add a client time, as it could have been
			// been written a long time ago. Don't include instance key or ID
			// either, since this came from a different instance.
			b = l.encodeText(b, true, 0, 0, 0)
		}

		if entries > 0 {
			buf.WriteByte(',')
		}
		buf.Write(b)
		entries++
	}

	buf.WriteByte(']')
	if buf.Len() <= len("[]") {
		return nil
	}
	return buf.Bytes()
}

// This is the goroutine that repeatedly uploads logs in the background.
func (l *Logger) uploading(ctx context.Context) {
	defer close(l.shutdownDone)

	for {
		body := l.drainPending()
		origlen := -1 // sentinel value: uncompressed
		// Don't attempt to compress tiny bodies; not worth the CPU cycles.
		if l.compressLogs && len(body) > 256 {
			zbody := zstdframe.AppendEncode(nil, body,
				zstdframe.FastestCompression, zstdframe.LowMemory(true))

			// Only send it compressed if the bandwidth savings are sufficient.
			// Just the extra headers associated with enabling compression
			// are 50 bytes by themselves.
			if len(body)-len(zbody) > 64 {
				origlen = len(body)
				body = zbody
			}
		}

		var lastError string
		var numFailures int
		var firstFailure time.Time
		for len(body) > 0 && ctx.Err() == nil {
			retryAfter, err := l.upload(ctx, body, origlen)
			if err != nil {
				numFailures++
				firstFailure = l.clock.Now()

				if !l.internetUp() {
					fmt.Fprintf(l.stderr, "logtail: internet down; waiting\n")
					l.awaitInternetUp(ctx)
					continue
				}

				// Only print the same message once.
				if currError := err.Error(); lastError != currError {
					fmt.Fprintf(l.stderr, "logtail: upload: %v\n", err)
					lastError = currError
				}

				// Sleep for the specified retryAfter period,
				// otherwise default to some random value.
				if retryAfter <= 0 {
					retryAfter = time.Duration(30+mrand.Intn(30)) * time.Second
				}
				tstime.Sleep(ctx, retryAfter)
			} else {
				// Only print a success message after recovery.
				if numFailures > 0 {
					fmt.Fprintf(l.stderr, "logtail: upload succeeded after %d failures and %s\n", numFailures, l.clock.Since(firstFailure).Round(time.Second))
				}
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

func (l *Logger) internetUp() bool {
	if l.netMonitor == nil {
		// No way to tell, so assume it is.
		return true
	}
	return l.netMonitor.InterfaceState().AnyInterfaceUp()
}

func (l *Logger) awaitInternetUp(ctx context.Context) {
	upc := make(chan bool, 1)
	defer l.netMonitor.RegisterChangeCallback(func(delta *netmon.ChangeDelta) {
		if delta.New.AnyInterfaceUp() {
			select {
			case upc <- true:
			default:
			}
		}
	})()
	if l.internetUp() {
		return
	}
	select {
	case <-upc:
		fmt.Fprintf(l.stderr, "logtail: internet back up\n")
	case <-ctx.Done():
	}
}

// upload uploads body to the log server.
// origlen indicates the pre-compression body length.
// origlen of -1 indicates that the body is not compressed.
func (l *Logger) upload(ctx context.Context, body []byte, origlen int) (retryAfter time.Duration, err error) {
	const maxUploadTime = 45 * time.Second
	ctx = sockstats.WithSockStats(ctx, l.sockstatsLabel.Load(), l.Logf)
	ctx, cancel := context.WithTimeout(ctx, maxUploadTime)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", l.url, bytes.NewReader(body))
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
	if runtime.GOOS == "js" {
		// We once advertised we'd accept optional client certs (for internal use)
		// on log.tailscale.io but then Tailscale SSH js/wasm clients prompted
		// users (on some browsers?) to pick a client cert. We'll fix the server's
		// TLS ServerHello, but we can also fix it client side for good measure.
		//
		// Corp details: https://github.com/tailscale/corp/issues/18177#issuecomment-2026598715
		// and https://github.com/tailscale/corp/pull/18775#issuecomment-2027505036
		//
		// See https://github.com/golang/go/wiki/WebAssembly#configuring-fetch-options-while-using-nethttp
		// and https://developer.mozilla.org/en-US/docs/Web/API/fetch#credentials
		req.Header.Set("js.fetch:credentials", "omit")
	}
	req.Header["User-Agent"] = nil // not worth writing one; save some bytes

	compressedNote := "not-compressed"
	if origlen != -1 {
		compressedNote = "compressed"
	}

	l.httpDoCalls.Add(1)
	resp, err := l.httpc.Do(req)
	if err != nil {
		return 0, fmt.Errorf("log upload of %d bytes %s failed: %v", len(body), compressedNote, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		n, _ := strconv.Atoi(resp.Header.Get("Retry-After"))
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
		return time.Duration(n) * time.Second, fmt.Errorf("log upload of %d bytes %s failed %d: %s", len(body), compressedNote, resp.StatusCode, bytes.TrimSpace(b))
	}
	return 0, nil
}

// Flush uploads all logs to the server. It blocks until complete or there is an
// unrecoverable error.
//
// TODO(bradfitz): this apparently just returns nil, as of tailscale/corp@9c2ec35.
// Finish cleaning this up.
func (l *Logger) Flush() error {
	return nil
}

// StartFlush starts a log upload, if anything is pending.
//
// If l is nil, StartFlush is a no-op.
func (l *Logger) StartFlush() {
	if l != nil {
		l.tryDrainWake()
	}
}

// logtailDisabled is whether logtail uploads to logcatcher are disabled.
var logtailDisabled atomic.Bool

// Disable disables logtail uploads for the lifetime of the process.
func Disable() {
	logtailDisabled.Store(true)
}

var debugWakesAndUploads = envknob.RegisterBool("TS_DEBUG_LOGTAIL_WAKES")

// tryDrainWake tries to send to lg.drainWake, to cause an uploading wakeup.
// It does not block.
func (l *Logger) tryDrainWake() {
	l.flushPending.Store(false)
	if debugWakesAndUploads() {
		// Using println instead of log.Printf here to avoid recursing back into
		// ourselves.
		println("logtail: try drain wake, numHTTP:", l.httpDoCalls.Load())
	}
	select {
	case l.drainWake <- struct{}{}:
	default:
	}
}

func (l *Logger) sendLocked(jsonBlob []byte) (int, error) {
	tapSend(jsonBlob)
	if logtailDisabled.Load() {
		return len(jsonBlob), nil
	}

	n, err := l.buffer.Write(jsonBlob)

	flushDelay := defaultFlushDelay
	if l.flushDelayFn != nil {
		flushDelay = l.flushDelayFn()
	}
	if flushDelay > 0 {
		if l.flushPending.CompareAndSwap(false, true) {
			if l.flushTimer == nil {
				l.flushTimer = l.clock.AfterFunc(flushDelay, l.tryDrainWake)
			} else {
				l.flushTimer.Reset(flushDelay)
			}
		}
	} else {
		l.tryDrainWake()
	}
	return n, err
}

// TODO: instead of allocating, this should probably just append
// directly into the output log buffer.
func (l *Logger) encodeText(buf []byte, skipClientTime bool, procID uint32, procSequence uint64, level int) []byte {
	now := l.clock.Now()

	// Factor in JSON encoding overhead to try to only do one alloc
	// in the make below (so appends don't resize the buffer).
	overhead := len(`{"text": ""}\n`)
	includeLogtail := !skipClientTime || procID != 0 || procSequence != 0
	if includeLogtail {
		overhead += len(`"logtail": {},`)
	}
	if !skipClientTime {
		overhead += len(`"client_time": "2006-01-02T15:04:05.999999999Z07:00",`)
	}
	if procID != 0 {
		overhead += len(`"proc_id": 4294967296,`)
	}
	if procSequence != 0 {
		overhead += len(`"proc_seq": 9007199254740992,`)
	}
	// TODO: do a pass over buf and count how many backslashes will be needed?
	// For now just factor in a dozen.
	overhead += 12

	// Put a sanity cap on buf's size.
	max := 16 << 10
	if l.lowMem {
		max = 4 << 10
	}
	var nTruncated int
	if len(buf) > max {
		nTruncated = len(buf) - max
		// TODO: this can break a UTF-8 character
		// mid-encoding.  We don't tend to log
		// non-ASCII stuff ourselves, but e.g. client
		// names might be.
		buf = buf[:max]
	}

	b := make([]byte, 0, len(buf)+overhead)
	b = append(b, '{')

	if includeLogtail {
		b = append(b, `"logtail": {`...)
		if !skipClientTime {
			b = append(b, `"client_time": "`...)
			b = now.UTC().AppendFormat(b, time.RFC3339Nano)
			b = append(b, `",`...)
		}
		if procID != 0 {
			b = append(b, `"proc_id": `...)
			b = strconv.AppendUint(b, uint64(procID), 10)
			b = append(b, ',')
		}
		if procSequence != 0 {
			b = append(b, `"proc_seq": `...)
			b = strconv.AppendUint(b, procSequence, 10)
			b = append(b, ',')
		}
		b = bytes.TrimRight(b, ",")
		b = append(b, "}, "...)
	}

	if l.metricsDelta != nil {
		if d := l.metricsDelta(); d != "" {
			b = append(b, `"metrics": "`...)
			b = append(b, d...)
			b = append(b, `",`...)
		}
	}

	// Add the log level, if non-zero. Note that we only use log
	// levels 1 and 2 currently. It's unlikely we'll ever make it
	// past 9.
	if level > 0 && level < 10 {
		b = append(b, `"v":`...)
		b = append(b, '0'+byte(level))
		b = append(b, ',')
	}
	b = append(b, "\"text\": \""...)
	for _, c := range buf {
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
	}
	if nTruncated > 0 {
		b = append(b, "…+"...)
		b = strconv.AppendInt(b, int64(nTruncated), 10)
	}
	b = append(b, "\"}\n"...)
	return b
}

func (l *Logger) encodeLocked(buf []byte, level int) []byte {
	if l.includeProcSequence {
		l.procSequence++
	}
	if buf[0] != '{' {
		return l.encodeText(buf, l.skipClientTime, l.procID, l.procSequence, level) // text fast-path
	}

	now := l.clock.Now()

	obj := make(map[string]any)
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
	if !l.skipClientTime || l.procID != 0 || l.procSequence != 0 {
		logtail := map[string]any{}
		if !l.skipClientTime {
			logtail["client_time"] = now.UTC().Format(time.RFC3339Nano)
		}
		if l.procID != 0 {
			logtail["proc_id"] = l.procID
		}
		if l.procSequence != 0 {
			logtail["proc_seq"] = l.procSequence
		}
		obj["logtail"] = logtail
	}
	if level > 0 {
		obj["v"] = level
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

// Logf logs to l using the provided fmt-style format and optional arguments.
func (l *Logger) Logf(format string, args ...any) {
	fmt.Fprintf(l, format, args...)
}

var obscureIPs = envknob.RegisterBool("TS_OBSCURE_LOGGED_IPS")

// Write logs an encoded JSON blob.
//
// If the []byte passed to Write is not an encoded JSON blob,
// then contents is fit into a JSON blob and written.
//
// This is intended as an interface for the stdlib "log" package.
func (l *Logger) Write(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	inLen := len(buf) // length as provided to us, before modifications to downstream writers

	level, buf := parseAndRemoveLogLevel(buf)
	if l.stderr != nil && l.stderr != io.Discard && int64(level) <= atomic.LoadInt64(&l.stderrLevel) {
		if buf[len(buf)-1] == '\n' {
			l.stderr.Write(buf)
		} else {
			// The log package always line-terminates logs,
			// so this is an uncommon path.
			withNL := append(buf[:len(buf):len(buf)], '\n')
			l.stderr.Write(withNL)
		}
	}

	if obscureIPs() {
		buf = redactIPs(buf)
	}

	l.writeLock.Lock()
	defer l.writeLock.Unlock()

	b := l.encodeLocked(buf, level)
	_, err := l.sendLocked(b)
	return inLen, err
}

var (
	regexMatchesIPv6 = regexp.MustCompile(`([0-9a-fA-F]{1,4}):([0-9a-fA-F]{1,4}):([0-9a-fA-F:]{1,4})*`)
	regexMatchesIPv4 = regexp.MustCompile(`(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}`)
)

// redactIPs is a helper function used in Write() to redact IPs (other than tailscale IPs).
// This function takes a log line as a byte slice and
// uses regex matching to parse and find IP addresses. Based on if the IP address is IPv4 or
// IPv6, it parses and replaces the end of the addresses with an "x". This function returns the
// log line with the IPs redacted.
func redactIPs(buf []byte) []byte {
	out := regexMatchesIPv6.ReplaceAllFunc(buf, func(b []byte) []byte {
		ip, err := netip.ParseAddr(string(b))
		if err != nil || tsaddr.IsTailscaleIP(ip) {
			return b // don't change this one
		}

		prefix := bytes.Split(b, []byte(":"))
		return bytes.Join(append(prefix[:2], []byte("x")), []byte(":"))
	})

	out = regexMatchesIPv4.ReplaceAllFunc(out, func(b []byte) []byte {
		ip, err := netip.ParseAddr(string(b))
		if err != nil || tsaddr.IsTailscaleIP(ip) {
			return b // don't change this one
		}

		prefix := bytes.Split(b, []byte("."))
		return bytes.Join(append(prefix[:2], []byte("x.x")), []byte("."))
	})

	return []byte(out)
}

var (
	openBracketV = []byte("[v")
	v1           = []byte("[v1] ")
	v2           = []byte("[v2] ")
	vJSON        = []byte("[v\x00JSON]") // precedes log level '0'-'9' byte, then JSON value
)

// level 0 is normal (or unknown) level; 1+ are increasingly verbose
func parseAndRemoveLogLevel(buf []byte) (level int, cleanBuf []byte) {
	if len(buf) == 0 || buf[0] == '{' || !bytes.Contains(buf, openBracketV) {
		return 0, buf
	}
	if bytes.Contains(buf, v1) {
		return 1, bytes.ReplaceAll(buf, v1, nil)
	}
	if bytes.Contains(buf, v2) {
		return 2, bytes.ReplaceAll(buf, v2, nil)
	}
	if i := bytes.Index(buf, vJSON); i != -1 {
		rest := buf[i+len(vJSON):]
		if len(rest) >= 2 {
			v := rest[0]
			if v >= '0' && v <= '9' {
				return int(v - '0'), rest[1:]
			}
		}
	}
	return 0, buf
}

var (
	tapSetSize atomic.Int32
	tapMu      sync.Mutex
	tapSet     set.HandleSet[chan<- string]
)

// RegisterLogTap registers dst to get a copy of every log write. The caller
// must call unregister when done watching.
//
// This would ideally be a method on Logger, but Logger isn't really available
// in most places; many writes go via stderr which filch redirects to the
// singleton Logger set up early. For better or worse, there's basically only
// one Logger within the program. This mechanism at least works well for
// tailscaled. It works less well for a binary with multiple tsnet.Servers. Oh
// well. This then subscribes to all of them.
func RegisterLogTap(dst chan<- string) (unregister func()) {
	tapMu.Lock()
	defer tapMu.Unlock()
	h := tapSet.Add(dst)
	tapSetSize.Store(int32(len(tapSet)))
	return func() {
		tapMu.Lock()
		defer tapMu.Unlock()
		delete(tapSet, h)
		tapSetSize.Store(int32(len(tapSet)))
	}
}

// tapSend relays the JSON blob to any/all registered local debug log watchers
// (somebody running "tailscale debug daemon-logs").
func tapSend(jsonBlob []byte) {
	if tapSetSize.Load() == 0 {
		return
	}
	s := string(jsonBlob)
	tapMu.Lock()
	defer tapMu.Unlock()
	for _, dst := range tapSet {
		select {
		case dst <- s:
		default:
		}
	}
}
