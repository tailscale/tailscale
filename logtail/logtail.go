// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_logtail

// Package logtail sends logs to log.tailscale.com.
package logtail

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	mrand "math/rand/v2"
	"net/http"
	"os"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-json-experiment/json/jsontext"
	"tailscale.com/envknob"
	"tailscale.com/net/netmon"
	"tailscale.com/net/sockstats"
	"tailscale.com/tstime"
	tslogger "tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/util/set"
	"tailscale.com/util/truncate"
	"tailscale.com/util/zstdframe"
)

// maxSize is the maximum size that a single log entry can be.
// It is also the maximum body size that may be uploaded at a time.
const maxSize = 256 << 10

// maxTextSize is the maximum size for a text log message.
// Note that JSON log messages can be as large as maxSize.
const maxTextSize = 16 << 10

// lowMemRatio reduces maxSize and maxTextSize by this ratio in lowMem mode.
const lowMemRatio = 4

// bufferSize is the typical buffer size to retain.
// It is large enough to handle most log messages,
// but not too large to be a notable waste of memory if retained forever.
const bufferSize = 4 << 10

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
		maxUploadSize:  cfg.MaxUploadSize,
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
	maxUploadSize  int
	drainWake      chan struct{}        // signal to speed up drain
	drainBuf       []byte               // owned by drainPending for reuse
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
	writeBuf     [bufferSize]byte       // owned by Write for reuse
	bytesBuf     bytes.Buffer           // owned by appendTextOrJSONLocked for reuse
	jsonDec      jsontext.Decoder       // owned by appendTextOrJSONLocked for reuse

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

// SetNetMon sets the network monitor.
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
		l.httpc.CloseIdleConnections()
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
// The returned buffer is only valid until the next call to drainPending.
func (l *Logger) drainPending() (b []byte) {
	b = l.drainBuf[:0]
	b = append(b, '[')
	defer func() {
		b = bytes.TrimRight(b, ",")
		b = append(b, ']')
		l.drainBuf = b
		if len(b) <= len("[]") {
			b = nil
		}
	}()

	maxLen := cmp.Or(l.maxUploadSize, maxSize)
	if l.lowMem {
		// When operating in a low memory environment, it is better to upload
		// in multiple operations than it is to allocate a large body and OOM.
		// Even if maxLen is less than maxSize, we can still upload an entry
		// that is up to maxSize if we happen to encounter one.
		maxLen /= lowMemRatio
	}
	for len(b) < maxLen {
		line, err := l.buffer.TryReadLine()
		switch {
		case err == io.EOF:
			return b
		case err != nil:
			b = append(b, '{')
			b = l.appendMetadata(b, false, true, 0, 0, "reading ringbuffer: "+err.Error(), nil, 0)
			b = bytes.TrimRight(b, ",")
			b = append(b, '}')
			return b
		case line == nil:
			// If we read at least some log entries, return immediately.
			if len(b) > len("[") {
				return b
			}

			// We're about to block. If we're holding on to too much memory
			// in our buffer from a previous large write, let it go.
			if cap(b) > bufferSize {
				b = bytes.Clone(b)
				l.drainBuf = b
			}

			if shuttingDown := l.drainBlock(); shuttingDown {
				return b
			}
			continue
		}

		switch {
		case len(line) == 0:
			continue
		case line[0] == '{' && jsontext.Value(line).IsValid():
			// This is already a valid JSON object, so just append it.
			// This may exceed maxLen, but should be no larger than maxSize
			// so long as logic writing into the buffer enforces the limit.
			b = append(b, line...)
		default:
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
			// Do not add a client time, as it could be really old.
			// Do not include instance key or ID either,
			// since this came from a different instance.
			b = l.appendText(b, line, true, 0, 0, 0)
		}
		b = append(b, ',')
	}
	return b
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
					retryAfter = mrand.N(30*time.Second) + 30*time.Second
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
		// on log.tailscale.com but then Tailscale SSH js/wasm clients prompted
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

// appendMetadata appends optional "logtail", "metrics", and "v" JSON members.
// This assumes dst is already within a JSON object.
// Each member is comma-terminated.
func (l *Logger) appendMetadata(dst []byte, skipClientTime, skipMetrics bool, procID uint32, procSequence uint64, errDetail string, errData jsontext.Value, level int) []byte {
	// Append optional logtail metadata.
	if !skipClientTime || procID != 0 || procSequence != 0 || errDetail != "" || errData != nil {
		dst = append(dst, `"logtail":{`...)
		if !skipClientTime {
			dst = append(dst, `"client_time":"`...)
			dst = l.clock.Now().UTC().AppendFormat(dst, time.RFC3339Nano)
			dst = append(dst, '"', ',')
		}
		if procID != 0 {
			dst = append(dst, `"proc_id":`...)
			dst = strconv.AppendUint(dst, uint64(procID), 10)
			dst = append(dst, ',')
		}
		if procSequence != 0 {
			dst = append(dst, `"proc_seq":`...)
			dst = strconv.AppendUint(dst, procSequence, 10)
			dst = append(dst, ',')
		}
		if errDetail != "" || errData != nil {
			dst = append(dst, `"error":{`...)
			if errDetail != "" {
				dst = append(dst, `"detail":`...)
				dst, _ = jsontext.AppendQuote(dst, errDetail)
				dst = append(dst, ',')
			}
			if errData != nil {
				dst = append(dst, `"bad_data":`...)
				dst = append(dst, errData...)
				dst = append(dst, ',')
			}
			dst = bytes.TrimRight(dst, ",")
			dst = append(dst, '}', ',')
		}
		dst = bytes.TrimRight(dst, ",")
		dst = append(dst, '}', ',')
	}

	// Append optional metrics metadata.
	if !skipMetrics && l.metricsDelta != nil {
		if d := l.metricsDelta(); d != "" {
			dst = append(dst, `"metrics":"`...)
			dst = append(dst, d...)
			dst = append(dst, '"', ',')
		}
	}

	// Add the optional log level, if non-zero.
	// Note that we only use log levels 1 and 2 currently.
	// It's unlikely we'll ever make it past 9.
	if level > 0 && level < 10 {
		dst = append(dst, `"v":`...)
		dst = append(dst, '0'+byte(level))
		dst = append(dst, ',')
	}

	return dst
}

// appendText appends a raw text message in the Tailscale JSON log entry format.
func (l *Logger) appendText(dst, src []byte, skipClientTime bool, procID uint32, procSequence uint64, level int) []byte {
	dst = slices.Grow(dst, len(src))
	dst = append(dst, '{')
	dst = l.appendMetadata(dst, skipClientTime, false, procID, procSequence, "", nil, level)
	if len(src) == 0 {
		dst = bytes.TrimRight(dst, ",")
		return append(dst, "}\n"...)
	}

	// Append the text string, which may be truncated.
	// Invalid UTF-8 will be mangled with the Unicode replacement character.
	max := maxTextSize
	if l.lowMem {
		max /= lowMemRatio
	}
	dst = append(dst, `"text":`...)
	dst = appendTruncatedString(dst, src, max)
	return append(dst, "}\n"...)
}

// appendTruncatedString appends a JSON string for src,
// truncating the src to be no larger than n.
func appendTruncatedString(dst, src []byte, n int) []byte {
	srcLen := len(src)
	src = truncate.String(src, n)
	dst, _ = jsontext.AppendQuote(dst, src) // ignore error; only occurs for invalid UTF-8
	if srcLen > len(src) {
		dst = dst[:len(dst)-len(`"`)] // trim off preceding double-quote
		dst = append(dst, "…+"...)
		dst = strconv.AppendInt(dst, int64(srcLen-len(src)), 10)
		dst = append(dst, '"') // re-append succeeding double-quote
	}
	return dst
}

// appendTextOrJSONLocked appends a raw text message or a raw JSON object
// in the Tailscale JSON log format.
func (l *Logger) appendTextOrJSONLocked(dst, src []byte, level int) []byte {
	if l.includeProcSequence {
		l.procSequence++
	}
	if len(src) == 0 || src[0] != '{' {
		return l.appendText(dst, src, l.skipClientTime, l.procID, l.procSequence, level)
	}

	// Check whether the input is a valid JSON object and
	// whether it contains the reserved "logtail" name at the top-level.
	var logtailKeyOffset, logtailValOffset, logtailValLength int
	validJSON := func() bool {
		// The jsontext.NewDecoder API operates on an io.Reader, for which
		// bytes.Buffer provides a means to convert a []byte into an io.Reader.
		// However, bytes.NewBuffer normally allocates unless
		// we immediately shallow copy it into a pre-allocated Buffer struct.
		// See https://go.dev/issue/67004.
		l.bytesBuf = *bytes.NewBuffer(src)
		defer func() { l.bytesBuf = bytes.Buffer{} }() // avoid pinning src

		dec := &l.jsonDec
		dec.Reset(&l.bytesBuf)
		if tok, err := dec.ReadToken(); tok.Kind() != '{' || err != nil {
			return false
		}
		for dec.PeekKind() != '}' {
			keyOffset := dec.InputOffset()
			tok, err := dec.ReadToken()
			if err != nil {
				return false
			}
			isLogtail := tok.String() == "logtail"
			valOffset := dec.InputOffset()
			if dec.SkipValue() != nil {
				return false
			}
			if isLogtail {
				logtailKeyOffset = int(keyOffset)
				logtailValOffset = int(valOffset)
				logtailValLength = int(dec.InputOffset()) - logtailValOffset
			}
		}
		if tok, err := dec.ReadToken(); tok.Kind() != '}' || err != nil {
			return false
		}
		if _, err := dec.ReadToken(); err != io.EOF {
			return false // trailing junk after JSON object
		}
		return true
	}()

	// Treat invalid JSON as a raw text message.
	if !validJSON {
		return l.appendText(dst, src, l.skipClientTime, l.procID, l.procSequence, level)
	}

	// Check whether the JSON payload is too large.
	// Due to logtail metadata, the formatted log entry could exceed maxSize.
	// That's okay as the Tailscale log service limit is actually 2*maxSize.
	// However, so long as logging applications aim to target the maxSize limit,
	// there should be no trouble eventually uploading logs.
	maxLen := cmp.Or(l.maxUploadSize, maxSize)
	if len(src) > maxLen {
		errDetail := fmt.Sprintf("entry too large: %d bytes", len(src))
		errData := appendTruncatedString(nil, src, maxLen/len(`\uffff`)) // escaping could increase size

		dst = append(dst, '{')
		dst = l.appendMetadata(dst, l.skipClientTime, true, l.procID, l.procSequence, errDetail, errData, level)
		dst = bytes.TrimRight(dst, ",")
		return append(dst, "}\n"...)
	}

	// Check whether the reserved logtail member occurs in the log data.
	// If so, it is moved to the the logtail/error member.
	const jsonSeperators = ",:"      // per RFC 8259, section 2
	const jsonWhitespace = " \n\r\t" // per RFC 8259, section 2
	var errDetail string
	var errData jsontext.Value
	if logtailValLength > 0 {
		errDetail = "duplicate logtail member"
		errData = bytes.Trim(src[logtailValOffset:][:logtailValLength], jsonSeperators+jsonWhitespace)
	}
	dst = slices.Grow(dst, len(src))
	dst = append(dst, '{')
	dst = l.appendMetadata(dst, l.skipClientTime, true, l.procID, l.procSequence, errDetail, errData, level)
	if logtailValLength > 0 {
		// Exclude original logtail member from the message.
		dst = appendWithoutNewline(dst, src[len("{"):logtailKeyOffset])
		dst = bytes.TrimRight(dst, jsonSeperators+jsonWhitespace)
		dst = appendWithoutNewline(dst, src[logtailValOffset+logtailValLength:])
	} else {
		dst = appendWithoutNewline(dst, src[len("{"):])
	}
	dst = bytes.TrimRight(dst, jsonWhitespace)
	dst = dst[:len(dst)-len("}")]
	dst = bytes.TrimRight(dst, jsonSeperators+jsonWhitespace)
	return append(dst, "}\n"...)
}

// appendWithoutNewline appends src to dst except that it ignores newlines
// since newlines are used to frame individual log entries.
func appendWithoutNewline(dst, src []byte) []byte {
	for _, c := range src {
		if c != '\n' {
			dst = append(dst, c)
		}
	}
	return dst
}

// Logf logs to l using the provided fmt-style format and optional arguments.
func (l *Logger) Logf(format string, args ...any) {
	fmt.Fprintf(l, format, args...)
}

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

	l.writeLock.Lock()
	defer l.writeLock.Unlock()

	b := l.appendTextOrJSONLocked(l.writeBuf[:0], buf, level)
	_, err := l.sendLocked(b)
	return inLen, err
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
