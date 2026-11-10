// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package controlclient

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/klauspost/compress/zstd"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/health"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/persist"
	"tailscale.com/util/eventbus/eventbustest"
)

func TestMapRequestWatchdogTimeoutMetric(t *testing.T) {
	if !buildfeatures.HasClientMetrics {
		t.Skip("client metrics disabled")
	}
	for _, tt := range []struct {
		name         string
		inBody       bool
		cancel       bool
		transportErr bool
		want         int64
	}{
		{name: "initial_request", want: 1},
		{name: "map_response", inBody: true, want: 1},
		{name: "canceled_request", cancel: true},
		{name: "canceled_response", inBody: true, cancel: true},
		{name: "transport_error", transportErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				before := metricMapRequestWatchdogTimeout.Value()
				bus := eventbustest.NewBus(t)
				dialer := tsdial.NewDialer(netmon.NewStatic())
				dialer.SetBus(bus)
				defer dialer.Close()
				transportErr := errors.New("transport failed")
				httpc := &http.Client{Transport: mapWatchdogRoundTripper(func(r *http.Request) (*http.Response, error) {
					if tt.transportErr {
						return nil, transportErr
					}
					if tt.inBody {
						return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(mapWatchdogReader{r.Context()}), Header: make(http.Header)}, nil
					}
					<-r.Context().Done()
					return nil, r.Context().Err()
				})}
				machineKey := key.NewMachine()
				c, err := NewDirect(Options{
					ServerURL:            "https://control.example",
					GetMachinePrivateKey: func() (key.MachinePrivate, error) { return machineKey, nil },
					Persist:              persist.Persist{PrivateNodeKey: key.NewNode()},
					Hostinfo:             &tailcfg.Hostinfo{BackendLogID: "test-backend-log-id"},
					NoiseTestClient:      httpc,
					HealthTracker:        health.NewTracker(bus),
					Dialer:               dialer,
					Bus:                  bus,
					Logf:                 t.Logf,
				})
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				done := make(chan error, 1)
				start := time.Now()
				go func() { done <- c.sendMapRequest(ctx, true, &countingNetmapUpdater{}) }()
				synctest.Wait()
				if tt.cancel {
					cancel()
				}
				err = <-done // advances fake time only if the watchdog is needed
				if tt.transportErr {
					if !errors.Is(err, transportErr) {
						t.Fatalf("sendMapRequest error = %v; want transport error", err)
					}
				} else if !errors.Is(err, context.Canceled) {
					t.Fatalf("sendMapRequest error = %v; want context.Canceled", err)
				}
				synctest.Wait() // let the canceled watchdog goroutine exit
				if got := metricMapRequestWatchdogTimeout.Value() - before; got != tt.want {
					t.Errorf("watchdog timeout delta = %d; want %d", got, tt.want)
				}
				wantElapsed := time.Duration(tt.want) * watchdogTimeout
				if got := time.Since(start); got != wantElapsed {
					t.Errorf("request elapsed = %v; want %v", got, wantElapsed)
				}
			})
		})
	}
}

type mapWatchdogRoundTripper func(*http.Request) (*http.Response, error)

func (f mapWatchdogRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type mapWatchdogReader struct{ ctx context.Context }

func (r mapWatchdogReader) Read([]byte) (int, error) {
	<-r.ctx.Done()
	return 0, r.ctx.Err()
}

func TestSetDiscoPublicKey(t *testing.T) {
	initialKey := key.NewDisco().Public()

	c := &Direct{
		discoPubKey: initialKey,
	}

	c.mu.Lock()
	if c.discoPubKey != initialKey {
		t.Fatalf("initial disco key mismatch: got %v, want %v", c.discoPubKey, initialKey)
	}
	c.mu.Unlock()

	newKey := key.NewDisco().Public()
	c.SetDiscoPublicKey(newKey)

	c.mu.Lock()
	if c.discoPubKey != newKey {
		t.Fatalf("disco key not updated: got %v, want %v", c.discoPubKey, newKey)
	}
	if c.discoPubKey == initialKey {
		t.Fatal("disco key should have changed")
	}
	c.mu.Unlock()
}

func TestNewDirect(t *testing.T) {
	hi := hostinfo.New()
	ni := tailcfg.NetInfo{LinkType: "wired"}
	hi.NetInfo = &ni
	bus := eventbustest.NewBus(t)

	k := key.NewMachine()
	dialer := tsdial.NewDialer(netmon.NewStatic())
	dialer.SetBus(bus)
	opts := Options{
		ServerURL: "https://example.com",
		Hostinfo:  hi,
		GetMachinePrivateKey: func() (key.MachinePrivate, error) {
			return k, nil
		},
		Dialer: dialer,
		Bus:    bus,
	}
	c, err := NewDirect(opts)
	if err != nil {
		t.Fatal(err)
	}

	if c.serverURL != opts.ServerURL {
		t.Errorf("c.serverURL got %v want %v", c.serverURL, opts.ServerURL)
	}

	// hi is stored without its NetInfo field.
	hiWithoutNi := *hi
	hiWithoutNi.NetInfo = nil
	if !hiWithoutNi.Equal(c.hostinfo) {
		t.Errorf("c.hostinfo got %v want %v", c.hostinfo, hi)
	}

	changed := c.SetNetInfo(&ni)
	if changed {
		t.Errorf("c.SetNetInfo(ni) want false got %v", changed)
	}
	ni = tailcfg.NetInfo{LinkType: "wifi"}
	changed = c.SetNetInfo(&ni)
	if !changed {
		t.Errorf("c.SetNetInfo(ni) want true got %v", changed)
	}

	changed = c.SetHostinfo(hi)
	if changed {
		t.Errorf("c.SetHostinfo(hi) want false got %v", changed)
	}
	hi = hostinfo.New()
	hi.Hostname = "different host name"
	changed = c.SetHostinfo(hi)
	if !changed {
		t.Errorf("c.SetHostinfo(hi) want true got %v", changed)
	}

	endpoints := fakeEndpoints(1, 2, 3)
	changed = c.newEndpoints(endpoints)
	if !changed {
		t.Errorf("c.newEndpoints want true got %v", changed)
	}
	changed = c.newEndpoints(endpoints)
	if changed {
		t.Errorf("c.newEndpoints want false got %v", changed)
	}
	endpoints = fakeEndpoints(4, 5, 6)
	changed = c.newEndpoints(endpoints)
	if !changed {
		t.Errorf("c.newEndpoints want true got %v", changed)
	}
}

func fakeEndpoints(ports ...uint16) (ret []tailcfg.Endpoint) {
	for _, port := range ports {
		ret = append(ret, tailcfg.Endpoint{
			Addr: netip.AddrPortFrom(netip.Addr{}, port),
		})
	}
	return
}

func TestParseRateLimitError(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		retryAfter string // Retry-After header value
		wantMsg    string
		wantMin    time.Duration // minimum expected retryAfter
		wantMax    time.Duration // maximum expected retryAfter
	}{
		{
			name:       "retry-after-seconds",
			statusCode: 429,
			body:       "too many requests",
			retryAfter: "30",
			wantMsg:    "too many requests",
			wantMin:    30 * time.Second,
			wantMax:    30 * time.Second,
		},
		{
			name:       "no-retry-after-header",
			statusCode: 429,
			body:       "slow down",
			retryAfter: "",
			wantMsg:    "slow down",
			wantMin:    5 * time.Second,
			wantMax:    10 * time.Second,
		},
		{
			name:       "unparseable-retry-after",
			statusCode: 429,
			body:       "rate limited",
			retryAfter: "not-a-number",
			wantMsg:    "rate limited",
			wantMin:    5 * time.Second,
			wantMax:    10 * time.Second,
		},
		{
			name:       "empty-body",
			statusCode: 429,
			body:       "",
			retryAfter: "5",
			wantMsg:    "",
			wantMin:    5 * time.Second,
			wantMax:    5 * time.Second,
		},
		{
			name:       "body-with-whitespace",
			statusCode: 429,
			body:       "  too many requests  \n",
			retryAfter: "10",
			wantMsg:    "too many requests",
			wantMin:    10 * time.Second,
			wantMax:    10 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			if tt.retryAfter != "" {
				rec.Header().Set("Retry-After", tt.retryAfter)
			}
			rec.WriteHeader(tt.statusCode)
			rec.Body.WriteString(tt.body)
			res := rec.Result()

			err := parseRateLimitError(res)
			if err == nil {
				t.Fatal("expected non-nil error")
			}

			var rle *rateLimitError
			if !errors.As(err, &rle) {
				t.Fatalf("error is not a *rateLimitError: %T", err)
			}
			if rle.msg != tt.wantMsg {
				t.Errorf("msg = %q, want %q", rle.msg, tt.wantMsg)
			}
			if rle.retryAfter < tt.wantMin || rle.retryAfter > tt.wantMax {
				t.Errorf("retryAfter = %v, want between %v and %v", rle.retryAfter, tt.wantMin, tt.wantMax)
			}

			// Verify the Error() string contains useful information.
			errStr := err.Error()
			if !strings.Contains(errStr, "rate limited") {
				t.Errorf("Error() = %q, want it to contain 'rate limited'", errStr)
			}
		})
	}
}

func TestIsRateLimitedResponse(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		retryAfter string
		want       bool
	}{
		{name: "429-no-header", statusCode: 429, want: true},
		{name: "429-with-header", statusCode: 429, retryAfter: "30", want: true},
		{name: "503-with-header", statusCode: 503, retryAfter: "30", want: true},
		{name: "503-no-header", statusCode: 503, want: false},
		{name: "500-with-header", statusCode: 500, retryAfter: "30", want: false},
		{name: "200", statusCode: 200, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			if tt.retryAfter != "" {
				rec.Header().Set("Retry-After", tt.retryAfter)
			}
			rec.WriteHeader(tt.statusCode)

			if got := isRateLimitedResponse(rec.Result()); got != tt.want {
				t.Errorf("shouldHonorRetryAfter; got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRateLimitErrorIsError(t *testing.T) {
	err := &rateLimitError{msg: "test", retryAfter: 5 * time.Second}
	var target *rateLimitError
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match *rateLimitError")
	}
	if target.retryAfter != 5*time.Second {
		t.Errorf("retryAfter = %v, want 5s", target.retryAfter)
	}
}

func TestTsmpPing(t *testing.T) {
	hi := hostinfo.New()
	ni := tailcfg.NetInfo{LinkType: "wired"}
	hi.NetInfo = &ni
	bus := eventbustest.NewBus(t)

	k := key.NewMachine()
	dialer := tsdial.NewDialer(netmon.NewStatic())
	dialer.SetBus(bus)
	opts := Options{
		ServerURL: "https://example.com",
		Hostinfo:  hi,
		GetMachinePrivateKey: func() (key.MachinePrivate, error) {
			return k, nil
		},
		Dialer: dialer,
		Bus:    bus,
	}

	c, err := NewDirect(opts)
	if err != nil {
		t.Fatal(err)
	}

	pingRes := &tailcfg.PingResponse{
		Type:     "TSMP",
		IP:       "123.456.7890",
		Err:      "",
		NodeName: "testnode",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		body := new(ipnstate.PingResult)
		if err := json.NewDecoder(r.Body).Decode(body); err != nil {
			t.Fatal(err)
		}
		if pingRes.IP != body.IP {
			t.Fatalf("PingResult did not have the correct IP : got %v, expected : %v", body.IP, pingRes.IP)
		}
		w.WriteHeader(200)
	}))
	defer ts.Close()

	now := time.Now()

	pr := &tailcfg.PingRequest{
		URL: ts.URL,
	}

	err = postPingResult(now, t.Logf, c.httpc, pr, pingRes)
	if err != nil {
		t.Fatal(err)
	}
}

func TestReadMapResponseMessage(t *testing.T) {
	// Normal messages round-trip.
	var buf bytes.Buffer
	var siz [4]byte
	binary.LittleEndian.PutUint32(siz[:], 4)
	buf.Write(siz[:])
	buf.WriteString("body")
	msg, err := readMapResponseMessage(&buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(msg) != "body" {
		t.Fatalf("got message %q, want %q", msg, "body")
	}

	// The size prefix is a uint32 chosen by the control server. A
	// malicious server must not be able to make us allocate up to 4 GiB
	// before any body bytes are read.
	buf.Reset()
	binary.LittleEndian.PutUint32(siz[:], math.MaxUint32)
	buf.Write(siz[:])
	if _, err := readMapResponseMessage(&buf, msg); err == nil || !strings.Contains(err.Error(), "exceeds max") {
		t.Fatalf("readMapResponseMessage = %v, want size cap error", err)
	}
}

func TestDecodeMsgMaxDecodedSize(t *testing.T) {
	// A zstd frame whose header declares more decoded content than
	// maxDecodedMapResponseSize. The decoder rejects such a frame before
	// decoding any block, so a malicious control server can't make us
	// expand a small frame into an unbounded amount of JSON, and the test
	// doesn't need to allocate the decoded bytes either.
	oversized := []byte{
		0x28, 0xb5, 0x2f, 0xfd, // zstd frame magic
		0xc0,                                           // 8-byte frame content size, no single segment, no checksum, no dict ID
		0x00,                                           // window descriptor: 1 KiB window
		0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, // declared content size: 16 GiB + 1
		0x21, 0x00, 0x00, // block header: last block, raw block, 4 bytes
		'b', 'o', 'm', 'b',
	}
	ms := newMapSession(key.NewNode(), nil, nil)
	var resp tailcfg.MapResponse
	err := ms.decodeMsg(oversized, &resp)
	if !errors.Is(err, zstd.ErrDecoderSizeExceeded) {
		t.Fatalf("decodeMsg(oversized frame) = %v, want zstd.ErrDecoderSizeExceeded", err)
	}
}
