// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package sessionrecording contains session recording utils shared amongst
// Tailscale SSH and Kubernetes API server proxy session recording.
package sessionrecording

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
	"tailscale.com/tailcfg"
	"tailscale.com/util/httpm"
	"tailscale.com/util/multierr"
)

const (
	// Timeout for an individual DialFunc call for a single recorder address.
	perDialAttemptTimeout = 5 * time.Second
	// Timeout for the V2 API HEAD probe request (supportsV2).
	http2ProbeTimeout = 10 * time.Second
	// Maximum timeout for trying all available recorders, including V2 API
	// probes and dial attempts.
	allDialAttemptsTimeout = 30 * time.Second
)

// uploadAckWindow is the period of time to wait for an ackFrame from recorder
// before terminating the connection. This is a variable to allow overriding it
// in tests.
var uploadAckWindow = 30 * time.Second

// DialFunc is a function for dialing the recorder.
type DialFunc func(ctx context.Context, network, host string) (net.Conn, error)

// ConnectToRecorder connects to the recorder at any of the provided addresses.
// It returns the first successful response, or a multierr if all attempts fail.
//
// On success, it returns a WriteCloser that can be used to upload the
// recording, and a channel that will be sent an error (or nil) when the upload
// fails or completes.
//
// In both cases, a slice of SSHRecordingAttempts is returned which detail the
// attempted recorder IP and the error message, if the attempt failed. The
// attempts are in order the recorder(s) was attempted. If successful a
// successful connection is made, the last attempt in the slice is the
// attempt for connected recorder.
func ConnectToRecorder(ctx context.Context, recs []netip.AddrPort, dial DialFunc) (io.WriteCloser, []*tailcfg.SSHRecordingAttempt, <-chan error, error) {
	if len(recs) == 0 {
		return nil, nil, nil, errors.New("no recorders configured")
	}
	// We use a special context for dialing the recorder, so that we can
	// limit the time we spend dialing to 30 seconds and still have an
	// unbounded context for the upload.
	dialCtx, dialCancel := context.WithTimeout(ctx, allDialAttemptsTimeout)
	defer dialCancel()

	var errs []error
	var attempts []*tailcfg.SSHRecordingAttempt
	for _, ap := range recs {
		attempt := &tailcfg.SSHRecordingAttempt{
			Recorder: ap,
		}
		attempts = append(attempts, attempt)

		var pw io.WriteCloser
		var errChan <-chan error
		var err error
		hc := clientHTTP2(dialCtx, dial)
		// We need to probe V2 support using a separate HEAD request. Sending
		// an HTTP/2 POST request to a HTTP/1 server will just "hang" until the
		// request body is closed (instead of returning a 404 as one would
		// expect). Sending a HEAD request without a body does not have that
		// problem.
		if supportsV2(ctx, hc, ap) {
			pw, errChan, err = connectV2(ctx, hc, ap)
		} else {
			pw, errChan, err = connectV1(ctx, clientHTTP1(dialCtx, dial), ap)
		}
		if err != nil {
			err = fmt.Errorf("recording: error starting recording on %q: %w", ap, err)
			attempt.FailureMessage = err.Error()
			errs = append(errs, err)
			continue
		}
		return pw, attempts, errChan, nil
	}
	return nil, attempts, nil, multierr.New(errs...)
}

// supportsV2 checks whether a recorder instance supports the /v2/record
// endpoint.
func supportsV2(ctx context.Context, hc *http.Client, ap netip.AddrPort) bool {
	ctx, cancel := context.WithTimeout(ctx, http2ProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, httpm.HEAD, fmt.Sprintf("http://%s/v2/record", ap), nil)
	if err != nil {
		return false
	}
	resp, err := hc.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK && resp.ProtoMajor > 1
}

// connectV1 connects to the legacy /record endpoint on the recorder. It is
// used for backwards-compatibility with older tsrecorder instances.
//
// On success, it returns a WriteCloser that can be used to upload the
// recording, and a channel that will be sent an error (or nil) when the upload
// fails or completes.
func connectV1(ctx context.Context, hc *http.Client, ap netip.AddrPort) (io.WriteCloser, <-chan error, error) {
	// We dial the recorder and wait for it to send a 100-continue
	// response before returning from this function. This ensures that
	// the recorder is ready to accept the recording.

	// got100 is closed when we receive the 100-continue response.
	got100 := make(chan struct{})
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		Got100Continue: func() {
			close(got100)
		},
	})

	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("http://%s/record", ap), pr)
	if err != nil {
		return nil, nil, err
	}
	// We set the Expect header to 100-continue, so that the recorder
	// will send a 100-continue response before it starts reading the
	// request body.
	req.Header.Set("Expect", "100-continue")

	// errChan is used to indicate the result of the request.
	errChan := make(chan error, 1)
	go func() {
		defer close(errChan)
		resp, err := hc.Do(req)
		if err != nil {
			errChan <- err
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			errChan <- fmt.Errorf("recording: unexpected status: %v", resp.Status)
			return
		}
	}()
	select {
	case <-got100:
		return pw, errChan, nil
	case err := <-errChan:
		// If we get an error before we get the 100-continue response,
		// we need to try another recorder.
		if err == nil {
			// If the error is nil, we got a 200 response, which
			// is unexpected as we haven't sent any data yet.
			err = errors.New("recording: unexpected EOF")
		}
		return nil, nil, err
	}
}

// connectV2 connects to the /v2/record endpoint on the recorder over HTTP/2.
// It explicitly tracks ack frames sent in the response and terminates the
// connection if sent recording data is un-acked for uploadAckWindow.
//
// On success, it returns a WriteCloser that can be used to upload the
// recording, and a channel that will be sent an error (or nil) when the upload
// fails or completes.
func connectV2(ctx context.Context, hc *http.Client, ap netip.AddrPort) (io.WriteCloser, <-chan error, error) {
	pr, pw := io.Pipe()
	upload := &readCounter{r: pr}
	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("http://%s/v2/record", ap), upload)
	if err != nil {
		return nil, nil, err
	}

	// With HTTP/2, hc.Do will not block while the request body is being sent.
	// It will return immediately and allow us to consume the response body at
	// the same time.
	resp, err := hc.Do(req)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, nil, fmt.Errorf("recording: unexpected status: %v", resp.Status)
	}

	errChan := make(chan error, 1)
	acks := make(chan int64)
	// Read acks from the response and send them to the acks channel.
	go func() {
		defer close(errChan)
		defer close(acks)
		defer resp.Body.Close()
		defer pw.Close()
		dec := json.NewDecoder(resp.Body)
		for {
			var frame v2ResponseFrame
			if err := dec.Decode(&frame); err != nil {
				if !errors.Is(err, io.EOF) {
					errChan <- fmt.Errorf("recording: unexpected error receiving acks: %w", err)
				}
				return
			}
			if frame.Error != "" {
				errChan <- fmt.Errorf("recording: received error from the recorder: %q", frame.Error)
				return
			}
			select {
			case acks <- frame.Ack:
			case <-ctx.Done():
				return
			}
		}
	}()
	// Track acks from the acks channel.
	go func() {
		// Hack for tests: some tests modify uploadAckWindow and reset it when
		// the test ends. This can race with t.Reset call below. Making a copy
		// here is a lazy workaround to not wait for this goroutine to exit in
		// the test cases.
		uploadAckWindow := uploadAckWindow
		// This timer fires if we didn't receive an ack for too long.
		t := time.NewTimer(uploadAckWindow)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				// Close the pipe which terminates the connection and cleans up
				// other goroutines. Note that tsrecorder will send us ack
				// frames even if there is no new data to ack. This helps
				// detect broken recorder connection if the session is idle.
				pr.CloseWithError(errNoAcks)
				resp.Body.Close()
				return
			case _, ok := <-acks:
				if !ok {
					// acks channel closed means that the goroutine reading them
					// finished, which means that the request has ended.
					return
				}
				// TODO(awly): limit how far behind the received acks can be. This
				// should handle scenarios where a session suddenly dumps a lot of
				// output.
				t.Reset(uploadAckWindow)
			case <-ctx.Done():
				return
			}
		}
	}()

	return pw, errChan, nil
}

var errNoAcks = errors.New("did not receive ack frames from the recorder in 30s")

type v2ResponseFrame struct {
	// Ack is the number of bytes received from the client so far. The bytes
	// are not guaranteed to be durably stored yet.
	Ack int64 `json:"ack,omitempty"`
	// Error is an error encountered while storing the recording. Error is only
	// ever set as the last frame in the response.
	Error string `json:"error,omitempty"`
}

// readCounter is an io.Reader that counts how many bytes were read.
type readCounter struct {
	r    io.Reader
	sent atomic.Int64
}

func (u *readCounter) Read(buf []byte) (int, error) {
	n, err := u.r.Read(buf)
	u.sent.Add(int64(n))
	return n, err
}

// clientHTTP1 returns a claassic http.Client with a per-dial context. It uses
// dialCtx and adds a 5s timeout to it.
func clientHTTP1(dialCtx context.Context, dial DialFunc) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		perAttemptCtx, cancel := context.WithTimeout(ctx, perDialAttemptTimeout)
		defer cancel()
		go func() {
			select {
			case <-perAttemptCtx.Done():
			case <-dialCtx.Done():
				cancel()
			}
		}()
		return dial(perAttemptCtx, network, addr)
	}
	return &http.Client{Transport: tr}
}

// clientHTTP2 is like clientHTTP1 but returns an http.Client suitable for h2c
// requests (HTTP/2 over plaintext). Unfortunately the same client does not
// work for HTTP/1 so we need to split these up.
func clientHTTP2(dialCtx context.Context, dial DialFunc) *http.Client {
	return &http.Client{
		Transport: &http2.Transport{
			// Allow "http://" scheme in URLs.
			AllowHTTP: true,
			// Pretend like we're using TLS, but actually use the provided
			// DialFunc underneath. This is necessary to convince the transport
			// to actually dial.
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				perAttemptCtx, cancel := context.WithTimeout(ctx, perDialAttemptTimeout)
				defer cancel()
				go func() {
					select {
					case <-perAttemptCtx.Done():
					case <-dialCtx.Done():
						cancel()
					}
				}()
				return dial(perAttemptCtx, network, addr)
			},
		},
	}
}
