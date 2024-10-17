// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package sessionrecording contains session recording utils shared amongst
// Tailscale SSH and Kubernetes API server proxy session recording.
package sessionrecording

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/util/multierr"
)

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
func ConnectToRecorder(ctx context.Context, recs []netip.AddrPort, dial func(context.Context, string, string) (net.Conn, error)) (io.WriteCloser, []*tailcfg.SSHRecordingAttempt, <-chan error, error) {
	if len(recs) == 0 {
		return nil, nil, nil, errors.New("no recorders configured")
	}
	// We use a special context for dialing the recorder, so that we can
	// limit the time we spend dialing to 30 seconds and still have an
	// unbounded context for the upload.
	dialCtx, dialCancel := context.WithTimeout(ctx, 30*time.Second)
	defer dialCancel()
	hc, err := SessionRecordingClientForDialer(dialCtx, dial)
	if err != nil {
		return nil, nil, nil, err
	}

	var errs []error
	var attempts []*tailcfg.SSHRecordingAttempt
	for _, ap := range recs {
		attempt := &tailcfg.SSHRecordingAttempt{
			Recorder: ap,
		}
		attempts = append(attempts, attempt)

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
		req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("http://%s:%d/record", ap.Addr(), ap.Port()), pr)
		if err != nil {
			err = fmt.Errorf("recording: error starting recording: %w", err)
			attempt.FailureMessage = err.Error()
			errs = append(errs, err)
			continue
		}
		// We set the Expect header to 100-continue, so that the recorder
		// will send a 100-continue response before it starts reading the
		// request body.
		req.Header.Set("Expect", "100-continue")

		// errChan is used to indicate the result of the request.
		errChan := make(chan error, 1)
		go func() {
			resp, err := hc.Do(req)
			if err != nil {
				errChan <- fmt.Errorf("recording: error starting recording: %w", err)
				return
			}
			if resp.StatusCode != 200 {
				errChan <- fmt.Errorf("recording: unexpected status: %v", resp.Status)
				return
			}
			errChan <- nil
		}()
		select {
		case <-got100:
		case err := <-errChan:
			// If we get an error before we get the 100-continue response,
			// we need to try another recorder.
			if err == nil {
				// If the error is nil, we got a 200 response, which
				// is unexpected as we haven't sent any data yet.
				err = errors.New("recording: unexpected EOF")
			}
			attempt.FailureMessage = err.Error()
			errs = append(errs, err)
			continue // try the next recorder
		}
		return pw, attempts, errChan, nil
	}
	return nil, attempts, nil, multierr.New(errs...)
}

// SessionRecordingClientForDialer returns an http.Client that uses a clone of
// the provided Dialer's PeerTransport to dial connections. This is used to make
// requests to the session recording server to upload session recordings. It
// uses the provided dialCtx to dial connections, and limits a single dial to 5
// seconds.
func SessionRecordingClientForDialer(dialCtx context.Context, dial func(context.Context, string, string) (net.Conn, error)) (*http.Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()

	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		perAttemptCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
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
	return &http.Client{
		Transport: tr,
	}, nil
}
