// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"tailscale.com/tstime"
)

// loggingWriter knows how to send the provided bytes to the configured session
// recorder in asciinema format.
type loggingWriter struct {
	start time.Time
	clock tstime.Clock

	// failOpen specifies whether the session should be allowed to
	// continue if writing to the recording fails.
	failOpen bool

	// recordingFailedOpen specifies whether we've failed to write to
	// r.out and should stop trying. It is set to true if we fail to write
	// to r.out and r.failOpen is set.
	recordingFailedOpen bool
	log                 *zap.SugaredLogger

	mu              sync.Mutex // guards writes to sessionRecorder
	sessionRecorder io.WriteCloser
}

// Write appends timestamp to the provided bytes and sends them to the
// configured session recorder.
func (w *loggingWriter) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	if w.recordingFailedOpen {
		return 0, nil
	}
	j, err := json.Marshal([]any{
		w.clock.Now().Sub(w.start).Seconds(),
		"o",
		string(p),
	})
	if err != nil {
		return 0, fmt.Errorf("error marhalling payload: %w", err)
	}
	j = append(j, '\n')
	if err := w.writeCastLine(j); err != nil {
		if !w.failOpen {
			return 0, fmt.Errorf("error writing payload to recorder: %w", err)
		}
		w.recordingFailedOpen = true
	}
	return len(p), nil
}

func (w *loggingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.sessionRecorder == nil {
		return nil
	}
	err := w.sessionRecorder.Close()
	w.sessionRecorder = nil
	return err
}

// writeCastLine sends bytes to the session recorder. The bytes should be in
// asciinema format.
func (w *loggingWriter) writeCastLine(j []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.sessionRecorder == nil {
		return errors.New("logger closed")
	}
	_, err := w.sessionRecorder.Write(j)
	if err != nil {
		return fmt.Errorf("logger write error: %w", err)
	}
	return nil
}
