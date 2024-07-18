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
	"tailscale.com/tstime"
)

// recorder knows how to send the provided bytes to the configured tsrecorder
// instance in asciinema format.
type recorder struct {
	start time.Time
	clock tstime.Clock

	// failOpen specifies whether the session should be allowed to
	// continue if writing to the recording fails.
	failOpen bool

	// backOff is set to true if  we've failed open and should stop
	// attempting to write to tsrecorder.
	backOff bool

	mu   sync.Mutex     // guards writes to conn
	conn io.WriteCloser // connection to a tsrecorder instance
}

// Write appends timestamp to the provided bytes and sends them to the
// configured tsrecorder.
func (rec *recorder) Write(p []byte) (err error) {
	if len(p) == 0 {
		return nil
	}
	if rec.backOff {
		return nil
	}
	j, err := json.Marshal([]any{
		rec.clock.Now().Sub(rec.start).Seconds(),
		"o",
		string(p),
	})
	if err != nil {
		return fmt.Errorf("error marhalling payload: %w", err)
	}
	j = append(j, '\n')
	if err := rec.writeCastLine(j); err != nil {
		if !rec.failOpen {
			return fmt.Errorf("error writing payload to recorder: %w", err)
		}
		rec.backOff = true
	}
	return nil
}

func (rec *recorder) Close() error {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.conn == nil {
		return nil
	}
	err := rec.conn.Close()
	rec.conn = nil
	return err
}

// writeCastLine sends bytes to the tsrecorder. The bytes should be in
// asciinema format.
func (rec *recorder) writeCastLine(j []byte) error {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.conn == nil {
		return errors.New("recorder closed")
	}
	_, err := rec.conn.Write(j)
	if err != nil {
		return fmt.Errorf("recorder write error: %w", err)
	}
	return nil
}
