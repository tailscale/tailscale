// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package c2n registers support for C2N (Control-to-Node) communications.
package c2n

import (
	"bufio"
	"bytes"
	"context"
	"net/http"
	"time"

	"tailscale.com/control/controlclient"
	"tailscale.com/tailcfg"
	"tailscale.com/tempfork/httprec"
	"tailscale.com/types/logger"
)

func init() {
	controlclient.HookAnswerC2NPing.Set(answerC2NPing)
}

func answerC2NPing(logf logger.Logf, c2nHandler http.Handler, c *http.Client, pr *tailcfg.PingRequest) {
	if c2nHandler == nil {
		logf("answerC2NPing: c2nHandler not defined")
		return
	}
	hreq, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(pr.Payload)))
	if err != nil {
		logf("answerC2NPing: ReadRequest: %v", err)
		return
	}
	if pr.Log {
		logf("answerC2NPing: got c2n request for %v ...", hreq.RequestURI)
	}
	handlerTimeout := time.Minute
	if v := hreq.Header.Get("C2n-Handler-Timeout"); v != "" {
		handlerTimeout, _ = time.ParseDuration(v)
	}
	handlerCtx, cancel := context.WithTimeout(context.Background(), handlerTimeout)
	defer cancel()
	hreq = hreq.WithContext(handlerCtx)
	rec := httprec.NewRecorder()
	c2nHandler.ServeHTTP(rec, hreq)
	cancel()

	c2nResBuf := new(bytes.Buffer)
	rec.Result().Write(c2nResBuf)

	replyCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(replyCtx, "POST", pr.URL, c2nResBuf)
	if err != nil {
		logf("answerC2NPing: NewRequestWithContext: %v", err)
		return
	}
	if pr.Log {
		logf("answerC2NPing: sending POST ping to %v ...", pr.URL)
	}
	t0 := time.Now()
	_, err = c.Do(req)
	d := time.Since(t0).Round(time.Millisecond)
	if err != nil {
		logf("answerC2NPing error: %v to %v (after %v)", err, pr.URL, d)
	} else if pr.Log {
		logf("answerC2NPing complete to %v (after %v)", pr.URL, d)
	}
}
