// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

// Package syslog provides the tailscaled --syslog flag, which sends the
// daemon's logs to the system syslog daemon instead of stderr.
package syslog

import (
	"flag"
	"io"
	"log"
	"log/syslog"
	"sync"

	"tailscale.com/feature"
)

func init() {
	feature.Register("syslog")
	feature.HookRegisterLogSinkFlags.Set(registerFlags)
	feature.HookLogSink.Set(logSink)
}

var useSyslog bool

func registerFlags() {
	flag.BoolVar(&useSyslog, "syslog", false, "log to the system syslog daemon instead of stderr")
}

// logSink returns the writer to which logs should be sent, pointing the
// standard library's default logger at it on first call. It returns nil if
// syslog logging was not requested or the syslog daemon is unreachable.
var logSink = sync.OnceValue(func() io.Writer {
	if !useSyslog {
		return nil
	}
	w, err := syslog.New(syslog.LOG_DAEMON|syslog.LOG_INFO, "tailscaled")
	if err != nil {
		log.Printf("syslog: connecting to syslog daemon failed; continuing to log to stderr: %v", err)
		return nil
	}
	log.SetFlags(0) // syslog records its own timestamps
	log.SetOutput(w)
	return w
})
