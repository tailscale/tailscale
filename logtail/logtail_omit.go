// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_logtail

package logtail

import (
	"context"

	tslogger "tailscale.com/types/logger"
	"tailscale.com/types/logid"
)

// Noop implementations of everything when ts_omit_logtail is set.

type Logger struct{}

type Buffer any

func Disable() {}

func NewLogger(cfg Config, logf tslogger.Logf) *Logger {
	return &Logger{}
}

func (*Logger) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func (*Logger) Logf(format string, args ...any)    {}
func (*Logger) Shutdown(ctx context.Context) error { return nil }
func (*Logger) SetVerbosityLevel(level int)        {}

func (l *Logger) SetSockstatsLabel(label any) {}

func (l *Logger) PrivateID() logid.PrivateID { return logid.PrivateID{} }
func (l *Logger) StartFlush()                {}

func RegisterLogTap(dst chan<- string) (unregister func()) {
	return func() {}
}

func (*Logger) SetNetMon(any) {}
