// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	kzap "sigs.k8s.io/controller-runtime/pkg/log/zap"
	"tailscale.com/types/logger"
)

type (
	logfSink struct {
		logf logger.Logf
	}
)

// wrapZapCore returns a zapcore.Core implementation that splits the core chain using zapcore.NewTee. This causes
// logs to be simultaneously written to both the original core and the provided logger.Logf function.
func wrapZapCore(core zapcore.Core, logf logger.Logf) zapcore.Core {
	// We use a tee logger here so that logs are written to stdout/stderr normally while at the same time being
	// sent upstream.
	return zapcore.NewTee(core, zapcore.NewCore(&kzap.KubeAwareEncoder{
		Encoder: zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		Verbose: true,
	}, &logfSink{logf: logf}, zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
		return true
	})))
}

func (l *logfSink) Write(p []byte) (n int, err error) {
	l.logf("k8s: %s", p)
	return len(p), nil
}

func (l *logfSink) Sync() error {
	return nil
}
