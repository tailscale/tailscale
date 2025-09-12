// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"io"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	kzap "sigs.k8s.io/controller-runtime/pkg/log/zap"
)

// wrapZapCore returns a zapcore.Core implementation that splits the core chain using zapcore.NewTee. This causes
// logs to be simultaneously written to both the original core and the provided io.Writer implementation.
func wrapZapCore(core zapcore.Core, writer io.Writer) zapcore.Core {
	encoder := &kzap.KubeAwareEncoder{
		Encoder: zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
	}

	// We use a tee logger here so that logs are written to stdout/stderr normally while at the same time being
	// sent upstream.
	return zapcore.NewTee(core, zapcore.NewCore(encoder, zapcore.AddSync(writer), zap.DebugLevel))
}
