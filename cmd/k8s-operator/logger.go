// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"encoding/json"
	"math"
	"time"

	"go.uber.org/zap/zapcore"
	"tailscale.com/types/logger"
)

type (
	// The logfCore type is a zapcore.Core implementation that writes structured logs to a provided logger.Logf
	// implementation.
	logfCore struct {
		logf   logger.Logf
		fields []zapcore.Field
	}
)

// wrapZapCore returns a zapcore.Core implementation that splits the core chain using zapcore.NewTee. This causes
// logs to be simultaneously written to both the original core and the provided logger.Logf function.
func wrapZapCore(core zapcore.Core, logf logger.Logf) zapcore.Core {
	// We use a tee logger here so that logs are written to stdout/stderr normally while at the same time being
	// sent upstream.
	return zapcore.NewTee(core, &logfCore{
		logf: logf,
	})
}

// Enabled always returns true, as we want to forward logs of all levels to the logger.Logf function.
func (l *logfCore) Enabled(_ zapcore.Level) bool {
	return true
}

// With adds additional fields to the core, allowing them to be kept across log invocations.
func (l *logfCore) With(fields []zapcore.Field) zapcore.Core {
	return &logfCore{
		logf:   l.logf,
		fields: append(l.fields, fields...),
	}
}

// Check always add the core to the entry, so that we log every entry.
func (l *logfCore) Check(entry zapcore.Entry, checked *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	checked.AddCore(entry, l)
	return checked
}

// Write the provided entry and fields to the logger.Logf function. This method JSON-encodes the entry and fields.
func (l *logfCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	body := map[string]any{
		"level":         entry.Level.String(),
		"msg":           entry.Message,
		"time":          entry.Time,
		"@k8s-operator": true,
	}

	// Zap stores fields as zapcore.Field. This struct has a key but stores the value in one or more of 3 fields
	// depending on the type of the value. In most cases, it's as simple as grabbing the .String or .Integer field.
	// However, for some complex types we need to perform some math or use multiple fields to glean the full
	// value.
	//
	// This was mostly taken from the field.AddTo method, with modifications made where many of the same types are
	// handled as interfaces/integers.
	for _, field := range append(l.fields, fields...) {
		switch field.Type {
		case zapcore.BoolType:
			body[field.Key] = field.Integer == 1
		case zapcore.DurationType:
			body[field.Key] = time.Duration(field.Integer)
		case zapcore.Float64Type:
			body[field.Key] = math.Float64frombits(uint64(field.Integer))
		case zapcore.Float32Type:
			body[field.Key] = math.Float32frombits(uint32(field.Integer))
		case zapcore.Int64Type, zapcore.Int32Type, zapcore.Int16Type, zapcore.Int8Type, zapcore.Uint64Type,
			zapcore.Uint32Type, zapcore.Uint16Type, zapcore.Uint8Type, zapcore.UintptrType:
			// We have a lot of integer types to distinguish between and all of them are just stored
			// as an integer.
			body[field.Key] = field.Integer
		case zapcore.StringType:
			body[field.Key] = field.String
		case zapcore.TimeType:
			if field.Interface != nil {
				body[field.Key] = time.Unix(0, field.Integer).In(field.Interface.(*time.Location))
			} else {
				// Fall back to UTC if location is nil.
				body[field.Key] = time.Unix(0, field.Integer)
			}
		case zapcore.SkipType:
			continue
		default:
			// For most types, we can just safely use the given interface.
			body[field.Key] = field.Interface
		}
	}

	data, err := json.Marshal(body)
	if err != nil {
		return err
	}

	l.logf("%s", data)
	return nil
}

func (l *logfCore) Sync() error {
	return nil
}
