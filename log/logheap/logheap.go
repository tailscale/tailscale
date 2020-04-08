// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package logheap logs a heap pprof profile.
package logheap

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"runtime"
	"runtime/pprof"
	"time"
)

// LogHeap writes a JSON logtail record with the base64 heap pprof to
// os.Stderr.
func LogHeap() {
	logHeap(os.Stderr)
}

type logTail struct {
	ClientTime string `json:"client_time"`
}

type pprofRec struct {
	Heap []byte `json:"heap,omitempty"`
}

type logLine struct {
	LogTail logTail  `json:"logtail"`
	Pprof   pprofRec `json:"pprof"`
}

func logHeap(w io.Writer) error {
	runtime.GC()
	buf := new(bytes.Buffer)
	pprof.WriteHeapProfile(buf)
	return json.NewEncoder(w).Encode(logLine{
		LogTail: logTail{ClientTime: time.Now().Format(time.RFC3339Nano)},
		Pprof:   pprofRec{Heap: buf.Bytes()},
	})
}
