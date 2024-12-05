// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package filelogger provides localdisk log writing & rotation, primarily for Windows
// clients. (We get this for free on other platforms.)
package filelogger

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"tailscale.com/types/logger"
)

const (
	maxSize  = 100 << 20
	maxFiles = 50
)

// New returns a logf wrapper that appends to local disk log
// files on Windows, rotating old log files as needed to stay under
// file count & byte limits.
func New(fileBasePrefix, logID string, logf logger.Logf) logger.Logf {
	if runtime.GOOS != "windows" {
		panic("not yet supported on any platform except Windows")
	}
	if logf == nil {
		panic("nil logf")
	}
	dir := filepath.Join(os.Getenv("ProgramData"), "Tailscale", "Logs")

	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Printf("failed to create local log directory; not writing logs to disk: %v", err)
		return logf
	}
	logf("local disk logdir: %v", dir)
	lfw := &logFileWriter{
		fileBasePrefix: fileBasePrefix,
		logID:          logID,
		dir:            dir,
		wrappedLogf:    logf,
	}
	return lfw.Logf
}

// logFileWriter is the state for the log writer & rotator.
type logFileWriter struct {
	dir            string      // e.g. `C:\Users\FooBarUser\AppData\Local\Tailscale\Logs`
	logID          string      // hex logID
	fileBasePrefix string      // e.g. "tailscale-service" or "tailscale-gui"
	wrappedLogf    logger.Logf // underlying logger to send to

	mu   sync.Mutex   // guards following
	buf  bytes.Buffer // scratch buffer to avoid allocs
	fday civilDay     // day that f was opened; zero means no file yet open
	f    *os.File     // file currently opened for append
}

// civilDay is a year, month, and day in the local timezone.
// It's a comparable value type.
type civilDay struct {
	year  int
	month time.Month
	day   int
}

func dayOf(t time.Time) civilDay {
	return civilDay{t.Year(), t.Month(), t.Day()}
}

func (w *logFileWriter) Logf(format string, a ...any) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.buf.Reset()
	fmt.Fprintf(&w.buf, format, a...)
	if w.buf.Len() == 0 {
		return
	}
	out := w.buf.Bytes()
	w.wrappedLogf("%s", out)

	// Make sure there's a final newline before we write to the log file.
	if out[len(out)-1] != '\n' {
		w.buf.WriteByte('\n')
		out = w.buf.Bytes()
	}

	w.appendToFileLocked(out)
}

// out should end in a newline.
// w.mu must be held.
func (w *logFileWriter) appendToFileLocked(out []byte) {
	now := time.Now()
	day := dayOf(now)
	if w.fday != day {
		w.startNewFileLocked()
	}
	out = removeDatePrefix(out)
	if w.f != nil {
		// RFC3339Nano but with a fixed number (3) of nanosecond digits:
		const formatPre = "2006-01-02T15:04:05"
		const formatPost = "Z07:00"
		fmt.Fprintf(w.f, "%s.%03d%s: %s",
			now.Format(formatPre),
			now.Nanosecond()/int(time.Millisecond/time.Nanosecond),
			now.Format(formatPost),
			out)
	}
}

func isNum(b byte) bool { return '0' <= b && b <= '9' }

// removeDatePrefix returns a subslice of v with the log package's
// standard datetime prefix format removed, if present.
func removeDatePrefix(v []byte) []byte {
	const format = "2009/01/23 01:23:23 "
	if len(v) < len(format) {
		return v
	}
	for i, b := range v[:len(format)] {
		fb := format[i]
		if isNum(fb) {
			if !isNum(b) {
				return v
			}
			continue
		}
		if b != fb {
			return v
		}
	}
	return v[len(format):]
}

// startNewFileLocked opens a new log file for writing
// and also cleans up any old files.
//
// w.mu must be held.
func (w *logFileWriter) startNewFileLocked() {
	var oldName string
	if w.f != nil {
		oldName = filepath.Base(w.f.Name())
		w.f.Close()
		w.f = nil
		w.fday = civilDay{}
	}
	w.cleanLocked()

	now := time.Now()
	day := dayOf(now)
	name := filepath.Join(w.dir, fmt.Sprintf("%s-%04d%02d%02dT%02d%02d%02d-%d.txt",
		w.fileBasePrefix,
		day.year,
		day.month,
		day.day,
		now.Hour(),
		now.Minute(),
		now.Second(),
		now.Unix()))
	var err error
	w.f, err = os.Create(name)
	if err != nil {
		w.wrappedLogf("failed to create log file: %v", err)
		return
	}
	if oldName != "" {
		fmt.Fprintf(w.f, "(logID %q; continued from log file %s)\n", w.logID, oldName)
	} else {
		fmt.Fprintf(w.f, "(logID %q)\n", w.logID)
	}
	w.fday = day
}

// cleanLocked cleans up old log files.
//
// w.mu must be held.
func (w *logFileWriter) cleanLocked() {
	entries, _ := os.ReadDir(w.dir)
	prefix := w.fileBasePrefix + "-"
	fileSize := map[string]int64{}
	var files []string
	var sumSize int64
	for _, entry := range entries {
		fi, err := entry.Info()
		if err != nil {
			w.wrappedLogf("error getting log file info: %v", err)
			continue
		}

		baseName := filepath.Base(fi.Name())
		if !strings.HasPrefix(baseName, prefix) {
			continue
		}
		size := fi.Size()
		fileSize[baseName] = size
		sumSize += size
		files = append(files, baseName)
	}
	if sumSize > maxSize {
		w.wrappedLogf("cleaning log files; sum byte count %d > %d", sumSize, maxSize)
	}
	if len(files) > maxFiles {
		w.wrappedLogf("cleaning log files; number of files %d > %d", len(files), maxFiles)
	}
	for (sumSize > maxSize || len(files) > maxFiles) && len(files) > 0 {
		target := files[0]
		files = files[1:]

		targetSize := fileSize[target]
		targetFull := filepath.Join(w.dir, target)
		err := os.Remove(targetFull)
		if err != nil {
			w.wrappedLogf("error cleaning log file: %v", err)
		} else {
			sumSize -= targetSize
			w.wrappedLogf("cleaned log file %s (size %d); new bytes=%v, files=%v", targetFull, targetSize, sumSize, len(files))
		}
	}
}
