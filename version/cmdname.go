// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios

package version

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// CmdName returns either the base name of the current binary
// using os.Executable. If os.Executable fails (it shouldn't), then
// "cmd" is returned.
func CmdName() string {
	e, err := os.Executable()
	if err != nil {
		return "cmd"
	}
	return cmdName(e)
}

func cmdName(exe string) string {
	// fallbackName, the lowercase basename of the executable, is what we return if
	// we can't find the Go module metadata embedded in the file.
	fallbackName := filepath.Base(strings.TrimSuffix(strings.ToLower(exe), ".exe"))

	var ret string
	info, err := findModuleInfo(exe)
	if err != nil {
		return fallbackName
	}
	// v is like:
	// "path\ttailscale.com/cmd/tailscale\nmod\ttailscale.com\t(devel)\t\ndep\tgithub.com/apenwarr/fixconsole\tv0.0.0-20191012055117-5a9f6489cc29\th1:muXWUcay7DDy1/hEQWrYlBy+g0EuwT70sBHg65SeUc4=\ndep\tgithub....
	for _, line := range strings.Split(info, "\n") {
		if goPkg, ok := strings.CutPrefix(line, "path\t"); ok { // like "tailscale.com/cmd/tailscale"
			ret = path.Base(goPkg) // goPkg is always forward slashes; use path, not filepath
			break
		}
	}
	if strings.HasPrefix(ret, "wg") && fallbackName == "tailscale-ipn" {
		// The tailscale-ipn.exe binary for internal build system packaging reasons
		// has a path of "tailscale.io/win/wg64", "tailscale.io/win/wg32", etc.
		// Ignore that name and use "tailscale-ipn" instead.
		return fallbackName
	}
	if ret == "" {
		return fallbackName
	}
	return ret
}

// findModuleInfo returns the Go module info from the executable file.
func findModuleInfo(file string) (s string, err error) {
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer f.Close()
	// Scan through f until we find infoStart.
	buf := make([]byte, 65536)
	start, err := findOffset(f, buf, infoStart)
	if err != nil {
		return "", err
	}
	start += int64(len(infoStart))
	// Seek to the end of infoStart and scan for infoEnd.
	_, err = f.Seek(start, io.SeekStart)
	if err != nil {
		return "", err
	}
	end, err := findOffset(f, buf, infoEnd)
	if err != nil {
		return "", err
	}
	length := end - start
	// As of Aug 2021, tailscaled's mod info was about 2k.
	if length > int64(len(buf)) {
		return "", errors.New("mod info too large")
	}
	// We have located modinfo. Read it into buf.
	buf = buf[:length]
	_, err = f.Seek(start, io.SeekStart)
	if err != nil {
		return "", err
	}
	_, err = io.ReadFull(f, buf)
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

// findOffset finds the absolute offset of needle in f,
// starting at f's current read position,
// using temporary buffer buf.
func findOffset(f *os.File, buf, needle []byte) (int64, error) {
	for {
		// Fill buf and look within it.
		n, err := f.Read(buf)
		if err != nil {
			return -1, err
		}
		i := bytes.Index(buf[:n], needle)
		if i < 0 {
			// Not found. Rewind a little bit in case we happened to end halfway through needle.
			rewind, err := f.Seek(int64(-len(needle)), io.SeekCurrent)
			if err != nil {
				return -1, err
			}
			// If we're at EOF and rewound exactly len(needle) bytes, return io.EOF.
			_, err = f.ReadAt(buf[:1], rewind+int64(len(needle)))
			if err == io.EOF {
				return -1, err
			}
			continue
		}
		// Found! Figure out exactly where.
		cur, err := f.Seek(0, io.SeekCurrent)
		if err != nil {
			return -1, err
		}
		return cur - int64(n) + int64(i), nil
	}
}

// These constants are taken from rsc.io/goversion.

var (
	infoStart, _ = hex.DecodeString("3077af0c9274080241e1c107e6d618e6")
	infoEnd, _   = hex.DecodeString("f932433186182072008242104116d8f2")
)
