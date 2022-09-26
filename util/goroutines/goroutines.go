// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The goroutines package contains utilities for getting active goroutines.
package goroutines

import (
	"bytes"
	"fmt"
	"runtime"
	"strconv"
)

// ScrubbedGoroutineDump returns the list of all current goroutines, but with the actual
// values of arguments scrubbed out, lest it contain some private key material.
func ScrubbedGoroutineDump() []byte {
	var buf []byte
	// Grab stacks multiple times into increasingly larger buffer sizes
	// to minimize the risk that we blow past our iOS memory limit.
	for size := 1 << 10; size <= 1<<20; size += 1 << 10 {
		buf = make([]byte, size)
		buf = buf[:runtime.Stack(buf, true)]
		if len(buf) < size {
			// It fit.
			break
		}
	}
	return scrubHex(buf)
}

func scrubHex(buf []byte) []byte {
	saw := map[string][]byte{} // "0x123" => "v1%3" (unique value 1 and its value mod 8)

	foreachHexAddress(buf, func(in []byte) {
		if string(in) == "0x0" {
			return
		}
		if v, ok := saw[string(in)]; ok {
			for i := range in {
				in[i] = '_'
			}
			copy(in, v)
			return
		}
		inStr := string(in)
		u64, err := strconv.ParseUint(string(in[2:]), 16, 64)
		for i := range in {
			in[i] = '_'
		}
		if err != nil {
			in[0] = '?'
			return
		}
		v := []byte(fmt.Sprintf("v%d%%%d", len(saw)+1, u64%8))
		saw[inStr] = v
		copy(in, v)
	})
	return buf
}

var ohx = []byte("0x")

// foreachHexAddress calls f with each subslice of b that matches
// regexp `0x[0-9a-f]*`.
func foreachHexAddress(b []byte, f func([]byte)) {
	for len(b) > 0 {
		i := bytes.Index(b, ohx)
		if i == -1 {
			return
		}
		b = b[i:]
		hx := hexPrefix(b)
		f(hx)
		b = b[len(hx):]
	}
}

func hexPrefix(b []byte) []byte {
	for i, c := range b {
		if i < 2 {
			continue
		}
		if !isHexByte(c) {
			return b[:i]
		}
	}
	return b
}

func isHexByte(b byte) bool {
	return '0' <= b && b <= '9' || 'a' <= b && b <= 'f' || 'A' <= b && b <= 'F'
}
