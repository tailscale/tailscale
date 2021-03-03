// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlclient

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"runtime"
	"strconv"
	"time"
)

func dumpGoroutinesToURL(c *http.Client, targetURL string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	zbuf := new(bytes.Buffer)
	zw := gzip.NewWriter(zbuf)
	zw.Write(scrubbedGoroutineDump())
	zw.Close()

	req, err := http.NewRequestWithContext(ctx, "PUT", targetURL, zbuf)
	if err != nil {
		log.Printf("dumpGoroutinesToURL: %v", err)
		return
	}
	req.Header.Set("Content-Encoding", "gzip")
	t0 := time.Now()
	_, err = c.Do(req)
	d := time.Since(t0).Round(time.Millisecond)
	if err != nil {
		log.Printf("dumpGoroutinesToURL error: %v to %v (after %v)", err, targetURL, d)
	} else {
		log.Printf("dumpGoroutinesToURL complete to %v (after %v)", targetURL, d)
	}
}

var reHexArgs = regexp.MustCompile(`\b0x[0-9a-f]+\b`)

// scrubbedGoroutineDump returns the list of all current goroutines, but with the actual
// values of arguments scrubbed out, lest it contain some private key material.
func scrubbedGoroutineDump() []byte {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]

	saw := map[string][]byte{} // "0x123" => "v1%3" (unique value 1 and its value mod 8)
	return reHexArgs.ReplaceAllFunc(buf, func(in []byte) []byte {
		if string(in) == "0x0" {
			return in
		}
		if v, ok := saw[string(in)]; ok {
			return v
		}
		u64, err := strconv.ParseUint(string(in[2:]), 16, 64)
		if err != nil {
			return []byte("??")
		}
		v := []byte(fmt.Sprintf("v%d%%%d", len(saw)+1, u64%8))
		saw[string(in)] = v
		return v
	})
}
