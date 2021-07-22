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
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode"
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

func isHexString(s string) bool {
	if len(s) <= 2 || s[0:2] != "0x" {
		return false
	}
	_, err := strconv.ParseUint(s[2:], 16, 64)
	return err == nil
}

func separator(r rune) bool {
	if unicode.IsLetter(r) || unicode.IsNumber(r) {
		return false
	}
	return true
}

func scrubGoroutineDump(buf []byte) []byte {
	saw := map[string]string{} // "0x123" => "v1%3" (unique value 1 and its value mod 8)
	sbuf := string(buf)
	for _, field := range strings.FieldsFunc(sbuf, separator) {
		if isHexString(field) {
			if _, ok := saw[field]; ok {
				continue
			}
			var v string
			u64, err := strconv.ParseUint(field[2:], 16, 64)
			if err != nil {
				v = "??"
			} else if u64 == 0 {
				v = "0x0"
			} else {
				v = fmt.Sprintf("v%d%%%%%d", len(saw)+1, u64%8)
			}
			saw[field] = v
		}
	}
	for oldString, newString := range saw {
		sbuf = strings.ReplaceAll(sbuf, oldString, newString)
	}
	return []byte(sbuf)
}

// scrubbedGoroutineDump returns the list of all current goroutines, but with the actual
// values of arguments scrubbed out, lest it contain some private key material.
func scrubbedGoroutineDump() []byte {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	return scrubGoroutineDump(buf)
}
