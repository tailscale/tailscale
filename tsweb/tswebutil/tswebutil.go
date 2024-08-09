// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package tswebutil contains helper code used in various Tailscale webservers, without the tsweb kitchen sink.
package tswebutil

import (
	"net/http"
	"strings"

	"go4.org/mem"
)

// AcceptsEncoding reports whether r accepts the named encoding
// ("gzip", "br", etc).
func AcceptsEncoding(r *http.Request, enc string) bool {
	h := r.Header.Get("Accept-Encoding")
	if h == "" {
		return false
	}
	if !strings.Contains(h, enc) && !mem.ContainsFold(mem.S(h), mem.S(enc)) {
		return false
	}
	remain := h
	for len(remain) > 0 {
		var part string
		part, remain, _ = strings.Cut(remain, ",")
		part = strings.TrimSpace(part)
		part, _, _ = strings.Cut(part, ";")
		if part == enc {
			return true
		}
	}
	return false
}
