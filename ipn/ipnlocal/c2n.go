// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnlocal

import (
	"io"
	"net/http"
)

func (b *LocalBackend) handleC2N(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/echo":
		// Test handler.
		body, _ := io.ReadAll(r.Body)
		w.Write(body)
	default:
		http.Error(w, "unknown c2n path", http.StatusBadRequest)
	}
}
