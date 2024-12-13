// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package httpclient has helpers for http clients
package httpclient

import (
	"testing"
)

func TestIsSuccess(t *testing.T) {
	if IsSuccess(-1) {
		t.Error("status code = -1  returns a successful http response")
	}
	if IsSuccess(0) {
		t.Error("status code = 0   returns a successful http response")
	}
	if IsSuccess(199) {
		t.Error("status code = 199 returns a successful http response")
	}
	if !IsSuccess(200) {
		t.Error("status code = 200 returns a failed http response")
	}
	if !IsSuccess(299) {
		t.Error("status code = 299 returns a failed http response")
	}
	if IsSuccess(300) {
		t.Error("status code = 300 returns a successful http response")
	}
}
