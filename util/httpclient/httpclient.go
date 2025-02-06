// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package httpclient has helpers for http clients
// Inspiration: https://github.com/bradfitz/exp-httpclient/blob/master/problems.md
package httpclient

import (
	"net/http"
)

// IsSuccess returns true if the http response was successful based on the response's status code
// Defined by RFC 7231 in section 6.3: https://www.rfc-editor.org/rfc/rfc7231#section-6.3
// Cribbed from: https://github.com/bradfitz/exp-httpclient/blob/53da77bc832c4fe16ffd283306738ebe93ed083e/http/status.go#L61-L65
func IsSuccess(statusCode int) bool {
	return statusCode >= http.StatusOK && statusCode < http.StatusMultipleChoices // StatusMultipleChoices == 300
}
