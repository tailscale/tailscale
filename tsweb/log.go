// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tsweb

import (
	"encoding/json"
	"strings"
	"time"
)

// AccessLogRecord is a record of one HTTP request served.
type AccessLogRecord struct {
	// Timestamp at which request processing started.
	Time time.Time `json:"time"`
	// Time it took to finish processing the request. It does not
	// include the entire lifetime of the underlying connection in
	// cases like connection hijacking, only the lifetime of the HTTP
	// request handler.
	Seconds float64 `json:"duration,omitempty"`

	// The client's ip:port.
	RemoteAddr string `json:"remote_addr,omitempty"`
	// The HTTP protocol version, usually "HTTP/1.1 or HTTP/2".
	Proto string `json:"proto,omitempty"`
	// Whether the request was received over TLS.
	TLS bool `json:"tls,omitempty"`
	// The target hostname in the request.
	Host string `json:"host,omitempty"`
	// The HTTP method invoked.
	Method string `json:"method,omitempty"`
	// The unescaped request URI, including query parameters.
	RequestURI string `json:"request_uri,omitempty"`

	// The client's user-agent
	UserAgent string `json:"user_agent,omitempty"`
	// Where the client was before making this request.
	Referer string `json:"referer,omitempty"`

	// The HTTP response code sent to the client.
	Code int `json:"code,omitempty"`
	// Number of bytes sent in response body to client. If the request
	// was hijacked, only includes bytes sent up to the point of
	// hijacking.
	Bytes int `json:"bytes,omitempty"`
	// Error encountered during request processing.
	Err string `json:"err,omitempty"`
	// RequestID is a unique ID for this request. If the *http.Request context
	// carries this value via SetRequestID, then it will be displayed to the
	// client immediately after the error text, as well as logged here. This
	// makes it easier to correlate support requests with server logs. If a
	// RequestID generator is not configured, RequestID will be empty.
	RequestID RequestID `json:"request_id,omitempty"`
}

// String returns m as a JSON string.
func (m AccessLogRecord) String() string {
	if m.Time.IsZero() {
		m.Time = time.Now()
	}
	var buf strings.Builder
	json.NewEncoder(&buf).Encode(m)
	return strings.TrimRight(buf.String(), "\n")
}
