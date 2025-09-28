// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package logtail

import (
	"io"
	"net/http"
	"time"

	"tailscale.com/tstime"
	"tailscale.com/types/logid"
)

// DefaultHost is the default host name to upload logs to when
// Config.BaseURL isn't provided.
const DefaultHost = "log.tailscale.com"

const defaultFlushDelay = 2 * time.Second

const (
	// CollectionNode is the name of a logtail Config.Collection
	// for tailscaled (or equivalent: IPNExtension, Android app).
	CollectionNode = "tailnode.log.tailscale.io"
)

type Config struct {
	Collection     string          // collection name, a domain name
	PrivateID      logid.PrivateID // private ID for the primary log stream
	CopyPrivateID  logid.PrivateID // private ID for a log stream that is a superset of this log stream
	BaseURL        string          // if empty defaults to "https://log.tailscale.com"
	HTTPC          *http.Client    // if empty defaults to http.DefaultClient
	SkipClientTime bool            // if true, client_time is not written to logs
	LowMemory      bool            // if true, logtail minimizes memory use
	Clock          tstime.Clock    // if set, Clock.Now substitutes uses of time.Now
	Stderr         io.Writer       // if set, logs are sent here instead of os.Stderr
	StderrLevel    int             // max verbosity level to write to stderr; 0 means the non-verbose messages only
	Buffer         Buffer          // temp storage, if nil a MemoryBuffer
	CompressLogs   bool            // whether to compress the log uploads
	MaxUploadSize  int             // maximum upload size; 0 means using the default

	// MetricsDelta, if non-nil, is a func that returns an encoding
	// delta in clientmetrics to upload alongside existing logs.
	// It can return either an empty string (for nothing) or a string
	// that's safe to embed in a JSON string literal without further escaping.
	MetricsDelta func() string

	// FlushDelayFn, if non-nil is a func that returns how long to wait to
	// accumulate logs before uploading them. 0 or negative means to upload
	// immediately.
	//
	// If nil, a default value is used. (currently 2 seconds)
	FlushDelayFn func() time.Duration

	// IncludeProcID, if true, results in an ephemeral process identifier being
	// included in logs. The ID is random and not guaranteed to be globally
	// unique, but it can be used to distinguish between different instances
	// running with same PrivateID.
	IncludeProcID bool

	// IncludeProcSequence, if true, results in an ephemeral sequence number
	// being included in the logs. The sequence number is incremented for each
	// log message sent, but is not persisted across process restarts.
	IncludeProcSequence bool
}
