// Package httpstat traces HTTP latency infomation (DNSLookup, TCP Connection and so on) on any golang HTTP request.
// It uses `httptrace` package. Just create `go-httpstat` powered `context.Context` and give it your `http.Request` (no big code modification is required).
package httpstat

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"
)

// Result stores httpstat info.
type Result struct {
	// The following are duration for each phase
	DNSLookup        time.Duration
	TCPConnection    time.Duration
	TLSHandshake     time.Duration
	ServerProcessing time.Duration
	contentTransfer  time.Duration

	// The followings are timeline of request
	NameLookup    time.Duration
	Connect       time.Duration
	Pretransfer   time.Duration
	StartTransfer time.Duration
	total         time.Duration

	t0 time.Time
	t1 time.Time
	t2 time.Time
	t3 time.Time
	t4 time.Time
	t5 time.Time // need to be provided from outside

	dnsStart      time.Time
	dnsDone       time.Time
	tcpStart      time.Time
	tcpDone       time.Time
	tlsStart      time.Time
	tlsDone       time.Time
	serverStart   time.Time
	serverDone    time.Time
	transferStart time.Time
	trasferDone   time.Time // need to be provided from outside

	// isTLS is true when connection seems to use TLS
	isTLS bool

	// isReused is true when connection is reused (keep-alive)
	isReused bool
}

func (r *Result) durations() map[string]time.Duration {
	return map[string]time.Duration{
		"DNSLookup":        r.DNSLookup,
		"TCPConnection":    r.TCPConnection,
		"TLSHandshake":     r.TLSHandshake,
		"ServerProcessing": r.ServerProcessing,
		"ContentTransfer":  r.contentTransfer,

		"NameLookup":    r.NameLookup,
		"Connect":       r.Connect,
		"Pretransfer":   r.Connect,
		"StartTransfer": r.StartTransfer,
		"Total":         r.total,
	}
}

// ContentTransfer returns the duration of content transfer time.
// It is from first response byte to the given time. The time must
// be time after read body (go-httpstat can not detect that time).
func (r *Result) ContentTransfer(t time.Time) time.Duration {
	return t.Sub(r.t4)
}

// Total returns the duration of total http request.
// It is from dns lookup start time to the given time. The
// time must be time after read body (go-httpstat can not detect that time).
func (r *Result) Total(t time.Time) time.Duration {
	return t.Sub(r.t0)
}

// Format formats stats result.
func (r Result) Format(s fmt.State, verb rune) {
	switch verb {
	case 'v':
		if s.Flag('+') {
			var buf bytes.Buffer
			fmt.Fprintf(&buf, "DNS lookup:        %4d ms\n",
				int(r.DNSLookup/time.Millisecond))
			fmt.Fprintf(&buf, "TCP connection:    %4d ms\n",
				int(r.TCPConnection/time.Millisecond))
			fmt.Fprintf(&buf, "TLS handshake:     %4d ms\n",
				int(r.TLSHandshake/time.Millisecond))
			fmt.Fprintf(&buf, "Server processing: %4d ms\n",
				int(r.ServerProcessing/time.Millisecond))

			if !r.t5.IsZero() {
				fmt.Fprintf(&buf, "Content transfer:  %4d ms\n\n",
					int(r.contentTransfer/time.Millisecond))
			} else {
				fmt.Fprintf(&buf, "Content transfer:  %4s ms\n\n", "-")
			}

			fmt.Fprintf(&buf, "Name Lookup:    %4d ms\n",
				int(r.NameLookup/time.Millisecond))
			fmt.Fprintf(&buf, "Connect:        %4d ms\n",
				int(r.Connect/time.Millisecond))
			fmt.Fprintf(&buf, "Pre Transfer:   %4d ms\n",
				int(r.Pretransfer/time.Millisecond))
			fmt.Fprintf(&buf, "Start Transfer: %4d ms\n",
				int(r.StartTransfer/time.Millisecond))

			if !r.t5.IsZero() {
				fmt.Fprintf(&buf, "Total:          %4d ms\n",
					int(r.total/time.Millisecond))
			} else {
				fmt.Fprintf(&buf, "Total:          %4s ms\n", "-")
			}
			io.WriteString(s, buf.String())
			return
		}

		fallthrough
	case 's', 'q':
		d := r.durations()
		list := make([]string, 0, len(d))
		for k, v := range d {
			// Handle when End function is not called
			if (k == "ContentTransfer" || k == "Total") && r.t5.IsZero() {
				list = append(list, fmt.Sprintf("%s: - ms", k))
				continue
			}
			list = append(list, fmt.Sprintf("%s: %d ms", k, v/time.Millisecond))
		}
		io.WriteString(s, strings.Join(list, ", "))
	}

}

// WithHTTPStat is a wrapper of httptrace.WithClientTrace. It records the
// time of each httptrace hooks.
func WithHTTPStat(ctx context.Context, r *Result) context.Context {
	return withClientTrace(ctx, r)
}
