// +build !go1.8

package httpstat

import (
	"context"
	"net"
	"net/http/httptrace"
	"time"
)

// End sets the time when reading response is done.
// This must be called after reading response body.
func (r *Result) End(t time.Time) {
	r.t5 = t

	// This means result is empty (it does nothing).
	// Skip setting value(contentTransfer and total will be zero).
	if r.t0.IsZero() {
		return
	}

	r.contentTransfer = r.t5.Sub(r.t4)
	r.total = r.t5.Sub(r.t0)
}

func withClientTrace(ctx context.Context, r *Result) context.Context {
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GetConn: func(hostPort string) {
			_, port, err := net.SplitHostPort(hostPort)
			if err != nil {
				return
			}

			// Heuristic way to detect
			if port == "443" {
				r.isTLS = true
			}
		},

		DNSStart: func(i httptrace.DNSStartInfo) {
			r.t0 = time.Now()
		},
		DNSDone: func(i httptrace.DNSDoneInfo) {
			r.t1 = time.Now()
			r.DNSLookup = r.t1.Sub(r.t0)
			r.NameLookup = r.t1.Sub(r.t0)
		},

		ConnectStart: func(_, _ string) {
			// When connecting to IP
			if r.t0.IsZero() {
				r.t0 = time.Now()
				r.t1 = r.t0
			}
		},

		ConnectDone: func(network, addr string, err error) {
			r.t2 = time.Now()
			if r.isTLS {
				r.TCPConnection = r.t2.Sub(r.t1)
				r.Connect = r.t2.Sub(r.t0)
			}
		},

		GotConn: func(i httptrace.GotConnInfo) {
			// Handle when keep alive is enabled and connection is reused.
			// DNSStart(Done) and ConnectStart(Done) is skipped
			if i.Reused {
				r.t0 = time.Now()
				r.t1 = r.t0
				r.t2 = r.t0

				r.isReused = true
			}
		},

		WroteRequest: func(info httptrace.WroteRequestInfo) {
			r.t3 = time.Now()

			// This means DNSStart, Done and ConnectStart is not
			// called. This happens if client doesn't use DialContext
			// or using net package before go1.7.
			if r.t0.IsZero() && r.t1.IsZero() && r.t2.IsZero() {
				r.t0 = time.Now()
				r.t1 = r.t0
				r.t2 = r.t0
				r.t3 = r.t0
			}

			// When connection is reused, TLS handshake is skipped.
			if r.isReused {
				r.t3 = r.t0
			}

			if r.isTLS {
				r.TLSHandshake = r.t3.Sub(r.t2)
				r.Pretransfer = r.t3.Sub(r.t0)
				return
			}

			r.TCPConnection = r.t3.Sub(r.t1)
			r.Connect = r.t3.Sub(r.t0)

			r.TLSHandshake = r.t3.Sub(r.t3)
			r.Pretransfer = r.Connect
		},
		GotFirstResponseByte: func() {
			r.t4 = time.Now()
			r.ServerProcessing = r.t4.Sub(r.t3)
			r.StartTransfer = r.t4.Sub(r.t0)
		},
	})
}
