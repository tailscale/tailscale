// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package sessionrecording

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func TestConnectToRecorder(t *testing.T) {
	tests := []struct {
		desc  string
		http2 bool
		// setup returns a recorder server mux, and a channel which sends the
		// hash of the recording uploaded to it. The channel is expected to
		// fire only once.
		setup   func(t *testing.T) (*http.ServeMux, <-chan []byte)
		wantErr bool
	}{
		{
			desc: "v1 recorder",
			setup: func(t *testing.T) (*http.ServeMux, <-chan []byte) {
				uploadHash := make(chan []byte, 1)
				mux := http.NewServeMux()
				mux.HandleFunc("POST /record", func(w http.ResponseWriter, r *http.Request) {
					hash := sha256.New()
					if _, err := io.Copy(hash, r.Body); err != nil {
						t.Error(err)
					}
					uploadHash <- hash.Sum(nil)
				})
				return mux, uploadHash
			},
		},
		{
			desc:  "v2 recorder",
			http2: true,
			setup: func(t *testing.T) (*http.ServeMux, <-chan []byte) {
				uploadHash := make(chan []byte, 1)
				mux := http.NewServeMux()
				mux.HandleFunc("POST /record", func(w http.ResponseWriter, r *http.Request) {
					t.Error("received request to v1 endpoint")
					http.Error(w, "not found", http.StatusNotFound)
				})
				mux.HandleFunc("POST /v2/record", func(w http.ResponseWriter, r *http.Request) {
					// Force the status to send to unblock the client waiting
					// for it.
					w.WriteHeader(http.StatusOK)
					w.(http.Flusher).Flush()

					body := &readCounter{r: r.Body}
					hash := sha256.New()
					ctx, cancel := context.WithCancel(r.Context())
					go func() {
						defer cancel()
						if _, err := io.Copy(hash, body); err != nil {
							t.Error(err)
						}
					}()

					// Send acks for received bytes.
					tick := time.NewTicker(time.Millisecond)
					defer tick.Stop()
					enc := json.NewEncoder(w)
				outer:
					for {
						select {
						case <-ctx.Done():
							break outer
						case <-tick.C:
							if err := enc.Encode(v2ResponseFrame{Ack: body.sent.Load()}); err != nil {
								t.Errorf("writing ack frame: %v", err)
								break outer
							}
						}
					}

					uploadHash <- hash.Sum(nil)
				})
				// Probing HEAD endpoint which always returns 200 OK.
				mux.HandleFunc("HEAD /v2/record", func(http.ResponseWriter, *http.Request) {})
				return mux, uploadHash
			},
		},
		{
			desc:    "v2 recorder no acks",
			http2:   true,
			wantErr: true,
			setup: func(t *testing.T) (*http.ServeMux, <-chan []byte) {
				// Make the client no-ack timeout quick for the test.
				oldAckWindow := uploadAckWindow
				uploadAckWindow = 100 * time.Millisecond
				t.Cleanup(func() { uploadAckWindow = oldAckWindow })

				uploadHash := make(chan []byte, 1)
				mux := http.NewServeMux()
				mux.HandleFunc("POST /record", func(w http.ResponseWriter, r *http.Request) {
					t.Error("received request to v1 endpoint")
					http.Error(w, "not found", http.StatusNotFound)
				})
				mux.HandleFunc("POST /v2/record", func(w http.ResponseWriter, r *http.Request) {
					// Force the status to send to unblock the client waiting
					// for it.
					w.WriteHeader(http.StatusOK)
					w.(http.Flusher).Flush()

					// Consume the whole request body but don't send any acks
					// back.
					hash := sha256.New()
					if _, err := io.Copy(hash, r.Body); err != nil {
						t.Error(err)
					}
					// Goes in the channel buffer, non-blocking.
					uploadHash <- hash.Sum(nil)

					// Block until the parent test case ends to prevent the
					// request termination. We want to exercise the ack
					// tracking logic specifically.
					ctx, cancel := context.WithCancel(r.Context())
					t.Cleanup(cancel)
					<-ctx.Done()
				})
				mux.HandleFunc("HEAD /v2/record", func(http.ResponseWriter, *http.Request) {})
				return mux, uploadHash
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			mux, uploadHash := tt.setup(t)

			srv := httptest.NewUnstartedServer(mux)
			if tt.http2 {
				// Wire up h2c-compatible HTTP/2 server. This is optional
				// because the v1 recorder didn't support HTTP/2 and we try to
				// mimic that.
				s := &http2.Server{}
				srv.Config.Handler = h2c.NewHandler(mux, s)
				if err := http2.ConfigureServer(srv.Config, s); err != nil {
					t.Errorf("configuring HTTP/2 support in server: %v", err)
				}
			}
			srv.Start()
			t.Cleanup(srv.Close)

			d := new(net.Dialer)

			ctx := context.Background()
			w, _, errc, err := ConnectToRecorder(ctx, []netip.AddrPort{netip.MustParseAddrPort(srv.Listener.Addr().String())}, d.DialContext)
			if err != nil {
				t.Fatalf("ConnectToRecorder: %v", err)
			}

			// Send some random data and hash it to compare with the recorded
			// data hash.
			hash := sha256.New()
			const numBytes = 1 << 20 // 1MB
			if _, err := io.CopyN(io.MultiWriter(w, hash), rand.Reader, numBytes); err != nil {
				t.Fatalf("writing recording data: %v", err)
			}
			if err := w.Close(); err != nil {
				t.Fatalf("closing recording stream: %v", err)
			}
			if err := <-errc; err != nil && !tt.wantErr {
				t.Fatalf("error from the channel: %v", err)
			} else if err == nil && tt.wantErr {
				t.Fatalf("did not receive expected error from the channel")
			}

			if recv, sent := <-uploadHash, hash.Sum(nil); !bytes.Equal(recv, sent) {
				t.Errorf("mismatch in recording data hash, sent %x, received %x", sent, recv)
			}
		})
	}
}

func TestSendEvent(t *testing.T) {
	t.Run("supported", func(t *testing.T) {
		eventBody := `{"foo":"bar"}`
		eventRecieved := make(chan []byte, 1)
		mux := http.NewServeMux()
		mux.HandleFunc("HEAD /v2/event", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		mux.HandleFunc("POST /v2/event", func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
			}
			eventRecieved <- body
			w.WriteHeader(http.StatusOK)
		})

		srv := httptest.NewUnstartedServer(mux)
		s := &http2.Server{}
		srv.Config.Handler = h2c.NewHandler(mux, s)
		if err := http2.ConfigureServer(srv.Config, s); err != nil {
			t.Fatalf("configuring HTTP/2 support in server: %v", err)
		}
		srv.Start()
		t.Cleanup(srv.Close)

		d := new(net.Dialer)
		addr := netip.MustParseAddrPort(srv.Listener.Addr().String())
		err := SendEvent(addr, bytes.NewBufferString(eventBody), d.DialContext)
		if err != nil {
			t.Fatalf("SendEvent: %v", err)
		}

		if recv := string(<-eventRecieved); recv != eventBody {
			t.Errorf("mismatch in event body, sent %q, received %q", eventBody, recv)
		}
	})

	t.Run("not_supported", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("HEAD /v2/event", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})

		srv := httptest.NewUnstartedServer(mux)
		s := &http2.Server{}
		srv.Config.Handler = h2c.NewHandler(mux, s)
		if err := http2.ConfigureServer(srv.Config, s); err != nil {
			t.Fatalf("configuring HTTP/2 support in server: %v", err)
		}
		srv.Start()
		t.Cleanup(srv.Close)

		d := new(net.Dialer)
		addr := netip.MustParseAddrPort(srv.Listener.Addr().String())
		err := SendEvent(addr, nil, d.DialContext)
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		if !strings.Contains(err.Error(), fmt.Sprintf(addressNotSupportEventv2, srv.Listener.Addr().String())) {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("server_error", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("HEAD /v2/event", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		mux.HandleFunc("POST /v2/event", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})

		srv := httptest.NewUnstartedServer(mux)
		s := &http2.Server{}
		srv.Config.Handler = h2c.NewHandler(mux, s)
		if err := http2.ConfigureServer(srv.Config, s); err != nil {
			t.Fatalf("configuring HTTP/2 support in server: %v", err)
		}
		srv.Start()
		t.Cleanup(srv.Close)

		d := new(net.Dialer)
		addr := netip.MustParseAddrPort(srv.Listener.Addr().String())
		err := SendEvent(addr, nil, d.DialContext)
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		if !strings.Contains(err.Error(), "server returned non-OK status") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
