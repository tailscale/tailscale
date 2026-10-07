// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_taildrop

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/cmd/tailscale/cli/ffcomplete"
	"tailscale.com/feature/taildrop/taildroptype"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tstest"
	"tailscale.com/types/key"
)

// TestProgressPrinterConsent verifies that waiting for approval suppresses
// transfer rates until sending begins, including for empty files and streams of
// unknown size.
func TestProgressPrinterConsent(t *testing.T) {
	for _, size := range []int64{-1, 0, 100} {
		t.Run(formatIEC(float64(size), "B"), func(t *testing.T) {
			var output bytes.Buffer
			old := Stderr
			Stderr = &output
			defer func() { Stderr = old }()
			ctx, cancel := context.WithCancel(context.Background())
			waiting := true
			// Transition after the first paint, before cancellation's final paint.
			status := func() bool {
				if waiting {
					waiting = false
					cancel()
					return true
				}
				return false
			}
			progressPrinter(ctx, "example.txt", func() int64 { return 0 }, status, size, time.Hour)
			lines := strings.Split(output.String(), "\r\x1b[K")
			if len(lines) != 3 || !strings.Contains(lines[1], "waiting for approval") || strings.Contains(lines[1], "B/s") {
				t.Fatalf("missing waiting status or premature progress: %q", output.String())
			}
			if !strings.Contains(lines[2], "B/s") || strings.Contains(lines[2], "waiting for approval") || strings.Contains(lines[2], "NaN") {
				t.Fatalf("missing progress after approval: %q", output.String())
			}
		})
	}
}

// consentOutput acknowledges receipt of the waiting message so the fake daemon
// can finish the request without racing the bus reader.
type consentOutput struct {
	bytes.Buffer
	once    sync.Once
	waiting chan struct{}
}

func (w *consentOutput) Write(p []byte) (int, error) {
	n, err := w.Buffer.Write(p)
	if bytes.Contains(p, []byte("waiting for approval")) {
		w.once.Do(func() { close(w.waiting) })
	}
	return n, err
}

// TestRunCpConsent verifies that single-file copies surface daemon consent
// notifications and identify declined files in the returned error.
func TestRunCpConsent(t *testing.T) {
	for _, decline := range []bool{false, true} {
		t.Run(fmt.Sprint("decline=", decline), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			name := "a file%.txt"
			file := filepath.Join(t.TempDir(), name)
			if err := os.WriteFile(file, []byte("hello"), 0600); err != nil {
				t.Fatal(err)
			}
			output := &consentOutput{waiting: make(chan struct{})}
			tstest.Replace(t, &Stderr, io.Writer(output))
			tstest.Replace(t, &cpArgs, cpArgs)
			cpArgs.updateInterval = 0
			updates := make(chan *ipn.OutgoingFile)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/localapi/v0/status":
					json.NewEncoder(w).Encode(ipnstate.Status{
						Self: &ipnstate.PeerStatus{},
						Peer: map[key.NodePublic]*ipnstate.PeerStatus{{}: {
							ID: "peer", Online: true, TaildropTarget: ipnstate.TaildropTargetConsentRequired,
							TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
						}},
					})
				case r.URL.Path == "/localapi/v0/watch-ipn-bus":
					w.WriteHeader(http.StatusOK)
					w.(http.Flusher).Flush()
					for {
						select {
						case of := <-updates:
							json.NewEncoder(w).Encode(ipn.Notify{OutgoingFiles: []*ipn.OutgoingFile{of}})
							w.(http.Flusher).Flush()
						case <-r.Context().Done():
							return
						}
					}
				case strings.HasPrefix(r.URL.Path, "/localapi/v0/file-put/"):
					io.Copy(io.Discard, r.Body)
					select {
					case updates <- &ipn.OutgoingFile{PeerID: "peer", Name: url.PathEscape(name), WaitingForConsent: true}:
					case <-ctx.Done():
						return
					}
					select {
					case <-output.waiting:
					case <-ctx.Done():
						return
					}
					if decline {
						http.Error(w, "taildrop: transfer declined", http.StatusForbidden)
						return
					}
					w.WriteHeader(http.StatusOK)
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			tstest.Replace(t, &localClient, local.Client{Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
			}})
			err := runCp(ctx, []string{file, "100.64.0.1:"})
			if decline {
				if err == nil || !strings.Contains(err.Error(), "transfer declined") || !strings.Contains(err.Error(), name) {
					t.Fatalf("error = %v; want named decline", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if got := output.String(); got != name+": waiting for approval from 100.64.0.1\n" {
				t.Fatalf("output = %q", got)
			}
		})
	}
}

// TestConsentFileSummary verifies that consent summaries identify the file and
// total size without failing on an empty request.
func TestConsentFileSummary(t *testing.T) {
	tests := []struct {
		name string
		req  taildroptype.ConsentRequest
		want string
	}{
		{
			"one_file",
			taildroptype.ConsentRequest{
				Files:     []taildroptype.ConsentFile{{Name: "report.pdf", Size: 2048}},
				TotalSize: 2048,
			},
			"report.pdf (2.00KiB)",
		},
		{
			"several_files",
			taildroptype.ConsentRequest{
				Files: []taildroptype.ConsentFile{
					{Name: "a.txt", Size: 1},
					{Name: "b.txt", Size: 1},
					{Name: "c.txt", Size: 1},
				},
				TotalSize: 3,
			},
			"a.txt and 2 more (3.00B)",
		},
		{
			// Shouldn't happen, but the summary is for a human and must not
			// index off the end of an empty list.
			"no_files",
			taildroptype.ConsentRequest{},
			"(no files)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := consentFileSummary(tt.req); got != tt.want {
				t.Errorf("consentFileSummary = %q; want %q", got, tt.want)
			}
		})
	}
}

// TestRunCpBatchProgress verifies that batch copies continue after declines and
// report each file’s final outcome, while preserving quiet output for ordinary
// transfers.
func TestRunCpBatchProgress(t *testing.T) {
	for _, mode := range []string{"ordinary", "declined", "failed"} {
		consent := mode != "ordinary"
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var output bytes.Buffer
			tstest.Replace(t, &Stderr, io.Writer(&output))
			tstest.Replace(t, &cpArgs, cpArgs)
			cpArgs.updateInterval = 0
			var paths []string
			for _, name := range []string{"a file%.txt", "b.txt"} {
				p := filepath.Join(t.TempDir(), name)
				if err := os.WriteFile(p, []byte("hello"), 0600); err != nil {
					t.Fatal(err)
				}
				paths = append(paths, p)
			}
			var puts atomic.Int32
			updates := make(chan *ipn.OutgoingFile)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/localapi/v0/watch-ipn-bus":
					w.WriteHeader(http.StatusOK)
					w.(http.Flusher).Flush()
					for {
						select {
						case f := <-updates:
							json.NewEncoder(w).Encode(ipn.Notify{OutgoingFiles: []*ipn.OutgoingFile{f}})
							w.(http.Flusher).Flush()
						case <-r.Context().Done():
							return
						}
					}
				case strings.HasPrefix(r.URL.Path, "/localapi/v0/file-put/"):
					i := int(puts.Add(1)) - 1
					if r.Method != "PUT" {
						t.Errorf("method = %s; want PUT", r.Method)
					}
					body, err := io.ReadAll(r.Body)
					if err != nil || string(body) != "hello" || r.ContentLength != 5 {
						t.Errorf("body=%q length=%d error=%v", body, r.ContentLength, err)
					}
					name := strings.TrimPrefix(r.URL.EscapedPath(), "/localapi/v0/file-put/peer/")
					f := ipn.OutgoingFile{ID: r.Header.Get("X-Taildrop-Txid"), PeerID: "peer", Name: name, DeclaredSize: 5}
					if f.ID == "" {
						t.Error("missing transfer ID")
					}
					send := func(f ipn.OutgoingFile) {
						select {
						case updates <- &f:
						case <-ctx.Done():
						}
					}
					f.Started = time.Now()
					f.WaitingForConsent = consent
					send(f)
					f.WaitingForConsent = false
					f.Finished = true
					f.CompletedAt = f.Started.Add(2 * time.Second)
					f.Declined = mode == "declined" && i == 0
					f.Succeeded = !f.Declined && !(mode == "failed" && i == 1)
					if f.Succeeded {
						f.Sent = f.DeclaredSize
					}
					send(f)
					switch {
					case f.Declined:
						w.Header().Set("X-Taildrop-Consent-Error", "taildrop: transfer declined")
						http.Error(w, "transfer declined", http.StatusForbidden)
					case !f.Succeeded:
						http.Error(w, "transfer failed", http.StatusBadGateway)
					default:
						w.WriteHeader(http.StatusOK)
					}
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			tstest.Replace(t, &localClient, local.Client{Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
			}})
			err := runCpBatch(ctx, paths, "peer", "laptop")
			if got := puts.Load(); got != 2 {
				t.Fatalf("PUT count = %d; want 2", got)
			}
			if !consent {
				if err != nil || output.Len() != 0 {
					t.Fatalf("ordinary batch: error=%v output=%q", err, output.String())
				}
				return
			}
			if mode == "declined" {
				if err != ErrAlreadyReported {
					t.Fatalf("decline should already be reported: %v", err)
				}
			} else if err == nil || err == ErrAlreadyReported {
				t.Fatalf("other failures must still be reported: %v", err)
			}
			firstState, secondState := "declined (0.00B", "sent (5.00B"
			if mode == "failed" {
				firstState, secondState = "sent (5.00B", "failed (0.00B"
			}
			for _, want := range []string{
				`"a file%.txt": waiting for approval from laptop`,
				fmt.Sprintf(`"a file%%.txt": %s / 5.00B, 2s elapsed)`, firstState),
				`"b.txt": waiting for approval from laptop`,
				fmt.Sprintf(`"b.txt": %s / 5.00B, 2s elapsed)`, secondState),
			} {
				if !strings.Contains(output.String(), want) {
					t.Errorf("missing %q in %q", want, output.String())
				}
			}
			if strings.Contains(output.String(), "2 files") || strings.Contains(output.String(), "not confirmed") {
				t.Fatalf("incorrect batch state: %q", output.String())
			}
		})
	}
}

// Individual PUTs support repeated basenames and selections exceeding the
// multipart consent limit, including empty files.
func TestRunCpBatchIndividualPuts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var output bytes.Buffer
	tstest.Replace(t, &Stderr, io.Writer(&output))
	tstest.Replace(t, &cpArgs, cpArgs)
	cpArgs.updateInterval = 0
	var paths []string
	for i := range 10 {
		p := filepath.Join(t.TempDir(), "same name%.txt")
		if err := os.WriteFile(p, bytes.Repeat([]byte("x"), i), 0600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	var puts atomic.Int32
	var ids sync.Map
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/localapi/v0/watch-ipn-bus" {
			// File results must remain correct when bus progress is unavailable.
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		i := int(puts.Add(1)) - 1
		if r.Method != "PUT" || r.URL.Path != "/localapi/v0/file-put/peer/same name%.txt" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		id := r.Header.Get("X-Taildrop-Txid")
		if _, loaded := ids.LoadOrStore(id, true); id == "" || loaded {
			t.Errorf("missing or reused transfer ID %q", id)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != strings.Repeat("x", i) || r.ContentLength != int64(i) {
			t.Errorf("file %d: body=%q length=%d error=%v", i, body, r.ContentLength, err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	tstest.Replace(t, &localClient, local.Client{Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
	}})
	if err := runCpBatch(ctx, paths, "peer", "laptop"); err != nil {
		t.Fatal(err)
	}
	if got := puts.Load(); got != 10 {
		t.Fatalf("PUT count = %d; want 10", got)
	}
}

// TestFileConsentRespond verifies that accept and reject commands validate
// their arguments, handle individual or all pending requests, and continue
// reporting successes after a partial failure.
func TestFileConsentRespond(t *testing.T) {
	for _, allow := range []bool{true, false} {
		for _, mode := range []string{"all", "empty", "partial-failure", "list-failure", "single", "missing-id", "all-with-id"} {
			t.Run(fmt.Sprintf("allow=%v/%s", allow, mode), func(t *testing.T) {
				var output bytes.Buffer
				tstest.Replace(t, &Stdout, io.Writer(&output))
				var ids []string
				var listed bool
				tstest.Replace(t, &localClient, local.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
					w := httptest.NewRecorder()
					switch r.URL.Path {
					case "/localapi/v0/taildrop-consent/pending":
						listed = true
						if r.Method != "GET" {
							t.Errorf("pending method = %s", r.Method)
						}
						if mode == "list-failure" {
							http.Error(w, "unavailable", http.StatusInternalServerError)
							break
						}
						reqs := []taildroptype.ConsentRequest{}
						if mode != "empty" {
							reqs = append(reqs, taildroptype.ConsentRequest{RequestID: "first"}, taildroptype.ConsentRequest{RequestID: "second"})
						}
						json.NewEncoder(w).Encode(reqs)
					case "/localapi/v0/taildrop-consent/respond":
						if r.Method != "POST" {
							t.Errorf("respond method = %s", r.Method)
						}
						var response struct {
							ID    string `json:"id"`
							Allow bool   `json:"allow"`
						}
						if err := json.NewDecoder(r.Body).Decode(&response); err != nil {
							t.Fatal(err)
						}
						if response.Allow != allow {
							t.Errorf("allow = %v; want %v", response.Allow, allow)
						}
						ids = append(ids, response.ID)
						if mode == "partial-failure" && response.ID == "first" {
							http.Error(w, "expired", http.StatusNotFound)
						} else {
							w.WriteHeader(http.StatusNoContent)
						}
					default:
						t.Fatalf("unexpected request %s", r.URL.Path)
					}
					return w.Result(), nil
				})})
				args := []string{"--all"}
				switch mode {
				case "single":
					args = []string{"first"}
				case "missing-id":
					args = nil
				case "all-with-id":
					args = []string{"--all", "first"}
				}
				err := newFileConsentRespondCmd(allow).ParseAndRun(context.Background(), args)
				wantErr := mode == "partial-failure" || mode == "list-failure" || mode == "missing-id" || mode == "all-with-id"
				if (err != nil) != wantErr {
					t.Fatalf("error = %v; want error=%v", err, wantErr)
				}
				wantIDs, wantOutput := "", ""
				word := "Declined"
				if allow {
					word = "Approved"
				}
				switch mode {
				case "all":
					wantIDs = "first,second"
					wantOutput = word + " first.\n" + word + " second.\n"
				case "partial-failure":
					wantIDs = "first,second"
					wantOutput = word + " second.\n"
					if !strings.Contains(err.Error(), "first") {
						t.Fatalf("error omits failed request: %v", err)
					}
				case "single":
					wantIDs = "first"
					wantOutput = word + " first.\n"
				case "empty":
					wantOutput = "No transfers are awaiting approval.\n"
				}
				wantListed := mode == "all" || mode == "empty" || mode == "partial-failure" || mode == "list-failure"
				if strings.Join(ids, ",") != wantIDs || listed != wantListed || output.String() != wantOutput {
					t.Fatalf("ids=%v listed=%v output=%q; want ids=%s listed=%v output=%q", ids, listed, output.String(), wantIDs, wantListed, wantOutput)
				}
			})
		}
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// TestCompleteFileConsentRequests verifies that consent completion filters
// pending request IDs and describes their senders, avoiding daemon queries when
// no request argument is needed.
func TestCompleteFileConsentRequests(t *testing.T) {
	for _, tt := range []struct {
		name                 string
		args                 []string
		all, fail, wantQuery bool
		want                 string
	}{
		{name: "all_pending", args: []string{""}, wantQuery: true, want: "abc\t\"report.pdf (2.00KiB)\" from \"laptop\"\ndef\t\"notes.txt (1.00B)\" from \"peer-id\""},
		{name: "prefix", args: []string{"ab"}, wantQuery: true, want: "abc\t\"report.pdf (2.00KiB)\" from \"laptop\""},
		{name: "no_match", args: []string{"z"}, wantQuery: true},
		{name: "already_specified", args: []string{"abc", ""}},
		{name: "all_flag", args: []string{""}, all: true},
		{name: "completing_flag", args: []string{"--a"}},
		{name: "daemon_unavailable", args: []string{""}, fail: true, wantQuery: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			queried := false
			tstest.Replace(t, &localClient, local.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
				queried = true
				if r.Method != "GET" || r.URL.Path != "/localapi/v0/taildrop-consent/pending" {
					t.Fatalf("unexpected completion request: %s %s", r.Method, r.URL.Path)
				}
				w := httptest.NewRecorder()
				if tt.fail {
					http.Error(w, "unavailable", http.StatusServiceUnavailable)
				} else {
					json.NewEncoder(w).Encode([]taildroptype.ConsentRequest{
						{RequestID: "abc", PeerName: "laptop", TotalSize: 2048, Files: []taildroptype.ConsentFile{{Name: "report.pdf", Size: 2048}}},
						{RequestID: "def", PeerID: "peer-id", TotalSize: 1, Files: []taildroptype.ConsentFile{{Name: "notes.txt", Size: 1}}},
					})
				}
				return w.Result(), nil
			})})
			words, directive, err := completeFileConsentRequests(tt.args, tt.all)
			if (err != nil) != tt.fail || directive != ffcomplete.ShellCompDirectiveNoFileComp || strings.Join(words, "\n") != tt.want || queried != tt.wantQuery {
				t.Fatalf("words=%q directive=%v error=%v queried=%v; want words=%q error=%v queried=%v", words, directive, err, queried, tt.want, tt.fail, tt.wantQuery)
			}
		})
	}
}

// Policy denial must stop both single-file and batch sends before files are
// opened, the progress watcher starts, or any transfer request is made.
func TestRunCpPolicyDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/localapi/v0/status" {
			t.Errorf("unexpected request under policy denial: %s", r.URL.Path)
			http.Error(w, "unexpected request", http.StatusForbidden)
			return
		}
		json.NewEncoder(w).Encode(ipnstate.Status{
			Self: &ipnstate.PeerStatus{},
			Peer: map[key.NodePublic]*ipnstate.PeerStatus{{}: {
				ID: "peer", TaildropTarget: ipnstate.TaildropTargetPolicyDenied,
				TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
			}},
		})
	}))
	defer srv.Close()
	tstest.Replace(t, &localClient, local.Client{Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
	}})
	for _, args := range [][]string{{"missing", "100.64.0.1:"}, {"missing", "also-missing", "100.64.0.1:"}} {
		if err := runCp(t.Context(), args); err == nil || !strings.Contains(err.Error(), "disabled by IT policy") {
			t.Fatalf("runCp(%v) = %v; want policy denial", args, err)
		}
	}
}
