// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package beaconcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/client/local"
	"tailscale.com/feature/loginbeacon/api"
	"tailscale.com/ipn"
)

type beaconRoundTripper func(*http.Request) (*http.Response, error)

func (f beaconRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestBeaconApprovalHandoff(t *testing.T) {
	id := strings.Repeat("a", 32)
	for _, mode := range []string{"browser-success", "browser-failure", "print-url", "revoked", "correlation-mismatch", "untrusted-origin"} {
		t.Run(mode, func(t *testing.T) {
			var output bytes.Buffer
			opened, deleted := 0, 0
			open := func(raw string) error {
				opened++
				if mode == "browser-failure" {
					return errors.New("secret URL: " + raw)
				}
				return nil
			}
			lc := &local.Client{OmitAuth: true, Transport: beaconRoundTripper(func(r *http.Request) (*http.Response, error) {
				w := httptest.NewRecorder()
				switch {
				case r.Method == http.MethodPost:
					result := api.Approval{RequestID: id, AuthURL: "https://login.tailscale.com/a/secret"}
					if mode == "correlation-mismatch" {
						result.RequestID = strings.Repeat("b", 32)
					}
					if mode == "untrusted-origin" {
						result.AuthURL = "https://evil.example/a/secret"
					}
					json.NewEncoder(w).Encode(result)
				case r.Method == http.MethodGet:
					json.NewEncoder(w).Encode(api.Status{Allowed: mode != "revoked", AcceptRequests: true, Requests: []api.Pending{{Request: api.Request{RequestID: id}}}})
				case r.Method == http.MethodDelete:
					deleted++
					w.WriteHeader(http.StatusNoContent)
				default:
					t.Fatalf("unexpected method %s", r.Method)
				}
				return w.Result(), nil
			})}
			cmd := NewCommand(Options{Client: lc, Stdout: &output, OpenURL: open, NewFlagSet: func(name string) *flag.FlagSet { return flag.NewFlagSet(name, flag.ContinueOnError) }})
			var approve *ffcli.Command
			for _, sub := range cmd.Subcommands {
				if sub.Name == "approve" {
					approve = sub
				}
			}
			if mode == "print-url" {
				if err := approve.FlagSet.Parse([]string{"--print-url"}); err != nil {
					t.Fatal(err)
				}
			}
			err := approve.Exec(context.Background(), []string{id})
			success := mode == "browser-success" || mode == "print-url"
			if (err == nil) != success {
				t.Fatalf("error = %v", err)
			}
			if err != nil && strings.Contains(err.Error(), "secret") {
				t.Fatal("error leaked URL")
			}
			wantOpened, wantDeleted := 0, 0
			if mode == "browser-success" {
				wantOpened, wantDeleted = 1, 1
			}
			if mode == "browser-failure" {
				wantOpened = 1
			}
			if opened != wantOpened || deleted != wantDeleted {
				t.Fatalf("opened=%d deleted=%d", opened, deleted)
			}
			if mode == "print-url" && !strings.Contains(output.String(), "/a/secret") {
				t.Fatal("explicit URL output missing")
			}
		})
	}
}

func TestBeaconTerminalLabels(t *testing.T) {
	if got := beaconLabel(" TV\x1b[31m\n\u202e "); got != "TV[31m" {
		t.Fatalf("label=%q", got)
	}
	if got := beaconLabel("\n\t"); got != "Unknown device" {
		t.Fatalf("empty label=%q", got)
	}
}

func TestLoginBeaconRejectsInvalidIDs(t *testing.T) {
	lc := &local.Client{OmitAuth: true, Transport: beaconRoundTripper(func(*http.Request) (*http.Response, error) {
		t.Error("invalid ID reached HTTP transport")
		return nil, errors.New("unexpected request")
	})}
	for _, id := range []string{"", "../requests", strings.Repeat("z", 32)} {
		if err := lc.StartLoginBeacon(t.Context(), id, api.Broadcast{}); err == nil {
			t.Fatal("invalid broadcast ID accepted")
		}
		if _, err := lc.ApproveLoginBeacon(t.Context(), id); err == nil {
			t.Fatal("invalid approval ID accepted")
		}
	}
}

func TestWatchReconcilesSnapshotAndQueuedAnnouncements(t *testing.T) {
	var output bytes.Buffer
	subscribed := false
	snapshot := api.Request{RequestID: strings.Repeat("a", 32), Hostname: "snapshot"}
	live := api.Request{RequestID: strings.Repeat("b", 32), Hostname: "live"}
	lc := &local.Client{OmitAuth: true, Transport: beaconRoundTripper(func(r *http.Request) (*http.Response, error) {
		w := httptest.NewRecorder()
		enc := json.NewEncoder(w)
		switch r.URL.Path {
		case "/localapi/v0/watch-ipn-bus":
			subscribed = true
			enc.Encode(ipn.Notify{LoginBeaconRequest: &snapshot})
			enc.Encode(ipn.Notify{LoginBeaconRequest: &live})
			enc.Encode(ipn.Notify{LoginBeaconRequest: &live})
			enc.Encode(ipn.Notify{LoginBeaconRemoved: &live.RequestID})
			enc.Encode(ipn.Notify{LoginBeaconRemoved: &live.RequestID})
			enc.Encode(ipn.Notify{LoginBeaconRequest: &live}) // a sender can return after lease expiry
			message := "stream closed"
			enc.Encode(ipn.Notify{ErrMessage: &message})
		case "/localapi/v0/loginbeacon/requests":
			if !subscribed {
				t.Fatal("snapshot fetched before subscribing")
			}
			enc.Encode([]api.Pending{{Request: snapshot, Expires: time.Now().Add(api.RequestRetention)}})
		default:
			t.Fatalf("unexpected request %s", r.URL.Path)
		}
		return w.Result(), nil
	})}
	if err := watchLoginBeacons(t.Context(), nil, lc, &output); err == nil {
		t.Fatal("closed stream did not terminate watch")
	}
	want := snapshot.RequestID + "  snapshot wants to join Tailscale\n" +
		live.RequestID + "  live wants to join Tailscale\n" +
		live.RequestID + "  request removed\n" +
		live.RequestID + "  live wants to join Tailscale\n"
	if got := output.String(); got != want {
		t.Fatalf("watch output = %q; want %q", got, want)
	}
}

func TestLoginAttemptDrainsStartBeforeStop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		started, release, deleted := make(chan struct{}), make(chan struct{}), make(chan struct{})
		var attemptID string
		lc := &local.Client{OmitAuth: true, Transport: beaconRoundTripper(func(r *http.Request) (*http.Response, error) {
			switch r.Method {
			case http.MethodPut:
				attemptID = r.URL.Path
				close(started)
				<-release // A transport may still complete after login cancellation.
			case http.MethodDelete:
				if r.URL.Path != attemptID || r.Context().Err() != nil {
					t.Error("cleanup used the wrong attempt or a canceled context")
				}
				close(deleted)
			default:
				t.Errorf("unexpected method %s", r.Method)
			}
			w := httptest.NewRecorder()
			w.WriteHeader(http.StatusNoContent)
			return w.Result(), nil
		})}
		attempt := NewLoginAttempt(lc, "sender", cancel)
		go func() {
			defer attempt.PumpDone()
			attempt.Start(ctx)
		}()
		<-started
		stopped := make(chan error, 1)
		go func() { stopped <- attempt.Stop() }()
		<-ctx.Done()
		synctest.Wait()
		select {
		case <-deleted:
			t.Fatal("stop reached the daemon while start was still in flight")
		default:
		}
		close(release)
		if err := <-stopped; err != nil {
			t.Fatal(err)
		}
		select {
		case <-deleted:
		default:
			t.Fatal("stop did not clean up the attempt")
		}
	})
}
