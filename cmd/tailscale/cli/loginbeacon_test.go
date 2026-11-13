// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/feature/loginbeacon/api"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
)

type beaconRoundTripper func(*http.Request) (*http.Response, error)

func (f beaconRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestUpPreservesReceptionOptOut(t *testing.T) {
	p := ipn.NewPrefs()
	old := &ipn.Prefs{AcceptLoginRequests: false}
	applyImplicitPrefs(p, old, upCheckEnv{flagSet: newUpFlagSet("linux", new(upArgsT), "up")})
	if p.AcceptLoginRequests {
		t.Fatal("up reverted receiver opt-out")
	}
}

func TestUpLoginBeaconLifecycle(t *testing.T) {
	if !buildfeatures.HasLoginBeacon || !buildfeatures.HasIPNBus {
		t.Skip("beacon login requires beacon and IPN bus support")
	}
	for _, mode := range []string{"complete", "cancel-during-start"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			oldClient, oldFlags, oldOut, oldErr := localClient, upFlagSet, Stdout, Stderr
			t.Cleanup(func() { localClient, upFlagSet, Stdout, Stderr = oldClient, oldFlags, oldOut, oldErr })
			var output bytes.Buffer
			Stdout, Stderr = &output, &output
			var args upArgsT
			upFlagSet = newUpFlagSet(effectiveGOOS(), &args, "up")
			if err := upFlagSet.Parse([]string{"--enable-login-beacon", "--json"}); err != nil {
				t.Fatal(err)
			}
			var notifications bytes.Buffer
			enc := json.NewEncoder(&notifications)
			needsLogin, running := ipn.NeedsLogin, ipn.Running
			authURL := "https://login.tailscale.com/a/test"
			enc.Encode(ipn.Notify{State: &needsLogin})
			enc.Encode(ipn.Notify{BrowseToURL: &authURL})
			enc.Encode(ipn.Notify{State: &running})
			watched, loginStarted, stopped := false, false, false
			attemptID := ""
			localClient = local.Client{OmitAuth: true, Transport: beaconRoundTripper(func(r *http.Request) (*http.Response, error) {
				w := httptest.NewRecorder()
				switch r.URL.Path {
				case "/localapi/v0/status":
					json.NewEncoder(w).Encode(ipnstate.Status{BackendState: ipn.NeedsLogin.String(), Self: &ipnstate.PeerStatus{}})
				case "/localapi/v0/prefs":
					json.NewEncoder(w).Encode(ipn.NewPrefs())
				case "/localapi/v0/watch-ipn-bus":
					mask, _ := ipn.NotifyInitialState.MarshalText()
					if r.URL.Query().Get("mask") != string(mask) {
						t.Error("watch omitted initial URL/state")
					}
					watched = true
					w.Write(notifications.Bytes())
				case "/localapi/v0/check-prefs":
					w.WriteHeader(http.StatusOK)
				case "/localapi/v0/start", "/localapi/v0/login-interactive":
					if !watched {
						t.Error("login began before subscription")
					}
					loginStarted = true
					w.WriteHeader(http.StatusNoContent)
				default:
					const prefix = "/localapi/v0/loginbeacon/broadcasts/"
					if !strings.HasPrefix(r.URL.Path, prefix) {
						t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
						w.WriteHeader(http.StatusNotFound)
						break
					}
					id := strings.TrimPrefix(r.URL.Path, prefix)
					if r.Method == http.MethodPut {
						if !loginStarted || attemptID != "" {
							t.Error("attempt started before login or more than once")
						}
						attemptID = id
						var config api.Broadcast
						if err := json.NewDecoder(r.Body).Decode(&config); err != nil || !config.Expires.After(time.Now()) || time.Until(config.Expires) > 10*time.Minute {
							t.Errorf("unbounded attempt: %+v, %v", config, err)
						}
						if mode == "cancel-during-start" {
							cancel()
							return nil, context.Canceled
						}
					} else if r.Method == http.MethodDelete {
						if id != attemptID || r.Context().Err() != nil {
							t.Error("cleanup used wrong identity or canceled context")
						}
						stopped = true
					} else {
						t.Errorf("unexpected broadcast method: %s", r.Method)
					}
					w.WriteHeader(http.StatusNoContent)
				}
				return w.Result(), nil
			})}
			err := runUp(ctx, "up", nil, args)
			if (err == nil) != (mode == "complete") {
				t.Fatalf("runUp error = %v", err)
			}
			if attemptID == "" || !stopped {
				t.Fatal("login attempt was not started and cleaned up")
			}
		})
	}
}
