// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package localapi_test

import (
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/ipn/lapitest"
)

func TestResumeIPNBus(t *testing.T) {
	s := lapitest.NewServer(t, lapitest.WithLogging(false))
	c := s.Client()
	ctx := t.Context()

	if err := c.ResumeIPNBus(ctx, "bogus"); err == nil {
		t.Fatal("ResumeIPNBus of an unknown session succeeded; want error")
	}

	w, _ := c.WatchIPNBus(ctx, ipn.NotifyInitialState|ipn.NotifySuspendWhenBehind)
	ini, err := w.Next()
	if err != nil {
		t.Fatal(err)
	}
	if ini.SessionID == "" {
		t.Fatal("initial notification has no SessionID")
	}

	if err := s.Backend().SuspendWatchNotifications(ini.SessionID); err != nil {
		t.Fatalf("SuspendWatchNotifications: %v", err)
	}

	// What was already on the wire still arrives, then the suspension.
	n, err := w.Next()
	for ; err == nil && !n.Suspended; n, err = w.Next() {
	}
	if err != nil {
		t.Fatal(err)
	}

	// Resuming replays the initial notification.
	if err := c.ResumeIPNBus(ctx, ini.SessionID); err != nil {
		t.Fatalf("ResumeIPNBus: %v", err)
	}
	again, err := w.Next()
	if err != nil {
		t.Fatal(err)
	}
	if again.SessionID != ini.SessionID || again.State == nil {
		t.Errorf("after resume got %v; want initial notification %v", again, ini)
	}
}
