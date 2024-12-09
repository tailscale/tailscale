// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package keyfallback

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/nettest"
	"tailscale.com/util/must"
)

func TestHasValidControlKey(t *testing.T) {
	t.Parallel()
	keys, err := Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if keys.PublicKey.IsZero() {
		t.Fatalf("zero key")
	}
}

// TestKeyIsUpToDate fetches the control key from the control server and
// compares it to the baked-in key, to verify that it's up-to-date. If the
// control server is unreachable, the test is skipped.
func TestKeyIsUpToDate(t *testing.T) {
	nettest.SkipIfNoNetwork(t)

	// Optimistically fetch the control key and check if it's up to date,
	// but ignore if we don't have network access (e.g. running tests on an
	// airplane).
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	keyURL := fmt.Sprintf("%v/key?v=%d", ipn.DefaultControlURL, tailcfg.CurrentCapabilityVersion)
	req := must.Get(http.NewRequestWithContext(ctx, "GET", keyURL, nil))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Logf("fetch control key: %v", err)
		return
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		t.Fatalf("fetch control key: bad status; got %v, want 200", res.Status)
	}
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read control key: %v", err)
	}

	// Verify that the key is up to date and matches the baked-in key.
	out := &tailcfg.OverTLSPublicKeyResponse{}
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatalf("unmarshal control key: %v", err)
	}

	keys, err := Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if !reflect.DeepEqual(keys, out) {
		t.Errorf("control key is out of date")
		t.Logf("old key: %v", keys)
		t.Logf("new key: %v", out)
	}
}
