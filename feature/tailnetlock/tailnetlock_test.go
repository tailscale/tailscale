// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailnetlock

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/tka"
	"tailscale.com/types/key"
	"tailscale.com/util/must"
)

func TestHandleC2NDebugTKA(t *testing.T) {
	makeTKA := func(length int) (tka.CompactableChonk, *tka.Authority) {
		if length == 0 {
			return nil, nil
		}

		disablementSecret := bytes.Repeat([]byte{0xa5}, 32)
		signerKey := key.NewNLPrivate()
		key1 := tka.Key{Kind: tka.Key25519, Public: signerKey.Public().Verifier(), Votes: 2}

		chonk := tka.ChonkMem()
		authority, _, err := tka.Create(chonk, tka.State{
			Keys:              []tka.Key{key1},
			DisablementValues: [][]byte{tka.DisablementKDF(disablementSecret)},
		}, signerKey)
		if err != nil {
			t.Fatalf("tka.Create() failed: %v", err)
		}

		for range length - 1 {
			updater := authority.NewUpdater(signerKey)
			key2 := tka.Key{Kind: tka.Key25519, Public: key.NewNLPrivate().Public().Verifier(), Votes: 2}
			updater.AddKey(key2)
			aums := must.Get(updater.Finalize(chonk))
			must.Do(authority.Inform(chonk, aums))
		}

		return chonk, authority
	}

	bodyHead := func(body *bytes.Buffer) string {
		count := 0
		var sb strings.Builder
		for line := range strings.Lines(body.String()) {
			if count == 10 {
				sb.WriteString("...")
				break
			}
			sb.WriteString(line)
			count++
		}
		return sb.String()
	}

	// matches [jsonoutput.PrintNetworkLockLogJSONV1]
	type response struct {
		SchemaVersion string
		Messages      []any
	}

	t.Run("tailnet-lock-disabled", func(t *testing.T) {
		b := ipnlocal.LocalBackendWithTKAForTest(nil, nil)

		req := httptest.NewRequest("GET", "/debug/tka/log", nil)
		rec := httptest.NewRecorder()
		b.HandleC2NForTest(rec, req)

		if rec.Code != 400 {
			t.Fatalf("got status code: %v, want: 400\nBody: %s", rec.Code, rec.Body)
		}
	})

	t.Run("tailnet-lock-enabled", func(t *testing.T) {
		chonk, authority := makeTKA(2)
		b := ipnlocal.LocalBackendWithTKAForTest(chonk, authority)

		req := httptest.NewRequest("GET", "/debug/tka/log", nil)
		rec := httptest.NewRecorder()
		b.HandleC2NForTest(rec, req)

		if rec.Code != 200 {
			t.Fatalf("got status code: %v, want: 200\nBody: %s", rec.Code, bodyHead(rec.Body))
		}

		var got response
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("couldn't parse JSON: %v\nbody: %s", err, bodyHead(rec.Body))
		}

		if len(got.Messages) != 2 {
			t.Fatalf("got %d items, want 2", len(got.Messages))
		}
	})

	t.Run("default-limit", func(t *testing.T) {
		chonk, authority := makeTKA(60)
		b := ipnlocal.LocalBackendWithTKAForTest(chonk, authority)

		req := httptest.NewRequest("GET", "/debug/tka/log", nil)
		rec := httptest.NewRecorder()
		b.HandleC2NForTest(rec, req)

		if rec.Code != 200 {
			t.Fatalf("got status code: %v, want: 200\nBody: %s", rec.Code, bodyHead(rec.Body))
		}

		var got response
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("couldn't parse JSON: %v\nbody: %s", err, bodyHead(rec.Body))
		}

		if len(got.Messages) != 50 {
			t.Fatalf("got %d items, want 50", len(got.Messages))
		}
	})

	t.Run("override-limit", func(t *testing.T) {
		chonk, authority := makeTKA(65)
		b := ipnlocal.LocalBackendWithTKAForTest(chonk, authority)

		req := httptest.NewRequest("GET", "/debug/tka/log?limit=60", nil)
		rec := httptest.NewRecorder()
		b.HandleC2NForTest(rec, req)

		if rec.Code != 200 {
			t.Fatalf("got status code: %v, want: 200\nBody: %s", rec.Code, bodyHead(rec.Body))
		}

		var got response
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("couldn't parse JSON: %v\nbody: %s", err, bodyHead(rec.Body))
		}

		if len(got.Messages) != 60 {
			t.Fatalf("got %d items, want 60", len(got.Messages))
		}
	})
}
