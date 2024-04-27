// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package controlclient

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/hostinfo"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestNewDirect(t *testing.T) {
	hi := hostinfo.New()
	ni := tailcfg.NetInfo{LinkType: "wired"}
	hi.NetInfo = &ni

	k := key.NewMachine()
	opts := Options{
		ServerURL: "https://example.com",
		Hostinfo:  hi,
		GetMachinePrivateKey: func() (key.MachinePrivate, error) {
			return k, nil
		},
		Dialer: tsdial.NewDialer(netmon.NewStatic()),
	}
	c, err := NewDirect(opts)
	if err != nil {
		t.Fatal(err)
	}

	if c.serverURL != opts.ServerURL {
		t.Errorf("c.serverURL got %v want %v", c.serverURL, opts.ServerURL)
	}

	// hi is stored without its NetInfo field.
	hiWithoutNi := *hi
	hiWithoutNi.NetInfo = nil
	if !hiWithoutNi.Equal(c.hostinfo) {
		t.Errorf("c.hostinfo got %v want %v", c.hostinfo, hi)
	}

	changed := c.SetNetInfo(&ni)
	if changed {
		t.Errorf("c.SetNetInfo(ni) want false got %v", changed)
	}
	ni = tailcfg.NetInfo{LinkType: "wifi"}
	changed = c.SetNetInfo(&ni)
	if !changed {
		t.Errorf("c.SetNetInfo(ni) want true got %v", changed)
	}

	changed = c.SetHostinfo(hi)
	if changed {
		t.Errorf("c.SetHostinfo(hi) want false got %v", changed)
	}
	hi = hostinfo.New()
	hi.Hostname = "different host name"
	changed = c.SetHostinfo(hi)
	if !changed {
		t.Errorf("c.SetHostinfo(hi) want true got %v", changed)
	}

	endpoints := fakeEndpoints(1, 2, 3)
	changed = c.newEndpoints(endpoints)
	if !changed {
		t.Errorf("c.newEndpoints want true got %v", changed)
	}
	changed = c.newEndpoints(endpoints)
	if changed {
		t.Errorf("c.newEndpoints want false got %v", changed)
	}
	endpoints = fakeEndpoints(4, 5, 6)
	changed = c.newEndpoints(endpoints)
	if !changed {
		t.Errorf("c.newEndpoints want true got %v", changed)
	}
}

func fakeEndpoints(ports ...uint16) (ret []tailcfg.Endpoint) {
	for _, port := range ports {
		ret = append(ret, tailcfg.Endpoint{
			Addr: netip.AddrPortFrom(netip.Addr{}, port),
		})
	}
	return
}

func TestTsmpPing(t *testing.T) {
	hi := hostinfo.New()
	ni := tailcfg.NetInfo{LinkType: "wired"}
	hi.NetInfo = &ni

	k := key.NewMachine()
	opts := Options{
		ServerURL: "https://example.com",
		Hostinfo:  hi,
		GetMachinePrivateKey: func() (key.MachinePrivate, error) {
			return k, nil
		},
		Dialer: tsdial.NewDialer(netmon.NewStatic()),
	}

	c, err := NewDirect(opts)
	if err != nil {
		t.Fatal(err)
	}

	pingRes := &tailcfg.PingResponse{
		Type:     "TSMP",
		IP:       "123.456.7890",
		Err:      "",
		NodeName: "testnode",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		body := new(ipnstate.PingResult)
		if err := json.NewDecoder(r.Body).Decode(body); err != nil {
			t.Fatal(err)
		}
		if pingRes.IP != body.IP {
			t.Fatalf("PingResult did not have the correct IP : got %v, expected : %v", body.IP, pingRes.IP)
		}
		w.WriteHeader(200)
	}))
	defer ts.Close()

	now := time.Now()

	pr := &tailcfg.PingRequest{
		URL: ts.URL,
	}

	err = postPingResult(now, t.Logf, c.httpc, pr, pingRes)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDecodeWrappedAuthkey(t *testing.T) {
	k, isWrapped, sig, priv := decodeWrappedAuthkey("tskey-32mjsdkdsffds9o87dsfkjlh", nil)
	if want := "tskey-32mjsdkdsffds9o87dsfkjlh"; k != want {
		t.Errorf("decodeWrappedAuthkey(<unwrapped-key>).key = %q, want %q", k, want)
	}
	if isWrapped {
		t.Error("decodeWrappedAuthkey(<unwrapped-key>).isWrapped = true, want false")
	}
	if sig != nil {
		t.Errorf("decodeWrappedAuthkey(<unwrapped-key>).sig = %v, want nil", sig)
	}
	if priv != nil {
		t.Errorf("decodeWrappedAuthkey(<unwrapped-key>).priv = %v, want nil", priv)
	}

	k, isWrapped, sig, priv = decodeWrappedAuthkey("tskey-auth-k7UagY1CNTRL-ZZZZZ--TLpAEDA1ggnXuw4/fWnNWUwcoOjLemhOvml1juMl5lhLmY5sBUsj8EWEAfL2gdeD9g8VDw5tgcxCiHGlEb67BgU2DlFzZApi4LheLJraA+pYjTGChVhpZz1iyiBPD+U2qxDQAbM3+WFY0EBlggxmVqG53Hu0Rg+KmHJFMlUhfgzo+AQP6+Kk9GzvJJOs4-k36RdoSFqaoARfQo0UncHAV0t3YTqrkD5r/z2jTrE43GZWobnce7RGD4qYckUyVSF+DOj4BA/r4qT0bO8kk6zg", nil)
	if want := "tskey-auth-k7UagY1CNTRL-ZZZZZ"; k != want {
		t.Errorf("decodeWrappedAuthkey(<wrapped-key>).key = %q, want %q", k, want)
	}
	if !isWrapped {
		t.Error("decodeWrappedAuthkey(<wrapped-key>).isWrapped = false, want true")
	}

	if sig == nil {
		t.Fatal("decodeWrappedAuthkey(<wrapped-key>).sig = nil, want non-nil signature")
	}
	sigHash := sig.SigHash()
	if !ed25519.Verify(sig.KeyID, sigHash[:], sig.Signature) {
		t.Error("signature failed to verify")
	}

	// Make sure the private is correct by using it.
	someSig := ed25519.Sign(priv, []byte{1, 2, 3, 4})
	if !ed25519.Verify(sig.WrappingPubkey, []byte{1, 2, 3, 4}, someSig) {
		t.Error("failed to use priv")
	}

}
