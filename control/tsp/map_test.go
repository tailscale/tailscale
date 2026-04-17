// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsp

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/key"
)

func TestMapAgainstTestControl(t *testing.T) {
	ctrl := &testcontrol.Server{}
	ctrl.HTTPTestServer = httptest.NewUnstartedServer(ctrl)
	ctrl.HTTPTestServer.Start()
	t.Cleanup(ctrl.HTTPTestServer.Close)
	baseURL := ctrl.HTTPTestServer.URL

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverKey, err := DiscoverServerKey(ctx, baseURL)
	if err != nil {
		t.Fatalf("DiscoverServerKey: %v", err)
	}

	register := func(hostname string) (nodeKey key.NodePrivate, machineKey key.MachinePrivate) {
		t.Helper()
		nodeKey = key.NewNode()
		machineKey = key.NewMachine()
		c, err := NewClient(ClientOpts{
			ServerURL:  baseURL,
			MachineKey: machineKey,
		})
		if err != nil {
			t.Fatalf("NewClient %s: %v", hostname, err)
		}
		defer c.Close()
		c.SetControlPublicKey(serverKey)
		if _, err := c.Register(ctx, RegisterOpts{
			NodeKey:  nodeKey,
			Hostinfo: &tailcfg.Hostinfo{Hostname: hostname},
		}); err != nil {
			t.Fatalf("Register %s: %v", hostname, err)
		}
		return nodeKey, machineKey
	}

	nodeKeyA, machineKeyA := register("a")
	nodeKeyB, _ := register("b")

	clientA, err := NewClient(ClientOpts{
		ServerURL:  baseURL,
		MachineKey: machineKeyA,
	})
	if err != nil {
		t.Fatalf("NewClient A: %v", err)
	}
	defer clientA.Close()
	clientA.SetControlPublicKey(serverKey)

	session, err := clientA.Map(ctx, MapOpts{
		NodeKey:  nodeKeyA,
		Hostinfo: &tailcfg.Hostinfo{Hostname: "a"},
		Stream:   true,
	})
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	defer session.Close()

	// nextNonKeepalive returns the next non-keepalive MapResponse, to keep
	// the test robust if a server-side keepalive arrives mid-test.
	nextNonKeepalive := func() *tailcfg.MapResponse {
		t.Helper()
		for {
			resp, err := session.Next()
			if err != nil {
				t.Fatalf("session.Next: %v", err)
			}
			if resp.KeepAlive {
				continue
			}
			return resp
		}
	}

	// First MapResponse: expect node A as self and node B in Peers.
	first := nextNonKeepalive()
	if first.Node == nil {
		t.Fatal("first response has nil Node")
	}
	if got, want := first.Node.Key, nodeKeyA.Public(); got != want {
		t.Errorf("first Node.Key = %v, want %v", got, want)
	}
	var foundB bool
	for _, p := range first.Peers {
		if p.Key == nodeKeyB.Public() {
			foundB = true
			break
		}
	}
	if !foundB {
		t.Errorf("peer B (%v) not in first response's Peers (%d peers)", nodeKeyB.Public(), len(first.Peers))
	}

	// Inject raw MapResponses and verify they come out the reader, in order.
	// msgToSend is single-slot, so we must consume each before injecting the next.
	for i := range 3 {
		want := fmt.Sprintf("injected-%d.example.com", i)
		inject := &tailcfg.MapResponse{Domain: want}
		if !ctrl.AddRawMapResponse(nodeKeyA.Public(), inject) {
			t.Fatalf("AddRawMapResponse %d: node not connected", i)
		}
		got := nextNonKeepalive()
		if got.Domain != want {
			t.Errorf("injected %d: got Domain=%q, want %q", i, got.Domain, want)
		}
	}
}

// TestSendMapUpdateAgainstTestControl verifies that a [Client.SendMapUpdate]
// call from one node lands on the coordination server and that peer nodes
// subsequently observe the updated DiscoKey via their own streaming map poll.
func TestSendMapUpdateAgainstTestControl(t *testing.T) {
	ctrl := &testcontrol.Server{}
	ctrl.HTTPTestServer = httptest.NewUnstartedServer(ctrl)
	ctrl.HTTPTestServer.Start()
	t.Cleanup(ctrl.HTTPTestServer.Close)
	baseURL := ctrl.HTTPTestServer.URL

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverKey, err := DiscoverServerKey(ctx, baseURL)
	if err != nil {
		t.Fatalf("DiscoverServerKey: %v", err)
	}

	register := func(hostname string) (nodeKey key.NodePrivate, machineKey key.MachinePrivate) {
		t.Helper()
		nodeKey = key.NewNode()
		machineKey = key.NewMachine()
		c, err := NewClient(ClientOpts{
			ServerURL:  baseURL,
			MachineKey: machineKey,
		})
		if err != nil {
			t.Fatalf("NewClient %s: %v", hostname, err)
		}
		defer c.Close()
		c.SetControlPublicKey(serverKey)
		if _, err := c.Register(ctx, RegisterOpts{
			NodeKey:  nodeKey,
			Hostinfo: &tailcfg.Hostinfo{Hostname: hostname},
		}); err != nil {
			t.Fatalf("Register %s: %v", hostname, err)
		}
		return nodeKey, machineKey
	}

	nodeKeyA, machineKeyA := register("a")
	nodeKeyB, machineKeyB := register("b")

	// B starts a streaming map poll so we can observe updates about peer A.
	clientB, err := NewClient(ClientOpts{
		ServerURL:  baseURL,
		MachineKey: machineKeyB,
	})
	if err != nil {
		t.Fatalf("NewClient B: %v", err)
	}
	defer clientB.Close()
	clientB.SetControlPublicKey(serverKey)

	session, err := clientB.Map(ctx, MapOpts{
		NodeKey:  nodeKeyB,
		Hostinfo: &tailcfg.Hostinfo{Hostname: "b"},
		Stream:   true,
	})
	if err != nil {
		t.Fatalf("Map B: %v", err)
	}
	defer session.Close()

	nextNonKeepalive := func() *tailcfg.MapResponse {
		t.Helper()
		for {
			resp, err := session.Next()
			if err != nil {
				t.Fatalf("session.Next: %v", err)
			}
			if resp.KeepAlive {
				continue
			}
			return resp
		}
	}

	// Drain B's initial MapResponse. A should be present as a peer with a
	// zero DiscoKey (it never pushed one).
	first := nextNonKeepalive()
	var initialA *tailcfg.Node
	for _, p := range first.Peers {
		if p.Key == nodeKeyA.Public() {
			initialA = p
			break
		}
	}
	if initialA == nil {
		t.Fatalf("peer A (%v) not in B's first MapResponse", nodeKeyA.Public())
	}
	if !initialA.DiscoKey.IsZero() {
		t.Fatalf("peer A initial DiscoKey = %v, want zero", initialA.DiscoKey)
	}

	// A pushes its disco key via SendMapUpdate.
	clientA, err := NewClient(ClientOpts{
		ServerURL:  baseURL,
		MachineKey: machineKeyA,
	})
	if err != nil {
		t.Fatalf("NewClient A: %v", err)
	}
	defer clientA.Close()
	clientA.SetControlPublicKey(serverKey)

	wantDisco := key.NewDisco().Public()
	if err := clientA.SendMapUpdate(ctx, SendMapUpdateOpts{
		NodeKey:  nodeKeyA,
		DiscoKey: wantDisco,
		Hostinfo: &tailcfg.Hostinfo{Hostname: "a"},
	}); err != nil {
		t.Fatalf("SendMapUpdate: %v", err)
	}

	// B should now observe A's new DiscoKey in a subsequent MapResponse.
	for {
		resp := nextNonKeepalive()
		for _, p := range resp.Peers {
			if p.Key != nodeKeyA.Public() {
				continue
			}
			if p.DiscoKey == wantDisco {
				return // success
			}
		}
	}
}

// newTestPipeline builds the same framedReader → zstd → boundedReader →
// json.Decoder pipeline that [Client.Map] builds for a live session, but
// feeds it from a raw byte slice. Returned jdec can be used with Decode to
// pull out MapResponses.
func newTestPipeline(t testing.TB, wire []byte, maxMessageSize int64) *json.Decoder {
	t.Helper()
	bounded := &boundedReader{max: maxMessageSize, remain: maxMessageSize}
	fr := &framedReader{
		r:          bytes.NewReader(wire),
		maxSize:    maxMessageSize,
		onNewFrame: bounded.reset,
	}
	zdec, err := zstd.NewReader(fr, zstd.WithDecoderConcurrency(1))
	if err != nil {
		t.Fatalf("zstd.NewReader: %v", err)
	}
	t.Cleanup(zdec.Close)
	bounded.r = zdec
	return json.NewDecoder(bounded)
}

// zstdFrame returns a zstd-compressed frame of b.
func zstdFrame(t testing.TB, b []byte) []byte {
	t.Helper()
	enc, err := zstd.NewWriter(io.Discard, zstd.WithEncoderConcurrency(1))
	if err != nil {
		t.Fatalf("zstd.NewWriter: %v", err)
	}
	defer enc.Close()
	return enc.EncodeAll(b, nil)
}

// wireFrame writes a 4-byte little-endian length prefix plus payload to buf.
func wireFrame(buf *bytes.Buffer, payload []byte) {
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], uint32(len(payload)))
	buf.Write(hdr[:])
	buf.Write(payload)
}

// TestMapFrameSizeTooLarge verifies that a 4-byte length prefix claiming
// a frame larger than the configured cap is rejected before any payload
// bytes are read from the stream.
func TestMapFrameSizeTooLarge(t *testing.T) {
	const max = 4 << 20
	var wire bytes.Buffer
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], (max + 1))
	wire.Write(hdr[:])

	jdec := newTestPipeline(t, wire.Bytes(), max)
	var resp tailcfg.MapResponse
	err := jdec.Decode(&resp)
	if err == nil {
		t.Fatal("Decode: got nil error, want frame-too-large")
	}
	if !strings.Contains(err.Error(), "exceeds max") {
		t.Errorf("Decode error = %q, want one containing %q", err, "exceeds max")
	}
}

// TestMapDecodedSizeTooLarge verifies that a small on-wire frame (well
// under the cap) which decompresses into a huge JSON payload is rejected.
// This is the "zstd bomb" case: a tiny compressed frame that would
// explode into a huge decoded payload for json.Decoder to consume.
func TestMapDecodedSizeTooLarge(t *testing.T) {
	const max = 4 << 20
	big := strings.Repeat("a", 5<<20) // 5 MiB of 'a'
	raw, err := json.Marshal(&tailcfg.MapResponse{Domain: big})
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(raw)) <= max {
		t.Fatalf("raw JSON unexpectedly small: %d", len(raw))
	}
	compressed := zstdFrame(t, raw)
	if int64(len(compressed)) >= max {
		t.Fatalf("compressed too large (%d); test needs a more compressible payload", len(compressed))
	}

	var wire bytes.Buffer
	wireFrame(&wire, compressed)

	jdec := newTestPipeline(t, wire.Bytes(), max)
	var resp tailcfg.MapResponse
	err = jdec.Decode(&resp)
	if err == nil {
		t.Fatal("Decode: got nil error, want decoded-size-exceeded")
	}
	if !strings.Contains(err.Error(), "exceeds max") {
		t.Errorf("Decode error = %q, want one containing %q", err, "exceeds max")
	}
}

// TestMapBudgetResetsBetweenFrames verifies that the per-message decoded
// budget is reset at each new frame boundary. Two consecutive 3-MiB frames
// should both decode successfully under a 4-MiB per-frame cap. Without the
// reset, the second frame would fail (remaining budget after frame 1 =
// 4MiB - 3MiB = 1MiB, and we'd try to read 3MiB more).
func TestMapBudgetResetsBetweenFrames(t *testing.T) {
	const max = 4 << 20
	payload := strings.Repeat("a", 3<<20)
	r1 := &tailcfg.MapResponse{Domain: payload + "-one"}
	r2 := &tailcfg.MapResponse{Domain: payload + "-two"}

	var wire bytes.Buffer
	for _, r := range []*tailcfg.MapResponse{r1, r2} {
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if int64(len(raw)) >= max {
			t.Fatalf("raw JSON size %d >= max %d; would fail budget check by itself", len(raw), max)
		}
		compressed := zstdFrame(t, raw)
		if int64(len(compressed)) >= max {
			t.Fatalf("compressed size %d >= max %d", len(compressed), max)
		}
		wireFrame(&wire, compressed)
	}

	jdec := newTestPipeline(t, wire.Bytes(), max)

	var got1, got2 tailcfg.MapResponse
	if err := jdec.Decode(&got1); err != nil {
		t.Fatalf("first Decode: %v", err)
	}
	if got1.Domain != r1.Domain {
		t.Errorf("first Domain mismatch (len %d vs %d)", len(got1.Domain), len(r1.Domain))
	}
	if err := jdec.Decode(&got2); err != nil {
		t.Fatalf("second Decode: %v", err)
	}
	if got2.Domain != r2.Domain {
		t.Errorf("second Domain mismatch (len %d vs %d)", len(got2.Domain), len(r2.Domain))
	}
}
