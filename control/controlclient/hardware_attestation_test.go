// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package controlclient

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/health"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/tstime"
	"tailscale.com/types/key"
	"tailscale.com/types/persist"
	"tailscale.com/util/eventbus/eventbustest"
)

type testHardwareAttestationKey struct {
	private   *ecdsa.PrivateKey
	signCalls *atomic.Int64
	fail      bool
}

func (k *testHardwareAttestationKey) Public() crypto.PublicKey { return &k.private.PublicKey }

func (k *testHardwareAttestationKey) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	k.signCalls.Add(1)
	if k.fail {
		return nil, errors.New("hardware signer unavailable")
	}
	return ecdsa.SignASN1(rand.Reader, k.private, digest)
}

func (k *testHardwareAttestationKey) MarshalJSON() ([]byte, error) { return []byte(`{}`), nil }
func (k *testHardwareAttestationKey) UnmarshalJSON([]byte) error   { return nil }
func (k *testHardwareAttestationKey) Close() error                 { return nil }
func (k *testHardwareAttestationKey) IsZero() bool                 { return false }
func (k *testHardwareAttestationKey) Clone() key.HardwareAttestationKey {
	return &testHardwareAttestationKey{private: k.private, signCalls: k.signCalls, fail: k.fail}
}

func TestHardwareAttestationSignFailureIsNotRetried(t *testing.T) {
	control := &testcontrol.Server{Logf: t.Logf}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()
	t.Cleanup(control.HTTPTestServer.Close)

	bus := eventbustest.NewBus(t)
	dialer := tsdial.NewDialer(netmon.NewStatic())
	dialer.SetBus(bus)
	d, err := NewDirect(Options{
		Persist: persist.Persist{},
		GetMachinePrivateKey: func() (key.MachinePrivate, error) {
			return key.NewMachine(), nil
		},
		ServerURL: control.HTTPTestServer.URL,
		Clock:     tstime.StdClock{},
		Hostinfo: &tailcfg.Hostinfo{
			BackendLogID: "test-backend-log-id",
		},
		DiscoPublicKey: key.NewDisco().Public(),
		Logf:           t.Logf,
		HealthTracker:  health.NewTracker(bus),
		Dialer:         dialer,
		Bus:            bus,
	})
	if err != nil {
		t.Fatalf("NewDirect: %v", err)
	}
	t.Cleanup(func() { d.Close() })

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if _, err := d.TryLogin(ctx, LoginEphemeral); err != nil {
		t.Fatalf("TryLogin: %v", err)
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var signCalls atomic.Int64
	p := d.persist.AsStruct()
	p.AttestationKey = &testHardwareAttestationKey{
		private:   privateKey,
		signCalls: &signCalls,
		fail:      true,
	}
	d.persist = p.View()

	for range 2 {
		if err := d.SendUpdate(ctx); err != nil {
			t.Fatalf("SendUpdate: %v", err)
		}
	}
	if got, want := signCalls.Load(), int64(1); got != want {
		t.Fatalf("hardware attestation Sign calls = %d; want %d", got, want)
	}
}

func TestHardwareAttestationSuccessSignsEveryRequest(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var signCalls atomic.Int64
	k := &testHardwareAttestationKey{private: privateKey, signCalls: &signCalls}
	d := &Direct{clock: tstime.StdClock{}, logf: t.Logf}
	nodeKey := key.NewNode().Public()

	for range 2 {
		request := new(tailcfg.MapRequest)
		d.addHardwareAttestation(request, k, nodeKey)
		if request.HardwareAttestationKey.IsZero() {
			t.Fatal("hardware attestation public key is zero")
		}
		if len(request.HardwareAttestationKeySignature) == 0 {
			t.Fatal("hardware attestation signature is empty")
		}
		if request.HardwareAttestationKeySignatureTimestamp.IsZero() {
			t.Fatal("hardware attestation signature timestamp is zero")
		}
	}
	if got, want := signCalls.Load(), int64(2); got != want {
		t.Fatalf("hardware attestation Sign calls = %d; want %d", got, want)
	}
}
