// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnlocal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/logtail/backoff"
	"tailscale.com/tailcfg"
	"tailscale.com/tka"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/types/tkatype"
)

var networkLockAvailable = envknob.RegisterBool("TS_EXPERIMENTAL_NETWORK_LOCK")

type tkaState struct {
	authority *tka.Authority
	storage   *tka.FS
}

// tkaSyncIfNeededLocked examines TKA info reported from the control plane,
// performing the steps necessary to synchronize local tka state.
//
// There are 4 scenarios handled here:
//   - Enablement: nm.TKAEnabled but b.tka == nil
//     ∴ reach out to /machine/tka/bootstrap to get the genesis AUM, then
//     initialize TKA.
//   - Disablement: !nm.TKAEnabled but b.tka != nil
//     ∴ reach out to /machine/tka/bootstrap to read the disablement secret,
//     then verify and clear tka local state.
//   - Sync needed: b.tka.Head != nm.TKAHead
//     ∴ complete multi-step synchronization flow.
//   - Everything up to date: All other cases.
//     ∴ no action necessary.
//
// b.mu must be held. b.mu will be stepped out of (and back in) during network
// RPCs.
func (b *LocalBackend) tkaSyncIfNeededLocked(nm *netmap.NetworkMap) error {
	if !networkLockAvailable() {
		// If the feature flag is not enabled, pretend we don't exist.
		return nil
	}
	if nm.SelfNode == nil {
		return errors.New("SelfNode missing")
	}

	isEnabled := b.tka != nil
	wantEnabled := nm.TKAEnabled
	if isEnabled != wantEnabled {
		var ourHead tka.AUMHash
		if b.tka != nil {
			ourHead = b.tka.authority.Head()
		}

		// Regardless of whether we are moving to disabled or enabled, we
		// need information from the tka bootstrap endpoint.
		b.mu.Unlock()
		bs, err := b.tkaFetchBootstrap(nm.SelfNode.ID, ourHead)
		b.mu.Lock()
		if err != nil {
			return fmt.Errorf("fetching bootstrap: %v", err)
		}

		if wantEnabled && !isEnabled {
			if err := b.tkaBootstrapFromGenesisLocked(bs.GenesisAUM); err != nil {
				return fmt.Errorf("bootstrap: %v", err)
			}
			isEnabled = true
		} else if !wantEnabled && isEnabled {
			if b.tka.authority.ValidDisablement(bs.DisablementSecret) {
				b.tka = nil
				isEnabled = false

				if err := os.RemoveAll(b.chonkPath()); err != nil {
					return fmt.Errorf("os.RemoveAll: %v", err)
				}
			} else {
				b.logf("Disablement secret did not verify, leaving TKA enabled.")
			}
		} else {
			return fmt.Errorf("[bug] unreachable invariant of wantEnabled /w isEnabled")
		}
	}

	if isEnabled && b.tka.authority.Head() != nm.TKAHead {
		// TODO(tom): Implement sync
	}

	return nil
}

// chonkPath returns the absolute path to the directory in which TKA
// state (the 'tailchonk') is stored.
func (b *LocalBackend) chonkPath() string {
	return filepath.Join(b.TailscaleVarRoot(), "tka")
}

// tkaBootstrapFromGenesisLocked initializes the local (on-disk) state of the
// tailnet key authority, based on the given genesis AUM.
//
// b.mu must be held.
func (b *LocalBackend) tkaBootstrapFromGenesisLocked(g tkatype.MarshaledAUM) error {
	if !b.CanSupportNetworkLock() {
		return errors.New("network lock not supported in this configuration")
	}

	var genesis tka.AUM
	if err := genesis.Unserialize(g); err != nil {
		return fmt.Errorf("reading genesis: %v", err)
	}

	chonkDir := b.chonkPath()
	if err := os.Mkdir(chonkDir, 0755); err != nil && !os.IsExist(err) {
		return fmt.Errorf("mkdir: %v", err)
	}

	chonk, err := tka.ChonkDir(chonkDir)
	if err != nil {
		return fmt.Errorf("chonk: %v", err)
	}
	authority, err := tka.Bootstrap(chonk, genesis)
	if err != nil {
		return fmt.Errorf("tka bootstrap: %v", err)
	}

	b.tka = &tkaState{
		authority: authority,
		storage:   chonk,
	}
	return nil
}

// CanSupportNetworkLock returns true if tailscaled is able to operate
// a local tailnet key authority (and hence enforce network lock).
func (b *LocalBackend) CanSupportNetworkLock() bool {
	if b.tka != nil {
		// The TKA is being used, so yeah its supported.
		return true
	}

	if b.TailscaleVarRoot() != "" {
		// Theres a var root (aka --statedir), so if network lock gets
		// initialized we have somewhere to store our AUMs. Thats all
		// we need.
		return true
	}
	return false
}

// NetworkLockStatus returns a structure describing the state of the
// tailnet key authority, if any.
func (b *LocalBackend) NetworkLockStatus() *ipnstate.NetworkLockStatus {
	if b.tka == nil {
		return &ipnstate.NetworkLockStatus{
			Enabled:   false,
			PublicKey: b.nlPrivKey.Public(),
		}
	}

	var head [32]byte
	h := b.tka.authority.Head()
	copy(head[:], h[:])

	return &ipnstate.NetworkLockStatus{
		Enabled:   true,
		Head:      &head,
		PublicKey: b.nlPrivKey.Public(),
	}
}

// NetworkLockInit enables network-lock for the tailnet, with the tailnets'
// key authority initialized to trust the provided keys.
//
// Initialization involves two RPCs with control, termed 'begin' and 'finish'.
// The Begin RPC transmits the genesis Authority Update Message, which
// encodes the initial state of the authority, and the list of all nodes
// needing signatures is returned as a response.
// The Finish RPC submits signatures for all these nodes, at which point
// Control has everything it needs to atomically enable network lock.
func (b *LocalBackend) NetworkLockInit(keys []tka.Key) error {
	if b.tka != nil {
		return errors.New("network-lock is already initialized")
	}
	if !networkLockAvailable() {
		return errors.New("this is an experimental feature in your version of tailscale - Please upgrade to the latest to use this.")
	}
	if !b.CanSupportNetworkLock() {
		return errors.New("network-lock is not supported in this configuration. Did you supply a --statedir?")
	}
	nm := b.NetMap()
	if nm == nil {
		return errors.New("no netmap: are you logged into tailscale?")
	}

	// Generates a genesis AUM representing trust in the provided keys.
	// We use an in-memory tailchonk because we don't want to commit to
	// the filesystem until we've finished the initialization sequence,
	// just in case something goes wrong.
	_, genesisAUM, err := tka.Create(&tka.Mem{}, tka.State{
		Keys: keys,
		// TODO(tom): Actually plumb a real disablement value.
		DisablementSecrets: [][]byte{bytes.Repeat([]byte{1}, 32)},
	}, b.nlPrivKey)
	if err != nil {
		return fmt.Errorf("tka.Create: %v", err)
	}

	b.logf("Generated genesis AUM to initialize network lock, trusting the following keys:")
	for i, k := range genesisAUM.State.Keys {
		b.logf(" - key[%d] = nlpub:%x with %d votes", i, k.Public, k.Votes)
	}

	// Phase 1/2 of initialization: Transmit the genesis AUM to Control.
	initResp, err := b.tkaInitBegin(nm, genesisAUM)
	if err != nil {
		return fmt.Errorf("tka init-begin RPC: %w", err)
	}

	// Our genesis AUM was accepted but before Control turns on enforcement of
	// node-key signatures, we need to sign keys for all the existing nodes.
	// If we don't get these signatures ahead of time, everyone will loose
	// connectivity because control won't have any signatures to send which
	// satisfy network-lock checks.
	sigs := make(map[tailcfg.NodeID]tkatype.MarshaledSignature, len(initResp.NeedSignatures))
	for _, nodeInfo := range initResp.NeedSignatures {
		nks, err := signNodeKey(nodeInfo, b.nlPrivKey)
		if err != nil {
			return fmt.Errorf("generating signature: %v", err)
		}

		sigs[nodeInfo.NodeID] = nks.Serialize()
	}

	// Finalize enablement by transmitting signature for all nodes to Control.
	_, err = b.tkaInitFinish(nm, sigs)
	return err
}

func signNodeKey(nodeInfo tailcfg.TKASignInfo, signer key.NLPrivate) (*tka.NodeKeySignature, error) {
	p, err := nodeInfo.NodePublic.MarshalBinary()
	if err != nil {
		return nil, err
	}

	sig := tka.NodeKeySignature{
		SigKind:        tka.SigDirect,
		KeyID:          signer.KeyID(),
		Pubkey:         p,
		WrappingPubkey: nodeInfo.RotationPubkey,
	}
	sig.Signature, err = signer.SignNKS(sig.SigHash())
	if err != nil {
		return nil, fmt.Errorf("signature failed: %w", err)
	}
	return &sig, nil
}

func (b *LocalBackend) tkaInitBegin(nm *netmap.NetworkMap, aum tka.AUM) (*tailcfg.TKAInitBeginResponse, error) {
	var req bytes.Buffer
	if err := json.NewEncoder(&req).Encode(tailcfg.TKAInitBeginRequest{
		NodeID:     nm.SelfNode.ID,
		GenesisAUM: aum.Serialize(),
	}); err != nil {
		return nil, fmt.Errorf("encoding request: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	bo := backoff.NewBackoff("tka-init-begin", b.logf, 5*time.Second)
	for {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("ctx: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, "GET", "https://unused/machine/tka/init/begin", &req)
		if err != nil {
			return nil, fmt.Errorf("req: %w", err)
		}
		res, err := b.DoNoiseRequest(req)
		if err != nil {
			bo.BackOff(ctx, err)
			continue
		}
		if res.StatusCode != 200 {
			body, _ := io.ReadAll(res.Body)
			res.Body.Close()
			return nil, fmt.Errorf("request returned (%d): %s", res.StatusCode, string(body))
		}
		a := new(tailcfg.TKAInitBeginResponse)
		err = json.NewDecoder(res.Body).Decode(a)
		res.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("decoding JSON: %w", err)
		}

		return a, nil
	}
}

func (b *LocalBackend) tkaInitFinish(nm *netmap.NetworkMap, nks map[tailcfg.NodeID]tkatype.MarshaledSignature) (*tailcfg.TKAInitFinishResponse, error) {
	var req bytes.Buffer
	if err := json.NewEncoder(&req).Encode(tailcfg.TKAInitFinishRequest{
		NodeID:     nm.SelfNode.ID,
		Signatures: nks,
	}); err != nil {
		return nil, fmt.Errorf("encoding request: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	bo := backoff.NewBackoff("tka-init-finish", b.logf, 5*time.Second)
	for {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("ctx: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, "GET", "https://unused/machine/tka/init/finish", &req)
		if err != nil {
			return nil, fmt.Errorf("req: %w", err)
		}
		res, err := b.DoNoiseRequest(req)
		if err != nil {
			bo.BackOff(ctx, err)
			continue
		}
		if res.StatusCode != 200 {
			body, _ := io.ReadAll(res.Body)
			res.Body.Close()
			return nil, fmt.Errorf("request returned (%d): %s", res.StatusCode, string(body))
		}
		a := new(tailcfg.TKAInitFinishResponse)
		err = json.NewDecoder(res.Body).Decode(a)
		res.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("decoding JSON: %w", err)
		}

		return a, nil
	}
}

// tkaFetchBootstrap sends a /machine/tka/bootstrap RPC to the control plane
// over noise. This is used to get values necessary to enable or disable TKA.
func (b *LocalBackend) tkaFetchBootstrap(nodeID tailcfg.NodeID, head tka.AUMHash) (*tailcfg.TKABootstrapResponse, error) {
	bootstrapReq := tailcfg.TKABootstrapRequest{
		NodeID: nodeID,
	}
	if !head.IsZero() {
		head, err := head.MarshalText()
		if err != nil {
			return nil, fmt.Errorf("head.MarshalText failed: %v", err)
		}
		bootstrapReq.Head = string(head)
	}

	var req bytes.Buffer
	if err := json.NewEncoder(&req).Encode(bootstrapReq); err != nil {
		return nil, fmt.Errorf("encoding request: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("ctx: %w", err)
	}
	req2, err := http.NewRequestWithContext(ctx, "GET", "https://unused/machine/tka/bootstrap", &req)
	if err != nil {
		return nil, fmt.Errorf("req: %w", err)
	}
	res, err := b.DoNoiseRequest(req2)
	if err != nil {
		return nil, fmt.Errorf("resp: %w", err)
	}
	if res.StatusCode != 200 {
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return nil, fmt.Errorf("request returned (%d): %s", res.StatusCode, string(body))
	}
	a := new(tailcfg.TKABootstrapResponse)
	err = json.NewDecoder(res.Body).Decode(a)
	res.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("decoding JSON: %w", err)
	}

	return a, nil
}
