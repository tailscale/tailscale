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
	"tailscale.com/tailcfg"
	"tailscale.com/tka"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/types/tkatype"
)

// TODO(tom): RPC retry/backoff was broken and has been removed. Fix?

var (
	errMissingNetmap        = errors.New("missing netmap: verify that you are logged in")
	errNetworkLockNotActive = errors.New("network-lock is not active")
)

type tkaState struct {
	authority *tka.Authority
	storage   *tka.FS
}

// tkaFilterNetmapLocked checks the signatures on each node key, dropping
// nodes from the netmap who's signature does not verify.
//
// b.mu must be held.
func (b *LocalBackend) tkaFilterNetmapLocked(nm *netmap.NetworkMap) {
	if !envknob.UseWIPCode() {
		return // Feature-flag till network-lock is in Alpha.
	}
	if b.tka == nil {
		return // TKA not enabled.
	}

	toDelete := make(map[int]struct{}, len(nm.Peers))
	for i, p := range nm.Peers {
		if len(p.KeySignature) == 0 {
			b.logf("Network lock is dropping peer %v(%v) due to missing signature", p.ID, p.StableID)
			toDelete[i] = struct{}{}
		} else {
			if err := b.tka.authority.NodeKeyAuthorized(p.Key, p.KeySignature); err != nil {
				b.logf("Network lock is dropping peer %v(%v) due to failed signature check: %v", p.ID, p.StableID, err)
				toDelete[i] = struct{}{}
			}
		}
	}

	// nm.Peers is ordered, so deletion must be order-preserving.
	peers := make([]*tailcfg.Node, 0, len(nm.Peers))
	for i, p := range nm.Peers {
		if _, delete := toDelete[i]; !delete {
			peers = append(peers, p)
		}
	}
	nm.Peers = peers
}

// tkaSyncIfNeeded examines TKA info reported from the control plane,
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
// tkaSyncIfNeeded immediately takes b.takeSyncLock which is held throughout,
// and may take b.mu as required.
func (b *LocalBackend) tkaSyncIfNeeded(nm *netmap.NetworkMap) error {
	if !envknob.UseWIPCode() {
		// If the feature flag is not enabled, pretend we don't exist.
		return nil
	}

	b.tkaSyncLock.Lock() // take tkaSyncLock to make this function an exclusive section.
	defer b.tkaSyncLock.Unlock()
	b.mu.Lock() // take mu to protect access to synchronized fields.
	defer b.mu.Unlock()

	ourNodeKey := b.prefs.Persist.PrivateNodeKey.Public()

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
		bs, err := b.tkaFetchBootstrap(ourNodeKey, ourHead)
		b.mu.Lock()
		if err != nil {
			return fmt.Errorf("fetching bootstrap: %w", err)
		}

		if wantEnabled && !isEnabled {
			if err := b.tkaBootstrapFromGenesisLocked(bs.GenesisAUM); err != nil {
				return fmt.Errorf("bootstrap: %w", err)
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
		if err := b.tkaSyncLocked(ourNodeKey); err != nil {
			return fmt.Errorf("tka sync: %w", err)
		}
	}

	return nil
}

func toSyncOffer(head string, ancestors []string) (tka.SyncOffer, error) {
	var out tka.SyncOffer
	if err := out.Head.UnmarshalText([]byte(head)); err != nil {
		return tka.SyncOffer{}, fmt.Errorf("head.UnmarshalText: %v", err)
	}
	out.Ancestors = make([]tka.AUMHash, len(ancestors))
	for i, a := range ancestors {
		if err := out.Ancestors[i].UnmarshalText([]byte(a)); err != nil {
			return tka.SyncOffer{}, fmt.Errorf("ancestor[%d].UnmarshalText: %v", i, err)
		}
	}
	return out, nil
}

// tkaSyncLocked synchronizes TKA state with control. b.mu must be held
// and tka must be initialized. b.mu will be stepped out of (and back into)
// during network RPCs.
//
// b.mu must be held.
func (b *LocalBackend) tkaSyncLocked(ourNodeKey key.NodePublic) error {
	offer, err := b.tka.authority.SyncOffer(b.tka.storage)
	if err != nil {
		return fmt.Errorf("offer: %w", err)
	}

	b.mu.Unlock()
	offerResp, err := b.tkaDoSyncOffer(ourNodeKey, offer)
	b.mu.Lock()
	if err != nil {
		return fmt.Errorf("offer RPC: %w", err)
	}
	controlOffer, err := toSyncOffer(offerResp.Head, offerResp.Ancestors)
	if err != nil {
		return fmt.Errorf("control offer: %v", err)
	}

	if controlOffer.Head == offer.Head {
		// We are up to date.
		return nil
	}

	// Compute missing AUMs before we apply any AUMs from the control-plane,
	// so we still submit AUMs to control even if they are not part of the
	// active chain.
	toSendAUMs, err := b.tka.authority.MissingAUMs(b.tka.storage, controlOffer)
	if err != nil {
		return fmt.Errorf("computing missing AUMs: %w", err)
	}

	// If we got this far, then we are not up to date. Either the control-plane
	// has updates for us, or we have updates for the control plane.
	//
	// TODO(tom): Do we want to keep processing even if the Inform fails? Need
	// to think through if theres holdback concerns here or not.
	if len(offerResp.MissingAUMs) > 0 {
		aums := make([]tka.AUM, len(offerResp.MissingAUMs))
		for i, a := range offerResp.MissingAUMs {
			if err := aums[i].Unserialize(a); err != nil {
				return fmt.Errorf("MissingAUMs[%d]: %v", i, err)
			}
		}

		if err := b.tka.authority.Inform(b.tka.storage, aums); err != nil {
			return fmt.Errorf("inform failed: %v", err)
		}
	}

	// NOTE(tom): We could short-circuit here if our HEAD equals the
	// control-plane's head, but we don't just so control always has a
	// copy of all forks that clients had.

	b.mu.Unlock()
	sendResp, err := b.tkaDoSyncSend(ourNodeKey, toSendAUMs, false)
	b.mu.Lock()
	if err != nil {
		return fmt.Errorf("send RPC: %v", err)
	}

	var remoteHead tka.AUMHash
	if err := remoteHead.UnmarshalText([]byte(sendResp.Head)); err != nil {
		return fmt.Errorf("head unmarshal: %v", err)
	}
	if remoteHead != b.tka.authority.Head() {
		b.logf("TKA desync: expected consensus after sync but our head is %v and the control plane's is %v", b.tka.authority.Head(), remoteHead)
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
	if err := b.CanSupportNetworkLock(); err != nil {
		return err
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

// CanSupportNetworkLock returns nil if tailscaled is able to operate
// a local tailnet key authority (and hence enforce network lock).
func (b *LocalBackend) CanSupportNetworkLock() error {
	if !envknob.UseWIPCode() {
		return errors.New("this feature is not yet complete, a later release may support this functionality")
	}

	if b.tka != nil {
		// If the TKA is being used, it is supported.
		return nil
	}

	if b.TailscaleVarRoot() == "" {
		return errors.New("network-lock is not supported in this configuration, try setting --statedir")
	}

	// There's a var root (aka --statedir), so if network lock gets
	// initialized we have somewhere to store our AUMs. That's all
	// we need.
	return nil
}

// NetworkLockStatus returns a structure describing the state of the
// tailnet key authority, if any.
func (b *LocalBackend) NetworkLockStatus() *ipnstate.NetworkLockStatus {
	b.mu.Lock()
	defer b.mu.Unlock()

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
	if err := b.CanSupportNetworkLock(); err != nil {
		return err
	}

	var ourNodeKey key.NodePublic
	b.mu.Lock()
	if b.prefs != nil {
		ourNodeKey = b.prefs.Persist.PrivateNodeKey.Public()
	}
	b.mu.Unlock()
	if ourNodeKey.IsZero() {
		return errors.New("no node-key: is tailscale logged in?")
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
	initResp, err := b.tkaInitBegin(ourNodeKey, genesisAUM)
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
	_, err = b.tkaInitFinish(ourNodeKey, sigs)
	return err
}

// Only use is in tests.
func (b *LocalBackend) NetworkLockVerifySignatureForTest(nks tkatype.MarshaledSignature, nodeKey key.NodePublic) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.tka == nil {
		return errNetworkLockNotActive
	}
	return b.tka.authority.NodeKeyAuthorized(nodeKey, nks)
}

// Only use is in tests.
func (b *LocalBackend) NetworkLockKeyTrustedForTest(keyID tkatype.KeyID) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.tka == nil {
		panic("network lock not initialized")
	}
	return b.tka.authority.KeyTrusted(keyID)
}

// NetworkLockModify adds and/or removes keys in the tailnet's key authority.
func (b *LocalBackend) NetworkLockModify(addKeys, removeKeys []tka.Key) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("modify network-lock keys: %w", err)
		}
	}()

	b.mu.Lock()
	defer b.mu.Unlock()

	if err := b.CanSupportNetworkLock(); err != nil {
		return err
	}
	if b.tka == nil {
		return errNetworkLockNotActive
	}

	updater := b.tka.authority.NewUpdater(b.nlPrivKey)

	for _, addKey := range addKeys {
		if err := updater.AddKey(addKey); err != nil {
			return err
		}
	}
	for _, removeKey := range removeKeys {
		if err := updater.RemoveKey(removeKey.ID()); err != nil {
			return err
		}
	}

	aums, err := updater.Finalize(b.tka.storage)
	if err != nil {
		return err
	}

	if len(aums) == 0 {
		return nil
	}

	ourNodeKey := b.prefs.Persist.PrivateNodeKey.Public()
	b.mu.Unlock()
	resp, err := b.tkaDoSyncSend(ourNodeKey, aums, true)
	b.mu.Lock()
	if err != nil {
		return err
	}

	var controlHead tka.AUMHash
	if err := controlHead.UnmarshalText([]byte(resp.Head)); err != nil {
		return err
	}

	lastHead := aums[len(aums)-1].Hash()
	if controlHead != lastHead {
		return errors.New("central tka head differs from submitted AUM, try again")
	}

	return nil
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

func (b *LocalBackend) tkaInitBegin(ourNodeKey key.NodePublic, aum tka.AUM) (*tailcfg.TKAInitBeginResponse, error) {
	var req bytes.Buffer
	if err := json.NewEncoder(&req).Encode(tailcfg.TKAInitBeginRequest{
		Version:    tailcfg.CurrentCapabilityVersion,
		NodeKey:    ourNodeKey,
		GenesisAUM: aum.Serialize(),
	}); err != nil {
		return nil, fmt.Errorf("encoding request: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	req2, err := http.NewRequestWithContext(ctx, "GET", "https://unused/machine/tka/init/begin", &req)
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
	a := new(tailcfg.TKAInitBeginResponse)
	err = json.NewDecoder(res.Body).Decode(a)
	res.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("decoding JSON: %w", err)
	}

	return a, nil
}

func (b *LocalBackend) tkaInitFinish(ourNodeKey key.NodePublic, nks map[tailcfg.NodeID]tkatype.MarshaledSignature) (*tailcfg.TKAInitFinishResponse, error) {
	var req bytes.Buffer
	if err := json.NewEncoder(&req).Encode(tailcfg.TKAInitFinishRequest{
		Version:    tailcfg.CurrentCapabilityVersion,
		NodeKey:    ourNodeKey,
		Signatures: nks,
	}); err != nil {
		return nil, fmt.Errorf("encoding request: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	req2, err := http.NewRequestWithContext(ctx, "GET", "https://unused/machine/tka/init/finish", &req)
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
	a := new(tailcfg.TKAInitFinishResponse)
	err = json.NewDecoder(res.Body).Decode(a)
	res.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("decoding JSON: %w", err)
	}

	return a, nil
}

// tkaFetchBootstrap sends a /machine/tka/bootstrap RPC to the control plane
// over noise. This is used to get values necessary to enable or disable TKA.
func (b *LocalBackend) tkaFetchBootstrap(ourNodeKey key.NodePublic, head tka.AUMHash) (*tailcfg.TKABootstrapResponse, error) {
	bootstrapReq := tailcfg.TKABootstrapRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: ourNodeKey,
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

func fromSyncOffer(offer tka.SyncOffer) (head string, ancestors []string, err error) {
	headBytes, err := offer.Head.MarshalText()
	if err != nil {
		return "", nil, fmt.Errorf("head.MarshalText: %v", err)
	}

	ancestors = make([]string, len(offer.Ancestors))
	for i, ancestor := range offer.Ancestors {
		hash, err := ancestor.MarshalText()
		if err != nil {
			return "", nil, fmt.Errorf("ancestor[%d].MarshalText: %v", i, err)
		}
		ancestors[i] = string(hash)
	}
	return string(headBytes), ancestors, nil
}

// tkaDoSyncOffer sends a /machine/tka/sync/offer RPC to the control plane
// over noise. This is the first of two RPCs implementing tka synchronization.
func (b *LocalBackend) tkaDoSyncOffer(ourNodeKey key.NodePublic, offer tka.SyncOffer) (*tailcfg.TKASyncOfferResponse, error) {
	head, ancestors, err := fromSyncOffer(offer)
	if err != nil {
		return nil, fmt.Errorf("encoding offer: %v", err)
	}
	syncReq := tailcfg.TKASyncOfferRequest{
		Version:   tailcfg.CurrentCapabilityVersion,
		NodeKey:   ourNodeKey,
		Head:      head,
		Ancestors: ancestors,
	}

	var req bytes.Buffer
	if err := json.NewEncoder(&req).Encode(syncReq); err != nil {
		return nil, fmt.Errorf("encoding request: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	req2, err := http.NewRequestWithContext(ctx, "GET", "https://unused/machine/tka/sync/offer", &req)
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
	a := new(tailcfg.TKASyncOfferResponse)
	err = json.NewDecoder(res.Body).Decode(a)
	res.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("decoding JSON: %w", err)
	}

	return a, nil
}

// tkaDoSyncSend sends a /machine/tka/sync/send RPC to the control plane
// over noise. This is the second of two RPCs implementing tka synchronization.
func (b *LocalBackend) tkaDoSyncSend(ourNodeKey key.NodePublic, aums []tka.AUM, interactive bool) (*tailcfg.TKASyncSendResponse, error) {
	sendReq := tailcfg.TKASyncSendRequest{
		Version:     tailcfg.CurrentCapabilityVersion,
		NodeKey:     ourNodeKey,
		MissingAUMs: make([]tkatype.MarshaledAUM, len(aums)),
		Interactive: interactive,
	}
	for i, a := range aums {
		sendReq.MissingAUMs[i] = a.Serialize()
	}

	var req bytes.Buffer
	if err := json.NewEncoder(&req).Encode(sendReq); err != nil {
		return nil, fmt.Errorf("encoding request: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	req2, err := http.NewRequestWithContext(ctx, "GET", "https://unused/machine/tka/sync/send", &req)
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
	a := new(tailcfg.TKASyncSendResponse)
	err = json.NewDecoder(res.Body).Decode(a)
	res.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("decoding JSON: %w", err)
	}

	return a, nil
}
