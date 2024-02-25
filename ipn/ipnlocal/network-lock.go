// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"tailscale.com/health"
	"tailscale.com/health/healthmsg"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tka"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/types/persist"
	"tailscale.com/types/tkatype"
	"tailscale.com/util/mak"
)

// TODO(tom): RPC retry/backoff was broken and has been removed. Fix?

var (
	errMissingNetmap        = errors.New("missing netmap: verify that you are logged in")
	errNetworkLockNotActive = errors.New("network-lock is not active")

	tkaCompactionDefaults = tka.CompactionOptions{
		MinChain: 24,                  // Keep at minimum 24 AUMs since head.
		MinAge:   14 * 24 * time.Hour, // Keep 2 weeks of AUMs.
	}
)

type tkaState struct {
	profile   ipn.ProfileID
	authority *tka.Authority
	storage   *tka.FS
	filtered  []ipnstate.TKAFilteredPeer
}

// tkaFilterNetmapLocked checks the signatures on each node key, dropping
// nodes from the netmap whose signature does not verify.
//
// b.mu must be held.
func (b *LocalBackend) tkaFilterNetmapLocked(nm *netmap.NetworkMap) {
	if b.tka == nil && !b.capTailnetLock {
		health.SetTKAHealth(nil)
		return
	}
	if b.tka == nil {
		health.SetTKAHealth(nil)
		return // TKA not enabled.
	}

	var toDelete map[int]bool // peer index => true
	for i, p := range nm.Peers {
		if p.UnsignedPeerAPIOnly() {
			// Not subject to tailnet lock.
			continue
		}
		if p.KeySignature().Len() == 0 {
			b.logf("Network lock is dropping peer %v(%v) due to missing signature", p.ID(), p.StableID())
			mak.Set(&toDelete, i, true)
		} else {
			if err := b.tka.authority.NodeKeyAuthorized(p.Key(), p.KeySignature().AsSlice()); err != nil {
				b.logf("Network lock is dropping peer %v(%v) due to failed signature check: %v", p.ID(), p.StableID(), err)
				mak.Set(&toDelete, i, true)
			}
		}
	}

	// nm.Peers is ordered, so deletion must be order-preserving.
	if len(toDelete) > 0 {
		peers := make([]tailcfg.NodeView, 0, len(nm.Peers))
		filtered := make([]ipnstate.TKAFilteredPeer, 0, len(toDelete))
		for i, p := range nm.Peers {
			if !toDelete[i] {
				peers = append(peers, p)
			} else {
				// Record information about the node we filtered out.
				fp := ipnstate.TKAFilteredPeer{
					Name:         p.Name(),
					ID:           p.ID(),
					StableID:     p.StableID(),
					TailscaleIPs: make([]netip.Addr, p.Addresses().Len()),
					NodeKey:      p.Key(),
				}
				for i := range p.Addresses().Len() {
					addr := p.Addresses().At(i)
					if addr.IsSingleIP() && tsaddr.IsTailscaleIP(addr.Addr()) {
						fp.TailscaleIPs[i] = addr.Addr()
					}
				}
				filtered = append(filtered, fp)
			}
		}
		nm.Peers = peers
		b.tka.filtered = filtered
	} else {
		b.tka.filtered = nil
	}

	// Check that we ourselves are not locked out, report a health issue if so.
	if nm.SelfNode.Valid() && b.tka.authority.NodeKeyAuthorized(nm.SelfNode.Key(), nm.SelfNode.KeySignature().AsSlice()) != nil {
		health.SetTKAHealth(errors.New(healthmsg.LockedOut))
	} else {
		health.SetTKAHealth(nil)
	}
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
func (b *LocalBackend) tkaSyncIfNeeded(nm *netmap.NetworkMap, prefs ipn.PrefsView) error {
	b.tkaSyncLock.Lock() // take tkaSyncLock to make this function an exclusive section.
	defer b.tkaSyncLock.Unlock()
	b.mu.Lock() // take mu to protect access to synchronized fields.
	defer b.mu.Unlock()

	if b.tka == nil && !b.capTailnetLock {
		return nil
	}

	if b.tka != nil || nm.TKAEnabled {
		b.logf("tkaSyncIfNeeded: enabled=%v, head=%v", nm.TKAEnabled, nm.TKAHead)
	}

	ourNodeKey := prefs.Persist().PublicNodeKey()

	isEnabled := b.tka != nil
	wantEnabled := nm.TKAEnabled
	didJustEnable := false
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
			if err := b.tkaBootstrapFromGenesisLocked(bs.GenesisAUM, prefs.Persist()); err != nil {
				return fmt.Errorf("bootstrap: %w", err)
			}
			isEnabled = true
			didJustEnable = true
		} else if !wantEnabled && isEnabled {
			if err := b.tkaApplyDisablementLocked(bs.DisablementSecret); err != nil {
				// We log here instead of returning an error (which itself would be
				// logged), so that sync will continue even if control gives us an
				// incorrect disablement secret.
				b.logf("Disablement failed, leaving TKA enabled. Error: %v", err)
			} else {
				isEnabled = false
				health.SetTKAHealth(nil)
			}
		} else {
			return fmt.Errorf("[bug] unreachable invariant of wantEnabled w/ isEnabled")
		}
	}

	// We always transmit the sync RPCs if TKA was just enabled.
	// This informs the control plane that our TKA state is now
	// initialized to the transmitted TKA head hash.
	if isEnabled && (b.tka.authority.Head() != nm.TKAHead || didJustEnable) {
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

	// NOTE(tom): We always send this RPC so control knows what TKA
	// head we landed at.
	head := b.tka.authority.Head()
	b.mu.Unlock()
	sendResp, err := b.tkaDoSyncSend(ourNodeKey, head, toSendAUMs, false)
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

// tkaApplyDisablementLocked checks a disablement secret and locally disables
// TKA (if correct). An error is returned if disablement failed.
//
// b.mu must be held & TKA must be initialized.
func (b *LocalBackend) tkaApplyDisablementLocked(secret []byte) error {
	if b.tka.authority.ValidDisablement(secret) {
		if err := os.RemoveAll(b.chonkPathLocked()); err != nil {
			return err
		}
		b.tka = nil
		return nil
	}
	return errors.New("incorrect disablement secret")
}

// chonkPathLocked returns the absolute path to the directory in which TKA
// state (the 'tailchonk') is stored.
//
// b.mu must be held.
func (b *LocalBackend) chonkPathLocked() string {
	return filepath.Join(b.TailscaleVarRoot(), "tka-profiles", string(b.pm.CurrentProfile().ID))
}

// tkaBootstrapFromGenesisLocked initializes the local (on-disk) state of the
// tailnet key authority, based on the given genesis AUM.
//
// b.mu must be held.
func (b *LocalBackend) tkaBootstrapFromGenesisLocked(g tkatype.MarshaledAUM, persist persist.PersistView) error {
	if err := b.CanSupportNetworkLock(); err != nil {
		return err
	}

	var genesis tka.AUM
	if err := genesis.Unserialize(g); err != nil {
		return fmt.Errorf("reading genesis: %v", err)
	}

	if persist.Valid() && persist.DisallowedTKAStateIDs().Len() > 0 {
		if genesis.State == nil {
			return errors.New("invalid genesis: missing State")
		}
		bootstrapStateID := fmt.Sprintf("%d:%d", genesis.State.StateID1, genesis.State.StateID2)

		for i := 0; i < persist.DisallowedTKAStateIDs().Len(); i++ {
			stateID := persist.DisallowedTKAStateIDs().At(i)
			if stateID == bootstrapStateID {
				return fmt.Errorf("TKA with stateID of %q is disallowed on this node", stateID)
			}
		}
	}

	chonkDir := b.chonkPathLocked()
	if err := os.Mkdir(filepath.Dir(chonkDir), 0755); err != nil && !os.IsExist(err) {
		return fmt.Errorf("creating chonk root dir: %v", err)
	}
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
		profile:   b.pm.CurrentProfile().ID,
		authority: authority,
		storage:   chonk,
	}
	return nil
}

// CanSupportNetworkLock returns nil if tailscaled is able to operate
// a local tailnet key authority (and hence enforce network lock).
func (b *LocalBackend) CanSupportNetworkLock() error {
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

	var (
		nodeKey *key.NodePublic
		nlPriv  key.NLPrivate
	)
	if p := b.pm.CurrentPrefs(); p.Valid() && p.Persist().Valid() && !p.Persist().PrivateNodeKey().IsZero() {
		nkp := p.Persist().PublicNodeKey()
		nodeKey = &nkp
		nlPriv = p.Persist().NetworkLockKey()
	}

	if nlPriv.IsZero() {
		return &ipnstate.NetworkLockStatus{
			Enabled: false,
			NodeKey: nodeKey,
		}
	}
	if b.tka == nil {
		return &ipnstate.NetworkLockStatus{
			Enabled:   false,
			NodeKey:   nodeKey,
			PublicKey: nlPriv.Public(),
		}
	}

	var head [32]byte
	h := b.tka.authority.Head()
	copy(head[:], h[:])

	var selfAuthorized bool
	if b.netMap != nil {
		selfAuthorized = b.tka.authority.NodeKeyAuthorized(b.netMap.SelfNode.Key(), b.netMap.SelfNode.KeySignature().AsSlice()) == nil
	}

	keys := b.tka.authority.Keys()
	outKeys := make([]ipnstate.TKAKey, len(keys))
	for i, k := range keys {
		outKeys[i] = ipnstate.TKAKey{
			Key:      key.NLPublicFromEd25519Unsafe(k.Public),
			Metadata: k.Meta,
			Votes:    k.Votes,
		}
	}

	filtered := make([]*ipnstate.TKAFilteredPeer, len(b.tka.filtered))
	for i := 0; i < len(filtered); i++ {
		filtered[i] = b.tka.filtered[i].Clone()
	}

	stateID1, _ := b.tka.authority.StateIDs()

	return &ipnstate.NetworkLockStatus{
		Enabled:       true,
		Head:          &head,
		PublicKey:     nlPriv.Public(),
		NodeKey:       nodeKey,
		NodeKeySigned: selfAuthorized,
		TrustedKeys:   outKeys,
		FilteredPeers: filtered,
		StateID:       stateID1,
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
func (b *LocalBackend) NetworkLockInit(keys []tka.Key, disablementValues [][]byte, supportDisablement []byte) error {
	if err := b.CanSupportNetworkLock(); err != nil {
		return err
	}

	var ourNodeKey key.NodePublic
	var nlPriv key.NLPrivate
	b.mu.Lock()

	if !b.capTailnetLock {
		b.mu.Unlock()
		return errors.New("not permitted to enable tailnet lock")
	}

	if p := b.pm.CurrentPrefs(); p.Valid() && p.Persist().Valid() && !p.Persist().PrivateNodeKey().IsZero() {
		ourNodeKey = p.Persist().PublicNodeKey()
		nlPriv = p.Persist().NetworkLockKey()
	}
	b.mu.Unlock()
	if ourNodeKey.IsZero() || nlPriv.IsZero() {
		return errors.New("no node-key: is tailscale logged in?")
	}

	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return err
	}

	// Generates a genesis AUM representing trust in the provided keys.
	// We use an in-memory tailchonk because we don't want to commit to
	// the filesystem until we've finished the initialization sequence,
	// just in case something goes wrong.
	_, genesisAUM, err := tka.Create(&tka.Mem{}, tka.State{
		Keys: keys,
		// TODO(tom): s/tka.State.DisablementSecrets/tka.State.DisablementValues
		//   This will center on consistent nomenclature:
		//    - DisablementSecret: value needed to disable.
		//    - DisablementValue: the KDF of the disablement secret, a public value.
		DisablementSecrets: disablementValues,

		StateID1: binary.LittleEndian.Uint64(entropy[:8]),
		StateID2: binary.LittleEndian.Uint64(entropy[8:]),
	}, nlPriv)
	if err != nil {
		return fmt.Errorf("tka.Create: %v", err)
	}

	b.logf("Generated genesis AUM to initialize network lock, trusting the following keys:")
	for i, k := range genesisAUM.State.Keys {
		b.logf(" - key[%d] = tlpub:%x with %d votes", i, k.Public, k.Votes)
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
		nks, err := signNodeKey(nodeInfo, nlPriv)
		if err != nil {
			return fmt.Errorf("generating signature: %v", err)
		}

		sigs[nodeInfo.NodeID] = nks.Serialize()
	}

	// Finalize enablement by transmitting signature for all nodes to Control.
	_, err = b.tkaInitFinish(ourNodeKey, sigs, supportDisablement)
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

// NetworkLockForceLocalDisable shuts down TKA locally, and denylists the current
// TKA from being initialized locally in future.
func (b *LocalBackend) NetworkLockForceLocalDisable() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.tka == nil {
		return errNetworkLockNotActive
	}

	id1, id2 := b.tka.authority.StateIDs()
	stateID := fmt.Sprintf("%d:%d", id1, id2)

	newPrefs := b.pm.CurrentPrefs().AsStruct().Clone() // .Persist should always be initialized here.
	newPrefs.Persist.DisallowedTKAStateIDs = append(newPrefs.Persist.DisallowedTKAStateIDs, stateID)
	if err := b.pm.SetPrefs(newPrefs.View(), ipn.NetworkProfile{
		MagicDNSName: b.netMap.MagicDNSSuffix(),
		DomainName:   b.netMap.DomainName(),
	}); err != nil {
		return fmt.Errorf("saving prefs: %w", err)
	}

	if err := os.RemoveAll(b.chonkPathLocked()); err != nil {
		return fmt.Errorf("deleting TKA state: %w", err)
	}
	b.tka = nil
	return nil
}

// NetworkLockSign signs the given node-key and submits it to the control plane.
// rotationPublic, if specified, must be an ed25519 public key.
func (b *LocalBackend) NetworkLockSign(nodeKey key.NodePublic, rotationPublic []byte) error {
	ourNodeKey, sig, err := func(nodeKey key.NodePublic, rotationPublic []byte) (key.NodePublic, tka.NodeKeySignature, error) {
		b.mu.Lock()
		defer b.mu.Unlock()

		var nlPriv key.NLPrivate
		if p := b.pm.CurrentPrefs(); p.Valid() && p.Persist().Valid() {
			nlPriv = p.Persist().NetworkLockKey()
		}
		if nlPriv.IsZero() {
			return key.NodePublic{}, tka.NodeKeySignature{}, errMissingNetmap
		}

		if b.tka == nil {
			return key.NodePublic{}, tka.NodeKeySignature{}, errNetworkLockNotActive
		}
		if !b.tka.authority.KeyTrusted(nlPriv.KeyID()) {
			return key.NodePublic{}, tka.NodeKeySignature{}, errors.New("this node is not trusted by network lock")
		}

		p, err := nodeKey.MarshalBinary()
		if err != nil {
			return key.NodePublic{}, tka.NodeKeySignature{}, err
		}
		sig := tka.NodeKeySignature{
			SigKind:        tka.SigDirect,
			KeyID:          nlPriv.KeyID(),
			Pubkey:         p,
			WrappingPubkey: rotationPublic,
		}
		sig.Signature, err = nlPriv.SignNKS(sig.SigHash())
		if err != nil {
			return key.NodePublic{}, tka.NodeKeySignature{}, fmt.Errorf("signature failed: %w", err)
		}

		return b.pm.CurrentPrefs().Persist().PublicNodeKey(), sig, nil
	}(nodeKey, rotationPublic)
	if err != nil {
		return err
	}

	b.logf("Generated network-lock signature for %v, submitting to control plane", nodeKey)
	if _, err := b.tkaSubmitSignature(ourNodeKey, sig.Serialize()); err != nil {
		return err
	}
	return nil
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

	var ourNodeKey key.NodePublic
	if p := b.pm.CurrentPrefs(); p.Valid() && p.Persist().Valid() && !p.Persist().PrivateNodeKey().IsZero() {
		ourNodeKey = p.Persist().PublicNodeKey()
	}
	if ourNodeKey.IsZero() {
		return errors.New("no node-key: is tailscale logged in?")
	}

	var nlPriv key.NLPrivate
	if p := b.pm.CurrentPrefs(); p.Valid() && p.Persist().Valid() {
		nlPriv = p.Persist().NetworkLockKey()
	}
	if nlPriv.IsZero() {
		return errMissingNetmap
	}
	if b.tka == nil {
		return errNetworkLockNotActive
	}
	if !b.tka.authority.KeyTrusted(nlPriv.KeyID()) {
		return errors.New("this node does not have a trusted tailnet lock key")
	}

	updater := b.tka.authority.NewUpdater(nlPriv)

	for _, addKey := range addKeys {
		if err := updater.AddKey(addKey); err != nil {
			return err
		}
	}
	for _, removeKey := range removeKeys {
		keyID, err := removeKey.ID()
		if err != nil {
			return err
		}
		if err := updater.RemoveKey(keyID); err != nil {
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

	head := b.tka.authority.Head()
	b.mu.Unlock()
	resp, err := b.tkaDoSyncSend(ourNodeKey, head, aums, true)
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

// NetworkLockDisable disables network-lock using the provided disablement secret.
func (b *LocalBackend) NetworkLockDisable(secret []byte) error {
	var (
		ourNodeKey key.NodePublic
		head       tka.AUMHash
		err        error
	)

	b.mu.Lock()
	if p := b.pm.CurrentPrefs(); p.Valid() && p.Persist().Valid() && !p.Persist().PrivateNodeKey().IsZero() {
		ourNodeKey = p.Persist().PublicNodeKey()
	}
	if b.tka == nil {
		err = errNetworkLockNotActive
	} else {
		head = b.tka.authority.Head()
		if !b.tka.authority.ValidDisablement(secret) {
			err = errors.New("incorrect disablement secret")
		}
	}
	b.mu.Unlock()
	if err != nil {
		return err
	}

	if ourNodeKey.IsZero() {
		return errors.New("no node-key: is tailscale logged in?")
	}
	_, err = b.tkaDoDisablement(ourNodeKey, head, secret)
	return err
}

// NetworkLockLog returns the changelog of TKA state up to maxEntries in size.
func (b *LocalBackend) NetworkLockLog(maxEntries int) ([]ipnstate.NetworkLockUpdate, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.tka == nil {
		return nil, errNetworkLockNotActive
	}

	var out []ipnstate.NetworkLockUpdate
	cursor := b.tka.authority.Head()
	for i := 0; i < maxEntries; i++ {
		aum, err := b.tka.storage.AUM(cursor)
		if err != nil {
			if err == os.ErrNotExist {
				break
			}
			return out, fmt.Errorf("reading AUM: %w", err)
		}

		update := ipnstate.NetworkLockUpdate{
			Hash:   cursor,
			Change: aum.MessageKind.String(),
			Raw:    aum.Serialize(),
		}
		out = append(out, update)

		parent, hasParent := aum.Parent()
		if !hasParent {
			break
		}
		cursor = parent
	}

	return out, nil
}

// NetworkLockAffectedSigs returns the signatures which would be invalidated
// by removing trust in the specified KeyID.
func (b *LocalBackend) NetworkLockAffectedSigs(keyID tkatype.KeyID) ([]tkatype.MarshaledSignature, error) {
	var (
		ourNodeKey key.NodePublic
		err        error
	)
	b.mu.Lock()
	if p := b.pm.CurrentPrefs(); p.Valid() && p.Persist().Valid() && !p.Persist().PrivateNodeKey().IsZero() {
		ourNodeKey = p.Persist().PublicNodeKey()
	}
	if b.tka == nil {
		err = errNetworkLockNotActive
	}
	b.mu.Unlock()
	if err != nil {
		return nil, err
	}

	resp, err := b.tkaReadAffectedSigs(ourNodeKey, keyID)
	if err != nil {
		return nil, err
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.tka == nil {
		return nil, errNetworkLockNotActive
	}

	// Confirm for ourselves tha the signatures would actually be invalidated
	// by removal of trusted in the specified key.
	for i, sigBytes := range resp.Signatures {
		var sig tka.NodeKeySignature
		if err := sig.Unserialize(sigBytes); err != nil {
			return nil, fmt.Errorf("failed decoding signature %d: %w", i, err)
		}

		sigKeyID, err := sig.UnverifiedAuthorizingKeyID()
		if err != nil {
			return nil, fmt.Errorf("extracting SigID from signature %d: %w", i, err)
		}
		if !bytes.Equal(keyID, sigKeyID) {
			return nil, fmt.Errorf("got signature with keyID %X from request for %X", sigKeyID, keyID)
		}

		var nodeKey key.NodePublic
		if err := nodeKey.UnmarshalBinary(sig.Pubkey); err != nil {
			return nil, fmt.Errorf("failed decoding pubkey for signature %d: %w", i, err)
		}
		if err := b.tka.authority.NodeKeyAuthorized(nodeKey, sigBytes); err != nil {
			return nil, fmt.Errorf("signature %d is not valid: %w", i, err)
		}
	}

	return resp.Signatures, nil
}

// NetworkLockGenerateRecoveryAUM generates an AUM which retroactively removes trust in the
// specified keys. This AUM is signed by the current node and returned.
//
// If forkFrom is specified, it is used as the parent AUM to fork from. If the zero value,
// the parent AUM is determined automatically.
func (b *LocalBackend) NetworkLockGenerateRecoveryAUM(removeKeys []tkatype.KeyID, forkFrom tka.AUMHash) (*tka.AUM, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.tka == nil {
		return nil, errNetworkLockNotActive
	}
	var nlPriv key.NLPrivate
	if p := b.pm.CurrentPrefs(); p.Valid() && p.Persist().Valid() {
		nlPriv = p.Persist().NetworkLockKey()
	}
	if nlPriv.IsZero() {
		return nil, errMissingNetmap
	}

	aum, err := b.tka.authority.MakeRetroactiveRevocation(b.tka.storage, removeKeys, nlPriv.KeyID(), forkFrom)
	if err != nil {
		return nil, err
	}

	// Sign it ourselves.
	aum.Signatures, err = nlPriv.SignAUM(aum.SigHash())
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	return aum, nil
}

// NetworkLockCosignRecoveryAUM co-signs the provided recovery AUM and returns
// the updated structure.
//
// The recovery AUM provided should be the output from a previous call to
// NetworkLockGenerateRecoveryAUM or NetworkLockCosignRecoveryAUM.
func (b *LocalBackend) NetworkLockCosignRecoveryAUM(aum *tka.AUM) (*tka.AUM, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.tka == nil {
		return nil, errNetworkLockNotActive
	}
	var nlPriv key.NLPrivate
	if p := b.pm.CurrentPrefs(); p.Valid() && p.Persist().Valid() {
		nlPriv = p.Persist().NetworkLockKey()
	}
	if nlPriv.IsZero() {
		return nil, errMissingNetmap
	}
	for _, sig := range aum.Signatures {
		if bytes.Equal(sig.KeyID, nlPriv.KeyID()) {
			return nil, errors.New("this node has already signed this recovery AUM")
		}
	}

	// Sign it ourselves.
	sigs, err := nlPriv.SignAUM(aum.SigHash())
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}
	aum.Signatures = append(aum.Signatures, sigs...)

	return aum, nil
}

func (b *LocalBackend) NetworkLockSubmitRecoveryAUM(aum *tka.AUM) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.tka == nil {
		return errNetworkLockNotActive
	}
	var ourNodeKey key.NodePublic
	if p := b.pm.CurrentPrefs(); p.Valid() && p.Persist().Valid() && !p.Persist().PrivateNodeKey().IsZero() {
		ourNodeKey = p.Persist().PublicNodeKey()
	}
	if ourNodeKey.IsZero() {
		return errors.New("no node-key: is tailscale logged in?")
	}

	b.mu.Unlock()
	_, err := b.tkaDoSyncSend(ourNodeKey, aum.Hash(), []tka.AUM{*aum}, false)
	b.mu.Lock()
	return err
}

var tkaSuffixEncoder = base64.RawStdEncoding

// NetworkLockWrapPreauthKey wraps a pre-auth key with information to
// enable unattended bringup in the locked tailnet.
//
// The provided trusted tailnet-lock key is used to sign
// a SigCredential structure, which is encoded along with the
// private key and appended to the pre-auth key.
func (b *LocalBackend) NetworkLockWrapPreauthKey(preauthKey string, tkaKey key.NLPrivate) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.tka == nil {
		return "", errNetworkLockNotActive
	}

	pub, priv, err := ed25519.GenerateKey(nil) // nil == crypto/rand
	if err != nil {
		return "", err
	}

	sig := tka.NodeKeySignature{
		SigKind:        tka.SigCredential,
		KeyID:          tkaKey.KeyID(),
		WrappingPubkey: pub,
	}
	sig.Signature, err = tkaKey.SignNKS(sig.SigHash())
	if err != nil {
		return "", fmt.Errorf("signing failed: %w", err)
	}

	b.logf("Generated network-lock credential signature using %s", tkaKey.Public().CLIString())
	return fmt.Sprintf("%s--TL%s-%s", preauthKey, tkaSuffixEncoder.EncodeToString(sig.Serialize()), tkaSuffixEncoder.EncodeToString(priv)), nil
}

// NetworkLockVerifySigningDeeplink asks the authority to verify the given deeplink
// URL. See the comment for ValidateDeeplink for details.
func (b *LocalBackend) NetworkLockVerifySigningDeeplink(url string) tka.DeeplinkValidationResult {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.tka == nil {
		return tka.DeeplinkValidationResult{IsValid: false, Error: errNetworkLockNotActive.Error()}
	}

	return b.tka.authority.ValidateDeeplink(url)
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
	err = json.NewDecoder(&io.LimitedReader{R: res.Body, N: 10 * 1024 * 1024}).Decode(a)
	res.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("decoding JSON: %w", err)
	}

	return a, nil
}

func (b *LocalBackend) tkaInitFinish(ourNodeKey key.NodePublic, nks map[tailcfg.NodeID]tkatype.MarshaledSignature, supportDisablement []byte) (*tailcfg.TKAInitFinishResponse, error) {
	var req bytes.Buffer
	if err := json.NewEncoder(&req).Encode(tailcfg.TKAInitFinishRequest{
		Version:            tailcfg.CurrentCapabilityVersion,
		NodeKey:            ourNodeKey,
		Signatures:         nks,
		SupportDisablement: supportDisablement,
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
	err = json.NewDecoder(&io.LimitedReader{R: res.Body, N: 1024 * 1024}).Decode(a)
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
	err = json.NewDecoder(&io.LimitedReader{R: res.Body, N: 1024 * 1024}).Decode(a)
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
	err = json.NewDecoder(&io.LimitedReader{R: res.Body, N: 10 * 1024 * 1024}).Decode(a)
	res.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("decoding JSON: %w", err)
	}

	return a, nil
}

// tkaDoSyncSend sends a /machine/tka/sync/send RPC to the control plane
// over noise. This is the second of two RPCs implementing tka synchronization.
func (b *LocalBackend) tkaDoSyncSend(ourNodeKey key.NodePublic, head tka.AUMHash, aums []tka.AUM, interactive bool) (*tailcfg.TKASyncSendResponse, error) {
	headBytes, err := head.MarshalText()
	if err != nil {
		return nil, fmt.Errorf("head.MarshalText: %w", err)
	}

	sendReq := tailcfg.TKASyncSendRequest{
		Version:     tailcfg.CurrentCapabilityVersion,
		NodeKey:     ourNodeKey,
		Head:        string(headBytes),
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
	err = json.NewDecoder(&io.LimitedReader{R: res.Body, N: 10 * 1024 * 1024}).Decode(a)
	res.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("decoding JSON: %w", err)
	}

	return a, nil
}

func (b *LocalBackend) tkaDoDisablement(ourNodeKey key.NodePublic, head tka.AUMHash, secret []byte) (*tailcfg.TKADisableResponse, error) {
	headBytes, err := head.MarshalText()
	if err != nil {
		return nil, fmt.Errorf("head.MarshalText: %w", err)
	}

	var req bytes.Buffer
	if err := json.NewEncoder(&req).Encode(tailcfg.TKADisableRequest{
		Version:           tailcfg.CurrentCapabilityVersion,
		NodeKey:           ourNodeKey,
		Head:              string(headBytes),
		DisablementSecret: secret,
	}); err != nil {
		return nil, fmt.Errorf("encoding request: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	req2, err := http.NewRequestWithContext(ctx, "GET", "https://unused/machine/tka/disable", &req)
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
	a := new(tailcfg.TKADisableResponse)
	err = json.NewDecoder(&io.LimitedReader{R: res.Body, N: 1024 * 1024}).Decode(a)
	res.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("decoding JSON: %w", err)
	}

	return a, nil
}

func (b *LocalBackend) tkaSubmitSignature(ourNodeKey key.NodePublic, sig tkatype.MarshaledSignature) (*tailcfg.TKASubmitSignatureResponse, error) {
	var req bytes.Buffer
	if err := json.NewEncoder(&req).Encode(tailcfg.TKASubmitSignatureRequest{
		Version:   tailcfg.CurrentCapabilityVersion,
		NodeKey:   ourNodeKey,
		Signature: sig,
	}); err != nil {
		return nil, fmt.Errorf("encoding request: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	req2, err := http.NewRequestWithContext(ctx, "GET", "https://unused/machine/tka/sign", &req)
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
	a := new(tailcfg.TKASubmitSignatureResponse)
	err = json.NewDecoder(&io.LimitedReader{R: res.Body, N: 1024 * 1024}).Decode(a)
	res.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("decoding JSON: %w", err)
	}

	return a, nil
}

func (b *LocalBackend) tkaReadAffectedSigs(ourNodeKey key.NodePublic, key tkatype.KeyID) (*tailcfg.TKASignaturesUsingKeyResponse, error) {
	var encodedReq bytes.Buffer
	if err := json.NewEncoder(&encodedReq).Encode(tailcfg.TKASignaturesUsingKeyRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: ourNodeKey,
		KeyID:   key,
	}); err != nil {
		return nil, fmt.Errorf("encoding request: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "https://unused/machine/tka/affected-sigs", &encodedReq)
	if err != nil {
		return nil, fmt.Errorf("req: %w", err)
	}
	resp, err := b.DoNoiseRequest(req)
	if err != nil {
		return nil, fmt.Errorf("resp: %w", err)
	}
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("request returned (%d): %s", resp.StatusCode, string(body))
	}
	a := new(tailcfg.TKASignaturesUsingKeyResponse)
	err = json.NewDecoder(&io.LimitedReader{R: resp.Body, N: 1024 * 1024}).Decode(a)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("decoding JSON: %w", err)
	}

	return a, nil
}
