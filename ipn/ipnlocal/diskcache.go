// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"tailscale.com/feature/buildfeatures"
	"tailscale.com/tailcfg"
	"tailscale.com/tka"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
)

// diskCache is the state netmap caching to disk.
type diskCache struct {
	// all fields guarded by LocalBackend.mu

	dir       string               // active directory to write to
	wantBase  set.Set[string]      // base names we want to have on disk
	lastWrote map[string]lastWrote // base name => contents written
}

type lastWrote struct {
	baseDir  string
	contents []byte
	at       time.Time
}

func validBasename(name string) bool {
	if len(name) == 0 || len(name) > 255 {
		return false
	}
	if strings.ContainsAny(name, "\\/\x00") {
		return false
	}
	return true
}

func (dc *diskCache) writeJSON(baseName string, v any) error {
	if !validBasename(baseName) {
		return fmt.Errorf("invalid baseName %q", baseName)
	}
	j, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("errror JSON marshalling %q: %w", baseName, err)
	}
	last, ok := dc.lastWrote[baseName]
	if ok && last.baseDir == dc.dir && bytes.Equal(j, last.contents) {
		// Avoid disk writes
		return nil
	}
	err = os.WriteFile(filepath.Join(dc.dir, baseName), j, 0600)
	if err != nil {
		return err
	}
	dc.wantBase.Make()
	dc.wantBase.Add(baseName)
	mak.Set(&dc.lastWrote, baseName, lastWrote{
		baseDir:  dc.dir,
		contents: j,
		at:       time.Now(),
	})
	return nil
}

func (dc *diskCache) removeUnwantedFiles() error {
	ents, err := os.ReadDir(dc.dir)
	if err != nil {
		return err
	}
	for _, de := range ents {
		baseName := de.Name()
		if !dc.wantBase.Contains(baseName) {
			if err := os.Remove(filepath.Join(dc.dir, baseName)); err != nil {
				return err
			}
		}
	}
	return nil
}

// netmapJSON are some misc small, low-churn netmap.NetworkMap fields we
// serialize to disk together.
//
// (We never write a whole NetworkMap to disk; it's not considered a stable format)
type netmapJSON struct {
	MachineKey       key.MachinePublic
	CollectServices  bool                                                `json:",omitzero"`
	DisplayMessages  map[tailcfg.DisplayMessageID]tailcfg.DisplayMessage `json:",omitempty"`
	TKAEnabled       bool                                                `json:",omitzero"`
	TKAHead          tka.AUMHash                                         `json:",omitzero"`
	Domain           string
	DomainAuditLogID string `json:",omitzero"`
}

func (b *LocalBackend) writeNetmapToDiskLocked(nm *netmap.NetworkMap) error {
	if !buildfeatures.HasCacheNetMap || nm == nil || nm.Cached {
		return nil
	}
	b.logf("writing netmap to disk cache")

	selfUID := nm.User()
	if selfUID == 0 {
		return errors.New("no user in netmap")
	}
	prof, ok := nm.UserProfiles[selfUID]
	if !ok {
		return errors.New("no profile for current user in netmap")
	}
	root := b.varRoot
	if root == "" {
		return errors.New("no varRoot")
	}

	dc := &b.diskCache
	// TODO(bradfitz): the (ID integer, LoginName string) tuple is not sufficiently
	// globally unique. It doesn't include the control plane server URL. We should
	// make each profile have a local UUID.
	dc.dir = filepath.Join(root, fmt.Sprintf("nm-%d-%s", prof.ID(), prof.LoginName()))

	if err := os.MkdirAll(dc.dir, 0700); err != nil {
		return err
	}

	dc.wantBase = nil

	misc := &netmapJSON{
		MachineKey:       nm.MachineKey,
		CollectServices:  nm.CollectServices,
		DisplayMessages:  nm.DisplayMessages,
		TKAEnabled:       nm.TKAEnabled,
		TKAHead:          nm.TKAHead,
		Domain:           nm.Domain,
		DomainAuditLogID: nm.DomainAuditLogID,
	}
	if err := dc.writeJSON("misc", misc); err != nil {
		return err
	}

	if buildfeatures.HasSSH && nm.SSHPolicy != nil {
		if err := dc.writeJSON("ssh", nm.SSHPolicy); err != nil {
			return err
		}
	}
	if err := dc.writeJSON("dns", nm.DNS); err != nil {
		return err
	}
	if err := dc.writeJSON("derpmap", nm.DERPMap); err != nil {
		return err
	}
	if err := dc.writeJSON("self", nm.SelfNode); err != nil {
		return err
	}
	for _, p := range nm.Peers {
		if err := dc.writeJSON("peer-"+string(p.StableID()), p); err != nil {
			return err
		}
	}
	for uid, p := range nm.UserProfiles {
		if err := dc.writeJSON(fmt.Sprintf("user-%d", uid), p); err != nil {
			return err
		}
	}

	if err := dc.removeUnwantedFiles(); err != nil {
		return fmt.Errorf("cleaning old files from netmap disk cache: %w", err)
	}

	return nil
}

func (b *LocalBackend) loadDiskCache(prof tailcfg.UserProfile) (_ *netmap.NetworkMap, ok bool) {
	if !buildfeatures.HasCacheNetMap {
		return nil, false
	}
	root := b.varRoot
	if root == "" {
		return nil, false
	}

	dir := filepath.Join(root, fmt.Sprintf("nm-%d-%s", prof.ID, prof.LoginName))
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false
		}
		b.logf("loading netmap from disk cache: reading dir %q: %v", dir, err)
		return nil, false
	}
	if len(ents) == 0 {
		return nil, false
	}

	nm := &netmap.NetworkMap{Cached: true}
	dc := diskCache{dir: dir}
	for _, de := range ents {
		if err := dc.readFile(nm, de.Name()); err != nil {
			b.logf("loading netmap from disk cache: reading file %q: %v", de.Name(), err)
			return nil, false
		}
	}
	slices.SortFunc(nm.Peers, func(a, b tailcfg.NodeView) int {
		return cmp.Compare(a.ID(), b.ID())
	})
	return nm, true
}

func (dc *diskCache) readFile(nm *netmap.NetworkMap, base string) error {
	j, err := os.ReadFile(filepath.Join(dc.dir, base))
	if err != nil {
		return err
	}
	if strings.HasPrefix(base, "peer-") {
		var p tailcfg.Node
		if err := setField(&p, j); err != nil {
			return err
		}
		nm.Peers = append(nm.Peers, p.View())
		return nil
	}
	if strings.HasPrefix(base, "user-") {
		var up tailcfg.UserProfile
		if err := setField(&up, j); err != nil {
			return err
		}
		mak.Set(&nm.UserProfiles, up.ID, up.View())
		return nil
	}

	switch base {
	case "derpmap":
		return setField(&nm.DERPMap, j)
	case "dns":
		return setField(&nm.DNS, j)
	case "ssh":
		return setField(&nm.SSHPolicy, j)
	case "self":
		var n *tailcfg.Node
		if err := setField(&n, j); err != nil {
			return err
		}
		nm.SelfNode = n.View()
		nm.NodeKey = n.Key

		capSet := set.Set[tailcfg.NodeCapability]{}
		for _, c := range n.Capabilities {
			capSet.Add(c)
		}
		for c := range n.CapMap {
			capSet.Add(c)
		}
		nm.AllCaps = capSet

	case "misc":
		misc := &netmapJSON{}
		if err := setField(misc, j); err != nil {
			return err
		}
		nm.MachineKey = misc.MachineKey
		nm.CollectServices = misc.CollectServices
		nm.DisplayMessages = misc.DisplayMessages
		nm.TKAEnabled = misc.TKAEnabled
		nm.TKAHead = misc.TKAHead
		nm.Domain = misc.Domain
		nm.DomainAuditLogID = misc.DomainAuditLogID
		return nil
	default:
		log.Printf("unknown netmap disk cache file %q; ignoring", base)
	}
	return nil
}

func setField[T any](ptr *T, j []byte) error {
	return json.Unmarshal(j, ptr)
}
