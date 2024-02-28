// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"regexp"
	"strings"

	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/tailfs"
	"tailscale.com/types/netmap"
)

const (
	// TailFSLocalPort is the port on which the TailFS listens for location
	// connections on quad 100.
	TailFSLocalPort = 8080

	tailfsSharesStateKey = ipn.StateKey("_tailfs-shares")
)

var (
	shareNameRegex      = regexp.MustCompile(`^[a-z0-9_\(\) ]+$`)
	errInvalidShareName = errors.New("Share names may only contain the letters a-z, underscore _, parentheses (), or spaces")
)

// TailFSSharingEnabled reports whether sharing to remote nodes via tailfs is
// enabled. This is currently based on checking for the tailfs:share node
// attribute.
func (b *LocalBackend) TailFSSharingEnabled() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.tailFSSharingEnabledLocked()
}

func (b *LocalBackend) tailFSSharingEnabledLocked() bool {
	return b.netMap != nil && b.netMap.SelfNode.HasCap(tailcfg.NodeAttrsTailFSShare)
}

// TailFSAccessEnabled reports whether accessing TailFS shares on remote nodes
// is enabled. This is currently based on checking for the tailfs:access node
// attribute.
func (b *LocalBackend) TailFSAccessEnabled() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.tailFSAccessEnabledLocked()
}

func (b *LocalBackend) tailFSAccessEnabledLocked() bool {
	return b.netMap != nil && b.netMap.SelfNode.HasCap(tailcfg.NodeAttrsTailFSAccess)
}

// TailFSSetFileServerAddr tells tailfs to use the given address for connecting
// to the tailfs.FileServer that's exposing local files as an unprivileged
// user.
func (b *LocalBackend) TailFSSetFileServerAddr(addr string) error {
	fs, ok := b.sys.TailFSForRemote.GetOK()
	if !ok {
		return errors.New("tailfs not enabled")
	}

	fs.SetFileServerAddr(addr)
	return nil
}

// TailFSAddShare adds the given share if no share with that name exists, or
// replaces the existing share if one with the same name already exists.
// To avoid potential incompatibilities across file systems, share names are
// limited to alphanumeric characters and the underscore _.
func (b *LocalBackend) TailFSAddShare(share *tailfs.Share) error {
	var err error
	share.Name, err = normalizeShareName(share.Name)
	if err != nil {
		return err
	}

	b.mu.Lock()
	shares, err := b.tailfsAddShareLocked(share)
	b.mu.Unlock()
	if err != nil {
		return err
	}

	b.tailfsNotifyShares(shares)
	return nil
}

// normalizeShareName normalizes the given share name and returns an error if
// it contains any disallowed characters.
func normalizeShareName(name string) (string, error) {
	// Force all share names to lowercase to avoid potential incompatibilities
	// with clients that don't support case-sensitive filenames.
	name = strings.ToLower(name)

	// Trim whitespace
	name = strings.TrimSpace(name)

	if !shareNameRegex.MatchString(name) {
		return "", errInvalidShareName
	}

	return name, nil
}

func (b *LocalBackend) tailfsAddShareLocked(share *tailfs.Share) (map[string]*tailfs.Share, error) {
	fs, ok := b.sys.TailFSForRemote.GetOK()
	if !ok {
		return nil, errors.New("tailfs not enabled")
	}

	shares, err := b.tailFSGetSharesLocked()
	if err != nil {
		return nil, err
	}
	shares[share.Name] = share
	data, err := json.Marshal(shares)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	err = b.store.WriteState(tailfsSharesStateKey, data)
	if err != nil {
		return nil, fmt.Errorf("write state: %w", err)
	}
	fs.SetShares(shares)

	return maps.Clone(shares), nil
}

// TailFSRemoveShare removes the named share. Share names are forced to
// lowercase.
func (b *LocalBackend) TailFSRemoveShare(name string) error {
	// Force all share names to lowercase to avoid potential incompatibilities
	// with clients that don't support case-sensitive filenames.
	var err error
	name, err = normalizeShareName(name)
	if err != nil {
		return err
	}

	b.mu.Lock()
	shares, err := b.tailfsRemoveShareLocked(name)
	b.mu.Unlock()
	if err != nil {
		return err
	}

	b.tailfsNotifyShares(shares)
	return nil
}

func (b *LocalBackend) tailfsRemoveShareLocked(name string) (map[string]*tailfs.Share, error) {
	fs, ok := b.sys.TailFSForRemote.GetOK()
	if !ok {
		return nil, errors.New("tailfs not enabled")
	}

	shares, err := b.tailFSGetSharesLocked()
	if err != nil {
		return nil, err
	}
	_, shareExists := shares[name]
	if !shareExists {
		return nil, os.ErrNotExist
	}
	delete(shares, name)
	data, err := json.Marshal(shares)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	err = b.store.WriteState(tailfsSharesStateKey, data)
	if err != nil {
		return nil, fmt.Errorf("write state: %w", err)
	}
	fs.SetShares(shares)

	return maps.Clone(shares), nil
}

// tailfsNotifyShares notifies IPN bus listeners (e.g. Mac Application process)
// about the latest set of shares, supplied as a map of name -> directory.
func (b *LocalBackend) tailfsNotifyShares(shares map[string]*tailfs.Share) {
	b.send(ipn.Notify{TailFSShares: shares})
}

// tailFSNotifyCurrentSharesLocked sends an ipn.Notify with the current set of
// TailFS shares.
func (b *LocalBackend) tailFSNotifyCurrentSharesLocked() {
	shares, err := b.tailFSGetSharesLocked()
	if err != nil {
		b.logf("error notifying current tailfs shares: %v", err)
		return
	}
	// Do the below on a goroutine to avoid deadlocking on b.mu in b.send().
	go b.tailfsNotifyShares(maps.Clone(shares))
}

// TailFSGetShares returns the current set of shares from the state store,
// stored under ipn.StateKey("_tailfs-shares").
func (b *LocalBackend) TailFSGetShares() (map[string]*tailfs.Share, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.tailFSGetSharesLocked()
}

func (b *LocalBackend) tailFSGetSharesLocked() (map[string]*tailfs.Share, error) {
	data, err := b.store.ReadState(tailfsSharesStateKey)
	if err != nil {
		if errors.Is(err, ipn.ErrStateNotExist) {
			return make(map[string]*tailfs.Share), nil
		}
		return nil, fmt.Errorf("read state: %w", err)
	}

	var shares map[string]*tailfs.Share
	err = json.Unmarshal(data, &shares)
	if err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	return shares, nil
}

// updateTailFSPeersLocked sets all applicable peers from the netmap as tailfs
// remotes.
func (b *LocalBackend) updateTailFSPeersLocked(nm *netmap.NetworkMap) {
	fs, ok := b.sys.TailFSForLocal.GetOK()
	if !ok {
		return
	}

	tailfsRemotes := make([]*tailfs.Remote, 0, len(nm.Peers))
	for _, p := range nm.Peers {
		peerID := p.ID()
		url := fmt.Sprintf("%s/%s", peerAPIBase(nm, p), tailFSPrefix[1:])
		tailfsRemotes = append(tailfsRemotes, &tailfs.Remote{
			Name: p.DisplayName(false),
			URL:  url,
			Available: func() bool {
				// TODO(oxtoacart): need to figure out a performant and reliable way to only
				// show the peers that have shares to which we have access
				// This will require work on the control server to transmit the inverse
				// of the "tailscale.com/cap/tailfs" capability.
				// For now, at least limit it only to nodes that are online.
				// Note, we have to iterate the latest netmap because the peer we got from the first iteration may not be it
				b.mu.Lock()
				latestNetMap := b.netMap
				b.mu.Unlock()

				for _, candidate := range latestNetMap.Peers {
					if candidate.ID() == peerID {
						online := candidate.Online()
						// TODO(oxtoacart): for some reason, this correctly
						// catches when a node goes from offline to online,
						// but not the other way around...
						return online != nil && *online
					}
				}

				// peer not found, must not be available
				return false
			},
		})
	}
	fs.SetRemotes(b.netMap.Domain, tailfsRemotes, &tailFSTransport{b: b})
}
