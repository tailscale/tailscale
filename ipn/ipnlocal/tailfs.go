// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/tailfs"
	"tailscale.com/types/netmap"
	"tailscale.com/types/views"
)

const (
	// TailFSLocalPort is the port on which the TailFS listens for location
	// connections on quad 100.
	TailFSLocalPort = 8080
)

var (
	shareNameRegex      = regexp.MustCompile(`^[a-z0-9_\(\) ]+$`)
	ErrTailFSNotEnabled = errors.New("TailFS not enabled")
	ErrInvalidShareName = errors.New("Share names may only contain the letters a-z, underscore _, parentheses (), or spaces")
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
		return ErrTailFSNotEnabled
	}

	fs.SetFileServerAddr(addr)
	return nil
}

// TailFSSetShare adds the given share if no share with that name exists, or
// replaces the existing share if one with the same name already exists. To
// avoid potential incompatibilities across file systems, share names are
// limited to alphanumeric characters and the underscore _.
func (b *LocalBackend) TailFSSetShare(share *tailfs.Share) error {
	var err error
	share.Name, err = normalizeShareName(share.Name)
	if err != nil {
		return err
	}

	b.mu.Lock()
	shares, err := b.tailFSSetShareLocked(share)
	b.mu.Unlock()
	if err != nil {
		return err
	}

	b.tailFSNotifyShares(shares)
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
		return "", ErrInvalidShareName
	}

	return name, nil
}

func (b *LocalBackend) tailFSSetShareLocked(share *tailfs.Share) (views.SliceView[*tailfs.Share, tailfs.ShareView], error) {
	existingShares := b.pm.prefs.TailFSShares()

	fs, ok := b.sys.TailFSForRemote.GetOK()
	if !ok {
		return existingShares, ErrTailFSNotEnabled
	}

	addedShare := false
	var shares []*tailfs.Share
	for i := 0; i < existingShares.Len(); i++ {
		existing := existingShares.At(i)
		if existing.Name() != share.Name {
			if !addedShare && existing.Name() > share.Name {
				// Add share in order
				shares = append(shares, share)
				addedShare = true
			}
			shares = append(shares, existing.AsStruct())
		}
	}
	if !addedShare {
		shares = append(shares, share)
	}

	err := b.tailFSSetSharesLocked(shares)
	if err != nil {
		return existingShares, err
	}
	fs.SetShares(shares)

	return b.pm.prefs.TailFSShares(), nil
}

// TailFSRenameShare renames the share at old name to new name. To avoid
// potential incompatibilities across file systems, the new share name is
// limited to alphanumeric characters and the underscore _.
// Any of the following will result in an error.
// - no share found under old name
// - new share name contains disallowed characters
// - share already exists under new name
func (b *LocalBackend) TailFSRenameShare(oldName, newName string) error {
	var err error
	newName, err = normalizeShareName(newName)
	if err != nil {
		return err
	}

	b.mu.Lock()
	shares, err := b.tailFSRenameShareLocked(oldName, newName)
	b.mu.Unlock()
	if err != nil {
		return err
	}

	b.tailFSNotifyShares(shares)
	return nil
}

func (b *LocalBackend) tailFSRenameShareLocked(oldName, newName string) (views.SliceView[*tailfs.Share, tailfs.ShareView], error) {
	existingShares := b.pm.prefs.TailFSShares()

	fs, ok := b.sys.TailFSForRemote.GetOK()
	if !ok {
		return existingShares, ErrTailFSNotEnabled
	}

	found := false
	var shares []*tailfs.Share
	for i := 0; i < existingShares.Len(); i++ {
		existing := existingShares.At(i)
		if existing.Name() == newName {
			return existingShares, os.ErrExist
		}
		if existing.Name() == oldName {
			share := existing.AsStruct()
			share.Name = newName
			shares = append(shares, share)
			found = true
		} else {
			shares = append(shares, existing.AsStruct())
		}
	}

	if !found {
		return existingShares, os.ErrNotExist
	}

	slices.SortFunc(shares, tailfs.CompareShares)
	err := b.tailFSSetSharesLocked(shares)
	if err != nil {
		return existingShares, err
	}
	fs.SetShares(shares)

	return b.pm.prefs.TailFSShares(), nil
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
	shares, err := b.tailFSRemoveShareLocked(name)
	b.mu.Unlock()
	if err != nil {
		return err
	}

	b.tailFSNotifyShares(shares)
	return nil
}

func (b *LocalBackend) tailFSRemoveShareLocked(name string) (views.SliceView[*tailfs.Share, tailfs.ShareView], error) {
	existingShares := b.pm.prefs.TailFSShares()

	fs, ok := b.sys.TailFSForRemote.GetOK()
	if !ok {
		return existingShares, ErrTailFSNotEnabled
	}

	found := false
	var shares []*tailfs.Share
	for i := 0; i < existingShares.Len(); i++ {
		existing := existingShares.At(i)
		if existing.Name() != name {
			shares = append(shares, existing.AsStruct())
		} else {
			found = true
		}
	}

	if !found {
		return existingShares, os.ErrNotExist
	}

	err := b.tailFSSetSharesLocked(shares)
	if err != nil {
		return existingShares, err
	}
	fs.SetShares(shares)

	return b.pm.prefs.TailFSShares(), nil
}

func (b *LocalBackend) tailFSSetSharesLocked(shares []*tailfs.Share) error {
	prefs := b.pm.prefs.AsStruct()
	prefs.ApplyEdits(&ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			TailFSShares: shares,
		},
		TailFSSharesSet: true,
	})
	return b.pm.setPrefsLocked(prefs.View())
}

// tailFSNotifyShares notifies IPN bus listeners (e.g. Mac Application process)
// about the latest list of shares.
func (b *LocalBackend) tailFSNotifyShares(shares views.SliceView[*tailfs.Share, tailfs.ShareView]) {
	// Ensures shares is not nil to distinguish "no shares" from "not notifying shares"
	if shares.IsNil() {
		shares = views.SliceOfViews(make([]*tailfs.Share, 0))
	}
	b.send(ipn.Notify{TailFSShares: shares})
}

// tailFSNotifyCurrentSharesLocked sends an ipn.Notify if the current set of
// shares has changed since the last notification.
func (b *LocalBackend) tailFSNotifyCurrentSharesLocked() {
	var shares views.SliceView[*tailfs.Share, tailfs.ShareView]
	if b.tailFSSharingEnabledLocked() {
		// Only populate shares if sharing is enabled.
		shares = b.pm.prefs.TailFSShares()
	}

	lastNotified := b.lastNotifiedTailFSShares.Load()
	if lastNotified == nil || !tailFSShareViewsEqual(lastNotified, shares) {
		// Do the below on a goroutine to avoid deadlocking on b.mu in b.send().
		go b.tailFSNotifyShares(shares)
	}
}

func tailFSShareViewsEqual(a *views.SliceView[*tailfs.Share, tailfs.ShareView], b views.SliceView[*tailfs.Share, tailfs.ShareView]) bool {
	if a == nil {
		return false
	}

	if a.Len() != b.Len() {
		return false
	}

	for i := 0; i < a.Len(); i++ {
		if !tailfs.ShareViewsEqual(a.At(i), b.At(i)) {
			return false
		}
	}

	return true
}

// TailFSGetShares() gets the current list of TailFS shares, sorted by name.
func (b *LocalBackend) TailFSGetShares() views.SliceView[*tailfs.Share, tailfs.ShareView] {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.pm.prefs.TailFSShares()
}

// updateTailFSPeersLocked sets all applicable peers from the netmap as tailfs
// remotes.
func (b *LocalBackend) updateTailFSPeersLocked(nm *netmap.NetworkMap) {
	fs, ok := b.sys.TailFSForLocal.GetOK()
	if !ok {
		return
	}

	var tailFSRemotes []*tailfs.Remote
	if b.tailFSAccessEnabledLocked() {
		// Only populate peers if access is enabled, otherwise leave blank.
		tailFSRemotes = b.tailFSRemotesFromPeers(nm)
	}

	fs.SetRemotes(b.netMap.Domain, tailFSRemotes, &tailFSTransport{b: b})
}

func (b *LocalBackend) tailFSRemotesFromPeers(nm *netmap.NetworkMap) []*tailfs.Remote {
	tailFSRemotes := make([]*tailfs.Remote, 0, len(nm.Peers))
	for _, p := range nm.Peers {
		// Exclude mullvad exit nodes from list of TailFS peers
		// TODO(oxtoacart) - once we have a better mechanism for finding only accessible sharers
		// (see below) we can remove this logic.
		if strings.HasSuffix(p.Name(), ".mullvad.ts.net.") {
			continue
		}

		peerID := p.ID()
		url := fmt.Sprintf("%s/%s", peerAPIBase(nm, p), tailFSPrefix[1:])
		tailFSRemotes = append(tailFSRemotes, &tailfs.Remote{
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
	return tailFSRemotes
}
