// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"tailscale.com/drive"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
	"tailscale.com/types/views"
)

const (
	// DriveLocalPort is the port on which the Taildrive listens for location
	// connections on quad 100.
	DriveLocalPort = 8080
)

// DriveSharingEnabled reports whether sharing to remote nodes via Taildrive is
// enabled. This is currently based on checking for the drive:share node
// attribute.
func (b *LocalBackend) DriveSharingEnabled() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.driveSharingEnabledLocked()
}

func (b *LocalBackend) driveSharingEnabledLocked() bool {
	return b.netMap != nil && b.netMap.SelfNode.HasCap(tailcfg.NodeAttrsTaildriveShare)
}

// DriveAccessEnabled reports whether accessing Taildrive shares on remote nodes
// is enabled. This is currently based on checking for the drive:access node
// attribute.
func (b *LocalBackend) DriveAccessEnabled() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.driveAccessEnabledLocked()
}

func (b *LocalBackend) driveAccessEnabledLocked() bool {
	return b.netMap != nil && b.netMap.SelfNode.HasCap(tailcfg.NodeAttrsTaildriveAccess)
}

// DriveSetServerAddr tells Taildrive to use the given address for connecting
// to the drive.FileServer that's exposing local files as an unprivileged
// user.
func (b *LocalBackend) DriveSetServerAddr(addr string) error {
	fs, ok := b.sys.DriveForRemote.GetOK()
	if !ok {
		return drive.ErrDriveNotEnabled
	}

	fs.SetFileServerAddr(addr)
	return nil
}

// DriveSetShare adds the given share if no share with that name exists, or
// replaces the existing share if one with the same name already exists. To
// avoid potential incompatibilities across file systems, share names are
// limited to alphanumeric characters and the underscore _.
func (b *LocalBackend) DriveSetShare(share *drive.Share) error {
	var err error
	share.Name, err = drive.NormalizeShareName(share.Name)
	if err != nil {
		return err
	}

	b.mu.Lock()
	shares, err := b.driveSetShareLocked(share)
	b.mu.Unlock()
	if err != nil {
		return err
	}

	b.driveNotifyShares(shares)
	return nil
}

func (b *LocalBackend) driveSetShareLocked(share *drive.Share) (views.SliceView[*drive.Share, drive.ShareView], error) {
	existingShares := b.pm.prefs.DriveShares()

	fs, ok := b.sys.DriveForRemote.GetOK()
	if !ok {
		return existingShares, drive.ErrDriveNotEnabled
	}

	addedShare := false
	var shares []*drive.Share
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

	err := b.driveSetSharesLocked(shares)
	if err != nil {
		return existingShares, err
	}
	fs.SetShares(shares)

	return b.pm.prefs.DriveShares(), nil
}

// DriveRenameShare renames the share at old name to new name. To avoid
// potential incompatibilities across file systems, the new share name is
// limited to alphanumeric characters and the underscore _.
// Any of the following will result in an error.
// - no share found under old name
// - new share name contains disallowed characters
// - share already exists under new name
func (b *LocalBackend) DriveRenameShare(oldName, newName string) error {
	var err error
	newName, err = drive.NormalizeShareName(newName)
	if err != nil {
		return err
	}

	b.mu.Lock()
	shares, err := b.driveRenameShareLocked(oldName, newName)
	b.mu.Unlock()
	if err != nil {
		return err
	}

	b.driveNotifyShares(shares)
	return nil
}

func (b *LocalBackend) driveRenameShareLocked(oldName, newName string) (views.SliceView[*drive.Share, drive.ShareView], error) {
	existingShares := b.pm.prefs.DriveShares()

	fs, ok := b.sys.DriveForRemote.GetOK()
	if !ok {
		return existingShares, drive.ErrDriveNotEnabled
	}

	found := false
	var shares []*drive.Share
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

	slices.SortFunc(shares, drive.CompareShares)
	err := b.driveSetSharesLocked(shares)
	if err != nil {
		return existingShares, err
	}
	fs.SetShares(shares)

	return b.pm.prefs.DriveShares(), nil
}

// DriveRemoveShare removes the named share. Share names are forced to
// lowercase.
func (b *LocalBackend) DriveRemoveShare(name string) error {
	// Force all share names to lowercase to avoid potential incompatibilities
	// with clients that don't support case-sensitive filenames.
	var err error
	name, err = drive.NormalizeShareName(name)
	if err != nil {
		return err
	}

	b.mu.Lock()
	shares, err := b.driveRemoveShareLocked(name)
	b.mu.Unlock()
	if err != nil {
		return err
	}

	b.driveNotifyShares(shares)
	return nil
}

func (b *LocalBackend) driveRemoveShareLocked(name string) (views.SliceView[*drive.Share, drive.ShareView], error) {
	existingShares := b.pm.prefs.DriveShares()

	fs, ok := b.sys.DriveForRemote.GetOK()
	if !ok {
		return existingShares, drive.ErrDriveNotEnabled
	}

	found := false
	var shares []*drive.Share
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

	err := b.driveSetSharesLocked(shares)
	if err != nil {
		return existingShares, err
	}
	fs.SetShares(shares)

	return b.pm.prefs.DriveShares(), nil
}

func (b *LocalBackend) driveSetSharesLocked(shares []*drive.Share) error {
	prefs := b.pm.prefs.AsStruct()
	prefs.ApplyEdits(&ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			DriveShares: shares,
		},
		DriveSharesSet: true,
	})
	return b.pm.setPrefsLocked(prefs.View())
}

// driveNotifyShares notifies IPN bus listeners (e.g. Mac Application process)
// about the latest list of shares.
func (b *LocalBackend) driveNotifyShares(shares views.SliceView[*drive.Share, drive.ShareView]) {
	// Ensures shares is not nil to distinguish "no shares" from "not notifying shares"
	if shares.IsNil() {
		shares = views.SliceOfViews(make([]*drive.Share, 0))
	}
	b.send(ipn.Notify{DriveShares: shares})
}

// driveNotifyCurrentSharesLocked sends an ipn.Notify if the current set of
// shares has changed since the last notification.
func (b *LocalBackend) driveNotifyCurrentSharesLocked() {
	var shares views.SliceView[*drive.Share, drive.ShareView]
	if b.driveSharingEnabledLocked() {
		// Only populate shares if sharing is enabled.
		shares = b.pm.prefs.DriveShares()
	}

	lastNotified := b.lastNotifiedDriveShares.Load()
	if lastNotified == nil || !driveShareViewsEqual(lastNotified, shares) {
		// Do the below on a goroutine to avoid deadlocking on b.mu in b.send().
		go b.driveNotifyShares(shares)
	}
}

func driveShareViewsEqual(a *views.SliceView[*drive.Share, drive.ShareView], b views.SliceView[*drive.Share, drive.ShareView]) bool {
	if a == nil {
		return false
	}

	if a.Len() != b.Len() {
		return false
	}

	for i := 0; i < a.Len(); i++ {
		if !drive.ShareViewsEqual(a.At(i), b.At(i)) {
			return false
		}
	}

	return true
}

// DriveGetShares gets the current list of Taildrive shares, sorted by name.
func (b *LocalBackend) DriveGetShares() views.SliceView[*drive.Share, drive.ShareView] {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.pm.prefs.DriveShares()
}

// updateDrivePeersLocked sets all applicable peers from the netmap as Taildrive
// remotes.
func (b *LocalBackend) updateDrivePeersLocked(nm *netmap.NetworkMap) {
	fs, ok := b.sys.DriveForLocal.GetOK()
	if !ok {
		return
	}

	var driveRemotes []*drive.Remote
	if b.driveAccessEnabledLocked() {
		// Only populate peers if access is enabled, otherwise leave blank.
		driveRemotes = b.driveRemotesFromPeers(nm)
	}

	fs.SetRemotes(b.netMap.Domain, driveRemotes, &driveTransport{b: b})
}

func (b *LocalBackend) driveRemotesFromPeers(nm *netmap.NetworkMap) []*drive.Remote {
	driveRemotes := make([]*drive.Remote, 0, len(nm.Peers))
	for _, p := range nm.Peers {
		// Exclude mullvad exit nodes from list of Taildrive peers
		// TODO(oxtoacart) - once we have a better mechanism for finding only accessible sharers
		// (see below) we can remove this logic.
		if strings.HasSuffix(p.Name(), ".mullvad.ts.net.") {
			continue
		}

		peerID := p.ID()
		url := fmt.Sprintf("%s/%s", peerAPIBase(nm, p), taildrivePrefix[1:])
		driveRemotes = append(driveRemotes, &drive.Remote{
			Name: p.DisplayName(false),
			URL:  url,
			Available: func() bool {
				// TODO(oxtoacart): need to figure out a performant and reliable way to only
				// show the peers that have shares to which we have access
				// This will require work on the control server to transmit the inverse
				// of the "tailscale.com/cap/drive" capability.
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
	return driveRemotes
}
