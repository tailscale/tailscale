// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_drive

package ipnlocal

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"slices"

	"tailscale.com/drive"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/views"
	"tailscale.com/util/httpm"
)

func init() {
	hookSetNetMapLockedDrive.Set(setNetMapLockedDrive)
}

func setNetMapLockedDrive(b *LocalBackend, nm *netmap.NetworkMap) {
	b.updateDrivePeersLocked(nm)
	b.driveNotifyCurrentSharesLocked()
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
	for _, existing := range existingShares.All() {
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
	for _, existing := range existingShares.All() {
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
	for _, existing := range existingShares.All() {
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
	return b.pm.setPrefsNoPermCheck(prefs.View())
}

// driveNotifyShares notifies IPN bus listeners (e.g. Mac Application process)
// about the latest list of shares, if and only if the shares have changed since
// the last time we notified.
func (b *LocalBackend) driveNotifyShares(shares views.SliceView[*drive.Share, drive.ShareView]) {
	b.lastNotifiedDriveSharesMu.Lock()
	defer b.lastNotifiedDriveSharesMu.Unlock()
	if b.lastNotifiedDriveShares != nil && driveShareViewsEqual(b.lastNotifiedDriveShares, shares) {
		// shares are unchanged since last notification, don't bother notifying
		return
	}
	b.lastNotifiedDriveShares = &shares

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
	if b.DriveSharingEnabled() {
		// Only populate shares if sharing is enabled.
		shares = b.pm.prefs.DriveShares()
	}

	// Do the below on a goroutine to avoid deadlocking on b.mu in b.send().
	go b.driveNotifyShares(shares)
}

func driveShareViewsEqual(a *views.SliceView[*drive.Share, drive.ShareView], b views.SliceView[*drive.Share, drive.ShareView]) bool {
	if a == nil {
		return false
	}

	if a.Len() != b.Len() {
		return false
	}

	for i := range a.Len() {
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
	if b.DriveAccessEnabled() {
		// Only populate peers if access is enabled, otherwise leave blank.
		driveRemotes = b.driveRemotesFromPeers(nm)
	}

	fs.SetRemotes(nm.Domain, driveRemotes, b.newDriveTransport())
}

func (b *LocalBackend) driveRemotesFromPeers(nm *netmap.NetworkMap) []*drive.Remote {
	b.logf("[v1] taildrive: setting up drive remotes from peers")
	driveRemotes := make([]*drive.Remote, 0, len(nm.Peers))
	for _, p := range nm.Peers {
		peer := p
		peerID := peer.ID()
		peerKey := peer.Key().ShortString()
		b.logf("[v1] taildrive: appending remote for peer %s", peerKey)
		driveRemotes = append(driveRemotes, &drive.Remote{
			Name: p.DisplayName(false),
			URL: func() string {
				url := fmt.Sprintf("%s/%s", b.currentNode().PeerAPIBase(peer), taildrivePrefix[1:])
				b.logf("[v2] taildrive: url for peer %s: %s", peerKey, url)
				return url
			},
			Available: func() bool {
				// Peers are available to Taildrive if:
				// - They are online
				// - Their PeerAPI is reachable
				// - They are allowed to share at least one folder with us
				cn := b.currentNode()
				peer, ok := cn.NodeByID(peerID)
				if !ok {
					b.logf("[v2] taildrive: Available(): peer %s not found", peerKey)
					return false
				}

				// Exclude offline peers.
				// TODO(oxtoacart): for some reason, this correctly
				// catches when a node goes from offline to online,
				// but not the other way around...
				// TODO(oxtoacart,nickkhyl): the reason was probably
				// that we were using netmap.Peers instead of b.peers.
				// The netmap.Peers slice is not updated in all cases.
				// It should be fixed now that we use PeerByIDOk.
				if !peer.Online().Get() {
					b.logf("[v2] taildrive: Available(): peer %s offline", peerKey)
					return false
				}

				if b.currentNode().PeerAPIBase(peer) == "" {
					b.logf("[v2] taildrive: Available(): peer %s PeerAPI unreachable", peerKey)
					return false
				}

				// Check that the peer is allowed to share with us.
				if cn.PeerHasCap(peer, tailcfg.PeerCapabilityTaildriveSharer) {
					b.logf("[v2] taildrive: Available(): peer %s available", peerKey)
					return true
				}

				b.logf("[v2] taildrive: Available(): peer %s not allowed to share", peerKey)
				return false
			},
		})
	}
	return driveRemotes
}

// responseBodyWrapper wraps an io.ReadCloser and stores
// the number of bytesRead.
type responseBodyWrapper struct {
	io.ReadCloser
	logVerbose    bool
	bytesRx       int64
	bytesTx       int64
	log           logger.Logf
	method        string
	statusCode    int
	contentType   string
	fileExtension string
	shareNodeKey  string
	selfNodeKey   string
	contentLength int64
}

// logAccess logs the taildrive: access: log line. If the logger is nil,
// the log will not be written.
func (rbw *responseBodyWrapper) logAccess(err string) {
	if rbw.log == nil {
		return
	}

	// Some operating systems create and copy lots of 0 length hidden files for
	// tracking various states. Omit these to keep logs from being too verbose.
	if rbw.logVerbose || rbw.contentLength > 0 {
		levelPrefix := ""
		if rbw.logVerbose {
			levelPrefix = "[v1] "
		}
		rbw.log(
			"%staildrive: access: %s from %s to %s: status-code=%d ext=%q content-type=%q content-length=%.f tx=%.f rx=%.f err=%q",
			levelPrefix,
			rbw.method,
			rbw.selfNodeKey,
			rbw.shareNodeKey,
			rbw.statusCode,
			rbw.fileExtension,
			rbw.contentType,
			roundTraffic(rbw.contentLength),
			roundTraffic(rbw.bytesTx), roundTraffic(rbw.bytesRx), err)
	}
}

// Read implements the io.Reader interface.
func (rbw *responseBodyWrapper) Read(b []byte) (int, error) {
	n, err := rbw.ReadCloser.Read(b)
	rbw.bytesRx += int64(n)
	if err != nil && !errors.Is(err, io.EOF) {
		rbw.logAccess(err.Error())
	}

	return n, err
}

// Close implements the io.Close interface.
func (rbw *responseBodyWrapper) Close() error {
	err := rbw.ReadCloser.Close()
	var errStr string
	if err != nil {
		errStr = err.Error()
	}
	rbw.logAccess(errStr)

	return err
}

// driveTransport is an http.RoundTripper that wraps
// b.Dialer().PeerAPITransport() with metrics tracking.
type driveTransport struct {
	b  *LocalBackend
	tr http.RoundTripper
}

func (b *LocalBackend) newDriveTransport() *driveTransport {
	return &driveTransport{
		b:  b,
		tr: b.Dialer().PeerAPITransport(),
	}
}

func (dt *driveTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Some WebDAV clients include origin and refer headers, which peerapi does
	// not like. Remove them.
	req.Header.Del("origin")
	req.Header.Del("referer")

	bw := &requestBodyWrapper{}
	if req.Body != nil {
		bw.ReadCloser = req.Body
		req.Body = bw
	}

	resp, err := dt.tr.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	contentType := "unknown"
	if ct := req.Header.Get("Content-Type"); ct != "" {
		contentType = ct
	}

	dt.b.mu.Lock()
	selfNodeKey := dt.b.currentNode().Self().Key().ShortString()
	dt.b.mu.Unlock()
	n, _, ok := dt.b.WhoIs("tcp", netip.MustParseAddrPort(req.URL.Host))
	shareNodeKey := "unknown"
	if ok {
		shareNodeKey = string(n.Key().ShortString())
	}

	rbw := responseBodyWrapper{
		log:           dt.b.logf,
		logVerbose:    req.Method != httpm.GET && req.Method != httpm.PUT, // other requests like PROPFIND are quite chatty, so we log those at verbose level
		method:        req.Method,
		bytesTx:       int64(bw.bytesRead),
		selfNodeKey:   selfNodeKey,
		shareNodeKey:  shareNodeKey,
		contentType:   contentType,
		contentLength: resp.ContentLength,
		fileExtension: parseDriveFileExtensionForLog(req.URL.Path),
		statusCode:    resp.StatusCode,
		ReadCloser:    resp.Body,
	}

	if resp.StatusCode >= 400 {
		// in case of error response, just log immediately
		rbw.logAccess("")
	} else {
		resp.Body = &rbw
	}

	return resp, nil
}
