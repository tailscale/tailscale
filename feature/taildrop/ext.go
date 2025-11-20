// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/cmd/tailscaled/tailscaledhooks"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
	"tailscale.com/types/empty"
	"tailscale.com/types/logger"
	"tailscale.com/util/osshare"
	"tailscale.com/util/set"
)

func init() {
	ipnext.RegisterExtension("taildrop", newExtension)

	if runtime.GOOS == "windows" {
		tailscaledhooks.UninstallSystemDaemonWindows.Add(func() {
			// Remove file sharing from Windows shell.
			osshare.SetFileSharingEnabled(false, logger.Discard)
		})
	}
}

func newExtension(logf logger.Logf, b ipnext.SafeBackend) (ipnext.Extension, error) {
	e := &Extension{
		sb:         b,
		stateStore: b.Sys().StateStore.Get(),
		logf:       logger.WithPrefix(logf, "taildrop: "),
	}
	e.setPlatformDefaultDirectFileRoot()
	return e, nil
}

// Extension implements Taildrop.
type Extension struct {
	logf       logger.Logf
	sb         ipnext.SafeBackend
	stateStore ipn.StateStore
	host       ipnext.Host // from Init

	// directFileRoot, if non-empty, means to write received files
	// directly to this directory, without staging them in an
	// intermediate buffered directory for "pick-up" later. If
	// empty, the files are received in a daemon-owned location
	// and the localapi is used to enumerate, download, and delete
	// them. This is used on macOS where the GUI lifetime is the
	// same as the Network Extension lifetime and we can thus avoid
	// double-copying files by writing them to the right location
	// immediately.
	// It's also used on several NAS platforms (Synology, TrueNAS, etc)
	// but in that case DoFinalRename is also set true, which moves the
	// *.partial file to its final name on completion.
	directFileRoot string

	// FileOps abstracts platform-specific file operations needed for file transfers.
	// This is currently being used for Android to use the Storage Access Framework.
	fileOps FileOps

	nodeBackendForTest ipnext.NodeBackend // if non-nil, pretend we're this node state for tests

	mu             sync.Mutex // Lock order: lb.mu > e.mu
	backendState   ipn.State
	selfUID        tailcfg.UserID
	capFileSharing bool
	fileWaiters    set.HandleSet[context.CancelFunc] // of wake-up funcs
	mgr            atomic.Pointer[manager]           // mutex held to write; safe to read without lock;
	// outgoingFiles keeps track of Taildrop outgoing files keyed to their OutgoingFile.ID
	outgoingFiles map[string]*ipn.OutgoingFile
}

func (e *Extension) Name() string {
	return "taildrop"
}

func (e *Extension) Init(h ipnext.Host) error {
	e.host = h

	osshare.SetFileSharingEnabled(false, e.logf)

	h.Hooks().ProfileStateChange.Add(e.onChangeProfile)
	h.Hooks().OnSelfChange.Add(e.onSelfChange)
	h.Hooks().MutateNotifyLocked.Add(e.setNotifyFilesWaiting)
	h.Hooks().SetPeerStatus.Add(e.setPeerStatus)
	h.Hooks().BackendStateChange.Add(e.onBackendStateChange)

	// TODO(nickkhyl): remove this after the profileManager refactoring.
	// See tailscale/tailscale#15974.
	// This same workaround appears in feature/portlist/portlist.go.
	profile, prefs := h.Profiles().CurrentProfileState()
	e.onChangeProfile(profile, prefs, false)
	return nil
}

func (e *Extension) onBackendStateChange(st ipn.State) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.backendState = st
}

func (e *Extension) onSelfChange(self tailcfg.NodeView) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.selfUID = 0
	if self.Valid() {
		e.selfUID = self.User()
	}
	e.capFileSharing = self.Valid() && self.CapMap().Contains(tailcfg.CapabilityFileSharing)
	osshare.SetFileSharingEnabled(e.capFileSharing, e.logf)
}

func (e *Extension) setMgrLocked(mgr *manager) {
	if old := e.mgr.Swap(mgr); old != nil {
		old.Shutdown()
	}
}

func (e *Extension) onChangeProfile(profile ipn.LoginProfileView, _ ipn.PrefsView, sameNode bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	uid := profile.UserProfile().ID
	activeLogin := profile.UserProfile().LoginName

	if uid == 0 {
		e.setMgrLocked(nil)
		e.outgoingFiles = nil
		return
	}

	if sameNode && e.manager() != nil {
		return
	}

	// Use the provided [FileOps] implementation (typically for SAF access on Android),
	// or create an [fsFileOps] instance rooted at fileRoot.
	//
	// A non-nil [FileOps] also implies that we are in DirectFileMode.
	fops := e.fileOps
	isDirectFileMode := fops != nil
	if fops == nil {
		var fileRoot string
		if fileRoot, isDirectFileMode = e.fileRoot(uid, activeLogin); fileRoot == "" {
			e.logf("no Taildrop directory configured")
			e.setMgrLocked(nil)
			return
		}

		var err error
		if fops, err = newFileOps(fileRoot); err != nil {
			e.logf("taildrop: cannot create FileOps: %v", err)
			e.setMgrLocked(nil)
			return
		}
	}

	e.setMgrLocked(managerOptions{
		Logf:           e.logf,
		Clock:          tstime.DefaultClock{Clock: e.sb.Clock()},
		State:          e.stateStore,
		DirectFileMode: isDirectFileMode,
		fileOps:        fops,
		SendFileNotify: e.sendFileNotify,
	}.New())
}

// fileRoot returns where to store Taildrop files for the given user and whether
// to write received files directly to this directory, without staging them in
// an intermediate buffered directory for "pick-up" later.
//
// It is safe to call this with b.mu held but it does not require it or acquire
// it itself.
func (e *Extension) fileRoot(uid tailcfg.UserID, activeLogin string) (root string, isDirect bool) {
	if v := e.directFileRoot; v != "" {
		return v, true
	}
	varRoot := e.sb.TailscaleVarRoot()
	if varRoot == "" {
		e.logf("Taildrop disabled; no state directory")
		return "", false
	}

	if activeLogin == "" {
		e.logf("taildrop: no active login; can't select a target directory")
		return "", false
	}

	baseDir := fmt.Sprintf("%s-uid-%d",
		strings.ReplaceAll(activeLogin, "@", "-"),
		uid)
	return filepath.Join(varRoot, "files", baseDir), false
}

// hasCapFileSharing reports whether the current node has the file sharing
// capability.
func (e *Extension) hasCapFileSharing() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.capFileSharing
}

// manager returns the active Manager, or nil.
//
// Methods on a nil Manager are safe to call.
func (e *Extension) manager() *manager {
	return e.mgr.Load()
}

func (e *Extension) Clock() tstime.Clock {
	return e.sb.Clock()
}

func (e *Extension) Shutdown() error {
	e.manager().Shutdown() // no-op on nil receiver
	return nil
}

func (e *Extension) sendFileNotify() {
	mgr := e.manager()
	if mgr == nil {
		return
	}

	var n ipn.Notify

	e.mu.Lock()
	for _, wakeWaiter := range e.fileWaiters {
		wakeWaiter()
	}
	n.IncomingFiles = mgr.IncomingFiles()
	e.mu.Unlock()

	e.host.SendNotifyAsync(n)
}

func (e *Extension) setNotifyFilesWaiting(n *ipn.Notify) {
	if e.manager().HasFilesWaiting() {
		n.FilesWaiting = &empty.Message{}
	}
}

func (e *Extension) setPeerStatus(ps *ipnstate.PeerStatus, p tailcfg.NodeView, nb ipnext.NodeBackend) {
	ps.TaildropTarget = e.taildropTargetStatus(p, nb)
}

func (e *Extension) removeFileWaiter(handle set.Handle) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.fileWaiters, handle)
}

func (e *Extension) addFileWaiter(wakeWaiter context.CancelFunc) set.Handle {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.fileWaiters.Add(wakeWaiter)
}

func (e *Extension) WaitingFiles() ([]apitype.WaitingFile, error) {
	return e.manager().WaitingFiles()
}

// AwaitWaitingFiles is like WaitingFiles but blocks while ctx is not done,
// waiting for any files to be available.
//
// On return, exactly one of the results will be non-empty or non-nil,
// respectively.
func (e *Extension) AwaitWaitingFiles(ctx context.Context) ([]apitype.WaitingFile, error) {
	if ff, err := e.WaitingFiles(); err != nil || len(ff) > 0 {
		return ff, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for {
		gotFile, gotFileCancel := context.WithCancel(context.Background())
		defer gotFileCancel()

		handle := e.addFileWaiter(gotFileCancel)
		defer e.removeFileWaiter(handle)

		// Now that we've registered ourselves, check again, in case
		// of race. Otherwise there's a small window where we could
		// miss a file arrival and wait forever.
		if ff, err := e.WaitingFiles(); err != nil || len(ff) > 0 {
			return ff, err
		}

		select {
		case <-gotFile.Done():
			if ff, err := e.WaitingFiles(); err != nil || len(ff) > 0 {
				return ff, err
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (e *Extension) DeleteFile(name string) error {
	return e.manager().DeleteFile(name)
}

func (e *Extension) OpenFile(name string) (rc io.ReadCloser, size int64, err error) {
	return e.manager().OpenFile(name)
}

func (e *Extension) nodeBackend() ipnext.NodeBackend {
	if e.nodeBackendForTest != nil {
		return e.nodeBackendForTest
	}
	return e.host.NodeBackend()
}

// FileTargets lists nodes that the current node can send files to.
func (e *Extension) FileTargets() ([]*apitype.FileTarget, error) {
	var ret []*apitype.FileTarget

	e.mu.Lock()
	st := e.backendState
	self := e.selfUID
	e.mu.Unlock()

	if st != ipn.Running {
		return nil, errors.New("not connected to the tailnet")
	}
	if !e.hasCapFileSharing() {
		return nil, errors.New("file sharing not enabled by Tailscale admin")
	}
	nb := e.nodeBackend()
	peers := nb.AppendMatchingPeers(nil, func(p tailcfg.NodeView) bool {
		if !p.Valid() || p.Hostinfo().OS() == "tvOS" {
			return false
		}
		if self == p.User() {
			return true
		}
		if nb.PeerHasCap(p, tailcfg.PeerCapabilityFileSharingTarget) {
			// Explicitly noted in the netmap ACL caps as a target.
			return true
		}
		return false
	})
	for _, p := range peers {
		peerAPI := nb.PeerAPIBase(p)
		if peerAPI == "" {
			continue
		}
		ret = append(ret, &apitype.FileTarget{
			Node:       p.AsStruct(),
			PeerAPIURL: peerAPI,
		})
	}
	slices.SortFunc(ret, func(a, b *apitype.FileTarget) int {
		return cmp.Compare(a.Node.Name, b.Node.Name)
	})
	return ret, nil
}

func (e *Extension) taildropTargetStatus(p tailcfg.NodeView, nb ipnext.NodeBackend) ipnstate.TaildropTargetStatus {
	e.mu.Lock()
	st := e.backendState
	selfUID := e.selfUID
	capFileSharing := e.capFileSharing
	e.mu.Unlock()

	if st != ipn.Running {
		return ipnstate.TaildropTargetIpnStateNotRunning
	}

	if !capFileSharing {
		return ipnstate.TaildropTargetMissingCap
	}
	if !p.Valid() {
		return ipnstate.TaildropTargetNoPeerInfo
	}
	if !p.Online().Get() {
		return ipnstate.TaildropTargetOffline
	}
	if p.Hostinfo().OS() == "tvOS" {
		return ipnstate.TaildropTargetUnsupportedOS
	}
	if selfUID != p.User() {
		// Different user must have the explicit file sharing target capability
		if !nb.PeerHasCap(p, tailcfg.PeerCapabilityFileSharingTarget) {
			return ipnstate.TaildropTargetOwnedByOtherUser
		}
	}
	if !nb.PeerHasPeerAPI(p) {
		return ipnstate.TaildropTargetNoPeerAPI
	}
	return ipnstate.TaildropTargetAvailable
}

// updateOutgoingFiles updates b.outgoingFiles to reflect the given updates and
// sends an ipn.Notify with the full list of outgoingFiles.
func (e *Extension) updateOutgoingFiles(updates map[string]*ipn.OutgoingFile) {
	e.mu.Lock()
	if e.outgoingFiles == nil {
		e.outgoingFiles = make(map[string]*ipn.OutgoingFile, len(updates))
	}
	maps.Copy(e.outgoingFiles, updates)
	outgoingFiles := make([]*ipn.OutgoingFile, 0, len(e.outgoingFiles))
	for _, file := range e.outgoingFiles {
		outgoingFiles = append(outgoingFiles, file)
	}
	e.mu.Unlock()
	slices.SortFunc(outgoingFiles, func(a, b *ipn.OutgoingFile) int {
		t := a.Started.Compare(b.Started)
		if t != 0 {
			return t
		}
		return strings.Compare(a.Name, b.Name)
	})

	e.host.SendNotifyAsync(ipn.Notify{OutgoingFiles: outgoingFiles})
}
