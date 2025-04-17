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
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/taildrop"
	"tailscale.com/tsd"
	"tailscale.com/tstime"
	"tailscale.com/types/empty"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/util/osshare"
	"tailscale.com/util/set"
)

func init() {
	ipnext.RegisterExtension("taildrop", newExtension)

	ipnlocal.HookSetNotifyFilesWaitingLocked.Set(setNotifyFilesWaitingLocked)
	ipnlocal.HookSetPeerStatusTaildropTargetLocked.Set(setPeerStatusTaildropTargetLocked)
}

// FileRoot the type of an option used by cmd/tailscaled to explicitly
// configure a directory for Taildrop to use.
type FileRoot string

func newExtension(logf logger.Logf, sys *tsd.System) (ipnext.Extension, error) {
	return &extension{
		logf:  logger.WithPrefix(logf, "taildrop: "),
		state: sys.StateStore.Get(),
	}, nil
}

type extension struct {
	logf  logger.Logf
	lb    *ipnlocal.LocalBackend
	state ipn.StateStore

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

	stateForTest *ipn.State // if non-nil, pretend we're this state for tests

	mu             sync.Mutex // Lock order: lb.mu > e.mu
	netMap         *netmap.NetworkMap
	capFileSharing bool
	fileWaiters    set.HandleSet[context.CancelFunc] // of wake-up funcs
	mgr            atomic.Pointer[taildrop.Manager]  // mutex held to write; safe to read without lock;
	// outgoingFiles keeps track of Taildrop outgoing files keyed to their OutgoingFile.ID
	outgoingFiles map[string]*ipn.OutgoingFile
}

func (e *extension) Name() string {
	return "taildrop"
}

func (e *extension) Init(h ipnext.Host) error {
	type I interface {
		Backend() ipnlocal.Backend
	}
	e.lb = h.(I).Backend().(*ipnlocal.LocalBackend)

	osshare.SetFileSharingEnabled(false, e.logf)

	h.RegisterNetmapChangeCallback(e.onNewNetmap)
	e.mgr.Store(nil)

	h.RegisterOptionSetter(reflect.TypeFor[FileRoot](), func(v any) error {
		e.directFileRoot = string(v.(FileRoot))
		return nil
	})

	return nil
}

// fileRoot returns where to store Taildrop files for the given user and whether
// to write received files directly to this directory, without staging them in
// an intermediate buffered directory for "pick-up" later.
//
// It is safe to call this with b.mu held but it does not require it or acquire
// it itself.
func (e *extension) fileRoot(uid tailcfg.UserID) (root string, isDirect bool) {
	if v := e.directFileRoot; v != "" {
		return v, true
	}
	varRoot := e.lb.TailscaleVarRoot()
	if varRoot == "" {
		e.logf("Taildrop disabled; no state directory")
		return "", false
	}
	activeLogin := e.lb.ActiveLogin()
	baseDir := fmt.Sprintf("%s-uid-%d",
		strings.ReplaceAll(activeLogin, "@", "-"),
		uid)
	dir := filepath.Join(varRoot, "files", baseDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		e.logf("Taildrop disabled; error making directory: %v", err)
		return "", false
	}
	return dir, false
}

func (e *extension) onNewNetmap(nm *netmap.NetworkMap) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Clear state if the user has changed or we're logged out.
	if nm == nil || e.netMap != nil && e.netMap.User() != nm.User() {
		e.mgr.Store(nil)
		e.outgoingFiles = nil
	}

	// If we have a netmap, create a taildrop manager.
	if e.mgr.Load() == nil && nm != nil {
		fileRoot, isDirectFileMode := e.fileRoot(nm.User())
		if fileRoot == "" {
			e.logf("no Taildrop directory configured")
		}
		e.mgr.Store(taildrop.ManagerOptions{
			Logf:           e.logf,
			Clock:          tstime.DefaultClock{Clock: e.lb.Clock()},
			State:          e.state,
			Dir:            fileRoot,
			DirectFileMode: isDirectFileMode,
			SendFileNotify: e.sendFileNotify,
		}.New())
	}

	e.netMap = nm // possibly nil
	fs := nm.HasCap(tailcfg.CapabilityFileSharing)

	if fs != e.capFileSharing {
		osshare.SetFileSharingEnabled(fs, e.logf)
	}

	e.capFileSharing = fs
}

// HasCapFileSharing reports whether the current node has the file sharing
// capability.
func (e *extension) HasCapFileSharing() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.capFileSharing
}

// manager returns the active taildrop.Manager, or nil.
func (e *extension) manager() *taildrop.Manager {
	return e.mgr.Load()
}

func (e *extension) Clock() tstime.Clock {
	return e.lb.Clock()
}

func (e *extension) Shutdown() error {
	e.manager().Shutdown()
	return nil
}

func (e *extension) sendFileNotify() {
	var n ipn.Notify

	e.mu.Lock()
	for _, wakeWaiter := range e.fileWaiters {
		wakeWaiter()
	}
	mgr := e.mgr.Load()
	if mgr == nil {
		e.mu.Unlock()
		return
	}

	n.IncomingFiles = mgr.IncomingFiles()
	e.mu.Unlock()

	e.lb.SendNotify(n)
}

func setNotifyFilesWaitingLocked(b *ipnlocal.LocalBackend, n *ipn.Notify) {
	var e *extension
	if !b.FindMatchingExtension(&e) {
		return
	}

	if e.mgr.Load().HasFilesWaiting() {
		n.FilesWaiting = &empty.Message{}
	}
}

func setPeerStatusTaildropTargetLocked(b *ipnlocal.LocalBackend, ps *ipnstate.PeerStatus, p tailcfg.NodeView) {
	var e *extension
	if !b.FindMatchingExtension(&e) {
		return
	}
	ps.TaildropTarget = e.taildropTargetStatus(p)
}

func (e *extension) removeFileWaiter(handle set.Handle) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.fileWaiters, handle)
}

func (e *extension) addFileWaiter(wakeWaiter context.CancelFunc) set.Handle {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.fileWaiters.Add(wakeWaiter)
}

func (e *extension) WaitingFiles() ([]apitype.WaitingFile, error) {
	return e.manager().WaitingFiles()
}

// AwaitWaitingFiles is like WaitingFiles but blocks while ctx is not done,
// waiting for any files to be available.
//
// On return, exactly one of the results will be non-empty or non-nil,
// respectively.
func (e *extension) AwaitWaitingFiles(ctx context.Context) ([]apitype.WaitingFile, error) {
	if ff, err := e.WaitingFiles(); err != nil || len(ff) > 0 {
		return ff, err
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

func (e *extension) DeleteFile(name string) error {
	return e.manager().DeleteFile(name)
}

func (e *extension) OpenFile(name string) (rc io.ReadCloser, size int64, err error) {
	return e.manager().OpenFile(name)
}

func (e *extension) localBackendState() ipn.State {
	if e.stateForTest != nil {
		return *e.stateForTest
	}
	return e.lb.State()
}

// FileTargets lists nodes that the current node can send files to.
func (e *extension) FileTargets() ([]*apitype.FileTarget, error) {
	var ret []*apitype.FileTarget

	st := e.localBackendState()

	e.mu.Lock()
	nm := e.netMap
	e.mu.Unlock()

	if st != ipn.Running || nm == nil {
		return nil, errors.New("not connected to the tailnet")
	}
	if !e.HasCapFileSharing() {
		return nil, errors.New("file sharing not enabled by Tailscale admin")
	}
	for _, p := range nm.Peers {
		if !e.peerIsTaildropTarget(nm, p) {
			continue
		}
		if p.Hostinfo().OS() == "tvOS" {
			continue
		}
		peerAPI := ipnlocal.PeerAPIBase(e.netMap, p)
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

func (e *extension) taildropTargetStatus(p tailcfg.NodeView) ipnstate.TaildropTargetStatus {
	b := e.lb
	// TODO(bradfitz): optimize this State call in a loop:
	if b.State() != ipn.Running {
		return ipnstate.TaildropTargetIpnStateNotRunning
	}
	if e.netMap == nil {
		return ipnstate.TaildropTargetNoNetmapAvailable
	}
	if !e.capFileSharing {
		return ipnstate.TaildropTargetMissingCap
	}

	if !p.Online().Get() {
		return ipnstate.TaildropTargetOffline
	}

	if !p.Valid() {
		return ipnstate.TaildropTargetNoPeerInfo
	}
	if e.netMap.User() != p.User() {
		// Different user must have the explicit file sharing target capability
		if p.Addresses().Len() == 0 ||
			!b.PeerHasCap(p.Addresses().At(0).Addr(), tailcfg.PeerCapabilityFileSharingTarget) {
			return ipnstate.TaildropTargetOwnedByOtherUser
		}
	}

	if p.Hostinfo().OS() == "tvOS" {
		return ipnstate.TaildropTargetUnsupportedOS
	}
	if ipnlocal.PeerAPIBase(e.netMap, p) == "" {
		return ipnstate.TaildropTargetNoPeerAPI
	}
	return ipnstate.TaildropTargetAvailable
}

// peerIsTaildropTargetLocked reports whether p is a valid Taildrop file
// recipient from this node according to its ownership and the capabilities in
// the netmap.
//
// This method takes a netmap instead of using e.netMap so it doesn't require
// e.mu be held.
func (e *extension) peerIsTaildropTarget(nm *netmap.NetworkMap, p tailcfg.NodeView) bool {
	if nm == nil || !p.Valid() {
		return false
	}
	if nm.User() == p.User() {
		return true
	}
	if p.Addresses().Len() > 0 &&
		e.lb.PeerCapsWithNetmap(nm, p.Addresses().At(0).Addr()).HasCapability(tailcfg.PeerCapabilityFileSharingTarget) {
		// Explicitly noted in the netmap ACL caps as a target.
		return true
	}
	return false
}

// UpdateOutgoingFiles updates b.outgoingFiles to reflect the given updates and
// sends an ipn.Notify with the full list of outgoingFiles.
func (e *extension) UpdateOutgoingFiles(updates map[string]*ipn.OutgoingFile) {
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

	e.lb.SendNotify(ipn.Notify{OutgoingFiles: outgoingFiles})
}
