// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_taildrop

package ipnlocal

import (
	"cmp"
	"context"
	"errors"
	"io"
	"maps"
	"slices"
	"strings"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/taildrop"
	"tailscale.com/tstime"
	"tailscale.com/types/empty"
	"tailscale.com/util/set"
)

func init() {
	hookSetNotifyFilesWaitingLocked = (*LocalBackend).setNotifyFilesWaitingLocked
	hookSetPeerStatusTaildropTargetLocked = (*LocalBackend).setPeerStatusTaildropTargetLocked
}

type taildrop_Manager = taildrop.Manager

func (b *LocalBackend) newTaildropManager(fileRoot string) *taildrop.Manager {
	// TODO(bradfitz): move all this to an ipnext so ipnlocal doesn't need to depend
	// on taildrop at all.
	if fileRoot == "" {
		b.logf("no Taildrop directory configured")
	}
	return taildrop.ManagerOptions{
		Logf:           b.logf,
		Clock:          tstime.DefaultClock{Clock: b.clock},
		State:          b.store,
		Dir:            fileRoot,
		DirectFileMode: b.directFileRoot != "",
		SendFileNotify: b.sendFileNotify,
	}.New()
}

func (b *LocalBackend) sendFileNotify() {
	var n ipn.Notify

	b.mu.Lock()
	for _, wakeWaiter := range b.fileWaiters {
		wakeWaiter()
	}
	apiSrv := b.peerAPIServer
	if apiSrv == nil {
		b.mu.Unlock()
		return
	}

	n.IncomingFiles = apiSrv.taildrop.IncomingFiles()
	b.mu.Unlock()

	b.send(n)
}

// TaildropManager returns the taildrop manager for this backend.
//
// TODO(bradfitz): as of 2025-04-15, this is a temporary method during
// refactoring; the plan is for all taildrop code to leave the ipnlocal package
// and move to an extension. Baby steps.
func (b *LocalBackend) TaildropManager() (*taildrop.Manager, error) {
	b.mu.Lock()
	ps := b.peerAPIServer
	b.mu.Unlock()
	if ps == nil {
		return nil, errors.New("no peer API server initialized")
	}
	if ps.taildrop == nil {
		return nil, errors.New("no taildrop manager initialized")
	}
	return ps.taildrop, nil
}

func (b *LocalBackend) taildropOrNil() *taildrop.Manager {
	b.mu.Lock()
	ps := b.peerAPIServer
	b.mu.Unlock()
	if ps == nil {
		return nil
	}
	return ps.taildrop
}

func (b *LocalBackend) setNotifyFilesWaitingLocked(n *ipn.Notify) {
	if ps := b.peerAPIServer; ps != nil {
		if ps.taildrop.HasFilesWaiting() {
			n.FilesWaiting = &empty.Message{}
		}
	}
}

func (b *LocalBackend) setPeerStatusTaildropTargetLocked(ps *ipnstate.PeerStatus, p tailcfg.NodeView) {
	ps.TaildropTarget = b.taildropTargetStatus(p)
}

func (b *LocalBackend) removeFileWaiter(handle set.Handle) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.fileWaiters, handle)
}

func (b *LocalBackend) addFileWaiter(wakeWaiter context.CancelFunc) set.Handle {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.fileWaiters.Add(wakeWaiter)
}

func (b *LocalBackend) WaitingFiles() ([]apitype.WaitingFile, error) {
	return b.taildropOrNil().WaitingFiles()
}

// AwaitWaitingFiles is like WaitingFiles but blocks while ctx is not done,
// waiting for any files to be available.
//
// On return, exactly one of the results will be non-empty or non-nil,
// respectively.
func (b *LocalBackend) AwaitWaitingFiles(ctx context.Context) ([]apitype.WaitingFile, error) {
	if ff, err := b.WaitingFiles(); err != nil || len(ff) > 0 {
		return ff, err
	}

	for {
		gotFile, gotFileCancel := context.WithCancel(context.Background())
		defer gotFileCancel()

		handle := b.addFileWaiter(gotFileCancel)
		defer b.removeFileWaiter(handle)

		// Now that we've registered ourselves, check again, in case
		// of race. Otherwise there's a small window where we could
		// miss a file arrival and wait forever.
		if ff, err := b.WaitingFiles(); err != nil || len(ff) > 0 {
			return ff, err
		}

		select {
		case <-gotFile.Done():
			if ff, err := b.WaitingFiles(); err != nil || len(ff) > 0 {
				return ff, err
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (b *LocalBackend) DeleteFile(name string) error {
	return b.taildropOrNil().DeleteFile(name)
}

func (b *LocalBackend) OpenFile(name string) (rc io.ReadCloser, size int64, err error) {
	return b.taildropOrNil().OpenFile(name)
}

// HasCapFileSharing reports whether the current node has the file
// sharing capability enabled.
func (b *LocalBackend) HasCapFileSharing() bool {
	// TODO(bradfitz): remove this method and all Taildrop/Taildrive
	// references from LocalBackend as part of tailscale/tailscale#12614.
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.capFileSharing
}

// FileTargets lists nodes that the current node can send files to.
func (b *LocalBackend) FileTargets() ([]*apitype.FileTarget, error) {
	var ret []*apitype.FileTarget

	b.mu.Lock() // for b.{state,capFileSharing}
	defer b.mu.Unlock()
	cn := b.currentNode()
	nm := cn.NetMap()
	self := cn.SelfUserID()
	if b.state != ipn.Running || nm == nil {
		return nil, errors.New("not connected to the tailnet")
	}
	if !b.capFileSharing {
		return nil, errors.New("file sharing not enabled by Tailscale admin")
	}
	peers := cn.AppendMatchingPeers(nil, func(p tailcfg.NodeView) bool {
		if !p.Valid() || p.Hostinfo().OS() == "tvOS" {
			return false
		}
		if self != p.User() {
			return false
		}
		if p.Addresses().Len() != 0 && cn.PeerHasCap(p.Addresses().At(0).Addr(), tailcfg.PeerCapabilityFileSharingTarget) {
			// Explicitly noted in the netmap ACL caps as a target.
			return true
		}
		return false
	})
	for _, p := range peers {
		peerAPI := cn.PeerAPIBase(p)
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

func (b *LocalBackend) taildropTargetStatus(p tailcfg.NodeView) ipnstate.TaildropTargetStatus {
	if b.state != ipn.Running {
		return ipnstate.TaildropTargetIpnStateNotRunning
	}
	cn := b.currentNode()
	nm := cn.NetMap()
	if nm == nil {
		return ipnstate.TaildropTargetNoNetmapAvailable
	}
	if !b.capFileSharing {
		return ipnstate.TaildropTargetMissingCap
	}

	if !p.Online().Get() {
		return ipnstate.TaildropTargetOffline
	}

	if !p.Valid() {
		return ipnstate.TaildropTargetNoPeerInfo
	}
	if nm.User() != p.User() {
		// Different user must have the explicit file sharing target capability
		if p.Addresses().Len() == 0 || !cn.PeerHasCap(p.Addresses().At(0).Addr(), tailcfg.PeerCapabilityFileSharingTarget) {
			// Explicitly noted in the netmap ACL caps as a target.
			return ipnstate.TaildropTargetOwnedByOtherUser
		}
	}

	if p.Hostinfo().OS() == "tvOS" {
		return ipnstate.TaildropTargetUnsupportedOS
	}
	if !cn.PeerHasPeerAPI(p) {
		return ipnstate.TaildropTargetNoPeerAPI
	}
	return ipnstate.TaildropTargetAvailable
}

// UpdateOutgoingFiles updates b.outgoingFiles to reflect the given updates and
// sends an ipn.Notify with the full list of outgoingFiles.
func (b *LocalBackend) UpdateOutgoingFiles(updates map[string]*ipn.OutgoingFile) {
	b.mu.Lock()
	if b.outgoingFiles == nil {
		b.outgoingFiles = make(map[string]*ipn.OutgoingFile, len(updates))
	}
	maps.Copy(b.outgoingFiles, updates)
	outgoingFiles := make([]*ipn.OutgoingFile, 0, len(b.outgoingFiles))
	for _, file := range b.outgoingFiles {
		outgoingFiles = append(outgoingFiles, file)
	}
	b.mu.Unlock()
	slices.SortFunc(outgoingFiles, func(a, b *ipn.OutgoingFile) int {
		t := a.Started.Compare(b.Started)
		if t != 0 {
			return t
		}
		return strings.Compare(a.Name, b.Name)
	})
	b.send(ipn.Notify{OutgoingFiles: outgoingFiles})
}
