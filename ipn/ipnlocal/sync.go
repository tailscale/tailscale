// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_sync

package ipnlocal

import (
	"tailscale.com/tailcfg"
	"tailscale.com/tailsync"
)

// SyncSharingEnabled reports whether sharing sync roots via Tailsync is
// enabled. This is currently based on checking for the sync:share node
// attribute.
func (b *LocalBackend) SyncSharingEnabled() bool {
	return b.currentNode().SelfHasCap(tailcfg.NodeAttrsTailsyncShare)
}

// SyncSetRoot adds or updates a sync root.
func (b *LocalBackend) SyncSetRoot(root *tailsync.Root) error {
	svc, ok := b.sys.FileSync.GetOK()
	if !ok {
		return tailsync.ErrSyncNotEnabled
	}
	return svc.SetRoot(root)
}

// SyncRemoveRoot removes a sync root by name.
func (b *LocalBackend) SyncRemoveRoot(name string) error {
	svc, ok := b.sys.FileSync.GetOK()
	if !ok {
		return tailsync.ErrSyncNotEnabled
	}
	return svc.RemoveRoot(name)
}

// SyncGetRoots returns all configured sync roots.
func (b *LocalBackend) SyncGetRoots() []*tailsync.Root {
	svc, ok := b.sys.FileSync.GetOK()
	if !ok {
		return nil
	}
	return svc.GetRoots()
}

// SyncSetSession adds or updates a sync session.
func (b *LocalBackend) SyncSetSession(session *tailsync.Session) error {
	svc, ok := b.sys.FileSync.GetOK()
	if !ok {
		return tailsync.ErrSyncNotEnabled
	}
	return svc.SetSession(session)
}

// SyncRemoveSession removes a sync session by name.
func (b *LocalBackend) SyncRemoveSession(name string) error {
	svc, ok := b.sys.FileSync.GetOK()
	if !ok {
		return tailsync.ErrSyncNotEnabled
	}
	return svc.RemoveSession(name)
}

// SyncGetSessions returns all configured sync sessions.
func (b *LocalBackend) SyncGetSessions() []*tailsync.Session {
	svc, ok := b.sys.FileSync.GetOK()
	if !ok {
		return nil
	}
	return svc.GetSessions()
}

// SyncGetSessionStatus returns the status of a named sync session.
func (b *LocalBackend) SyncGetSessionStatus(name string) (*tailsync.SessionStatus, error) {
	svc, ok := b.sys.FileSync.GetOK()
	if !ok {
		return nil, tailsync.ErrSyncNotEnabled
	}
	return svc.GetSessionStatus(name)
}

// SyncGetAllStatuses returns the status of all sync sessions.
func (b *LocalBackend) SyncGetAllStatuses() []*tailsync.SessionStatus {
	svc, ok := b.sys.FileSync.GetOK()
	if !ok {
		return nil
	}
	sessions := svc.GetSessions()
	var statuses []*tailsync.SessionStatus
	for _, s := range sessions {
		st, err := svc.GetSessionStatus(s.Name)
		if err != nil {
			continue
		}
		statuses = append(statuses, st)
	}
	return statuses
}
