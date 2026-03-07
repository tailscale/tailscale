// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailsyncimpl

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"tailscale.com/tailsync"
	"tailscale.com/tailsync/tailsyncimpl/ignore"
	"tailscale.com/tailsync/tailsyncimpl/index"
	"tailscale.com/tailsync/tailsyncimpl/watcher"
	"tailscale.com/types/logger"
)

// sessionRunner manages the lifecycle of a single sync session.
type sessionRunner struct {
	logf    logger.Logf
	session *tailsync.Session
	root    *tailsync.Root
	idx     *index.Index

	mu        sync.RWMutex
	state     tailsync.SessionState
	conflicts []tailsync.ConflictInfo
	lastSync  time.Time
	errMsg    string
	bytesSent int64
	bytesRecv int64

	cancel context.CancelFunc
	done   chan struct{}
}

func newSessionRunner(logf logger.Logf, session *tailsync.Session, root *tailsync.Root) *sessionRunner {
	_, cancel := context.WithCancel(context.Background())
	return &sessionRunner{
		logf:    logf,
		session: session,
		root:    root,
		idx:     index.New(logf),
		state:   tailsync.SessionStateIdle,
		cancel:  cancel,
		done:    make(chan struct{}),
	}
}

func (sr *sessionRunner) run() {
	defer close(sr.done)

	sr.setState(tailsync.SessionStateReconciling)

	// Build ignore matcher.
	ignoreFile := filepath.Join(sr.root.Path, ".tailsyncignore")
	matcher := ignore.LoadFile(ignoreFile, sr.root.Ignore)

	// Start file watcher.
	w, err := watcher.New(watcher.Config{
		Root:    sr.root.Path,
		Matcher: matcher,
		Logf:    sr.logf,
	})
	if err != nil {
		sr.setError(fmt.Sprintf("failed to start watcher: %v", err))
		return
	}
	defer w.Close()

	// Initial full scan to build index.
	paths, err := w.ScanFull()
	if err != nil {
		sr.setError(fmt.Sprintf("initial scan failed: %v", err))
		return
	}

	builtIdx, err := index.BuildFromFS(sr.logf, sr.root.Path, paths)
	if err != nil {
		sr.setError(fmt.Sprintf("index build failed: %v", err))
		return
	}
	sr.idx = builtIdx

	sr.setState(tailsync.SessionStateIdle)
	sr.logf("tailsync: session %s: initial index built with %d files", sr.session.Name, sr.idx.Len())

	// Process events from watcher.
	ctx, cancel := context.WithCancel(context.Background())
	sr.mu.Lock()
	sr.cancel = cancel
	sr.mu.Unlock()

	tombstoneTicker := time.NewTicker(1 * time.Hour)
	defer tombstoneTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case events, ok := <-w.Events():
			if !ok {
				return
			}
			sr.handleEvents(events)
		case <-tombstoneTicker.C:
			if n := sr.idx.PurgeTombstones(); n > 0 {
				sr.logf("tailsync: session %s: purged %d tombstones", sr.session.Name, n)
			}
		}
	}
}

func (sr *sessionRunner) handleEvents(events []watcher.Event) {
	sr.setState(tailsync.SessionStateSyncing)
	defer sr.setState(tailsync.SessionStateIdle)

	for _, ev := range events {
		if ev.Path == "" {
			// Empty path signals full rescan needed.
			sr.fullRescan()
			continue
		}
		sr.processEvent(ev)
	}

	sr.mu.Lock()
	sr.lastSync = time.Now()
	sr.mu.Unlock()
}

func (sr *sessionRunner) processEvent(ev watcher.Event) {
	absPath := filepath.Join(sr.root.Path, ev.Path)

	switch ev.Op {
	case watcher.OpDelete, watcher.OpRename:
		if sr.idx.Delete(ev.Path) {
			sr.logf("[v2] tailsync: session %s: deleted %s", sr.session.Name, ev.Path)
		}
	case watcher.OpCreate, watcher.OpModify:
		info, err := os.Lstat(absPath)
		if err != nil {
			// File may have been deleted between event and stat.
			if os.IsNotExist(err) {
				sr.idx.Delete(ev.Path)
			}
			return
		}

		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(absPath)
			if err != nil {
				return
			}
			if filepath.IsAbs(target) {
				return
			}
			sr.idx.UpdateSymlink(ev.Path, target, info)
			return
		}

		if !info.Mode().IsRegular() {
			return
		}

		hash, err := index.HashFile(absPath)
		if err != nil {
			sr.logf("tailsync: session %s: hash error %s: %v", sr.session.Name, ev.Path, err)
			return
		}

		if sr.idx.Update(ev.Path, info, hash) {
			sr.logf("[v2] tailsync: session %s: updated %s", sr.session.Name, ev.Path)
		}
	}
}

func (sr *sessionRunner) fullRescan() {
	sr.logf("tailsync: session %s: performing full rescan", sr.session.Name)

	ignoreFile := filepath.Join(sr.root.Path, ".tailsyncignore")
	matcher := ignore.LoadFile(ignoreFile, sr.root.Ignore)

	var paths []string
	filepath.WalkDir(sr.root.Path, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(sr.root.Path, path)
		if err != nil {
			return nil
		}
		if rel == "." {
			return nil
		}
		if matcher.Match(rel, d.IsDir()) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.IsDir() {
			paths = append(paths, rel)
		}
		return nil
	})

	// Check for new/modified files.
	seen := make(map[string]bool)
	for _, relPath := range paths {
		seen[relPath] = true
		absPath := filepath.Join(sr.root.Path, relPath)
		info, err := os.Lstat(absPath)
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(absPath)
			if err != nil || filepath.IsAbs(target) {
				continue
			}
			sr.idx.UpdateSymlink(relPath, target, info)
			continue
		}
		if !info.Mode().IsRegular() {
			continue
		}
		hash, err := index.HashFile(absPath)
		if err != nil {
			continue
		}
		sr.idx.Update(relPath, info, hash)
	}

	// Check for deleted files.
	for path, entry := range sr.idx.Entries() {
		if !entry.Deleted && !seen[path] {
			sr.idx.Delete(path)
		}
	}
}

func (sr *sessionRunner) status() *tailsync.SessionStatus {
	sr.mu.RLock()
	defer sr.mu.RUnlock()

	conflicts := make([]tailsync.ConflictInfo, len(sr.conflicts))
	copy(conflicts, sr.conflicts)

	return &tailsync.SessionStatus{
		Name:         sr.session.Name,
		State:        sr.state,
		FilesInSync:  sr.idx.LiveCount(),
		FilesPending: 0,
		BytesSent:    sr.bytesSent,
		BytesRecv:    sr.bytesRecv,
		Conflicts:    conflicts,
		LastSyncAt:   sr.lastSync,
		Error:        sr.errMsg,
	}
}

func (sr *sessionRunner) setState(state tailsync.SessionState) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	sr.state = state
	sr.errMsg = ""
}

func (sr *sessionRunner) setError(msg string) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	sr.state = tailsync.SessionStateError
	sr.errMsg = msg
	sr.logf("tailsync: session %s: error: %s", sr.session.Name, msg)
}

func (sr *sessionRunner) stop() {
	sr.cancel()
	<-sr.done
}
