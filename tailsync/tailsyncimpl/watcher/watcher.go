// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package watcher provides filesystem change detection using fsnotify
// with periodic full-scan fallback for the tailsync subsystem.
package watcher

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"tailscale.com/tailsync/tailsyncimpl/ignore"
	"tailscale.com/types/logger"
)

// Event represents a filesystem change event.
type Event struct {
	// Path is the relative path within the watched root.
	Path string

	// Op is the type of change.
	Op Op
}

// Op describes the type of filesystem operation.
type Op uint8

const (
	OpCreate Op = iota
	OpModify
	OpDelete
	OpRename
)

// Watcher watches a directory tree for changes and emits events.
type Watcher struct {
	logf         logger.Logf
	root         string
	matcher      *ignore.Matcher
	debounce     time.Duration
	scanInterval time.Duration

	fsw    *fsnotify.Watcher
	events chan []Event
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Config configures a Watcher.
type Config struct {
	// Root is the absolute path to watch.
	Root string

	// Matcher determines which paths to ignore.
	Matcher *ignore.Matcher

	// Logf is the logging function.
	Logf logger.Logf

	// Debounce is how long to wait after the last event before emitting.
	// Defaults to 200ms.
	Debounce time.Duration

	// ScanInterval is how often to do a full reconciliation scan.
	// Defaults to 60s.
	ScanInterval time.Duration
}

// New creates and starts a new Watcher. Events are delivered on the
// channel returned by Events(). Call Close() to stop watching.
func New(cfg Config) (*Watcher, error) {
	if cfg.Debounce == 0 {
		cfg.Debounce = 200 * time.Millisecond
	}
	if cfg.ScanInterval == 0 {
		cfg.ScanInterval = 60 * time.Second
	}
	if cfg.Logf == nil {
		cfg.Logf = logger.Discard
	}

	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	w := &Watcher{
		logf:         cfg.Logf,
		root:         cfg.Root,
		matcher:      cfg.Matcher,
		debounce:     cfg.Debounce,
		scanInterval: cfg.ScanInterval,
		fsw:          fsw,
		events:       make(chan []Event, 64),
		cancel:       cancel,
	}

	if err := w.addWatchesRecursive(cfg.Root); err != nil {
		fsw.Close()
		cancel()
		return nil, err
	}

	w.wg.Add(2)
	go w.eventLoop(ctx)
	go w.scanLoop(ctx)

	return w, nil
}

// Events returns the channel on which batched events are delivered.
func (w *Watcher) Events() <-chan []Event {
	return w.events
}

// Close stops the watcher and releases resources.
func (w *Watcher) Close() error {
	w.cancel()
	err := w.fsw.Close()
	w.wg.Wait()
	close(w.events)
	return err
}

// ScanFull performs a full scan of the watched root and returns all
// file paths found (relative to root). This is used for initial index
// building and periodic reconciliation.
func (w *Watcher) ScanFull() ([]string, error) {
	return w.scanDir(w.root)
}

func (w *Watcher) scanDir(root string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip errors, log them
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		if rel == "." {
			return nil
		}
		if w.matcher.Match(rel, d.IsDir()) {
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
	return paths, err
}

func (w *Watcher) addWatchesRecursive(root string) error {
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(w.root, path)
		if err != nil {
			return nil
		}
		if rel != "." && w.matcher.Match(rel, true) {
			return filepath.SkipDir
		}
		if err := w.fsw.Add(path); err != nil {
			w.logf("tailsync: watcher: failed to watch %s: %v", path, err)
		}
		return nil
	})
}

func (w *Watcher) eventLoop(ctx context.Context) {
	defer w.wg.Done()

	var (
		pending = make(map[string]Op)
		timer   *time.Timer
		timerC  <-chan time.Time
	)

	flush := func() {
		if len(pending) == 0 {
			return
		}
		batch := make([]Event, 0, len(pending))
		for path, op := range pending {
			batch = append(batch, Event{Path: path, Op: op})
		}
		pending = make(map[string]Op)
		select {
		case w.events <- batch:
		case <-ctx.Done():
			return
		}
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case ev, ok := <-w.fsw.Events:
			if !ok {
				flush()
				return
			}
			rel, err := filepath.Rel(w.root, ev.Name)
			if err != nil {
				continue
			}

			info, statErr := os.Lstat(ev.Name)
			isDir := statErr == nil && info.IsDir()

			if w.matcher.Match(rel, isDir) {
				continue
			}

			// If a new directory was created, add watches for it.
			if isDir && ev.Has(fsnotify.Create) {
				w.addWatchesRecursive(ev.Name)
			}

			var op Op
			switch {
			case ev.Has(fsnotify.Create):
				op = OpCreate
			case ev.Has(fsnotify.Write):
				op = OpModify
			case ev.Has(fsnotify.Remove):
				op = OpDelete
			case ev.Has(fsnotify.Rename):
				op = OpRename
			default:
				continue
			}

			// For directories, skip (we care about files).
			if isDir && op != OpDelete {
				continue
			}

			pending[rel] = op

			if timer == nil {
				timer = time.NewTimer(w.debounce)
				timerC = timer.C
			} else {
				timer.Reset(w.debounce)
			}

		case err, ok := <-w.fsw.Errors:
			if !ok {
				flush()
				return
			}
			w.logf("tailsync: watcher error: %v", err)
			// On error, trigger a full scan.
			select {
			case w.events <- []Event{{Path: "", Op: OpModify}}: // empty path signals full rescan needed
			case <-ctx.Done():
				return
			}

		case <-timerC:
			flush()
			timer = nil
			timerC = nil
		}
	}
}

func (w *Watcher) scanLoop(ctx context.Context) {
	defer w.wg.Done()

	ticker := time.NewTicker(w.scanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Signal a periodic rescan by sending an empty-path event.
			select {
			case w.events <- []Event{{Path: "", Op: OpModify}}:
			case <-ctx.Done():
				return
			}
		}
	}
}
