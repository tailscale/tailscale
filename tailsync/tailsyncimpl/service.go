// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package tailsyncimpl implements the tailsync.Service interface.
package tailsyncimpl

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"tailscale.com/tailsync"
	"tailscale.com/types/logger"
)

// ConflictDir is the subdirectory for conflict copies.
const ConflictDir = ".tailsync-conflicts"

// Service implements tailsync.Service.
type Service struct {
	logf logger.Logf

	mu       sync.RWMutex
	roots    map[string]*tailsync.Root
	sessions map[string]*sessionRunner
	closed   bool
}

// NewService creates a new tailsync Service.
func NewService(logf logger.Logf) *Service {
	if logf == nil {
		logf = logger.Discard
	}
	return &Service{
		logf:     logf,
		roots:    make(map[string]*tailsync.Root),
		sessions: make(map[string]*sessionRunner),
	}
}

func (s *Service) SetRoot(root *tailsync.Root) error {
	name, err := tailsync.NormalizeRootName(root.Name)
	if err != nil {
		return err
	}
	root.Name = name

	root.Path = filepath.Clean(root.Path)
	fi, err := os.Stat(root.Path)
	if err != nil {
		return fmt.Errorf("stat root path: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", root.Path)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return tailsync.ErrSyncNotEnabled
	}
	s.roots[name] = root
	s.logf("tailsync: root set: %s -> %s", name, root.Path)
	return nil
}

func (s *Service) RemoveRoot(name string) error {
	name, err := tailsync.NormalizeRootName(name)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.roots[name]; !ok {
		return tailsync.ErrRootNotFound
	}

	// Stop any sessions using this root.
	for sname, sr := range s.sessions {
		if sr.session.LocalRoot == name {
			sr.stop()
			delete(s.sessions, sname)
		}
	}

	delete(s.roots, name)
	s.logf("tailsync: root removed: %s", name)
	return nil
}

func (s *Service) GetRoots() []*tailsync.Root {
	s.mu.RLock()
	defer s.mu.RUnlock()

	roots := make([]*tailsync.Root, 0, len(s.roots))
	for _, r := range s.roots {
		cp := *r
		roots = append(roots, &cp)
	}
	return roots
}

func (s *Service) SetSession(session *tailsync.Session) error {
	if session.Name == "" {
		return fmt.Errorf("session name is required")
	}
	if session.Mode == "" {
		session.Mode = tailsync.ModeTwoWaySafe
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return tailsync.ErrSyncNotEnabled
	}

	root, ok := s.roots[session.LocalRoot]
	if !ok {
		return fmt.Errorf("local root %q not found", session.LocalRoot)
	}

	// Stop existing session if any.
	if existing, ok := s.sessions[session.Name]; ok {
		existing.stop()
	}

	sr := newSessionRunner(s.logf, session, root)
	s.sessions[session.Name] = sr
	go sr.run()

	s.logf("tailsync: session started: %s (%s:%s <-> %s:%s, mode=%s)",
		session.Name, "local", session.LocalRoot, session.PeerID, session.RemoteRoot, session.Mode)
	return nil
}

func (s *Service) RemoveSession(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sr, ok := s.sessions[name]
	if !ok {
		return tailsync.ErrSessionNotFound
	}
	sr.stop()
	delete(s.sessions, name)
	s.logf("tailsync: session removed: %s", name)
	return nil
}

func (s *Service) GetSessions() []*tailsync.Session {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sessions := make([]*tailsync.Session, 0, len(s.sessions))
	for _, sr := range s.sessions {
		cp := *sr.session
		sessions = append(sessions, &cp)
	}
	return sessions
}

func (s *Service) GetSessionStatus(name string) (*tailsync.SessionStatus, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sr, ok := s.sessions[name]
	if !ok {
		return nil, tailsync.ErrSessionNotFound
	}
	return sr.status(), nil
}

// ServeHTTPWithPerms handles incoming PeerAPI sync requests from remote nodes.
func (s *Service) ServeHTTPWithPerms(permissions tailsync.Permissions, w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 {
		http.Error(w, "missing action", http.StatusBadRequest)
		return
	}

	action := parts[0]
	switch action {
	case "roots":
		s.handleRemoteRoots(permissions, w, r)
	case "index":
		s.handleRemoteIndex(permissions, w, r)
	case "push":
		s.handleRemotePush(permissions, w, r)
	case "pull":
		s.handleRemotePull(permissions, w, r)
	default:
		http.Error(w, "unknown action", http.StatusNotFound)
	}
}

func (s *Service) handleRemoteRoots(permissions tailsync.Permissions, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	var roots []string
	for name := range s.roots {
		if permissions.For(name) != tailsync.PermissionNone {
			roots = append(roots, name)
		}
	}
	json.NewEncoder(w).Encode(roots)
}

func (s *Service) handleRemoteIndex(permissions tailsync.Permissions, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rootName := r.URL.Query().Get("root")
	if permissions.For(rootName) == tailsync.PermissionNone {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	s.mu.RLock()
	sr := s.findSessionForRoot(rootName)
	s.mu.RUnlock()

	if sr == nil {
		http.Error(w, "no active session for root", http.StatusNotFound)
		return
	}

	data, err := sr.idx.Marshal()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// pushRequest is the JSON payload for a push.
type pushRequest struct {
	RootName string                `json:"root"`
	Entries  []*tailsync.FileEntry `json:"entries"`
}

func (s *Service) handleRemotePush(permissions tailsync.Permissions, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rootName := r.URL.Query().Get("root")
	if permissions.For(rootName) < tailsync.PermissionReadWrite {
		http.Error(w, "permission denied", http.StatusForbidden)
		return
	}

	s.mu.RLock()
	root, rootOK := s.roots[rootName]
	s.mu.RUnlock()
	if !rootOK {
		http.Error(w, "root not found", http.StatusNotFound)
		return
	}

	var req pushRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	applied := 0
	for _, entry := range req.Entries {
		if entry.Deleted {
			absPath := filepath.Join(root.Path, entry.Path)
			if err := os.Remove(absPath); err != nil && !os.IsNotExist(err) {
				s.logf("tailsync: push: failed to delete %s: %v", entry.Path, err)
			}
			applied++
			continue
		}
		applied++
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"applied": applied})
}

func (s *Service) handleRemotePull(permissions tailsync.Permissions, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rootName := r.URL.Query().Get("root")
	if permissions.For(rootName) == tailsync.PermissionNone {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	sinceSeq := uint64(0)
	if v := r.URL.Query().Get("since"); v != "" {
		fmt.Sscanf(v, "%d", &sinceSeq)
	}

	s.mu.RLock()
	sr := s.findSessionForRoot(rootName)
	s.mu.RUnlock()

	if sr == nil {
		http.Error(w, "no active session for root", http.StatusNotFound)
		return
	}

	entries := sr.idx.ChangedSince(sinceSeq)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

func (s *Service) findSessionForRoot(rootName string) *sessionRunner {
	for _, sr := range s.sessions {
		if sr.session.LocalRoot == rootName {
			return sr
		}
	}
	return nil
}

func (s *Service) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.closed = true
	for name, sr := range s.sessions {
		sr.stop()
		delete(s.sessions, name)
	}
	s.logf("tailsync: service closed")
	return nil
}

// fileWriter writes a file atomically via temp file + rename.
func fileWriter(absPath string, r io.Reader, mode os.FileMode) error {
	dir := filepath.Dir(absPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".tailsync-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := io.Copy(tmp, r); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close: %w", err)
	}

	if err := os.Chmod(tmpName, mode); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("chmod: %w", err)
	}

	if err := os.Rename(tmpName, absPath); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}
