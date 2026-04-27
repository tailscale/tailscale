// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_drive_magic

package driveimpl

import (
	"net/http"
	"os"
	"path/filepath"
	"sort"

	"github.com/tailscale/xnet/webdav"
	"tailscale.com/drive"
	"tailscale.com/drive/driveimpl/compositedav"
	"tailscale.com/drive/driveimpl/dirfs"
	"tailscale.com/drive/magic"
)

// topLevelDirWriteMethods are write-ish WebDAV methods that, when targeted
// at a magic share's top-level ACL directory itself (e.g. /<magic>/<acldir>),
// must be denied. Top-level dir creation/deletion is equivalent to writing
// a grant and is sharer-local only.
var topLevelDirWriteMethods = map[string]bool{
	"MKCOL":     true,
	"DELETE":    true,
	"MOVE":      true,
	"PROPPATCH": true,
	"COPY":      true,
}

// maybeServeMagic dispatches to the magic-share handler if share is a magic
// share, returning true if the request was handled.
func (s *FileSystemForRemote) maybeServeMagic(authz drive.Authz, share *drive.Share, pathComponents []string, w http.ResponseWriter, r *http.Request) bool {
	if !share.IsMagic() {
		return false
	}
	s.serveMagic(authz, share, pathComponents, w, r)
	return true
}

// serveMagic handles a request whose first path segment is a magic share.
// It enforces ACL-name filtering: peers only see (and can only descend into)
// top-level directories whose name encodes an ACL they match. Top-level dir
// creation/deletion is denied for remote peers.
func (s *FileSystemForRemote) serveMagic(authz drive.Authz, share *drive.Share, pathComponents []string, w http.ResponseWriter, r *http.Request) {
	if len(pathComponents) == 1 || (len(pathComponents) == 2 && pathComponents[1] == "") {
		if writeMethods[r.Method] {
			http.Error(w, "magic share top-level is read-only for remote peers", http.StatusForbidden)
			return
		}
		s.serveMagicTopLevel(authz, share, w, r)
		return
	}

	aclDir := pathComponents[1]
	if !aclDirGrantsPeer(authz, share.Path, aclDir) {
		// Use 404 rather than 403 to avoid confirming the dir's existence.
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	if len(pathComponents) == 2 && topLevelDirWriteMethods[r.Method] {
		http.Error(w, "magic top-level dir is sharer-local only", http.StatusForbidden)
		return
	}

	// Forward to the regular compositedav pipeline. We rebuild children
	// rather than reusing the cached map directly, because the magic share
	// must remain accessible here even though it was filtered out above.
	s.mu.RLock()
	childrenMap := s.children
	s.mu.RUnlock()

	children := make([]*compositedav.Child, 0, len(childrenMap))
	for name, child := range childrenMap {
		if name != share.Name && authz.Permissions.For(name) == drive.PermissionNone {
			continue
		}
		children = append(children, child)
	}

	h := compositedav.Handler{Logf: s.logf}
	h.SetChildren("", children...)
	h.ServeHTTP(w, r)
}

// serveMagicTopLevel serves a synthetic listing of /<share>/ that contains
// only the top-level dirs the peer matches.
func (s *FileSystemForRemote) serveMagicTopLevel(authz drive.Authz, share *drive.Share, w http.ResponseWriter, r *http.Request) {
	var children []*dirfs.Child
	if authz.SharerLogin != "" {
		entries, err := os.ReadDir(share.Path)
		if err != nil {
			s.logf("taildrive magic: read dir %q: %v", share.Path, err)
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			acl, err := magic.ParseDirACL(e.Name())
			if err != nil {
				continue
			}
			if acl.Matches(authz.PeerLogin, authz.SharerLogin) {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		children = make([]*dirfs.Child, 0, len(names))
		for _, n := range names {
			children = append(children, &dirfs.Child{Name: n})
		}
	}
	wh := &webdav.Handler{
		LockSystem: webdav.NewMemLS(),
		FileSystem: &dirfs.FS{
			Children:   children,
			StaticRoot: share.Name,
		},
	}
	wh.ServeHTTP(w, r)
}

// aclDirGrantsPeer reports whether aclDir exists on disk under sharePath as a
// directory and its parsed ACL grants the peer access (sharer-in-name rule
// plus peer match). It does no enumeration; only the single aclDir is
// inspected.
func aclDirGrantsPeer(authz drive.Authz, sharePath, aclDir string) bool {
	if authz.SharerLogin == "" {
		return false
	}
	acl, err := magic.ParseDirACL(aclDir)
	if err != nil {
		return false
	}
	if !acl.Matches(authz.PeerLogin, authz.SharerLogin) {
		return false
	}
	fi, err := os.Stat(filepath.Join(sharePath, aclDir))
	if err != nil || !fi.IsDir() {
		return false
	}
	return true
}
