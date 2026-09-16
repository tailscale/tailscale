// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package auditlog

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"tailscale.com/ipn/store"
	"tailscale.com/types/lazy"
	"tailscale.com/types/logger"
	"tailscale.com/util/must"
)

var storeFilePath lazy.SyncValue[string]

// SetStoreFilePath sets the audit log store file path.
// It is optional on platforms with a default store path,
// but required on platforms without one (e.g., macOS).
// It panics if called more than once or after the store has been created.
func SetStoreFilePath(path string) {
	if !storeFilePath.Set(path) {
		panic("store file path already set or used")
	}
}

// DefaultStoreFilePath returns the default audit log store file path
// for the current platform, or an error if the platform does not have one.
func DefaultStoreFilePath() (string, error) {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("ProgramData"), "Tailscale", "audit-log.json"), nil
	default:
		// The auditlog package must either be omitted from the build,
		// have the platform-specific store path set with [SetStoreFilePath] (e.g., on macOS),
		// or have the default store path available on the current platform.
		return "", fmt.Errorf("[unexpected] no default store path available on %s", runtime.GOOS)
	}
}

// newDefaultLogStore returns a new [LogStore] for the current platform. Its
// file is the path set with [SetStoreFilePath] if any, else audit-log.json in
// varRoot (the backend's state directory) if that is known, else the platform
// default from [DefaultStoreFilePath]. For the Windows service the state
// directory is the platform default's directory anyway; the difference is for
// a tailscaled run by a user with their own --statedir, which cannot write
// under %ProgramData%.
func newDefaultLogStore(logf logger.Logf, varRoot string) (LogStore, error) {
	path, err := storeFilePath.GetErr(func() (string, error) {
		if varRoot != "" {
			return filepath.Join(varRoot, "audit-log.json"), nil
		}
		return DefaultStoreFilePath()
	})
	if err != nil {
		// This indicates that the auditlog package was not omitted from the build
		// on a platform without a default store path and that [SetStoreFilePath]
		// was not called to set a platform-specific store path.
		//
		// This is not expected to happen, but if it does, let's log it
		// and use an in-memory store as a fallback.
		logf("[unexpected] failed to get audit log store path: %v", err)
		return NewLogStore(must.Get(store.New(logf, "mem:auditlog"))), nil
	}
	fs, err := store.New(logf, path)
	if err != nil {
		return nil, fmt.Errorf("failed to create audit log store at %q: %w", path, err)
	}
	return NewLogStore(fs), nil
}
