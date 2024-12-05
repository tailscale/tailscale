// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package paths

import (
	"os"
	"path/filepath"

	"tailscale.com/types/logger"
)

// TryConfigFileMigration carefully copies the contents of oldFile to
// newFile, returning the path which should be used to read the config.
//   - if newFile already exists, don't modify it just return its path
//   - if neither oldFile nor newFile exist, return newFile for a fresh
//     default config to be written to.
//   - if oldFile exists but copying to newFile fails, return oldFile so
//     there will at least be some config to work with.
func TryConfigFileMigration(logf logger.Logf, oldFile, newFile string) string {
	_, err := os.Stat(newFile)
	if err == nil {
		// Common case for a system which has already been migrated.
		return newFile
	}
	if !os.IsNotExist(err) {
		logf("TryConfigFileMigration failed; new file: %v", err)
		return newFile
	}

	contents, err := os.ReadFile(oldFile)
	if err != nil {
		// Common case for a new user.
		return newFile
	}

	if err = MkStateDir(filepath.Dir(newFile)); err != nil {
		logf("TryConfigFileMigration failed; MkStateDir: %v", err)
		return oldFile
	}

	err = os.WriteFile(newFile, contents, 0600)
	if err != nil {
		removeErr := os.Remove(newFile)
		if removeErr != nil {
			logf("TryConfigFileMigration failed; write newFile no cleanup: %v, remove err: %v",
				err, removeErr)
			return oldFile
		}
		logf("TryConfigFileMigration failed; write newFile: %v", err)
		return oldFile
	}

	logf("TryConfigFileMigration: successfully migrated: from %v to %v",
		oldFile, newFile)

	return newFile
}
