// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package osshare provides utilities for enabling/disabling Taildrop file
// sharing on Windows.
package osshare

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/sys/windows/registry"
	"tailscale.com/types/lazy"
	"tailscale.com/types/logger"
	"tailscale.com/util/winutil"
)

const (
	sendFileShellKey = `*\shell\tailscale`
)

var ipnExePath lazy.SyncValue[string] // absolute path of the GUI executable

func getIpnExePath(logf logger.Logf) string {
	exe, err := winutil.GUIPathFromReg()
	if err == nil {
		return exe
	}

	return findGUIInSameDirAsThisExe(logf)
}

func findGUIInSameDirAsThisExe(logf logger.Logf) string {
	// Find the absolute path of the GUI, assuming that it's in the same
	// directory as this executable (tailscaled.exe).
	p, err := os.Executable()
	if err != nil {
		logf("os.Executable error: %v", err)
		return ""
	}
	if p, err = filepath.EvalSymlinks(p); err != nil {
		logf("filepath.EvalSymlinks error: %v", err)
		return ""
	}
	if p, err = filepath.Abs(p); err != nil {
		logf("filepath.Abs error: %v", err)
		return ""
	}
	d := filepath.Dir(p)
	candidates := []string{"tailscale-ipn.exe"}
	if runtime.GOARCH == "arm64" {
		// This name may be used on Windows 10 ARM64.
		candidates = append(candidates, "tailscale-gui-386.exe")
	}
	for _, c := range candidates {
		testPath := filepath.Join(d, c)
		if _, err := os.Stat(testPath); err == nil {
			return testPath
		}
	}
	return ""
}

// SetFileSharingEnabled adds/removes "Send with Tailscale" from the Windows shell menu.
func SetFileSharingEnabled(enabled bool, logf logger.Logf) {
	logf = logger.WithPrefix(logf, fmt.Sprintf("SetFileSharingEnabled(%v) error: ", enabled))
	if enabled {
		enableFileSharing(logf)
	} else {
		disableFileSharing(logf)
	}
}

func enableFileSharing(logf logger.Logf) {
	path := ipnExePath.Get(func() string {
		return getIpnExePath(logf)
	})
	if path == "" {
		return
	}

	k, _, err := registry.CreateKey(registry.CLASSES_ROOT, sendFileShellKey, registry.WRITE)
	if err != nil {
		logf("failed to create HKEY_CLASSES_ROOT\\%s reg key: %v", sendFileShellKey, err)
		return
	}
	defer k.Close()
	if err := k.SetStringValue("", "Send with Tailscale..."); err != nil {
		logf("k.SetStringValue error: %v", err)
		return
	}
	if err := k.SetStringValue("Icon", path+",1"); err != nil {
		logf("k.SetStringValue error: %v", err)
		return
	}
	c, _, err := registry.CreateKey(k, "command", registry.WRITE)
	if err != nil {
		logf("failed to create HKEY_CLASSES_ROOT\\%s\\command reg key: %v", sendFileShellKey, err)
		return
	}
	defer c.Close()
	if err := c.SetStringValue("", "\""+path+"\" /push \"%1\""); err != nil {
		logf("c.SetStringValue error: %v", err)
	}
}

func disableFileSharing(logf logger.Logf) {
	if err := registry.DeleteKey(registry.CLASSES_ROOT, sendFileShellKey+"\\command"); err != nil &&
		err != registry.ErrNotExist {
		logf("registry.DeleteKey error: %v\n", err)
		return
	}
	if err := registry.DeleteKey(registry.CLASSES_ROOT, sendFileShellKey); err != nil && err != registry.ErrNotExist {
		logf("registry.DeleteKey error: %v\n", err)
	}
}
