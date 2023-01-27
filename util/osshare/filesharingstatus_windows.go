// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package osshare

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/windows/registry"
	"tailscale.com/types/logger"
)

const (
	sendFileShellKey = `*\shell\tailscale`
)

var ipnExePath struct {
	sync.Mutex
	cache string // absolute path of tailscale-ipn.exe, populated lazily on first use
}

func getIpnExePath(logf logger.Logf) string {
	ipnExePath.Lock()
	defer ipnExePath.Unlock()

	if ipnExePath.cache != "" {
		return ipnExePath.cache
	}

	// Find the absolute path of tailscale-ipn.exe assuming that it's in the same
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
	p = filepath.Join(filepath.Dir(p), "tailscale-ipn.exe")
	if p, err = filepath.Abs(p); err != nil {
		logf("filepath.Abs error: %v", err)
		return ""
	}
	ipnExePath.cache = p

	return p
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
	path := getIpnExePath(logf)
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
	if err := k.SetStringValue("Icon", path+",0"); err != nil {
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
