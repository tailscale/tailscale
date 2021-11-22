// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hostinfo

import (
	"fmt"
	"sync/atomic"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func init() {
	osVersion = osVersionWindows
}

var winVerCache atomic.Value // of string

func osVersionWindows() string {
	if s, ok := winVerCache.Load().(string); ok {
		return s
	}
	major, minor, build := windows.RtlGetNtVersionNumbers()
	s := fmt.Sprintf("%d.%d.%d", major, minor, build)
	// Windows 11 still uses 10 as its major number internally
	if major == 10 {
		if ubr, err := getUBR(); err == nil {
			s += fmt.Sprintf(".%d", ubr)
		}
	}
	if s != "" {
		winVerCache.Store(s)
	}
	return s // "10.0.19041.388", ideally
}

// getUBR obtains a fourth version field, the "Update Build Revision",
// from the registry. This field is only available beginning with Windows 10.
func getUBR() (uint32, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return 0, err
	}
	defer key.Close()

	val, valType, err := key.GetIntegerValue("UBR")
	if err != nil {
		return 0, err
	}
	if valType != registry.DWORD {
		return 0, registry.ErrUnexpectedType
	}

	return uint32(val), nil
}
