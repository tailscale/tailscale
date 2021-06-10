// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build cgo

package groupmember

import (
	"os/user"
	"sync"
)

func isMemberOfGroup(group, name string) (bool, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return false, err
	}
	ugids, err := u.GroupIds()
	if err != nil {
		return false, err
	}
	gid, err := getGroupID(group)
	if err != nil {
		return false, err
	}
	for _, ugid := range ugids {
		if gid == ugid {
			return true, nil
		}
	}
	return false, nil
}

var groupIDCache sync.Map // of string

func getGroupID(groupName string) (string, error) {
	s, ok := groupIDCache.Load(groupName)
	if ok {
		return s.(string), nil
	}
	g, err := user.LookupGroup(groupName)
	if err != nil {
		return "", err
	}
	groupIDCache.Store(groupName, g.Gid)
	return g.Gid, nil
}
