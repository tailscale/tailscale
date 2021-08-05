// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !cgo && (linux || darwin)
// +build !cgo
// +build linux darwin

package groupmember

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"go4.org/mem"
	"tailscale.com/version/distro"
)

func isMemberOfGroup(group, name string) (bool, error) {
	if distro.Get() == distro.Synology {
		return isMemberOfGroupEtcGroup(group, name)
	}
	cmd := exec.Command("/usr/bin/env", "groups", name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, err
	}
	groups := strings.Split(strings.TrimSpace(string(out)), " ")
	for _, g := range groups {
		if g == group {
			return true, nil
		}
	}
	return false, nil
}

func isMemberOfGroupEtcGroup(group, name string) (bool, error) {
	f, err := os.Open("/etc/group")
	if err != nil {
		return false, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	var agLine string
	for s.Scan() {
		if !mem.HasPrefix(mem.B(s.Bytes()), mem.S(fmt.Sprintf("%s:", group))) {
			continue
		}
		agLine = s.Text()
		break
	}
	if err := s.Err(); err != nil {
		return false, err
	}
	if agLine == "" {
		return false, fmt.Errorf("admin group not defined")
	}
	agEntry := strings.Split(agLine, ":")
	if len(agEntry) < 4 {
		return false, fmt.Errorf("malformed admin group entry")
	}
	agMembers := agEntry[3]
	for _, m := range strings.Split(agMembers, ",") {
		if m == name {
			return true, nil
		}
	}
	return false, nil
}
