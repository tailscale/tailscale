// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package pidowner

import (
	"fmt"
	"os"
	"strings"

	"tailscale.com/util/lineread"
)

func ownerOfPID(pid int) (userID string, err error) {
	file := fmt.Sprintf("/proc/%d/status", pid)
	err = lineread.File(file, func(line []byte) error {
		if len(line) < 4 || string(line[:4]) != "Uid:" {
			return nil
		}
		f := strings.Fields(string(line))
		if len(f) >= 2 {
			userID = f[1] // real userid
		}
		return nil
	})
	if os.IsNotExist(err) {
		return "", ErrProcessNotFound
	}
	if err != nil {
		return
	}
	if userID == "" {
		return "", fmt.Errorf("missing Uid line in %s", file)
	}
	return userID, nil
}
