// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package integration

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// tryLinkat attempts to hardlink the file referenced by fd to newpath,
// avoiding a full copy of the binary. It uses /proc/self/fd/<N> with
// AT_SYMLINK_FOLLOW, which works without elevated privileges (unlike
// AT_EMPTY_PATH which requires CAP_DAC_READ_SEARCH).
func tryLinkat(fd *os.File, newpath string) error {
	procPath := fmt.Sprintf("/proc/self/fd/%d", fd.Fd())
	err := unix.Linkat(unix.AT_FDCWD, procPath, unix.AT_FDCWD, newpath, unix.AT_SYMLINK_FOLLOW)
	if err != nil {
		return fmt.Errorf("linkat via /proc/self/fd: %w", err)
	}
	return nil
}
