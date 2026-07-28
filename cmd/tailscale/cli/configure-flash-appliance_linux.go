// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_flashappliance

package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"
)

// discoverExternalDisks returns no disks on Linux: the user must pass
// --disk=/dev/sdX. We don't try to enumerate removable disks here because
// the right answer depends heavily on the host (servers don't have
// removable media; Pi-on-Pi flashing has no notion of "external"; LVM
// setups have arbitrary names).
func discoverExternalDisks(_ context.Context) ([]diskCandidate, error) {
	return nil, errors.New("on Linux, pass --disk=/dev/sdX (auto-discovery is macOS-only)")
}

// validateDiskPath rejects partition paths, the running root disk, and
// disks with any partition currently mounted.
func validateDiskPath(path string) error {
	if !strings.HasPrefix(path, "/dev/") {
		return fmt.Errorf("disk path %q must start with /dev/", path)
	}
	if isPartitionPath(path) {
		return fmt.Errorf("disk path %q looks like a partition; pass the whole disk", path)
	}
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if fi.Mode()&os.ModeDevice == 0 {
		return fmt.Errorf("%s is not a device file", path)
	}
	mounts, err := mountedSources()
	if err != nil {
		return err
	}
	for _, m := range mounts {
		if m == path || strings.HasPrefix(m, path) {
			return fmt.Errorf("%s (or one of its partitions) is currently mounted; unmount it first", path)
		}
	}
	return nil
}

// isPartitionPath reports whether path looks like a partition (e.g.
// /dev/sda1, /dev/nvme0n1p2, /dev/mmcblk0p1) rather than a whole disk.
func isPartitionPath(path string) bool {
	base := strings.TrimPrefix(path, "/dev/")
	switch {
	case strings.HasPrefix(base, "sd"), strings.HasPrefix(base, "hd"), strings.HasPrefix(base, "vd"):
		// /dev/sdaN — partition.
		if len(base) >= 4 && base[len(base)-1] >= '0' && base[len(base)-1] <= '9' {
			return true
		}
	case strings.HasPrefix(base, "nvme"), strings.HasPrefix(base, "mmcblk"), strings.HasPrefix(base, "loop"):
		// /dev/nvme0n1p1 — partition is "<diskname>p<digits>". The 'p'
		// must follow a digit (to distinguish loop0 from loop0p1).
		i := strings.LastIndexByte(base, 'p')
		if i <= 0 || i >= len(base)-1 || base[i-1] < '0' || base[i-1] > '9' {
			return false
		}
		for _, r := range base[i+1:] {
			if r < '0' || r > '9' {
				return false
			}
		}
		return true
	}
	return false
}

// mountedSources returns the source device paths from /proc/mounts.
func mountedSources() ([]string, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) > 0 {
			out = append(out, fields[0])
		}
	}
	return out, sc.Err()
}

// unmountDisk unmounts every entry in /proc/mounts whose source starts with
// path (covers /dev/sdb plus /dev/sdb1, /dev/sdb2, ...).
func unmountDisk(ctx context.Context, path string) error {
	mounts, err := mountedSources()
	if err != nil {
		return err
	}
	for _, m := range mounts {
		if m == path || strings.HasPrefix(m, path) {
			cmd := exec.CommandContext(ctx, "umount", m)
			cmd.Stdout = Stderr
			cmd.Stderr = Stderr
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("umount %s: %w", m, err)
			}
		}
	}
	return nil
}

func openBlockDevice(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|unix.O_SYNC, 0)
}

// rereadPartitionTable asks the kernel to re-scan the partition table on
// the open block device. Required on Linux before we can mkfs the perm
// partition we just wrote.
func rereadPartitionTable(f *os.File) error {
	return unix.IoctlSetInt(int(f.Fd()), unix.BLKRRPART, 0)
}

// syncBlockDevice flushes pending writes to disk.
func syncBlockDevice(f *os.File) error { return f.Sync() }

// ejectDisk is a no-op on Linux; the user just pulls the disk after
// the sync at the end of writeGAFToDisk. Returns false so the success
// message instructs the user to eject themselves.
func ejectDisk(_ context.Context, _ string) (bool, error) { return false, nil }

// blockDeviceSize returns the size in bytes of the open block device f.
// BLKGETSIZE64 returns a uint64; on 64-bit linux IoctlGetInt's int is wide
// enough to receive it without needing an unsafe.Pointer.
func blockDeviceSize(f *os.File) (int64, error) {
	size, err := unix.IoctlGetInt(int(f.Fd()), unix.BLKGETSIZE64)
	if err != nil {
		return 0, fmt.Errorf("BLKGETSIZE64: %w", err)
	}
	return int64(size), nil
}
