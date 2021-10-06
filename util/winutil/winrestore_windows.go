// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package winutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/windows"

	"tailscale.com/paths"
	"tailscale.com/util/winutil/vss"
)

// StopWalking is the error value that a WalkSnapshotsFunc should return when
// it successfully completes and no longer needs to examine any more snapshots.
var StopWalking error = errors.New("Stop walking")

// WalkSnapshotsFunc is the type of the function called by WalkSnapshotsForLegacyStateDir
// to visit each mapped VSS snapshot.
// The path argument is the path of the directory containing the Tailscale state.
// The props argument contains the snapshot properties of the current snapshot, and
// should be treated as read-only.
// The function may return StopWalking if further walking is no longer necessary.
// Otherwise it should return nil to proceed with the walk, or an error.
type WalkSnapshotsFunc func(path string, props vss.SnapshotProperties) error

// WalkSnapshotsForLegacyStateDir enumerates available snapshots from the
// Volume Shadow Copy service. For each snapshot originating from this computer's
// C: volume,	the snapshot is mounted to a temporary location inside the
// Tailscaled state directory.
// If the mounted snapshot contains a path to a legacy state directory (located under
// C:\Windows\System32\config\systemprofile\AppData\Local), the fn argument is
// invoked with the fully-qualified path to the mounted state directory, as well
// as the properties of the snapshot itself.
// A mounted snapshot that does not contain a path to a legacy state directory is
// not considered to be an error, the snapshot is ignored, and the walk continues.
// If fn returns StopWalking, then the walk is terminated but is considered to
// have been successful and nil is returned.
// If fn returns a different error, then the walk is terminated and fn's error
// is wrapped and then returned to the caller.
func WalkSnapshotsForLegacyStateDir(fn WalkSnapshotsFunc) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Ideally COM would be initialized process-wide, but until we have that
	// conversation this should be okay, especially given that this function will
	// only be called when a migration is necessary.
	err := windows.CoInitializeEx(0, windows.COINIT_MULTITHREADED)
	if err != nil {
		return err
	}
	defer windows.CoUninitialize()

	sysVol, err := getSystemVolumeName()
	if err != nil {
		return err
	}

	thisMachine, err := getFullyQualifiedComputerName()
	if err != nil {
		return err
	}

	// We'll map each snapshot to a subdir inside our tailscaled state dir
	mountPt := filepath.Dir(paths.DefaultTailscaledStateFile())

	vssSnapshotEnumerator, err := vss.NewSnapshotEnumerator()
	if err != nil {
		return err
	}
	defer vssSnapshotEnumerator.Close()

	snapshots, err := vssSnapshotEnumerator.QuerySnapshots()
	if err != nil {
		return err
	}
	defer snapshots.Close()

	for _, snap := range snapshots {
		if !strings.EqualFold(snap.Obj.OriginalVolumeName.String(), sysVol) ||
			!strings.EqualFold(snap.Obj.OriginatingMachine.String(), thisMachine) {
			// These snapshots do not belong to our computer's C: volume, so we should skip them.
			continue
		}

		mounted, err := mountSnapshotDevice(snap.Obj, mountPt)
		if err != nil {
			return fmt.Errorf("Mapping snapshot device %v: %w", snap.Obj.SnapshotDeviceObject.String(), err)
		}
		defer mounted.Close()

		legacyStateDir, err := mounted.findLegacyStateDir()
		if err != nil {
			// Not all snapshots will necessarily contain the state dir, so this is not fatal
			continue
		}

		err = fn(legacyStateDir, snap.Obj)
		if errors.Is(err, StopWalking) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("WalkSnapshotsFunc returned error %w", err)
		}
	}

	return nil
}

func getSystemVolumeName() (string, error) {
	// This is the exact length of a volume name, including nul terminator (per MSDN)
	var volName [50]uint16

	// Modern Windows always requires that the OS be installed on C:
	mountPt, err := windows.UTF16PtrFromString("C:\\")
	if err != nil {
		return "", err
	}

	err = windows.GetVolumeNameForVolumeMountPoint(mountPt, &volName[0], uint32(len(volName)))
	if err != nil {
		return "", err
	}

	return windows.UTF16ToString(volName[:len(volName)-1]), nil
}

type mountedSnapshot string

func (snap *mountedSnapshot) Close() error {
	os.Remove(string(*snap))
	*snap = ""
	return nil
}

func mountSnapshotDevice(snap vss.SnapshotProperties, mountPath string) (mountedSnapshot, error) {
	fi, err := os.Stat(mountPath)
	if err != nil {
		return "", err
	}
	if !fi.IsDir() {
		return "", os.ErrInvalid
	}

	devPath := snap.SnapshotDeviceObject.String()
	linkPath := filepath.Join(mountPath, filepath.Base(devPath))

	linkPathUTF16, err := windows.UTF16PtrFromString(linkPath)
	if err != nil {
		return "", err
	}

	// The target needs to end with a backslash or else the symlink won't resolve correctly
	deviceUTF16, err := windows.UTF16PtrFromString(devPath + "\\")
	if err != nil {
		return "", err
	}

	err = windows.CreateSymbolicLink(linkPathUTF16, deviceUTF16, windows.SYMBOLIC_LINK_FLAG_DIRECTORY)
	if err != nil {
		return "", err
	}

	return mountedSnapshot(linkPath), nil
}

func (snap *mountedSnapshot) findLegacyStateDir() (string, error) {
	legacyStateDir := filepath.Dir(paths.LegacyStateFilePath())
	relPath, err := filepath.Rel("C:\\", legacyStateDir)
	if err != nil {
		return "", err
	}

	snapStateDir := filepath.Join(string(*snap), relPath)
	fi, err := os.Stat(snapStateDir)
	if err != nil {
		return "", err
	}
	if !fi.IsDir() {
		return "", os.ErrInvalid
	}

	return snapStateDir, nil
}

func getFullyQualifiedComputerName() (string, error) {
	var desiredLen uint32
	err := windows.GetComputerNameEx(windows.ComputerNamePhysicalDnsFullyQualified, nil, &desiredLen)
	if !errors.Is(err, windows.ERROR_MORE_DATA) {
		return "", err
	}

	buf := make([]uint16, desiredLen+1)

	// Note: bufLen includes nul terminator on input, but excludes nul terminator as output
	bufLen := uint32(len(buf))
	err = windows.GetComputerNameEx(windows.ComputerNamePhysicalDnsFullyQualified, &buf[0], &bufLen)
	if err != nil {
		return "", err
	}

	return windows.UTF16ToString(buf[:bufLen]), nil
}
