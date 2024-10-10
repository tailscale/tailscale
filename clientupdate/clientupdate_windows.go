// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Windows-specific stuff that can't go in clientupdate.go because it needs
// x/sys/windows.

package clientupdate

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/sys/windows"
	"tailscale.com/util/winutil"
	"tailscale.com/util/winutil/authenticode"
)

const (
	// winMSIEnv is the environment variable that, if set, is the MSI file for
	// the update command to install. It's passed like this so we can stop the
	// tailscale.exe process from running before the msiexec process runs and
	// tries to overwrite ourselves.
	winMSIEnv = "TS_UPDATE_WIN_MSI"
	// winExePathEnv is the environment variable that is set along with
	// winMSIEnv and carries the full path of the calling tailscale.exe binary.
	// It is used to re-launch the GUI process (tailscale-ipn.exe) after
	// install is complete.
	winExePathEnv = "TS_UPDATE_WIN_EXE_PATH"
)

func makeSelfCopy() (origPathExe, tmpPathExe string, err error) {
	selfExe, err := os.Executable()
	if err != nil {
		return "", "", err
	}
	f, err := os.Open(selfExe)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	f2, err := os.CreateTemp("", "tailscale-updater-*.exe")
	if err != nil {
		return "", "", err
	}
	if err := markTempFileWindows(f2.Name()); err != nil {
		return "", "", err
	}
	if _, err := io.Copy(f2, f); err != nil {
		f2.Close()
		return "", "", err
	}
	return selfExe, f2.Name(), f2.Close()
}

func markTempFileWindows(name string) error {
	name16 := windows.StringToUTF16Ptr(name)
	return windows.MoveFileEx(name16, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
}

const certSubjectTailscale = "Tailscale Inc."

func verifyAuthenticode(path string) error {
	return authenticode.Verify(path, certSubjectTailscale)
}

func (up *Updater) updateWindows() error {
	if msi := os.Getenv(winMSIEnv); msi != "" {
		// stdout/stderr from this part of the install could be lost since the
		// parent tailscaled is replaced. Create a temp log file to have some
		// output to debug with in case update fails.
		close, err := up.switchOutputToFile()
		if err != nil {
			up.Logf("failed to create log file for installation: %v; proceeding with existing outputs", err)
		} else {
			defer close.Close()
		}

		up.Logf("installing %v ...", msi)
		if err := up.installMSI(msi); err != nil {
			up.Logf("MSI install failed: %v", err)
			return err
		}

		up.Logf("success.")
		return nil
	}

	if !winutil.IsCurrentProcessElevated() {
		return errors.New(`update must be run as Administrator

you can run the command prompt as Administrator one of these ways:
* right-click cmd.exe, select 'Run as administrator'
* press Windows+x, then press a
* press Windows+r, type in "cmd", then press Ctrl+Shift+Enter`)
	}
	ver, err := requestedTailscaleVersion(up.Version, up.Track)
	if err != nil {
		return err
	}
	arch := runtime.GOARCH
	if arch == "386" {
		arch = "x86"
	}
	if !up.confirm(ver) {
		return nil
	}

	tsDir := filepath.Join(os.Getenv("ProgramData"), "Tailscale")
	msiDir := filepath.Join(tsDir, "MSICache")
	if fi, err := os.Stat(tsDir); err != nil {
		return fmt.Errorf("expected %s to exist, got stat error: %w", tsDir, err)
	} else if !fi.IsDir() {
		return fmt.Errorf("expected %s to be a directory; got %v", tsDir, fi.Mode())
	}
	if err := os.MkdirAll(msiDir, 0700); err != nil {
		return err
	}
	up.cleanupOldDownloads(filepath.Join(msiDir, "*.msi"))
	pkgsPath := fmt.Sprintf("%s/tailscale-setup-%s-%s.msi", up.Track, ver, arch)
	msiTarget := filepath.Join(msiDir, path.Base(pkgsPath))
	if err := up.downloadURLToFile(pkgsPath, msiTarget); err != nil {
		return err
	}

	up.Logf("verifying MSI authenticode...")
	if err := verifyAuthenticode(msiTarget); err != nil {
		return fmt.Errorf("authenticode verification of %s failed: %w", msiTarget, err)
	}
	up.Logf("authenticode verification succeeded")

	up.Logf("making tailscale.exe copy to switch to...")
	up.cleanupOldDownloads(filepath.Join(os.TempDir(), "tailscale-updater-*.exe"))
	selfOrig, selfCopy, err := makeSelfCopy()
	if err != nil {
		return err
	}
	defer os.Remove(selfCopy)
	up.Logf("running tailscale.exe copy for final install...")

	cmd := exec.Command(selfCopy, "update")
	cmd.Env = append(os.Environ(), winMSIEnv+"="+msiTarget, winExePathEnv+"="+selfOrig)
	cmd.Stdout = up.Stderr
	cmd.Stderr = up.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Start(); err != nil {
		return err
	}
	// Once it's started, exit ourselves, so the binary is free
	// to be replaced.
	os.Exit(0)
	panic("unreachable")
}

func (up *Updater) installMSI(msi string) error {
	var err error
	for tries := 0; tries < 2; tries++ {
		cmd := exec.Command("msiexec.exe", "/i", filepath.Base(msi), "/quiet", "/norestart", "/qn")
		cmd.Dir = filepath.Dir(msi)
		cmd.Stdout = up.Stdout
		cmd.Stderr = up.Stderr
		cmd.Stdin = os.Stdin
		err = cmd.Run()
		if err == nil {
			break
		}
		up.Logf("Install attempt failed: %v", err)
		uninstallVersion := up.currentVersion
		if v := os.Getenv("TS_DEBUG_UNINSTALL_VERSION"); v != "" {
			uninstallVersion = v
		}
		// Assume it's a downgrade, which msiexec won't permit. Uninstall our current version first.
		up.Logf("Uninstalling current version %q for downgrade...", uninstallVersion)
		cmd = exec.Command("msiexec.exe", "/x", msiUUIDForVersion(uninstallVersion), "/norestart", "/qn")
		cmd.Stdout = up.Stdout
		cmd.Stderr = up.Stderr
		cmd.Stdin = os.Stdin
		err = cmd.Run()
		up.Logf("msiexec uninstall: %v", err)
	}
	return err
}

func msiUUIDForVersion(ver string) string {
	arch := runtime.GOARCH
	if arch == "386" {
		arch = "x86"
	}
	track, err := versionToTrack(ver)
	if err != nil {
		track = UnstableTrack
	}
	msiURL := fmt.Sprintf("https://pkgs.tailscale.com/%s/tailscale-setup-%s-%s.msi", track, ver, arch)
	return "{" + strings.ToUpper(uuid.NewSHA1(uuid.NameSpaceURL, []byte(msiURL)).String()) + "}"
}

func (up *Updater) switchOutputToFile() (io.Closer, error) {
	var logFilePath string
	exePath, err := os.Executable()
	if err != nil {
		logFilePath = filepath.Join(os.TempDir(), "tailscale-updater.log")
	} else {
		logFilePath = strings.TrimSuffix(exePath, ".exe") + ".log"
	}

	up.Logf("writing update output to %q", logFilePath)
	logFile, err := os.Create(logFilePath)
	if err != nil {
		return nil, err
	}

	up.Logf = func(m string, args ...any) {
		fmt.Fprintf(logFile, m+"\n", args...)
	}
	up.Stdout = logFile
	up.Stderr = logFile
	return logFile, nil
}
