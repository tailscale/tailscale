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
	"time"

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
	// winVersionEnv is the environment variable that is set along with
	// winMSIEnv and carries the version of tailscale that is being installed.
	// It is used for logging purposes.
	winVersionEnv = "TS_UPDATE_WIN_VERSION"
	// updaterPrefix is the prefix for the temporary executable created by [makeSelfCopy].
	updaterPrefix = "tailscale-updater"
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
	f2, err := os.CreateTemp("", updaterPrefix+"-*.exe")
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

func isTSGUIPresent() bool {
	us, err := os.Executable()
	if err != nil {
		return false
	}

	tsgui := filepath.Join(filepath.Dir(us), "tsgui.dll")
	_, err = os.Stat(tsgui)
	return err == nil
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

	qualifiers := []string{ver, arch}
	// TODO(aaron): Temporary hack so autoupdate still works on winui builds;
	// remove when we enable winui by default on the unstable track.
	if isTSGUIPresent() {
		qualifiers = append(qualifiers, "winui")
	}

	pkgsPath := fmt.Sprintf("%s/tailscale-setup-%s.msi", up.Track, strings.Join(qualifiers, "-"))
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
	up.cleanupOldDownloads(filepath.Join(os.TempDir(), updaterPrefix+"-*.exe"))
	_, selfCopy, err := makeSelfCopy()
	if err != nil {
		return err
	}
	defer os.Remove(selfCopy)
	up.Logf("running tailscale.exe copy for final install...")

	cmd := exec.Command(selfCopy, "update")
	cmd.Env = append(os.Environ(), winMSIEnv+"="+msiTarget, winVersionEnv+"="+ver)
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
		// msiexec.exe requires exclusive access to the log file, so create a dedicated one for each run.
		installLogPath := up.startNewLogFile("tailscale-installer", os.Getenv(winVersionEnv))
		up.Logf("Install log: %s", installLogPath)
		cmd := exec.Command("msiexec.exe", "/i", filepath.Base(msi), "/quiet", "/norestart", "/qn", "/L*v", installLogPath)
		cmd.Dir = filepath.Dir(msi)
		cmd.Stdout = up.Stdout
		cmd.Stderr = up.Stderr
		cmd.Stdin = os.Stdin
		err = cmd.Run()
		switch err := err.(type) {
		case nil:
			// Success.
			return nil
		case *exec.ExitError:
			// For possible error codes returned by Windows Installer, see
			// https://web.archive.org/web/20250409144914/https://learn.microsoft.com/en-us/windows/win32/msi/error-codes
			switch windows.Errno(err.ExitCode()) {
			case windows.ERROR_SUCCESS_REBOOT_REQUIRED:
				// In most cases, updating Tailscale should not require a reboot.
				// If it does, it might be because we failed to close the GUI
				// and the installer couldn't replace its executable.
				// The old GUI will continue to run until the next reboot.
				// Not ideal, but also not a retryable error.
				up.Logf("[unexpected] reboot required")
				return nil
			case windows.ERROR_SUCCESS_REBOOT_INITIATED:
				// Same as above, but perhaps the device is configured to prompt
				// the user to reboot and the user has chosen to reboot now.
				up.Logf("[unexpected] reboot initiated")
				return nil
			case windows.ERROR_INSTALL_ALREADY_RUNNING:
				// The Windows Installer service is currently busy.
				// It could be our own install initiated by user/MDM/GP, another MSI install or perhaps a Windows Update install.
				// Anyway, we can't do anything about it right now. The user (or tailscaled) can retry later.
				// Retrying now will likely fail, and is risky since we might uninstall the current version
				// and then fail to install the new one, leaving the user with no Tailscale at all.
				//
				// TODO(nickkhyl,awly): should we check if this is actually a downgrade before uninstalling the current version?
				// Also, maybe keep retrying the install longer if we uninstalled the current version due to a failed install attempt?
				up.Logf("another installation is already in progress")
				return err
			}
		default:
			// Everything else is a retryable error.
		}

		up.Logf("Install attempt failed: %v", err)
		uninstallVersion := up.currentVersion
		if v := os.Getenv("TS_DEBUG_UNINSTALL_VERSION"); v != "" {
			uninstallVersion = v
		}
		uninstallLogPath := up.startNewLogFile("tailscale-uninstaller", uninstallVersion)
		// Assume it's a downgrade, which msiexec won't permit. Uninstall our current version first.
		up.Logf("Uninstalling current version %q for downgrade...", uninstallVersion)
		up.Logf("Uninstall log: %s", uninstallLogPath)
		cmd = exec.Command("msiexec.exe", "/x", msiUUIDForVersion(uninstallVersion), "/norestart", "/qn", "/L*v", uninstallLogPath)
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
		logFilePath = up.startNewLogFile(updaterPrefix, os.Getenv(winVersionEnv))
	} else {
		// Use the same suffix as the self-copy executable.
		suffix := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(exePath), updaterPrefix), ".exe")
		logFilePath = up.startNewLogFile(updaterPrefix, os.Getenv(winVersionEnv)+suffix)
	}

	up.Logf("writing update output to: %s", logFilePath)
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

// startNewLogFile returns a name for a new log file.
// It cleans up any old log files with the same baseNamePrefix.
func (up *Updater) startNewLogFile(baseNamePrefix, baseNameSuffix string) string {
	baseName := fmt.Sprintf("%s-%s-%s.log", baseNamePrefix,
		time.Now().Format("20060102T150405"), baseNameSuffix)

	dir := filepath.Join(os.Getenv("ProgramData"), "Tailscale", "Logs")
	if err := os.MkdirAll(dir, 0700); err != nil {
		up.Logf("failed to create log directory: %v", err)
		return filepath.Join(os.TempDir(), baseName)
	}

	// TODO(nickkhyl): preserve up to N old log files?
	up.cleanupOldDownloads(filepath.Join(dir, baseNamePrefix+"-*.log"))
	return filepath.Join(dir, baseName)
}
