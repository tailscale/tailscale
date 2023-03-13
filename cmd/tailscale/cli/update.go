// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/net/tshttpproxy"
	"tailscale.com/util/must"
	"tailscale.com/util/winutil"
	"tailscale.com/version"
	"tailscale.com/version/distro"
)

var updateCmd = &ffcli.Command{
	Name:       "update",
	ShortUsage: "update",
	ShortHelp:  "[ALPHA] Update Tailscale to the latest/different version",
	Exec:       runUpdate,
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("update")
		fs.BoolVar(&updateArgs.yes, "yes", false, "update without interactive prompts")
		fs.BoolVar(&updateArgs.dryRun, "dry-run", false, "print what update would do without doing it, or prompts")
		fs.StringVar(&updateArgs.track, "track", "", `which track to check for updates: "stable" or "unstable" (dev); empty means same as current`)
		fs.StringVar(&updateArgs.version, "version", "", `explicit version to update/downgrade to`)
		return fs
	})(),
}

var updateArgs struct {
	yes     bool
	dryRun  bool
	track   string // explicit track; empty means same as current
	version string // explicit version; empty means auto
}

// winMSIEnv is the environment variable that, if set, is the MSI file for the
// update command to install. It's passed like this so we can stop the
// tailscale.exe process from running before the msiexec process runs and tries
// to overwrite ourselves.
const winMSIEnv = "TS_UPDATE_WIN_MSI"

func runUpdate(ctx context.Context, args []string) error {
	if msi := os.Getenv(winMSIEnv); msi != "" {
		log.Printf("installing %v ...", msi)
		if err := installMSI(msi); err != nil {
			log.Printf("MSI install failed: %v", err)
			return err
		}
		log.Printf("success.")
		return nil
	}
	if len(args) > 0 {
		return flag.ErrHelp
	}
	if updateArgs.version != "" && updateArgs.track != "" {
		return errors.New("cannot specify both --version and --track")
	}
	up, err := newUpdater()
	if err != nil {
		return err
	}
	return up.update()
}

func versionIsStable(v string) (stable, wellFormed bool) {
	_, rest, ok := strings.Cut(v, ".")
	if !ok {
		return false, false
	}
	minorStr, _, ok := strings.Cut(rest, ".")
	if !ok {
		return false, false
	}
	minor, err := strconv.Atoi(minorStr)
	if err != nil {
		return false, false
	}
	return minor%2 == 0, true
}

func newUpdater() (*updater, error) {
	up := &updater{
		track: updateArgs.track,
	}
	switch up.track {
	case "stable", "unstable":
	case "":
		if version.IsUnstableBuild() {
			up.track = "unstable"
		} else {
			up.track = "stable"
		}
		if updateArgs.version != "" {
			stable, ok := versionIsStable(updateArgs.version)
			if !ok {
				return nil, fmt.Errorf("malformed version %q", updateArgs.version)
			}
			if stable {
				up.track = "stable"
			} else {
				up.track = "unstable"
			}
		}
	default:
		return nil, fmt.Errorf("unknown track %q; must be 'stable' or 'unstable'", up.track)
	}
	switch runtime.GOOS {
	case "windows":
		up.update = up.updateWindows
	case "linux":
		switch distro.Get() {
		case distro.Synology:
			up.update = up.updateSynology
		case distro.Debian: // includes Ubuntu
			up.update = up.updateDebLike
		}
	case "darwin":
		switch {
		case !version.IsSandboxedMacOS():
			return nil, errors.New("The 'update' command is not yet supported on this platform; see https://github.com/tailscale/tailscale/wiki/Tailscaled-on-macOS/ for now")
		case strings.HasSuffix(os.Getenv("HOME"), "/io.tailscale.ipn.macsys/Data"):
			up.update = up.updateMacSys
		default:
			return nil, errors.New("This is the macOS App Store version of Tailscale; update in the App Store, or see https://tailscale.com/s/unstable-clients to use TestFlight or to install the non-App Store version")
		}
	}
	if up.update == nil {
		return nil, errors.New("The 'update' command is not supported on this platform; see https://tailscale.com/s/client-updates")
	}
	return up, nil
}

type updater struct {
	track  string
	update func() error
}

func (up *updater) currentOrDryRun(ver string) bool {
	if version.Short() == ver {
		fmt.Printf("already running %v; no update needed\n", ver)
		return true
	}
	if updateArgs.dryRun {
		fmt.Printf("Current: %v, Latest: %v\n", version.Short(), ver)
		return true
	}
	return false
}

func (up *updater) confirm(ver string) error {
	if updateArgs.yes {
		log.Printf("Updating Tailscale from %v to %v; --yes given, continuing without prompts.\n", version.Short(), ver)
		return nil
	}

	fmt.Printf("This will update Tailscale from %v to %v. Continue? [y/n] ", version.Short(), ver)
	var resp string
	fmt.Scanln(&resp)
	resp = strings.ToLower(resp)
	switch resp {
	case "y", "yes", "sure":
		return nil
	}
	return errors.New("aborting update")
}

func (up *updater) updateSynology() error {
	// TODO(bradfitz): detect, map GOARCH+CPU to the right Synology arch.
	// TODO(bradfitz): add pkgs.tailscale.com endpoint to get release info
	// TODO(bradfitz): require root/sudo
	// TODO(bradfitz): run /usr/syno/bin/synopkg install tailscale.spk
	return errors.New("The 'update' command is not yet implemented on Synology.")
}

func (up *updater) updateDebLike() error {
	ver := updateArgs.version
	if ver == "" {
		res, err := http.Get("https://pkgs.tailscale.com/" + up.track + "/?mode=json")
		if err != nil {
			return err
		}
		var latest struct {
			Tarballs map[string]string // ~goarch (ignoring "geode") => "tailscale_1.34.2_mips.tgz"
		}
		err = json.NewDecoder(res.Body).Decode(&latest)
		res.Body.Close()
		if err != nil {
			return fmt.Errorf("decoding JSON: %v: %w", res.Status, err)
		}
		f, ok := latest.Tarballs[runtime.GOARCH]
		if !ok {
			return fmt.Errorf("can't update architecture %q", runtime.GOARCH)
		}
		ver, _, ok = strings.Cut(strings.TrimPrefix(f, "tailscale_"), "_")
		if !ok {
			return fmt.Errorf("can't parse version from %q", f)
		}
	}
	if up.currentOrDryRun(ver) {
		return nil
	}

	track := "unstable"
	if stable, ok := versionIsStable(ver); !ok {
		return fmt.Errorf("malformed version %q", ver)
	} else if stable {
		track = "stable"
	}

	if os.Geteuid() != 0 {
		return errors.New("must be root; use sudo")
	}

	if updated, err := updateDebianAptSourcesList(track); err != nil {
		return err
	} else if updated {
		fmt.Printf("Updated %s to use the %s track\n", aptSourcesFile, track)
	}

	cmd := exec.Command("apt-get", "update",
		// Only update the tailscale repo, not the other ones, treating
		// the tailscale.list file as the main "sources.list" file.
		"-o", "Dir::Etc::SourceList=sources.list.d/tailscale.list",
		// Disable the "sources.list.d" directory:
		"-o", "Dir::Etc::SourceParts=-",
		// Don't forget about packages in the other repos just because
		// we're not updating them:
		"-o", "APT::Get::List-Cleanup=0",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}

	cmd = exec.Command("apt-get", "install", "--yes", "--allow-downgrades", "tailscale="+ver)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

const aptSourcesFile = "/etc/apt/sources.list.d/tailscale.list"

// updateDebianAptSourcesList updates the /etc/apt/sources.list.d/tailscale.list
// file to make sure it has the provided track (stable or unstable) in it.
//
// If it already has the right track (including containing both stable and
// unstable), it does nothing.
func updateDebianAptSourcesList(dstTrack string) (rewrote bool, err error) {
	was, err := os.ReadFile(aptSourcesFile)
	if err != nil {
		return false, err
	}
	newContent, err := updateDebianAptSourcesListBytes(was, dstTrack)
	if err != nil {
		return false, err
	}
	if bytes.Equal(was, newContent) {
		return false, nil
	}
	return true, os.WriteFile(aptSourcesFile, newContent, 0644)
}

func updateDebianAptSourcesListBytes(was []byte, dstTrack string) (newContent []byte, err error) {
	trackURLPrefix := []byte("https://pkgs.tailscale.com/" + dstTrack + "/")
	var buf bytes.Buffer
	var changes int
	bs := bufio.NewScanner(bytes.NewReader(was))
	hadCorrect := false
	commentLine := regexp.MustCompile(`^\s*\#`)
	pkgsURL := regexp.MustCompile(`\bhttps://pkgs\.tailscale\.com/((un)?stable)/`)
	for bs.Scan() {
		line := bs.Bytes()
		if !commentLine.Match(line) {
			line = pkgsURL.ReplaceAllFunc(line, func(m []byte) []byte {
				if bytes.Equal(m, trackURLPrefix) {
					hadCorrect = true
				} else {
					changes++
				}
				return trackURLPrefix
			})
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	if hadCorrect || (changes == 1 && bytes.Equal(bytes.TrimSpace(was), bytes.TrimSpace(buf.Bytes()))) {
		// Unchanged or close enough.
		return was, nil
	}
	if changes != 1 {
		// No changes, or an unexpected number of changes (what?). Bail.
		// They probably editted it by hand and we don't know what to do.
		return nil, fmt.Errorf("unexpected/unsupported %s contents", aptSourcesFile)
	}
	return buf.Bytes(), nil
}

func (up *updater) updateMacSys() error {
	// use sparkle? do we have permissions from this context? does sudo help?
	// We can at least fail with a command they can run to update from the shell.
	// Like "tailscale update --macsys | sudo sh" or something.
	//
	// TODO(bradfitz,mihai): implement. But for now:
	return errors.New("The 'update' command is not yet implemented on macOS.")
}

var (
	verifyAuthenticode func(string) error // or nil on non-Windows
	markTempFileFunc   func(string) error // or nil on non-Windows
)

func (up *updater) updateWindows() error {
	ver := updateArgs.version
	if ver == "" {
		res, err := http.Get("https://pkgs.tailscale.com/" + up.track + "/?mode=json&os=windows")
		if err != nil {
			return err
		}
		var latest struct {
			Version string
		}
		err = json.NewDecoder(res.Body).Decode(&latest)
		res.Body.Close()
		if err != nil {
			return fmt.Errorf("decoding JSON: %v: %w", res.Status, err)
		}
		ver = latest.Version
		if ver == "" {
			return errors.New("no version found")
		}
	}
	arch := runtime.GOARCH
	if arch == "386" {
		arch = "x86"
	}
	url := fmt.Sprintf("https://pkgs.tailscale.com/%s/tailscale-setup-%s-%s.msi", up.track, ver, arch)

	if up.currentOrDryRun(ver) {
		return nil
	}
	if !winutil.IsCurrentProcessElevated() {
		return errors.New("must be run as Administrator")
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

	if err := up.confirm(ver); err != nil {
		return err
	}
	msiTarget := filepath.Join(msiDir, path.Base(url))
	if err := downloadURLToFile(url, msiTarget); err != nil {
		return err
	}

	log.Printf("verifying MSI authenticode...")
	if err := verifyAuthenticode(msiTarget); err != nil {
		return fmt.Errorf("authenticode verification of %s failed: %w", msiTarget, err)
	}
	log.Printf("authenticode verification succeeded")

	log.Printf("making tailscale.exe copy to switch to...")
	selfCopy, err := makeSelfCopy()
	if err != nil {
		return err
	}
	defer os.Remove(selfCopy)
	log.Printf("running tailscale.exe copy for final install...")

	cmd := exec.Command(selfCopy, "update")
	cmd.Env = append(os.Environ(), winMSIEnv+"="+msiTarget)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Start(); err != nil {
		return err
	}
	// Once it's started, exit ourselves, so the binary is free
	// to be replaced.
	os.Exit(0)
	panic("unreachable")
}

func installMSI(msi string) error {
	var err error
	for tries := 0; tries < 2; tries++ {
		cmd := exec.Command("msiexec.exe", "/i", filepath.Base(msi), "/quiet", "/promptrestart", "/qn")
		cmd.Dir = filepath.Dir(msi)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		err = cmd.Run()
		if err == nil {
			break
		}
		uninstallVersion := version.Short()
		if v := os.Getenv("TS_DEBUG_UNINSTALL_VERSION"); v != "" {
			uninstallVersion = v
		}
		// Assume it's a downgrade, which msiexec won't permit. Uninstall our current version first.
		log.Printf("Uninstalling current version %q for downgrade...", uninstallVersion)
		cmd = exec.Command("msiexec.exe", "/x", msiUUIDForVersion(uninstallVersion), "/norestart", "/qn")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		err = cmd.Run()
		log.Printf("msiexec uninstall: %v", err)
	}
	return err
}

func msiUUIDForVersion(ver string) string {
	arch := runtime.GOARCH
	if arch == "386" {
		arch = "x86"
	}
	track := "unstable"
	if stable, ok := versionIsStable(ver); ok && stable {
		track = "stable"
	}
	msiURL := fmt.Sprintf("https://pkgs.tailscale.com/%s/tailscale-setup-%s-%s.msi", track, ver, arch)
	return "{" + strings.ToUpper(uuid.NewSHA1(uuid.NameSpaceURL, []byte(msiURL)).String()) + "}"
}

func makeSelfCopy() (tmpPathExe string, err error) {
	selfExe, err := os.Executable()
	if err != nil {
		return "", err
	}
	f, err := os.Open(selfExe)
	if err != nil {
		return "", err
	}
	defer f.Close()
	f2, err := os.CreateTemp("", "tailscale-updater-*.exe")
	if err != nil {
		return "", err
	}
	if f := markTempFileFunc; f != nil {
		if err := f(f2.Name()); err != nil {
			return "", err
		}
	}
	if _, err := io.Copy(f2, f); err != nil {
		f2.Close()
		return "", err
	}
	return f2.Name(), f2.Close()
}

func downloadURLToFile(urlSrc, fileDst string) (ret error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = tshttpproxy.ProxyFromEnvironment
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr}

	quickCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	headReq := must.Get(http.NewRequestWithContext(quickCtx, "HEAD", urlSrc, nil))

	res, err := c.Do(headReq)
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("HEAD %s: %v", urlSrc, res.Status)
	}
	if res.ContentLength <= 0 {
		return fmt.Errorf("HEAD %s: unexpected Content-Length %v", urlSrc, res.ContentLength)
	}
	log.Printf("Download size: %v", res.ContentLength)

	hashReq := must.Get(http.NewRequestWithContext(quickCtx, "GET", urlSrc+".sha256", nil))
	hashRes, err := c.Do(hashReq)
	if err != nil {
		return err
	}
	hashHex, err := io.ReadAll(io.LimitReader(hashRes.Body, 100))
	hashRes.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s.sha256: %v", urlSrc, res.Status)
	}
	if err != nil {
		return err
	}
	wantHash, err := hex.DecodeString(string(strings.TrimSpace(string(hashHex))))
	if err != nil {
		return err
	}
	hash := sha256.New()

	dlReq := must.Get(http.NewRequestWithContext(context.Background(), "GET", urlSrc, nil))
	dlRes, err := c.Do(dlReq)
	if err != nil {
		return err
	}
	// TODO(bradfitz): resume from existing partial file on disk
	if dlRes.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %v", urlSrc, dlRes.Status)
	}

	of, err := os.Create(fileDst)
	if err != nil {
		return err
	}
	defer func() {
		if ret != nil {
			of.Close()
			// TODO(bradfitz): os.Remove(fileDst) too? or keep it to resume from/debug later.
		}
	}()
	pw := &progressWriter{total: res.ContentLength}
	n, err := io.Copy(io.MultiWriter(hash, of, pw), io.LimitReader(dlRes.Body, res.ContentLength))
	if err != nil {
		return err
	}
	if n != res.ContentLength {
		return fmt.Errorf("downloaded %v; want %v", n, res.ContentLength)
	}
	if err := of.Close(); err != nil {
		return err
	}
	pw.print()

	if !bytes.Equal(hash.Sum(nil), wantHash) {
		return fmt.Errorf("SHA-256 of downloaded MSI didn't match expected value")
	}
	log.Printf("hash matched")

	return nil
}

type progressWriter struct {
	done      int64
	total     int64
	lastPrint time.Time
}

func (pw *progressWriter) Write(p []byte) (n int, err error) {
	pw.done += int64(len(p))
	if time.Since(pw.lastPrint) > 2*time.Second {
		pw.print()
	}
	return len(p), nil
}

func (pw *progressWriter) print() {
	pw.lastPrint = time.Now()
	log.Printf("Downloaded %v/%v (%.1f%%)", pw.done, pw.total, float64(pw.done)/float64(pw.total)*100)
}
