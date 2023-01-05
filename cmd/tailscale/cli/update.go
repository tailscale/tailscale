// Copyright (c) 2023 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/util/winutil"
	"tailscale.com/version"
	"tailscale.com/version/distro"
)

var updateCmd = &ffcli.Command{
	Name:       "update",
	ShortUsage: "update",
	ShortHelp:  "Update Tailscale to the latest/different version",
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

func runUpdate(ctx context.Context, args []string) error {
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
			return nil, errors.New("This is the macOS App Store version of Tailscale; update in the App Store, or see https://tailscale.com/kb/1083/install-unstable/ to use TestFlight or to install the non-App Store version")
		}
	}
	if up.update == nil {
		return nil, errors.New("The 'update' command is not supported on this platform; see https://tailscale.com/kb/1067/update/")
	}
	return up, nil
}

type updater struct {
	track  string
	update func() error
}

func (up *updater) currentOrDryRun(ver string) bool {
	if version.Short == ver {
		fmt.Printf("already running %v; no update needed\n", ver)
		return true
	}
	if updateArgs.dryRun {
		fmt.Printf("Current: %v, Latest: %v\n", version.Short, ver)
		return true
	}
	return false
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
	url := fmt.Sprintf("https://pkgs.tailscale.com/%s/debian/pool/tailscale_%s_%s.deb", up.track, ver, runtime.GOARCH)
	// TODO(bradfitz): require root/sudo
	// TODO(bradfitz): check https://pkgs.tailscale.com/stable/debian/dists/sid/InRelease, check gpg, get sha256
	// And https://pkgs.tailscale.com/stable/debian/dists/sid/main/binary-amd64/Packages.gz and sha256 of it
	//

	return errors.New("TODO: Debian/Ubuntu deb download of " + url)
}

func (up *updater) updateMacSys() error {
	// use sparkle? do we have permissions from this context? does sudo help?
	// We can at least fail with a command they can run to update from the shell.
	// Like "tailscale update --macsys | sudo sh" or something.
	//
	// TODO(bradfitz,mihai): implement. But for now:
	return errors.New("The 'update' command is not yet implemented on macOS.")
}

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
	// TODO(bradfitz): require elevated mode
	return errors.New("TODO: download + msiexec /i /quiet " + url)
}
