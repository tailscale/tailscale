// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_clientupdate

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"runtime"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/clientupdate"
	"tailscale.com/util/prompt"
	"tailscale.com/version"
	"tailscale.com/version/distro"
)

func init() {
	maybeUpdateCmd = func() *ffcli.Command { return updateCmd }

	clientupdateLatestTailscaleVersion.Set(func(track string) (string, error) {
		if track == "" {
			return clientupdate.LatestTailscaleVersion(clientupdate.CurrentTrack)
		}
		return clientupdate.LatestTailscaleVersion(track)
	})
}

var updateCmd = &ffcli.Command{
	Name:       "update",
	ShortUsage: "tailscale update",
	ShortHelp:  "Update Tailscale to the latest/different version",
	Exec:       runUpdate,
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("update")
		fs.BoolVar(&updateArgs.yes, "yes", false, "update without interactive prompts")
		fs.BoolVar(&updateArgs.dryRun, "dry-run", false, "print what update would do without doing it, or prompts")
		// These flags are not supported on several systems that only provide
		// the latest version of Tailscale:
		//
		//  - Arch (and other pacman-based distros)
		//  - Alpine (and other apk-based distros)
		//  - FreeBSD (and other pkg-based distros)
		//  - Unraid/QNAP/Synology
		//  - macOS
		if distro.Get() != distro.Arch &&
			distro.Get() != distro.Alpine &&
			distro.Get() != distro.QNAP &&
			distro.Get() != distro.Synology &&
			runtime.GOOS != "freebsd" &&
			runtime.GOOS != "darwin" {
			fs.StringVar(&updateArgs.track, "track", "", `which track to check for updates: "stable", "release-candidate", or "unstable" (dev); empty means same as current`)
			fs.StringVar(&updateArgs.version, "version", "", `explicit version to update/downgrade to`)
		}
		return fs
	})(),
}

var updateArgs struct {
	yes     bool
	dryRun  bool
	track   string // explicit track; empty means same as current
	version string // explicit version; empty means auto
}

const gokrazyUpdateFromURLMagicArg = "--gokrazy-update-from-url"

func runUpdate(ctx context.Context, args []string) error {
	if len(args) > 0 {
		if runtime.GOOS == "linux" && distro.Get() == distro.Gokrazy {
			gokArgs, err := gokrazyUpdateArgsFromMagicArg(args)
			if err != nil {
				return err
			}
			if gokArgs != nil {
				return clientupdate.GokrazyUpdateFromURL.Get()(ctx, *gokArgs)
			}
		}
		return flag.ErrHelp
	}
	if updateArgs.version != "" && updateArgs.track != "" {
		return errors.New("cannot specify both --version and --track")
	}
	err := clientupdate.Update(clientupdate.Arguments{
		Version: updateArgs.version,
		Track:   updateArgs.track,
		Logf:    func(f string, a ...any) { printf(f+"\n", a...) },
		Stdout:  Stdout,
		Stderr:  Stderr,
		Confirm: confirmUpdate,
	})
	if errors.Is(err, errors.ErrUnsupported) {
		return errors.New("The 'update' command is not supported on this platform; see https://tailscale.com/s/client-updates")
	}
	return err
}

func confirmUpdate(ver string) bool {
	if updateArgs.yes {
		fmt.Printf("Updating Tailscale from %v to %v; --yes given, continuing without prompts.\n", version.Short(), ver)
		return true
	}

	if updateArgs.dryRun {
		fmt.Printf("Current: %v, Latest: %v\n", version.Short(), ver)
		return false
	}

	msg := fmt.Sprintf("This will update Tailscale from %v to %v. Continue?", version.Short(), ver)
	return prompt.YesNo(msg, true)
}

// gokrazyUpdateArgsFromMagicArg parses the Gokrazy update-from-URL command-line
// flow. It returns nil if args do not select that flow. A non-nil result means
// the caller may safely invoke clientupdate.GokrazyUpdateFromURL.
func gokrazyUpdateArgsFromMagicArg(args []string) (*clientupdate.GokrazyUpdateArgs, error) {
	var updateURL string
	var unsigned bool

	fs := flag.NewFlagSet("gokrazy-update", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	// This flag path is exercised end-to-end by TestGokrazyUpdatesItselfToSameImage.
	fs.StringVar(&updateURL, gokrazyUpdateFromURLMagicArg[2:], "", "URL of the Gokrazy archive format file to install")
	fs.BoolVar(&unsigned, "unsigned", false, "skip GAF signature verification; for tests only")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() != 0 {
		return nil, nil
	}
	if updateURL == "" {
		return nil, nil
	}
	if !clientupdate.GokrazyUpdateFromURL.IsSet() {
		return nil, errors.New("gokrazy update support is not linked into this binary")
	}
	return &clientupdate.GokrazyUpdateArgs{
		URL:           updateURL,
		AllowUnsigned: unsigned,
		Logf: func(format string, args ...any) {
			printf(format+"\n", args...)
		},
	}, nil
}
