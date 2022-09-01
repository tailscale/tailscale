// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/hostinfo"
	"tailscale.com/version/distro"
)

var configureHostCmd = &ffcli.Command{
	Name:      "configure-host",
	Exec:      runConfigureHost,
	ShortHelp: "Configure Synology to enable more Tailscale features",
	LongHelp: strings.TrimSpace(`
The 'configure-host' command is intended to run at boot as root
to create the /dev/net/tun device and give the tailscaled binary
permission to use it.

See: https://tailscale.com/kb/1152/synology-outbound/
`),
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("configure-host")
		return fs
	})(),
}

var configureHostArgs struct{}

func runConfigureHost(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return errors.New("unknown arguments")
	}
	if runtime.GOOS != "linux" || distro.Get() != distro.Synology {
		return errors.New("only implemented on Synology")
	}
	if uid := os.Getuid(); uid != 0 {
		return fmt.Errorf("must be run as root, not %q (%v)", os.Getenv("USER"), uid)
	}
	osVer := hostinfo.GetOSVersion()
	isDSM6 := strings.HasPrefix(osVer, "Synology 6")
	isDSM7 := strings.HasPrefix(osVer, "Synology 7")
	if !isDSM6 && !isDSM7 {
		return fmt.Errorf("unsupported DSM version %q", osVer)
	}
	if _, err := os.Stat("/dev/net/tun"); os.IsNotExist(err) {
		if err := os.MkdirAll("/dev/net", 0755); err != nil {
			return fmt.Errorf("creating /dev/net: %v", err)
		}
		if out, err := exec.Command("/bin/mknod", "/dev/net/tun", "c", "10", "200").CombinedOutput(); err != nil {
			return fmt.Errorf("creating /dev/net/tun: %v, %s", err, out)
		}
	}
	if err := os.Chmod("/dev/net", 0755); err != nil {
		return err
	}
	if err := os.Chmod("/dev/net/tun", 0666); err != nil {
		return err
	}
	if isDSM6 {
		printf("/dev/net/tun exists and has permissions 0666. Skipping setcap on DSM6.\n")
		return nil
	}

	const daemonBin = "/var/packages/Tailscale/target/bin/tailscaled"
	if _, err := os.Stat(daemonBin); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("tailscaled binary not found at %s. Is the Tailscale *.spk package installed?", daemonBin)
		}
		return err
	}
	if out, err := exec.Command("/bin/setcap", "cap_net_admin,cap_net_raw+eip", daemonBin).CombinedOutput(); err != nil {
		return fmt.Errorf("setcap: %v, %s", err, out)
	}
	printf("Done. To restart Tailscale to use the new permissions, run:\n\n  sudo synosystemctl restart pkgctl-Tailscale.service\n\n")
	return nil
}
