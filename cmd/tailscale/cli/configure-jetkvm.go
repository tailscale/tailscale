// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android && arm

package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"os"
	"runtime"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/version/distro"
)

func init() {
	maybeJetKVMConfigureCmd = jetKVMConfigureCmd
}

func jetKVMConfigureCmd() *ffcli.Command {
	if runtime.GOOS != "linux" || distro.Get() != distro.JetKVM {
		return nil
	}
	return &ffcli.Command{
		Name:       "jetkvm",
		Exec:       runConfigureJetKVM,
		ShortUsage: "tailscale configure jetkvm",
		ShortHelp:  "Configure JetKVM to run tailscaled at boot",
		LongHelp: strings.TrimSpace(`
This command configures the JetKVM host to run tailscaled at boot.
`),
		FlagSet: (func() *flag.FlagSet {
			fs := newFlagSet("jetkvm")
			return fs
		})(),
	}
}

func runConfigureJetKVM(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return errors.New("unknown arguments")
	}
	if runtime.GOOS != "linux" || distro.Get() != distro.JetKVM {
		return errors.New("only implemented on JetKVM")
	}
	if err := os.MkdirAll("/userdata/init.d", 0755); err != nil {
		return errors.New("unable to create /userdata/init.d")
	}
	err := os.WriteFile("/userdata/init.d/S22tailscale", bytes.TrimLeft([]byte(`
#!/bin/sh
# /userdata/init.d/S22tailscale
# Start/stop tailscaled

case "$1" in
  start)
    /userdata/tailscale/tailscaled > /dev/null 2>&1 &
    ;;
  stop)
    killall tailscaled
    ;;
  *)
    echo "Usage: $0 {start|stop}"
    exit 1
    ;;
esac
`), "\n"), 0755)
	if err != nil {
		return err
	}

	if err := os.Symlink("/userdata/tailscale/tailscale", "/bin/tailscale"); err != nil {
		if !os.IsExist(err) {
			return err
		}
	}

	printf("Done. Now restart your JetKVM.\n")
	return nil
}
