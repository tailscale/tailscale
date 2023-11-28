// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
)

func init() {
	configureCmd.Subcommands = append(configureCmd.Subcommands, configureSSHconfigCmd)
}

var configureSSHconfigCmd = &ffcli.Command{
	Name:       "sshconfig",
	ShortHelp:  "[ALPHA] Configure $HOME/.ssh/config to check Tailscale for KnownHosts",
	ShortUsage: "sshconfig >> $HOME/.ssh/config",
	LongHelp: strings.TrimSpace(`
Run this command to output a ssh_config snippet that configures SSH to check
Tailscale for KnownHosts.

You can use this snippet by running: tailscale sshconfig >> $HOME/.ssh/config
or copy and paste it into your $HOME/.ssh/config file.
`),
	Exec: runConfigureSSHconfig,
}

func runConfigureSSHconfig(ctx context.Context, _ []string) error {
	tailscaleBin, err := os.Executable()
	if err != nil {
		return err
	}
	st, err := localClient.Status(ctx)
	if err != nil {
		return err
	}

	sshConfig, err := genSSHConfig(st, tailscaleBin)
	if err != nil {
		return err
	}
	fmt.Println(sshConfig)
	return nil
}
