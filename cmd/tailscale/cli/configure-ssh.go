// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/util/lineiter"
	"tailscale.com/version"
)

const tsConfigStartMark = "## BEGIN Tailscale ##"
const tsConfigEndMark = "## END Tailscale ##"

func init() {

	longHelp := strings.TrimSpace(`
Run this command to add a snippet to your $HOME/.ssh/config file that will use
Tailscale to check for KnownHosts.`)

	d := false

	if version.IsSandboxedMacOS() {
		longHelp = longHelp + `

On MacOS sandboxed apps the output will be displayed on stdout instead of
modifying the file in place. You can redirect the output to the file manually.
tailscale configure sshconfig >> $HOME/.ssh/config`

		d = true

	}
	configureSSHconfigCmd := &ffcli.Command{
		Name:       "sshconfig",
		ShortHelp:  "[ALPHA] Configure $HOME/.ssh/config to check Tailscale for KnownHosts",
		ShortUsage: "tailscale configure sshconfig >> $HOME/.ssh/config",
		LongHelp:   longHelp,
		FlagSet: (func() *flag.FlagSet {
			fs := newFlagSet("sshconfig")
			fs.BoolVar(&sshConfigArgs.display, "display", d, "Display the config snippet on stdout instead of modifying the file in place")
			return fs
		})(),
		Exec: runConfigureSSHconfig,
	}
	configureCmd.Subcommands = append(configureCmd.Subcommands, configureSSHconfigCmd)
}

var sshConfigArgs struct {
	display bool // display the config snippet on stdout or modify in place
}

// findConfigMark finds and returns the index of the tsConfigStartMark and
// tsConfigEndmark in a file. If the file doesn't contain the marks, it returns
// -1, -1
func findConfigMark(file []string) (int, int) {
	start := -1
	end := -1
	for i, v := range file {
		if strings.Contains(v, tsConfigStartMark) {
			start = i
		}
		if strings.Contains(v, tsConfigEndMark) {
			end = i
		}
	}

	return start, end
}

// replaceBetweenConfigMark replaces the lines between the tsConfigStartMark and
// tsConfigEndMark with the replacement string. If the marks are not present, it
// returns the original slice.
func replaceBetweenConfigMark(s []string, replacement string, start, end int) []string {
	if start == -1 || end == -1 {
		return s
	}
	n := append(s[:start+1], replacement, tsConfigEndMark)
	n = append(n, s[end+1:]...)
	return n
}

// runConfigureSSHconfig updates the user's $HOME/.ssh/config file to add the
// Tailscale config snippet. If the snippet is not present, it will be appended
// between the BEGIN and END marks. If it is present it will be updated if needed.
func runConfigureSSHconfig(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return errors.New("unexpected non-flag arguments to 'tailscale status'")
	}
	tailscaleBin, err := os.Executable()
	if err != nil {
		return err
	}
	st, err := localClient.Status(ctx)
	if err != nil {
		return err
	}

	tsSshConfig, err := genSSHConfig(st, tailscaleBin)
	if err != nil {
		return err
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	if !sshConfigArgs.display {
		sshConfigFilePath := filepath.Join(h, ".ssh", "config")
		var sshConfig []string

		// Create the file if it does not exist
		_, err = os.OpenFile(sshConfigFilePath, os.O_RDONLY|os.O_CREATE, 0644)
		if err != nil {
			return err
		}

		for lr := range lineiter.File(sshConfigFilePath) {
			line, err := lr.Value()
			if err != nil {
				return err
			}
			sshConfig = append(sshConfig, string(line))
		}

		start, end := findConfigMark(sshConfig)
		if start > end {
			return fmt.Errorf(strings.TrimSpace(`
Invalid config file. Start mark is after end mark. Please ensure that the
following is in your ~/.ssh/config file:

%s
%s
%s`),
				tsConfigStartMark, tsSshConfig, tsConfigEndMark)

		}
		if start == -1 || end == -1 {
			sshConfig = append(sshConfig, tsConfigStartMark)
			sshConfig = append(sshConfig, tsSshConfig)
			sshConfig = append(sshConfig, tsConfigEndMark)
		} else {
			existingConfig := strings.Join(sshConfig[start+1:end], "\n")
			if existingConfig != tsSshConfig {
				sshConfig = replaceBetweenConfigMark(sshConfig, tsSshConfig, start, end)
			}
		}

		sshFile, err := os.Create(sshConfigFilePath)
		if err != nil {
			return err

		}
		defer sshFile.Close()

		for _, line := range sshConfig {
			_, err := sshFile.WriteString(line + "\n")
			if err != nil {
				return err
			}
		}
		fmt.Printf("Updated %s\n", sshConfigFilePath)
	} else {
		fmt.Println(tsSshConfig)
	}

	return nil
}
