// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/feature/loginbeacon/beaconcli"
	"tailscale.com/types/iox"
)

func loginBeaconCmd() *ffcli.Command {
	if !buildfeatures.HasLoginBeacon || !buildfeatures.HasIPNBus {
		return nil
	}
	return beaconcli.NewCommand(beaconcli.Options{
		Client:     &localClient,
		Stdout:     iox.WriterFunc(func(p []byte) (int, error) { return Stdout.Write(p) }),
		NewFlagSet: newFlagSet,
		OpenURL:    hookOpenURL.GetOrNil(),
	})
}

// Keep the per-login action separate from the frozen upArgsT preference flags.
func loginBeaconEnabled(cmd string) bool {
	flags := upFlagSet
	if cmd == "login" {
		flags = loginFlagSet
	}
	f := flags.Lookup("enable-login-beacon")
	return f != nil && f.Value.String() == "true"
}
