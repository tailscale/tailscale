// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/feature"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/version"
)

var versionCmd = &ffcli.Command{
	Name:       "version",
	ShortUsage: "tailscale version [flags]",
	ShortHelp:  "Print Tailscale version",
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("version")
		fs.BoolVar(&versionArgs.daemon, "daemon", false, "also print local node's daemon version")
		fs.BoolVar(&versionArgs.json, "json", false, "output in JSON format")
		fs.BoolVar(&versionArgs.upstream, "upstream", false, "fetch and print the latest upstream release version from pkgs.tailscale.com")
		fs.StringVar(&versionArgs.track, "track", "", `which track to check for updates: "stable", "release-candidate", or "unstable" (dev); empty means same as current`)
		return fs
	})(),
	Exec: runVersion,
}

var versionArgs struct {
	daemon   bool // also check local node's daemon version
	json     bool
	upstream bool
	track    string
}

var clientupdateLatestTailscaleVersion feature.Hook[func(string) (string, error)]

func runVersion(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("too many non-flag arguments: %q", args)
	}
	var err error
	var st *ipnstate.Status

	if versionArgs.daemon {
		st, err = localClient.StatusWithoutPeers(ctx)
		if err != nil {
			return err
		}
	}

	var upstreamVer string
	if versionArgs.upstream {
		f, ok := clientupdateLatestTailscaleVersion.GetOk()
		if !ok {
			return fmt.Errorf("fetching latest version not supported in this build")
		}
		upstreamVer, err = f(versionArgs.track)
		if err != nil {
			return err
		}
	}

	if versionArgs.json {
		m := version.GetMeta()
		if st != nil {
			m.DaemonLong = st.Version
		}
		out := struct {
			version.Meta
			Upstream string `json:"upstream,omitempty"`
		}{
			Meta:     m,
			Upstream: upstreamVer,
		}
		e := json.NewEncoder(Stdout)
		e.SetIndent("", "\t")
		return e.Encode(out)
	}

	if st == nil {
		outln(version.String())
		if versionArgs.upstream {
			printf("  upstream: %s\n", upstreamVer)
		}
		return nil
	}
	printf("Client: %s\n", version.String())
	printf("Daemon: %s\n", st.Version)
	if versionArgs.upstream {
		printf("Upstream: %s\n", upstreamVer)
	}
	return nil
}
