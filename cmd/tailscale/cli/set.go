// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn"
	"tailscale.com/safesocket"
)

var setCmd = &ffcli.Command{
	Name:       "set",
	ShortUsage: "set [flags]",
	ShortHelp:  "Change specified preferences",
	LongHelp: `"tailscale set" allows changing specific preferences.

Unlike "tailscale up", this command does not require the complete set of desired settings.

Only settings explicitly mentioned will be set. There are no default values.`,
	FlagSet:   setFlagSet,
	Exec:      runSet,
	UsageFunc: usageFuncNoDefaultValues,
}

type setArgsT struct {
	acceptRoutes           bool
	acceptDNS              bool
	exitNodeIP             string
	exitNodeAllowLANAccess bool
	shieldsUp              bool
	runSSH                 bool
	hostname               string
	advertiseRoutes        string
	advertiseDefaultRoute  bool
	opUser                 string
	acceptedRisks          string
}

func newSetFlagSet(goos string, setArgs *setArgsT) *flag.FlagSet {
	setf := newFlagSet("set")

	setf.BoolVar(&setArgs.acceptRoutes, "accept-routes", false, "accept routes advertised by other Tailscale nodes")
	setf.BoolVar(&setArgs.acceptDNS, "accept-dns", false, "accept DNS configuration from the admin panel")
	setf.StringVar(&setArgs.exitNodeIP, "exit-node", "", "Tailscale exit node (IP or base name) for internet traffic, or empty string to not use an exit node")
	setf.BoolVar(&setArgs.exitNodeAllowLANAccess, "exit-node-allow-lan-access", false, "Allow direct access to the local network when routing traffic via an exit node")
	setf.BoolVar(&setArgs.shieldsUp, "shields-up", false, "don't allow incoming connections")
	setf.BoolVar(&setArgs.runSSH, "ssh", false, "run an SSH server, permitting access per tailnet admin's declared policy")
	setf.StringVar(&setArgs.hostname, "hostname", "", "hostname to use instead of the one provided by the OS")
	setf.StringVar(&setArgs.advertiseRoutes, "advertise-routes", "", "routes to advertise to other nodes (comma-separated, e.g. \"10.0.0.0/8,192.168.0.0/24\") or empty string to not advertise routes")
	setf.BoolVar(&setArgs.advertiseDefaultRoute, "advertise-exit-node", false, "offer to be an exit node for internet traffic for the tailnet")
	if safesocket.GOOSUsesPeerCreds(goos) {
		setf.StringVar(&setArgs.opUser, "operator", "", "Unix username to allow to operate on tailscaled without sudo")
	}
	registerAcceptRiskFlag(setf, &setArgs.acceptedRisks)
	return setf
}

var (
	setArgs    setArgsT
	setFlagSet = newSetFlagSet(effectiveGOOS(), &setArgs)
)

func runSet(ctx context.Context, args []string) (retErr error) {
	if len(args) > 0 {
		fatalf("too many non-flag arguments: %q", args)
	}

	st, err := localClient.Status(ctx)
	if err != nil {
		return err
	}

	routes, err := calcAdvertiseRoutes(setArgs.advertiseRoutes, setArgs.advertiseDefaultRoute)
	if err != nil {
		return err
	}

	maskedPrefs := &ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			RouteAll:               setArgs.acceptRoutes,
			CorpDNS:                setArgs.acceptDNS,
			ExitNodeAllowLANAccess: setArgs.exitNodeAllowLANAccess,
			ShieldsUp:              setArgs.shieldsUp,
			RunSSH:                 setArgs.runSSH,
			Hostname:               setArgs.hostname,
			AdvertiseRoutes:        routes,
			OperatorUser:           setArgs.opUser,
		},
	}

	if setArgs.exitNodeIP != "" {
		if err := maskedPrefs.Prefs.SetExitNodeIP(setArgs.exitNodeIP, st); err != nil {
			var e ipn.ExitNodeLocalIPError
			if errors.As(err, &e) {
				return fmt.Errorf("%w; did you mean --advertise-exit-node?", err)
			}
			return err
		}
	}

	setFlagSet.Visit(func(f *flag.Flag) {
		updateMaskedPrefsFromUpOrSetFlag(maskedPrefs, f.Name)
	})

	if maskedPrefs.IsEmpty() {
		return flag.ErrHelp
	}

	if maskedPrefs.RunSSHSet {
		curPrefs, err := localClient.GetPrefs(ctx)
		if err != nil {
			return err
		}

		wantSSH, haveSSH := maskedPrefs.RunSSH, curPrefs.RunSSH
		if err := presentSSHToggleRisk(wantSSH, haveSSH, setArgs.acceptedRisks); err != nil {
			return err
		}
	}

	_, err = localClient.EditPrefs(ctx, maskedPrefs)
	return err
}
