// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn"
	"tailscale.com/net/tsaddr"
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
	profileName            string
	forceDaemon            bool
}

func newSetFlagSet(goos string, setArgs *setArgsT) *flag.FlagSet {
	setf := newFlagSet("set")

	setf.StringVar(&setArgs.profileName, "nickname", "", "nickname for the login profile")
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
	switch goos {
	case "windows":
		setf.BoolVar(&setArgs.forceDaemon, "unattended", false, "run in \"Unattended Mode\" where Tailscale keeps running even after the current GUI user logs out (Windows-only)")
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

	maskedPrefs := &ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			ProfileName:            setArgs.profileName,
			RouteAll:               setArgs.acceptRoutes,
			CorpDNS:                setArgs.acceptDNS,
			ExitNodeAllowLANAccess: setArgs.exitNodeAllowLANAccess,
			ShieldsUp:              setArgs.shieldsUp,
			RunSSH:                 setArgs.runSSH,
			Hostname:               setArgs.hostname,
			OperatorUser:           setArgs.opUser,
			ForceDaemon:            setArgs.forceDaemon,
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

	var advertiseExitNodeSet, advertiseRoutesSet bool
	setFlagSet.Visit(func(f *flag.Flag) {
		updateMaskedPrefsFromUpOrSetFlag(maskedPrefs, f.Name)
		switch f.Name {
		case "advertise-exit-node":
			advertiseExitNodeSet = true
		case "advertise-routes":
			advertiseRoutesSet = true
		}
	})
	if maskedPrefs.IsEmpty() {
		return flag.ErrHelp
	}

	curPrefs, err := localClient.GetPrefs(ctx)
	if err != nil {
		return err
	}
	if maskedPrefs.AdvertiseRoutesSet {
		maskedPrefs.AdvertiseRoutes, err = calcAdvertiseRoutesForSet(advertiseExitNodeSet, advertiseRoutesSet, curPrefs, setArgs)
		if err != nil {
			return err
		}
	}

	if maskedPrefs.RunSSHSet {
		wantSSH, haveSSH := maskedPrefs.RunSSH, curPrefs.RunSSH
		if err := presentSSHToggleRisk(wantSSH, haveSSH, setArgs.acceptedRisks); err != nil {
			return err
		}
	}
	checkPrefs := curPrefs.Clone()
	checkPrefs.ApplyEdits(maskedPrefs)
	if err := localClient.CheckPrefs(ctx, checkPrefs); err != nil {
		return err
	}

	_, err = localClient.EditPrefs(ctx, maskedPrefs)
	return err
}

// calcAdvertiseRoutesForSet returns the new value for Prefs.AdvertiseRoutes based on the
// current value, the flags passed to "tailscale set".
// advertiseExitNodeSet is whether the --advertise-exit-node flag was set.
// advertiseRoutesSet is whether the --advertise-routes flag was set.
// curPrefs is the current Prefs.
// setArgs is the parsed command-line arguments.
func calcAdvertiseRoutesForSet(advertiseExitNodeSet, advertiseRoutesSet bool, curPrefs *ipn.Prefs, setArgs setArgsT) (routes []netip.Prefix, err error) {
	if advertiseExitNodeSet && advertiseRoutesSet {
		return calcAdvertiseRoutes(setArgs.advertiseRoutes, setArgs.advertiseDefaultRoute)

	}
	if advertiseRoutesSet {
		return calcAdvertiseRoutes(setArgs.advertiseRoutes, curPrefs.AdvertisesExitNode())
	}
	if advertiseExitNodeSet {
		alreadyAdvertisesExitNode := curPrefs.AdvertisesExitNode()
		if alreadyAdvertisesExitNode == setArgs.advertiseDefaultRoute {
			return curPrefs.AdvertiseRoutes, nil
		}
		routes = tsaddr.FilterPrefixesCopy(curPrefs.AdvertiseRoutes, func(p netip.Prefix) bool {
			return p.Bits() != 0
		})
		if setArgs.advertiseDefaultRoute {
			routes = append(routes, tsaddr.AllIPv4(), tsaddr.AllIPv6())
		}
		return routes, nil
	}
	return nil, nil
}
