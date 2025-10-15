// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/cmd/tailscale/cli/ffcomplete"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/ipn"
	"tailscale.com/net/netutil"
	"tailscale.com/net/tsaddr"
	"tailscale.com/safesocket"
	"tailscale.com/tsconst"
	"tailscale.com/types/opt"
	"tailscale.com/types/ptr"
	"tailscale.com/types/views"
	"tailscale.com/version"
)

var setCmd = &ffcli.Command{
	Name:       "set",
	ShortUsage: "tailscale set [flags]",
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
	runWebClient           bool
	hostname               string
	advertiseRoutes        string
	advertiseDefaultRoute  bool
	advertiseConnector     bool
	opUser                 string
	acceptedRisks          string
	profileName            string
	forceDaemon            bool
	updateCheck            bool
	updateApply            bool
	reportPosture          bool
	snat                   bool
	statefulFiltering      bool
	netfilterMode          string
	relayServerPort        string
}

func newSetFlagSet(goos string, setArgs *setArgsT) *flag.FlagSet {
	setf := newFlagSet("set")

	setf.StringVar(&setArgs.profileName, "nickname", "", "nickname for the current account")
	setf.BoolVar(&setArgs.acceptRoutes, "accept-routes", acceptRouteDefault(goos), "accept routes advertised by other Tailscale nodes")
	setf.BoolVar(&setArgs.acceptDNS, "accept-dns", true, "accept DNS configuration from the admin panel")
	setf.StringVar(&setArgs.exitNodeIP, "exit-node", "", "Tailscale exit node (IP, base name, or auto:any) for internet traffic, or empty string to not use an exit node")
	setf.BoolVar(&setArgs.exitNodeAllowLANAccess, "exit-node-allow-lan-access", false, "Allow direct access to the local network when routing traffic via an exit node")
	setf.BoolVar(&setArgs.shieldsUp, "shields-up", false, "don't allow incoming connections")
	setf.BoolVar(&setArgs.runSSH, "ssh", false, "run an SSH server, permitting access per tailnet admin's declared policy")
	setf.StringVar(&setArgs.hostname, "hostname", "", "hostname to use instead of the one provided by the OS")
	setf.StringVar(&setArgs.advertiseRoutes, "advertise-routes", "", "routes to advertise to other nodes (comma-separated, e.g. \"10.0.0.0/8,192.168.0.0/24\") or empty string to not advertise routes")
	setf.BoolVar(&setArgs.advertiseDefaultRoute, "advertise-exit-node", false, "offer to be an exit node for internet traffic for the tailnet")
	setf.BoolVar(&setArgs.advertiseConnector, "advertise-connector", false, "offer to be an app connector for domain specific internet traffic for the tailnet")
	setf.BoolVar(&setArgs.updateCheck, "update-check", true, "notify about available Tailscale updates")
	setf.BoolVar(&setArgs.updateApply, "auto-update", false, "automatically update to the latest available version")
	setf.BoolVar(&setArgs.reportPosture, "report-posture", false, "allow management plane to gather device posture information")
	setf.BoolVar(&setArgs.runWebClient, "webclient", false, "expose the web interface for managing this node over Tailscale at port 5252")
	setf.StringVar(&setArgs.relayServerPort, "relay-server-port", "", "UDP port number (0 will pick a random unused port) for the relay server to bind to, on all interfaces, or empty string to disable relay server functionality")

	ffcomplete.Flag(setf, "exit-node", func(args []string) ([]string, ffcomplete.ShellCompDirective, error) {
		st, err := localClient.Status(context.Background())
		if err != nil {
			return nil, 0, err
		}
		nodes := make([]string, 0, len(st.Peer))
		for _, node := range st.Peer {
			if !node.ExitNodeOption {
				continue
			}
			nodes = append(nodes, strings.TrimSuffix(node.DNSName, "."))
		}
		return nodes, ffcomplete.ShellCompDirectiveNoFileComp, nil
	})

	if safesocket.GOOSUsesPeerCreds(goos) {
		setf.StringVar(&setArgs.opUser, "operator", "", "Unix username to allow to operate on tailscaled without sudo")
	}
	switch goos {
	case "linux":
		setf.BoolVar(&setArgs.snat, "snat-subnet-routes", true, "source NAT traffic to local routes advertised with --advertise-routes")
		setf.BoolVar(&setArgs.statefulFiltering, "stateful-filtering", false, "apply stateful filtering to forwarded packets (subnet routers, exit nodes, etc.)")
		setf.StringVar(&setArgs.netfilterMode, "netfilter-mode", defaultNetfilterMode(), "netfilter mode (one of on, nodivert, off)")
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

	// Note that even though we set the values here regardless of whether the
	// user passed the flag, the value is only used if the user passed the flag.
	// See updateMaskedPrefsFromUpOrSetFlag.
	maskedPrefs := &ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			ProfileName:            setArgs.profileName,
			RouteAll:               setArgs.acceptRoutes,
			CorpDNS:                setArgs.acceptDNS,
			ExitNodeAllowLANAccess: setArgs.exitNodeAllowLANAccess,
			ShieldsUp:              setArgs.shieldsUp,
			RunSSH:                 setArgs.runSSH,
			RunWebClient:           setArgs.runWebClient,
			Hostname:               setArgs.hostname,
			OperatorUser:           setArgs.opUser,
			NoSNAT:                 !setArgs.snat,
			ForceDaemon:            setArgs.forceDaemon,
			AutoUpdate: ipn.AutoUpdatePrefs{
				Check: setArgs.updateCheck,
				Apply: opt.NewBool(setArgs.updateApply),
			},
			AppConnector: ipn.AppConnectorPrefs{
				Advertise: setArgs.advertiseConnector,
			},
			PostureChecking:     setArgs.reportPosture,
			NoStatefulFiltering: opt.NewBool(!setArgs.statefulFiltering),
		},
	}

	if effectiveGOOS() == "linux" {
		nfMode, warning, err := netfilterModeFromFlag(setArgs.netfilterMode)
		if err != nil {
			return err
		}
		if warning != "" {
			warnf(warning)
		}
		maskedPrefs.Prefs.NetfilterMode = nfMode
	}

	if setArgs.exitNodeIP != "" {
		if expr, useAutoExitNode := ipn.ParseAutoExitNodeString(setArgs.exitNodeIP); useAutoExitNode {
			maskedPrefs.AutoExitNode = expr
			maskedPrefs.AutoExitNodeSet = true
		} else if err := maskedPrefs.Prefs.SetExitNodeIP(setArgs.exitNodeIP, st); err != nil {
			var e ipn.ExitNodeLocalIPError
			if errors.As(err, &e) {
				return fmt.Errorf("%w; did you mean --advertise-exit-node?", err)
			}
			return err
		}
	}

	warnOnAdvertiseRoutes(ctx, &maskedPrefs.Prefs)
	if err := checkExitNodeRisk(ctx, &maskedPrefs.Prefs, setArgs.acceptedRisks); err != nil {
		return err
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

	if runtime.GOOS == "darwin" && maskedPrefs.AppConnector.Advertise {
		if err := presentRiskToUser(riskMacAppConnector, riskMacAppConnectorMessage, setArgs.acceptedRisks); err != nil {
			return err
		}
	}

	if maskedPrefs.RunSSHSet {
		wantSSH, haveSSH := maskedPrefs.RunSSH, curPrefs.RunSSH
		if err := presentSSHToggleRisk(wantSSH, haveSSH, setArgs.acceptedRisks); err != nil {
			return err
		}
	}
	if maskedPrefs.AutoUpdateSet.ApplySet && buildfeatures.HasClientUpdate && version.IsMacSysExt() {
		apply := "0"
		if maskedPrefs.AutoUpdate.Apply.EqualBool(true) {
			apply = "1"
		}
		out, err := exec.Command("defaults", "write", "io.tailscale.ipn.macsys", "SUAutomaticallyUpdate", apply).CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to enable automatic updates: %v, %q", err, out)
		}
	}

	if setArgs.relayServerPort != "" {
		uport, err := strconv.ParseUint(setArgs.relayServerPort, 10, 16)
		if err != nil {
			return fmt.Errorf("failed to set relay server port: %v", err)
		}
		maskedPrefs.Prefs.RelayServerPort = ptr.To(int(uport))
	}

	checkPrefs := curPrefs.Clone()
	checkPrefs.ApplyEdits(maskedPrefs)
	if err := localClient.CheckPrefs(ctx, checkPrefs); err != nil {
		return err
	}

	_, err = localClient.EditPrefs(ctx, maskedPrefs)
	if err != nil {
		return err
	}

	if setArgs.runWebClient && len(st.TailscaleIPs) > 0 {
		printf("\nWeb interface now running at %s:%d\n", st.TailscaleIPs[0], tsconst.WebListenPort)
	}

	return nil
}

// calcAdvertiseRoutesForSet returns the new value for Prefs.AdvertiseRoutes based on the
// current value, the flags passed to "tailscale set".
// advertiseExitNodeSet is whether the --advertise-exit-node flag was set.
// advertiseRoutesSet is whether the --advertise-routes flag was set.
// curPrefs is the current Prefs.
// setArgs is the parsed command-line arguments.
func calcAdvertiseRoutesForSet(advertiseExitNodeSet, advertiseRoutesSet bool, curPrefs *ipn.Prefs, setArgs setArgsT) (routes []netip.Prefix, err error) {
	if advertiseExitNodeSet && advertiseRoutesSet {
		return netutil.CalcAdvertiseRoutes(setArgs.advertiseRoutes, setArgs.advertiseDefaultRoute)

	}
	if advertiseRoutesSet {
		return netutil.CalcAdvertiseRoutes(setArgs.advertiseRoutes, curPrefs.AdvertisesExitNode())
	}
	if advertiseExitNodeSet {
		alreadyAdvertisesExitNode := curPrefs.AdvertisesExitNode()
		if alreadyAdvertisesExitNode == setArgs.advertiseDefaultRoute {
			return curPrefs.AdvertiseRoutes, nil
		}
		routes = tsaddr.FilterPrefixesCopy(views.SliceOf(curPrefs.AdvertiseRoutes), func(p netip.Prefix) bool {
			return p.Bits() != 0
		})
		if setArgs.advertiseDefaultRoute {
			routes = append(routes, tsaddr.AllIPv4(), tsaddr.AllIPv6())
		}
		return routes, nil
	}
	return nil, nil
}
