// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/peterbourgon/ff/v3/ffcli"
	qrcode "github.com/skip2/go-qrcode"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/logger"
	"tailscale.com/util/syspolicy/policyclient"
	"tailscale.com/version/distro"
)

var nodeKeyExpiryCmd = &ffcli.Command{
	Name:       "node-key-expiry",
	ShortUsage: "tailscale node-key-expiry [flags]",
	ShortHelp:  "Experimental command for testing seamless key expiry",

	LongHelp: strings.TrimSpace("Experimental command for testing seamless key expiry"),
	FlagSet:  upFlagSet,
	Exec: func(ctx context.Context, args []string) error {
		return runNke(ctx, "node-key-expiry", args, nkeArgsGlobal)
	},
}

var nkeArgsGlobal nkeArgsT

var nodeKeyExpiryFlagSet = newNkeFlagSet(effectiveGOOS(), &nkeArgsGlobal, "node-key-expiry")

// newNodeKeyExpiryFlagSet returns a new flag set for the "node-key-expiry" command.
func newNodeKeyExpiryFlagSet(nkeArgs *upArgsT, cmd string) *flag.FlagSet {
	nkef := newFlagSet(cmd)

	nkef.StringVar(&nkeArgs.authKeyOrFile, "auth-key", "", `node authorization key; if it begins with "file:", then it's a path to a file containing the authkey`)
	nkef.StringVar(&nkeArgs.server, "login-server", ipn.DefaultControlURL, "base URL of control server")
	nkef.DurationVar(&nkeArgs.timeout, "timeout", 0, "maximum amount of time to wait for tailscaled to enter a Running state; default (0s) blocks forever")
	nkef.BoolVar(&nkeArgs.forceReauth, "force-reauth", false, "force reauthentication (WARNING: this will bring down the Tailscale connection and thus should not be done remotely over SSH or RDP)")
	registerAcceptRiskFlag(nkef, &nkeArgs.acceptedRisks)

	return nkef
}

func newNkeFlagSet(goos string, upArgs *nkeArgsT, cmd string) *flag.FlagSet {
	upf := newFlagSet(cmd)

	// When adding new flags, prefer to put them under "tailscale set" instead
	// of here. Setting preferences via "tailscale up" is deprecated.
	upf.BoolVar(&upArgs.qr, "qr", false, "show QR code for login URLs")
	upf.StringVar(&upArgs.authKeyOrFile, "auth-key", "", `node authorization key; if it begins with "file:", then it's a path to a file containing the authkey`)

	upf.StringVar(&upArgs.server, "login-server", ipn.DefaultControlURL, "base URL of control server")

	upf.BoolVar(&upArgs.forceReauth, "force-reauth", false, "force reauthentication (WARNING: this will bring down the Tailscale connection and thus should not be done remotely over SSH or RDP)")
	registerAcceptRiskFlag(upf, &upArgs.acceptedRisks)

	return upf
}

// upArgsT is the type of upArgs, the argument struct for `tailscale up`.
// As of 2024-10-08, upArgsT is frozen and no new arguments should be
// added to it. Add new arguments to setArgsT instead.
type nkeArgsT struct {
	qr            bool
	server        string
	forceReauth   bool
	authKeyOrFile string // "secret" or "file:/path/to/secret"
	acceptedRisks string
}

func runNke(ctx context.Context, cmd string, args []string, upArgs nkeArgsT) (retErr error) {
	st, err := localClient.Status(ctx)
	if err != nil {
		return fixTailscaledConnectError(err)
	}
	origAuthURL := st.AuthURL

	// printAuthURL reports whether we should print out the
	// provided auth URL from an IPN notify.
	printAuthURL := func(url string) bool {
		if url == "" {
			// Probably unnecessary but we used to have a bug where tailscaled
			// could send an empty URL over the IPN bus. ~Harmless to keep.
			return false
		}
		if upArgs.authKeyOrFile != "" {
			// Issue 1755: when using an authkey, don't
			// show an authURL that might still be pending
			// from a previous non-completed interactive
			// login.
			return false
		}
		if upArgs.forceReauth && url == origAuthURL {
			return false
		}
		return true
	}
	prefs, err := prefsFromNkeArgs(upArgs, warnf, st, effectiveGOOS())
	if err != nil {
		fatalf("%s", err)
	}

	defer func() {
		if retErr == nil {
			checkUpWarnings(ctx)
		}
	}()

	watchCtx, cancelWatch := context.WithCancel(ctx)
	defer cancelWatch()

	go func() {
		interrupt := make(chan os.Signal, 1)
		signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
		select {
		case <-interrupt:
			cancelWatch()
		case <-watchCtx.Done():
		}
	}()

	running := make(chan bool, 1) // gets value once in state ipn.Running
	watchErr := make(chan error, 1)

	if err := localClient.CheckPrefs(ctx, prefs); err != nil {
		return err
	}

	authKey, err := upArgs.getAuthKey()
	if err != nil {
		return err
	}
	err = localClient.Start(ctx, ipn.Options{
		AuthKey:     authKey,
		UpdatePrefs: prefs,
	})
	if err != nil {
		return err
	}
	if upArgs.forceReauth || !st.HaveNodeKey {
		err := localClient.StartLoginInteractive(ctx)
		if err != nil {
			return err
		}
	}

	watcher, err := localClient.WatchIPNBus(watchCtx, ipn.NotifyInitialState)
	if err != nil {
		return err
	}
	defer watcher.Close()

	go func() {
		var lastURLPrinted string

		for {
			n, err := watcher.Next()
			if err != nil {
				watchErr <- err
				return
			}
			if n.ErrMessage != nil {
				msg := *n.ErrMessage
				fatalf("backend error: %v\n", msg)
			}
			if s := n.State; s != nil {
				switch *s {
				case ipn.NeedsMachineAuth:
					fmt.Fprintf(Stderr, "\nTo approve your machine, visit (as admin):\n\n\t%s\n\n", prefs.AdminPageURL(policyclient.Get()))
				case ipn.Running:
					// Done full authentication process
					// Only need to print an update if we printed the "please click" message earlier.
					fmt.Fprintf(Stderr, "Success.\n")
					select {
					case running <- true:
					default:
					}
					cancelWatch()
				}
			}
			if url := n.BrowseToURL; url != nil {
				authURL := *url
				if !printAuthURL(authURL) || authURL == lastURLPrinted {
					continue
				}
				lastURLPrinted = authURL

				fmt.Fprintf(Stderr, "\nTo authenticate, visit:\n\n\t%s\n\n", authURL)
				if upArgs.qr {
					q, err := qrcode.New(authURL, qrcode.Medium)
					if err != nil {
						log.Printf("QR code error: %v", err)
					} else {
						fmt.Fprintf(Stderr, "%s\n", q.ToString(false))
					}
				}
			}
		}
	}()

	return nil
}

func (a nkeArgsT) getAuthKey() (string, error) {
	v := a.authKeyOrFile
	if file, ok := strings.CutPrefix(v, "file:"); ok {
		b, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	return v, nil
}

type nkeCheckEnv struct {
	goos          string
	user          string
	flagSet       *flag.FlagSet
	upArgs        nkeArgsT
	backendState  string
	curExitNodeIP netip.Addr
	distro        distro.Distro
}

// prefsFromUpArgs returns the ipn.Prefs for the provided args.
//
// Note that the parameters upArgs and warnf are named intentionally
// to shadow the globals to prevent accidental misuse of them. This
// function exists for testing and should have no side effects or
// outside interactions (e.g. no making Tailscale LocalAPI calls).
func prefsFromNkeArgs(upArgs nkeArgsT, warnf logger.Logf, st *ipnstate.Status, goos string) (*ipn.Prefs, error) {
	prefs := ipn.NewPrefs()
	prefs.ControlURL = upArgs.server
	prefs.WantRunning = true
	return prefs, nil
}
