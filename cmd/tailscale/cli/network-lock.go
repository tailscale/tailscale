// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tka"
	"tailscale.com/types/key"
)

var netlockCmd = &ffcli.Command{
	Name:       "lock",
	ShortUsage: "lock <sub-command> <arguments>",
	ShortHelp:  "Manipulate the tailnet key authority",
	Subcommands: []*ffcli.Command{
		nlInitCmd,
		nlStatusCmd,
		nlAddCmd,
		nlRemoveCmd,
		nlSignCmd,
		nlDisableCmd,
		nlDisablementKDFCmd,
		nlLogCmd,
		nlLocalDisableCmd,
	},
	Exec: runNetworkLockStatus,
}

var nlInitArgs struct {
	numDisablements       int
	disablementForSupport bool
	confirm               bool
}

var nlInitCmd = &ffcli.Command{
	Name:       "init",
	ShortUsage: "init [--gen-disablement-for-support] --gen-disablements N <trusted-key>...",
	ShortHelp:  "Initialize tailnet lock",
	LongHelp: strings.TrimSpace(`

The 'tailscale lock init' command initializes tailnet lock across the
entire tailnet. The specified keys are initially trusted to sign nodes
or to make further changes to tailnet lock.

You can identify the key for a node you wish to trust by running 'tailscale lock'
on that node, and copying the node's tailnet lock key.

In the event that tailnet lock need be disabled, it can be disabled using
the 'tailscale lock disable' command and one of the disablement secrets.
The number of disablement secrets to be generated is specified using the
--gen-disablements flag. Initializing tailnet lock requires at least
one disablement.

If --gen-disablement-for-support is specified, an additional disablement secret
will be generated and transmitted to Tailscale, which support can use to disable
tailnet lock. We recommend setting this flag.

`),
	Exec: runNetworkLockInit,
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("lock init")
		fs.IntVar(&nlInitArgs.numDisablements, "gen-disablements", 1, "number of disablement secrets to generate")
		fs.BoolVar(&nlInitArgs.disablementForSupport, "gen-disablement-for-support", false, "generates and transmits a disablement secret for Tailscale support")
		fs.BoolVar(&nlInitArgs.confirm, "confirm", false, "do not prompt for confirmation")
		return fs
	})(),
}

func runNetworkLockInit(ctx context.Context, args []string) error {
	st, err := localClient.NetworkLockStatus(ctx)
	if err != nil {
		return fixTailscaledConnectError(err)
	}
	if st.Enabled {
		return errors.New("network-lock is already enabled")
	}

	// Parse initially-trusted keys & disablement values.
	keys, disablementValues, err := parseNLArgs(args, true, true)
	if err != nil {
		return err
	}

	fmt.Println("You are initializing tailnet lock with trust in the following keys:")
	for _, k := range keys {
		fmt.Printf(" - tlpub:%x (%s key)\n", k.Public, k.Kind.String())
	}
	fmt.Println()

	if !nlInitArgs.confirm {
		fmt.Printf("%d disablement secrets will be generated.\n", nlInitArgs.numDisablements)
		if nlInitArgs.disablementForSupport {
			fmt.Println("A disablement secret for support will be generated and transmitted to Tailscale.")
		}

		genSupportFlag := ""
		if nlInitArgs.disablementForSupport {
			genSupportFlag = "--gen-disablement-for-support "
		}
		fmt.Println("\nIf this is correct, please re-run this command with the --confirm flag:")
		fmt.Printf("\t%s lock init --confirm --gen-disablements %d %s%s", os.Args[0], nlInitArgs.numDisablements, genSupportFlag, strings.Join(args, " "))
		fmt.Println()
		return nil
	}

	fmt.Printf("%d disablement secrets have been generated and are printed below. Take note of them now, they WILL NOT be shown again.\n", nlInitArgs.numDisablements)
	for i := 0; i < nlInitArgs.numDisablements; i++ {
		var secret [32]byte
		if _, err := rand.Read(secret[:]); err != nil {
			return err
		}
		fmt.Printf("\tdisablement-secret:%X\n", secret[:])
		disablementValues = append(disablementValues, tka.DisablementKDF(secret[:]))
	}

	var supportDisablement []byte
	if nlInitArgs.disablementForSupport {
		supportDisablement = make([]byte, 32)
		if _, err := rand.Read(supportDisablement); err != nil {
			return err
		}
		disablementValues = append(disablementValues, tka.DisablementKDF(supportDisablement))
		fmt.Println("A disablement secret for support has been generated and will be transmitted to Tailscale upon initialization.")
	}

	// The state returned by NetworkLockInit likely doesn't contain the initialized state,
	// because that has to tick through from netmaps.
	if _, err := localClient.NetworkLockInit(ctx, keys, disablementValues, supportDisablement); err != nil {
		return err
	}

	fmt.Println("Initialization complete.")
	return nil
}

var nlStatusCmd = &ffcli.Command{
	Name:       "status",
	ShortUsage: "status",
	ShortHelp:  "Outputs the state of network lock",
	Exec:       runNetworkLockStatus,
}

func runNetworkLockStatus(ctx context.Context, args []string) error {
	st, err := localClient.NetworkLockStatus(ctx)
	if err != nil {
		return fixTailscaledConnectError(err)
	}
	if st.Enabled {
		fmt.Println("Tailnet-lock is ENABLED.")
	} else {
		fmt.Println("Tailnet-lock is NOT enabled.")
	}
	fmt.Println()

	if st.Enabled && st.NodeKey != nil && !st.PublicKey.IsZero() {
		if st.NodeKeySigned {
			fmt.Println("This node is accessible under tailnet-lock.")
		} else {
			fmt.Println("This node is LOCKED OUT by tailnet-lock, and action is required to establish connectivity.")
			fmt.Printf("Run the following command on a node with a trusted key:\n\ttailscale lock sign %v %s\n", st.NodeKey, st.PublicKey.CLIString())
		}
		fmt.Println()
	}

	if !st.PublicKey.IsZero() {
		fmt.Printf("This node's tailnet-lock key: %s\n", st.PublicKey.CLIString())
		fmt.Println()
	}

	if st.Enabled && len(st.TrustedKeys) > 0 {
		fmt.Println("Keys trusted to make changes to tailnet-lock:")
		for _, k := range st.TrustedKeys {
			var line strings.Builder
			line.WriteString("\t")
			line.WriteString(k.Key.CLIString())
			line.WriteString("\t")
			line.WriteString(fmt.Sprint(k.Votes))
			line.WriteString("\t")
			if k.Key == st.PublicKey {
				line.WriteString("(us)")
			}
			fmt.Println(line.String())
		}
	}

	if st.Enabled && len(st.FilteredPeers) > 0 {
		fmt.Println()
		fmt.Println("The following peers are locked out by tailnet lock & do not have connectivity:")
		for _, p := range st.FilteredPeers {
			var line strings.Builder
			line.WriteString("\t")
			line.WriteString(p.Name)
			line.WriteString("\t")
			for i, addr := range p.TailscaleIPs {
				line.WriteString(addr.String())
				if i < len(p.TailscaleIPs)-1 {
					line.WriteString(", ")
				}
			}
			line.WriteString("\t")
			line.WriteString(string(p.StableID))
			fmt.Println(line.String())
		}
	}

	return nil
}

var nlAddCmd = &ffcli.Command{
	Name:       "add",
	ShortUsage: "add <public-key>...",
	ShortHelp:  "Adds one or more signing keys to the tailnet key authority",
	Exec: func(ctx context.Context, args []string) error {
		return runNetworkLockModify(ctx, args, nil)
	},
}

var nlRemoveCmd = &ffcli.Command{
	Name:       "remove",
	ShortUsage: "remove <public-key>...",
	ShortHelp:  "Removes one or more signing keys to the tailnet key authority",
	Exec: func(ctx context.Context, args []string) error {
		return runNetworkLockModify(ctx, nil, args)
	},
}

// parseNLArgs parses a slice of strings into slices of tka.Key & disablement
// values/secrets.
// The keys encoded in args should be specified using their key.NLPublic.MarshalText
// representation with an optional '?<votes>' suffix.
// Disablement values or secrets must be encoded in hex with a prefix of 'disablement:' or
// 'disablement-secret:'.
//
// If any element could not be parsed,
// a nil slice is returned along with an appropriate error.
func parseNLArgs(args []string, parseKeys, parseDisablements bool) (keys []tka.Key, disablements [][]byte, err error) {
	for i, a := range args {
		if parseDisablements && (strings.HasPrefix(a, "disablement:") || strings.HasPrefix(a, "disablement-secret:")) {
			b, err := hex.DecodeString(a[strings.Index(a, ":")+1:])
			if err != nil {
				return nil, nil, fmt.Errorf("parsing disablement %d: %v", i+1, err)
			}
			disablements = append(disablements, b)
			continue
		}

		if !parseKeys {
			return nil, nil, fmt.Errorf("parsing argument %d: expected value with \"disablement:\" or \"disablement-secret:\" prefix, got %q", i+1, a)
		}

		var nlpk key.NLPublic
		spl := strings.SplitN(a, "?", 2)
		if err := nlpk.UnmarshalText([]byte(spl[0])); err != nil {
			return nil, nil, fmt.Errorf("parsing key %d: %v", i+1, err)
		}

		k := tka.Key{
			Kind:   tka.Key25519,
			Public: nlpk.Verifier(),
			Votes:  1,
		}
		if len(spl) > 1 {
			votes, err := strconv.Atoi(spl[1])
			if err != nil {
				return nil, nil, fmt.Errorf("parsing key %d votes: %v", i+1, err)
			}
			k.Votes = uint(votes)
		}
		keys = append(keys, k)
	}
	return keys, disablements, nil
}

func runNetworkLockModify(ctx context.Context, addArgs, removeArgs []string) error {
	st, err := localClient.NetworkLockStatus(ctx)
	if err != nil {
		return fixTailscaledConnectError(err)
	}
	if !st.Enabled {
		return errors.New("tailnet-lock is not enabled")
	}

	addKeys, _, err := parseNLArgs(addArgs, true, false)
	if err != nil {
		return err
	}
	removeKeys, _, err := parseNLArgs(removeArgs, true, false)
	if err != nil {
		return err
	}

	status, err := localClient.NetworkLockModify(ctx, addKeys, removeKeys)
	if err != nil {
		return err
	}

	fmt.Printf("Status: %+v\n\n", status)
	return nil
}

var nlSignCmd = &ffcli.Command{
	Name:       "sign",
	ShortUsage: "sign <node-key> [<rotation-key>]",
	ShortHelp:  "Signs a node-key and transmits that signature to the control plane",
	Exec:       runNetworkLockSign,
}

func runNetworkLockSign(ctx context.Context, args []string) error {
	var (
		nodeKey     key.NodePublic
		rotationKey key.NLPublic
	)

	if len(args) == 0 || len(args) > 2 {
		return errors.New("usage: lock sign <node-key> [<rotation-key>]")
	}
	if err := nodeKey.UnmarshalText([]byte(args[0])); err != nil {
		return fmt.Errorf("decoding node-key: %w", err)
	}
	if len(args) > 1 {
		if err := rotationKey.UnmarshalText([]byte(args[1])); err != nil {
			return fmt.Errorf("decoding rotation-key: %w", err)
		}
	}

	return localClient.NetworkLockSign(ctx, nodeKey, []byte(rotationKey.Verifier()))
}

var nlDisableCmd = &ffcli.Command{
	Name:       "disable",
	ShortUsage: "disable <disablement-secret>",
	ShortHelp:  "Consumes a disablement secret to shut down tailnet-lock across the tailnet",
	Exec:       runNetworkLockDisable,
}

func runNetworkLockDisable(ctx context.Context, args []string) error {
	_, secrets, err := parseNLArgs(args, false, true)
	if err != nil {
		return err
	}
	if len(secrets) != 1 {
		return errors.New("usage: lock disable <disablement-secret>")
	}
	return localClient.NetworkLockDisable(ctx, secrets[0])
}

var nlLocalDisableCmd = &ffcli.Command{
	Name:       "local-disable",
	ShortUsage: "local-disable",
	ShortHelp:  "Disables the currently-active tailnet lock for this node",
	Exec:       runNetworkLockLocalDisable,
}

func runNetworkLockLocalDisable(ctx context.Context, args []string) error {
	return localClient.NetworkLockForceLocalDisable(ctx)
}

var nlDisablementKDFCmd = &ffcli.Command{
	Name:       "disablement-kdf",
	ShortUsage: "disablement-kdf <hex-encoded-disablement-secret>",
	ShortHelp:  "Computes a disablement value from a disablement secret (advanced users only)",
	Exec:       runNetworkLockDisablementKDF,
}

func runNetworkLockDisablementKDF(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: lock disablement-kdf <hex-encoded-disablement-secret>")
	}
	secret, err := hex.DecodeString(args[0])
	if err != nil {
		return err
	}
	fmt.Printf("disablement:%x\n", tka.DisablementKDF(secret))
	return nil
}

var nlLogArgs struct {
	limit int
}

var nlLogCmd = &ffcli.Command{
	Name:       "log",
	ShortUsage: "log [--limit N]",
	ShortHelp:  "List changes applied to tailnet-lock",
	Exec:       runNetworkLockLog,
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("lock log")
		fs.IntVar(&nlLogArgs.limit, "limit", 50, "max number of updates to list")
		return fs
	})(),
}

func nlDescribeUpdate(update ipnstate.NetworkLockUpdate, color bool) (string, error) {
	terminalYellow := ""
	terminalClear := ""
	if color {
		terminalYellow = "\x1b[33m"
		terminalClear = "\x1b[0m"
	}

	var stanza strings.Builder
	printKey := func(key *tka.Key, prefix string) {
		fmt.Fprintf(&stanza, "%sType: %s\n", prefix, key.Kind.String())
		fmt.Fprintf(&stanza, "%sKeyID: %x\n", prefix, key.ID())
		fmt.Fprintf(&stanza, "%sVotes: %d\n", prefix, key.Votes)
		if key.Meta != nil {
			fmt.Fprintf(&stanza, "%sMetadata: %+v\n", prefix, key.Meta)
		}
	}

	var aum tka.AUM
	if err := aum.Unserialize(update.Raw); err != nil {
		return "", fmt.Errorf("decoding: %w", err)
	}

	fmt.Fprintf(&stanza, "%supdate %x (%s)%s\n", terminalYellow, update.Hash, update.Change, terminalClear)

	switch update.Change {
	case tka.AUMAddKey.String():
		printKey(aum.Key, "")
	case tka.AUMRemoveKey.String():
		fmt.Fprintf(&stanza, "KeyID: %x\n", aum.KeyID)

	case tka.AUMUpdateKey.String():
		fmt.Fprintf(&stanza, "KeyID: %x\n", aum.KeyID)
		if aum.Votes != nil {
			fmt.Fprintf(&stanza, "Votes: %d\n", aum.Votes)
		}
		if aum.Meta != nil {
			fmt.Fprintf(&stanza, "Metadata: %+v\n", aum.Meta)
		}

	case tka.AUMCheckpoint.String():
		fmt.Fprintln(&stanza, "Disablement values:")
		for _, v := range aum.State.DisablementSecrets {
			fmt.Fprintf(&stanza, " - %x\n", v)
		}
		fmt.Fprintln(&stanza, "Keys:")
		for _, k := range aum.State.Keys {
			printKey(&k, "  ")
		}

	default:
		// Print a JSON encoding of the AUM as a fallback.
		e := json.NewEncoder(&stanza)
		e.SetIndent("", "\t")
		if err := e.Encode(aum); err != nil {
			return "", err
		}
		stanza.WriteRune('\n')
	}

	return stanza.String(), nil
}

func runNetworkLockLog(ctx context.Context, args []string) error {
	updates, err := localClient.NetworkLockLog(ctx, nlLogArgs.limit)
	if err != nil {
		return fixTailscaledConnectError(err)
	}
	useColor := isatty.IsTerminal(os.Stdout.Fd())

	stdOut := colorable.NewColorableStdout()
	for _, update := range updates {
		stanza, err := nlDescribeUpdate(update, useColor)
		if err != nil {
			return err
		}
		fmt.Fprintln(stdOut, stanza)
	}
	return nil
}
