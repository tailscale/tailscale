// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_tailnetlock

package cli

import (
	"bytes"
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
	"time"

	"github.com/mattn/go-isatty"
	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tka"
	"tailscale.com/tsconst"
	"tailscale.com/types/key"
	"tailscale.com/types/tkatype"
	"tailscale.com/util/prompt"
)

func init() {
	maybeNetlockCmd = func() *ffcli.Command { return netlockCmd }
}

var netlockCmd = &ffcli.Command{
	Name:       "lock",
	ShortUsage: "tailscale lock <subcommand> [arguments...]",
	ShortHelp:  "Manage tailnet lock",
	LongHelp:   "Manage tailnet lock",
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
		nlRevokeKeysCmd,
	},
	Exec: runNetworkLockNoSubcommand,
}

func runNetworkLockNoSubcommand(ctx context.Context, args []string) error {
	// Detect & handle the deprecated command 'lock tskey-wrap'.
	if len(args) >= 2 && args[0] == "tskey-wrap" {
		return runTskeyWrapCmd(ctx, args[1:])
	}
	if len(args) > 0 {
		return fmt.Errorf("tailscale lock: unknown subcommand: %s", args[0])
	}

	return runNetworkLockStatus(ctx, args)
}

var nlInitArgs struct {
	numDisablements       int
	disablementForSupport bool
	confirm               bool
}

var nlInitCmd = &ffcli.Command{
	Name:       "init",
	ShortUsage: "tailscale lock init [--gen-disablement-for-support] --gen-disablements N <trusted-key>...",
	ShortHelp:  "Initialize tailnet lock",
	LongHelp: strings.TrimSpace(`

The 'tailscale lock init' command initializes tailnet lock for the
entire tailnet. The tailnet lock keys specified are those initially
trusted to sign nodes or to make further changes to tailnet lock.

You can identify the tailnet lock key for a node you wish to trust by
running 'tailscale lock' on that node, and copying the node's tailnet
lock key.

To disable tailnet lock, use the 'tailscale lock disable' command
along with one of the disablement secrets.
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
		return errors.New("tailnet lock is already enabled")
	}

	// Parse initially-trusted keys & disablement values.
	keys, disablementValues, err := parseNLArgs(args, true, true)
	if err != nil {
		return err
	}

	// Common mistake: Not specifying the current node's key as one of the trusted keys.
	foundSelfKey := false
	for _, k := range keys {
		keyID, err := k.ID()
		if err != nil {
			return err
		}
		if bytes.Equal(keyID, st.PublicKey.KeyID()) {
			foundSelfKey = true
			break
		}
	}
	if !foundSelfKey {
		return errors.New("the tailnet lock key of the current node must be one of the trusted keys during initialization")
	}

	fmt.Println("You are initializing tailnet lock with the following trusted signing keys:")
	for _, k := range keys {
		fmt.Printf(" - tlpub:%x (%s key)\n", k.Public, k.Kind.String())
	}
	fmt.Println()

	if !nlInitArgs.confirm {
		fmt.Printf("%d disablement secrets will be generated.\n", nlInitArgs.numDisablements)
		if nlInitArgs.disablementForSupport {
			fmt.Println("A disablement secret will be generated and transmitted to Tailscale support.")
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

	var successMsg strings.Builder

	fmt.Fprintf(&successMsg, "%d disablement secrets have been generated and are printed below. Take note of them now, they WILL NOT be shown again.\n", nlInitArgs.numDisablements)
	for range nlInitArgs.numDisablements {
		var secret [32]byte
		if _, err := rand.Read(secret[:]); err != nil {
			return err
		}
		fmt.Fprintf(&successMsg, "\tdisablement-secret:%X\n", secret[:])
		disablementValues = append(disablementValues, tka.DisablementKDF(secret[:]))
	}

	var supportDisablement []byte
	if nlInitArgs.disablementForSupport {
		supportDisablement = make([]byte, 32)
		if _, err := rand.Read(supportDisablement); err != nil {
			return err
		}
		disablementValues = append(disablementValues, tka.DisablementKDF(supportDisablement))
		fmt.Fprintln(&successMsg, "A disablement secret for Tailscale support has been generated and transmitted to Tailscale.")
	}

	// The state returned by NetworkLockInit likely doesn't contain the initialized state,
	// because that has to tick through from netmaps.
	if _, err := localClient.NetworkLockInit(ctx, keys, disablementValues, supportDisablement); err != nil {
		return err
	}

	fmt.Print(successMsg.String())
	fmt.Println("Initialization complete.")
	return nil
}

var nlStatusArgs struct {
	json bool
}

var nlStatusCmd = &ffcli.Command{
	Name:       "status",
	ShortUsage: "tailscale lock status",
	ShortHelp:  "Output the state of tailnet lock",
	Exec:       runNetworkLockStatus,
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("lock status")
		fs.BoolVar(&nlStatusArgs.json, "json", false, "output in JSON format (WARNING: format subject to change)")
		return fs
	})(),
}

func runNetworkLockStatus(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("tailscale lock status: unexpected argument")
	}

	st, err := localClient.NetworkLockStatus(ctx)
	if err != nil {
		return fixTailscaledConnectError(err)
	}

	if nlStatusArgs.json {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(st)
	}

	if st.Enabled {
		fmt.Println("Tailnet Lock is ENABLED.")
	} else {
		fmt.Println("Tailnet Lock is NOT enabled.")
	}
	fmt.Println()

	if st.Enabled && st.NodeKey != nil && !st.PublicKey.IsZero() {
		if st.NodeKeySigned {
			fmt.Println("This node is accessible under Tailnet Lock. Node signature:")
			fmt.Println(st.NodeKeySignature.String())
		} else {
			fmt.Println("This node is LOCKED OUT by Tailnet Lock, and action is required to establish connectivity.")
			fmt.Printf("Run the following command on a node with a trusted key:\n\ttailscale lock sign %v %s\n", st.NodeKey, st.PublicKey.CLIString())
		}
		fmt.Println()
	}

	if !st.PublicKey.IsZero() {
		fmt.Printf("This node's tailnet-lock key: %s\n", st.PublicKey.CLIString())
		fmt.Println()
	}

	if st.Enabled && len(st.TrustedKeys) > 0 {
		fmt.Println("Trusted signing keys:")
		for _, k := range st.TrustedKeys {
			var line strings.Builder
			line.WriteString("\t")
			line.WriteString(k.Key.CLIString())
			line.WriteString("\t")
			line.WriteString(fmt.Sprint(k.Votes))
			line.WriteString("\t")
			if k.Key == st.PublicKey {
				line.WriteString("(self)")
			}
			if k.Metadata["purpose"] == "pre-auth key" {
				if preauthKeyID := k.Metadata["authkey_stableid"]; preauthKeyID != "" {
					line.WriteString("(pre-auth key ")
					line.WriteString(preauthKeyID)
					line.WriteString(")")
				} else {
					line.WriteString("(pre-auth key)")
				}
			}
			fmt.Println(line.String())
		}
	}

	if st.Enabled && len(st.FilteredPeers) > 0 {
		fmt.Println()
		fmt.Println("The following nodes are locked out by tailnet lock and cannot connect to other nodes:")
		for _, p := range st.FilteredPeers {
			var line strings.Builder
			line.WriteString("\t")
			line.WriteString(p.Name)
			line.WriteString("\t")
			for i, addr := range p.TailscaleIPs {
				line.WriteString(addr.String())
				if i < len(p.TailscaleIPs)-1 {
					line.WriteString(",")
				}
			}
			line.WriteString("\t")
			line.WriteString(string(p.StableID))
			line.WriteString("\t")
			line.WriteString(p.NodeKey.String())
			fmt.Println(line.String())
		}
	}

	return nil
}

var nlAddCmd = &ffcli.Command{
	Name:       "add",
	ShortUsage: "tailscale lock add <public-key>...",
	ShortHelp:  "Add one or more trusted signing keys to tailnet lock",
	Exec: func(ctx context.Context, args []string) error {
		return runNetworkLockModify(ctx, args, nil)
	},
}

var nlRemoveArgs struct {
	resign bool
}

var nlRemoveCmd = &ffcli.Command{
	Name:       "remove",
	ShortUsage: "tailscale lock remove [--re-sign=false] <public-key>...",
	ShortHelp:  "Remove one or more trusted signing keys from tailnet lock",
	Exec:       runNetworkLockRemove,
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("lock remove")
		fs.BoolVar(&nlRemoveArgs.resign, "re-sign", true, "resign signatures which would be invalidated by removal of trusted signing keys")
		return fs
	})(),
}

func runNetworkLockRemove(ctx context.Context, args []string) error {
	removeKeys, _, err := parseNLArgs(args, true, false)
	if err != nil {
		return err
	}
	st, err := localClient.NetworkLockStatus(ctx)
	if err != nil {
		return fixTailscaledConnectError(err)
	}
	if !st.Enabled {
		return errors.New("tailnet lock is not enabled")
	}
	if len(st.TrustedKeys) == 1 {
		return errors.New("cannot remove the last trusted signing key; use 'tailscale lock disable' to disable tailnet lock instead, or add another signing key before removing one")
	}

	if nlRemoveArgs.resign {
		// Validate we are not removing trust in ourselves while resigning. This is because
		// we resign with our own key, so the signatures would be immediately invalid.
		for _, k := range removeKeys {
			kID, err := k.ID()
			if err != nil {
				return fmt.Errorf("computing KeyID for key %v: %w", k, err)
			}
			if bytes.Equal(st.PublicKey.KeyID(), kID) {
				return errors.New("cannot remove local trusted signing key while resigning; run command on a different node or with --re-sign=false")
			}
		}

		// Resign affected signatures for each of the keys we are removing.
		for _, k := range removeKeys {
			kID, _ := k.ID() // err already checked above
			sigs, err := localClient.NetworkLockAffectedSigs(ctx, kID)
			if err != nil {
				return fmt.Errorf("affected sigs for key %X: %w", kID, err)
			}

			for _, sigBytes := range sigs {
				var sig tka.NodeKeySignature
				if err := sig.Unserialize(sigBytes); err != nil {
					return fmt.Errorf("failed decoding signature: %w", err)
				}
				var nodeKey key.NodePublic
				if err := nodeKey.UnmarshalBinary(sig.Pubkey); err != nil {
					return fmt.Errorf("failed decoding pubkey for signature: %w", err)
				}

				// Safety: NetworkLockAffectedSigs() verifies all signatures before
				// successfully returning.
				rotationKey, _ := sig.UnverifiedWrappingPublic()
				if err := localClient.NetworkLockSign(ctx, nodeKey, []byte(rotationKey)); err != nil {
					return fmt.Errorf("failed to sign %v: %w", nodeKey, err)
				}
			}
		}
	} else {
		if isatty.IsTerminal(os.Stdout.Fd()) {
			fmt.Printf(`Warning
Removal of a signing key(s) without resigning nodes (--re-sign=false)
will cause any nodes signed by the the given key(s) to be locked out
of the Tailscale network. Proceed with caution.
`)
			if !prompt.YesNo("Are you sure you want to remove the signing key(s)?", true) {
				fmt.Printf("aborting removal of signing key(s)\n")
				os.Exit(0)
			}
		}
	}

	return localClient.NetworkLockModify(ctx, nil, removeKeys)
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
		return errors.New("tailnet lock is not enabled")
	}

	addKeys, _, err := parseNLArgs(addArgs, true, false)
	if err != nil {
		return err
	}
	removeKeys, _, err := parseNLArgs(removeArgs, true, false)
	if err != nil {
		return err
	}

	if err := localClient.NetworkLockModify(ctx, addKeys, removeKeys); err != nil {
		return err
	}
	return nil
}

var nlSignCmd = &ffcli.Command{
	Name:       "sign",
	ShortUsage: "tailscale lock sign <node-key> [<rotation-key>]\ntailscale lock sign <auth-key>",
	ShortHelp:  "Sign a node or pre-approved auth key",
	LongHelp: `Either:
  - signs a node key and transmits the signature to the coordination
    server, or
  - signs a pre-approved auth key, printing it in a form that can be
    used to bring up nodes under tailnet lock

If any of the key arguments begin with "file:", the key is retrieved from
the file at the path specified in the argument suffix.`,
	Exec: runNetworkLockSign,
}

func runNetworkLockSign(ctx context.Context, args []string) error {
	// If any of the arguments start with "file:", replace that argument
	// with the contents of the file. We do this early, before the check
	// to see if the first argument is an auth key.
	for i, arg := range args {
		if filename, ok := strings.CutPrefix(arg, "file:"); ok {
			b, err := os.ReadFile(filename)
			if err != nil {
				return err
			}
			args[i] = strings.TrimSpace(string(b))
		}
	}

	if len(args) > 0 && strings.HasPrefix(args[0], "tskey-auth-") {
		return runTskeyWrapCmd(ctx, args)
	}

	var (
		nodeKey     key.NodePublic
		rotationKey key.NLPublic
	)

	if len(args) == 0 || len(args) > 2 {
		return errors.New("usage: tailscale lock sign <node-key> [<rotation-key>]")
	}
	if err := nodeKey.UnmarshalText([]byte(args[0])); err != nil {
		return fmt.Errorf("decoding node-key: %w", err)
	}
	if len(args) > 1 {
		if err := rotationKey.UnmarshalText([]byte(args[1])); err != nil {
			return fmt.Errorf("decoding rotation-key: %w", err)
		}
	}

	err := localClient.NetworkLockSign(ctx, nodeKey, []byte(rotationKey.Verifier()))
	// Provide a better help message for when someone clicks through the signing flow
	// on the wrong device.
	if err != nil && strings.Contains(err.Error(), tsconst.TailnetLockNotTrustedMsg) {
		fmt.Fprintln(Stderr, "Error: Signing is not available on this device because it does not have a trusted tailnet lock key.")
		fmt.Fprintln(Stderr)
		fmt.Fprintln(Stderr, "Try again on a signing device instead. Tailnet admins can see signing devices on the admin panel.")
		fmt.Fprintln(Stderr)
	}
	return err
}

var nlDisableCmd = &ffcli.Command{
	Name:       "disable",
	ShortUsage: "tailscale lock disable <disablement-secret>",
	ShortHelp:  "Consume a disablement secret to shut down tailnet lock for the tailnet",
	LongHelp: strings.TrimSpace(`

The 'tailscale lock disable' command uses the specified disablement
secret to disable tailnet lock.

If tailnet lock is re-enabled, new disablement secrets can be generated.

Once this secret is used, it has been distributed
to all nodes in the tailnet and should be considered public.

`),
	Exec: runNetworkLockDisable,
}

func runNetworkLockDisable(ctx context.Context, args []string) error {
	_, secrets, err := parseNLArgs(args, false, true)
	if err != nil {
		return err
	}
	if len(secrets) != 1 {
		return errors.New("usage: tailscale lock disable <disablement-secret>")
	}
	return localClient.NetworkLockDisable(ctx, secrets[0])
}

var nlLocalDisableCmd = &ffcli.Command{
	Name:       "local-disable",
	ShortUsage: "tailscale lock local-disable",
	ShortHelp:  "Disable tailnet lock for this node only",
	LongHelp: strings.TrimSpace(`

The 'tailscale lock local-disable' command disables tailnet lock for only
the current node.

If the current node is locked out, this does not mean that it can initiate
connections in a tailnet with tailnet lock enabled. Rather, this means
that the current node will accept traffic from other nodes in the tailnet
that are locked out.

`),
	Exec: runNetworkLockLocalDisable,
}

func runNetworkLockLocalDisable(ctx context.Context, args []string) error {
	return localClient.NetworkLockForceLocalDisable(ctx)
}

var nlDisablementKDFCmd = &ffcli.Command{
	Name:       "disablement-kdf",
	ShortUsage: "tailscale lock disablement-kdf <hex-encoded-disablement-secret>",
	ShortHelp:  "Compute a disablement value from a disablement secret (advanced users only)",
	LongHelp:   "Compute a disablement value from a disablement secret (advanced users only)",
	Exec:       runNetworkLockDisablementKDF,
}

func runNetworkLockDisablementKDF(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: tailscale lock disablement-kdf <hex-encoded-disablement-secret>")
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
	json  bool
}

var nlLogCmd = &ffcli.Command{
	Name:       "log",
	ShortUsage: "tailscale lock log [--limit N]",
	ShortHelp:  "List changes applied to tailnet lock",
	LongHelp:   "List changes applied to tailnet lock",
	Exec:       runNetworkLockLog,
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("lock log")
		fs.IntVar(&nlLogArgs.limit, "limit", 50, "max number of updates to list")
		fs.BoolVar(&nlLogArgs.json, "json", false, "output in JSON format (WARNING: format subject to change)")
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
		if keyID, err := key.ID(); err == nil {
			fmt.Fprintf(&stanza, "%sKeyID: tlpub:%x\n", prefix, keyID)
		} else {
			// Older versions of the client shouldn't explode when they encounter an
			// unknown key type.
			fmt.Fprintf(&stanza, "%sKeyID: <Error: %v>\n", prefix, err)
		}
		if key.Meta != nil {
			fmt.Fprintf(&stanza, "%sMetadata: %+v\n", prefix, key.Meta)
		}
	}

	var aum tka.AUM
	if err := aum.Unserialize(update.Raw); err != nil {
		return "", fmt.Errorf("decoding: %w", err)
	}

	tkaHead, err := aum.Hash().MarshalText()
	if err != nil {
		return "", fmt.Errorf("decoding AUM hash: %w", err)
	}
	fmt.Fprintf(&stanza, "%supdate %s (%s)%s\n", terminalYellow, string(tkaHead), update.Change, terminalClear)

	switch update.Change {
	case tka.AUMAddKey.String():
		printKey(aum.Key, "")
	case tka.AUMRemoveKey.String():
		fmt.Fprintf(&stanza, "KeyID: tlpub:%x\n", aum.KeyID)

	case tka.AUMUpdateKey.String():
		fmt.Fprintf(&stanza, "KeyID: tlpub:%x\n", aum.KeyID)
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
	st, err := localClient.NetworkLockStatus(ctx)
	if err != nil {
		return fixTailscaledConnectError(err)
	}
	if !st.Enabled {
		return errors.New("Tailnet Lock is not enabled")
	}

	updates, err := localClient.NetworkLockLog(ctx, nlLogArgs.limit)
	if err != nil {
		return fixTailscaledConnectError(err)
	}
	if nlLogArgs.json {
		enc := json.NewEncoder(Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(updates)
	}

	out, useColor := colorableOutput()

	for _, update := range updates {
		stanza, err := nlDescribeUpdate(update, useColor)
		if err != nil {
			return err
		}
		fmt.Fprintln(out, stanza)
	}
	return nil
}

func runTskeyWrapCmd(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: lock tskey-wrap <tailscale pre-auth key>")
	}
	if strings.Contains(args[0], "--TL") {
		return errors.New("Error: provided key was already wrapped")
	}

	st, err := localClient.StatusWithoutPeers(ctx)
	if err != nil {
		return fixTailscaledConnectError(err)
	}

	return wrapAuthKey(ctx, args[0], st)
}

func wrapAuthKey(ctx context.Context, keyStr string, status *ipnstate.Status) error {
	// Generate a separate tailnet-lock key just for the credential signature.
	// We use the free-form meta strings to mark a little bit of metadata about this
	// key.
	priv := key.NewNLPrivate()
	m := map[string]string{
		"purpose":            "pre-auth key",
		"wrapper_stableid":   string(status.Self.ID),
		"wrapper_createtime": fmt.Sprint(time.Now().Unix()),
	}
	if strings.HasPrefix(keyStr, "tskey-auth-") && strings.Index(keyStr[len("tskey-auth-"):], "-") > 0 {
		// We don't want to accidentally embed the nonce part of the authkey in
		// the event the format changes. As such, we make sure its in the format we
		// expect (tskey-auth-<stableID, inc CNTRL suffix>-nonce) before we parse
		// out and embed the stableID.
		s := strings.TrimPrefix(keyStr, "tskey-auth-")
		m["authkey_stableid"] = s[:strings.Index(s, "-")]
	}
	k := tka.Key{
		Kind:   tka.Key25519,
		Public: priv.Public().Verifier(),
		Votes:  1,
		Meta:   m,
	}

	wrapped, err := localClient.NetworkLockWrapPreauthKey(ctx, keyStr, priv)
	if err != nil {
		return fmt.Errorf("wrapping failed: %w", err)
	}
	if err := localClient.NetworkLockModify(ctx, []tka.Key{k}, nil); err != nil {
		return fmt.Errorf("add key failed: %w", err)
	}

	fmt.Println(wrapped)
	return nil
}

var nlRevokeKeysArgs struct {
	cosign   bool
	finish   bool
	forkFrom string
}

var nlRevokeKeysCmd = &ffcli.Command{
	Name:       "revoke-keys",
	ShortUsage: "tailscale lock revoke-keys <tailnet-lock-key>...\n  revoke-keys [--cosign] [--finish] <recovery-blob>",
	ShortHelp:  "Revoke compromised tailnet-lock keys",
	LongHelp: `Retroactively revoke the specified tailnet lock keys (tlpub:abc).

Revoked keys are prevented from being used in the future. Any nodes previously signed
by revoked keys lose their authorization and must be signed again.

Revocation is a multi-step process that requires several signing nodes to ` + "`--cosign`" + ` the revocation. Use ` + "`tailscale lock remove`" + ` instead if the key has not been compromised.

1. To start, run ` + "`tailscale revoke-keys <tlpub-keys>`" + ` with the tailnet lock keys to revoke.
2. Re-run the ` + "`--cosign`" + ` command output by ` + "`revoke-keys`" + ` on other signing nodes. Use the
   most recent command output on the next signing node in sequence.
3. Once the number of ` + "`--cosign`" + `s is greater than the number of keys being revoked,
   run the command one final time with ` + "`--finish`" + ` instead of ` + "`--cosign`" + `.`,
	Exec: runNetworkLockRevokeKeys,
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("lock revoke-keys")
		fs.BoolVar(&nlRevokeKeysArgs.cosign, "cosign", false, "continue generating the recovery using the tailnet lock key on this device and the provided recovery blob")
		fs.BoolVar(&nlRevokeKeysArgs.finish, "finish", false, "finish the recovery process by transmitting the revocation")
		fs.StringVar(&nlRevokeKeysArgs.forkFrom, "fork-from", "", "parent AUM hash to rewrite from (advanced users only)")
		return fs
	})(),
}

func runNetworkLockRevokeKeys(ctx context.Context, args []string) error {
	// First step in the process
	if !nlRevokeKeysArgs.cosign && !nlRevokeKeysArgs.finish {
		removeKeys, _, err := parseNLArgs(args, true, false)
		if err != nil {
			return err
		}

		keyIDs := make([]tkatype.KeyID, len(removeKeys))
		for i, k := range removeKeys {
			keyIDs[i], err = k.ID()
			if err != nil {
				return fmt.Errorf("generating keyID: %v", err)
			}
		}

		var forkFrom tka.AUMHash
		if nlRevokeKeysArgs.forkFrom != "" {
			if len(nlRevokeKeysArgs.forkFrom) == (len(forkFrom) * 2) {
				// Hex-encoded: like the output of the lock log command.
				b, err := hex.DecodeString(nlRevokeKeysArgs.forkFrom)
				if err != nil {
					return fmt.Errorf("invalid fork-from hash: %v", err)
				}
				copy(forkFrom[:], b)
			} else {
				if err := forkFrom.UnmarshalText([]byte(nlRevokeKeysArgs.forkFrom)); err != nil {
					return fmt.Errorf("invalid fork-from hash: %v", err)
				}
			}
		}

		aumBytes, err := localClient.NetworkLockGenRecoveryAUM(ctx, keyIDs, forkFrom)
		if err != nil {
			return fmt.Errorf("generation of recovery AUM failed: %w", err)
		}

		fmt.Printf(`Run the following command on another machine with a trusted tailnet lock key:
	%s lock revoke-keys --cosign %X
`, os.Args[0], aumBytes)
		return nil
	}

	// If we got this far, we need to co-sign the AUM and/or transmit it for distribution.
	b, err := hex.DecodeString(args[0])
	if err != nil {
		return fmt.Errorf("parsing hex: %v", err)
	}
	var recoveryAUM tka.AUM
	if err := recoveryAUM.Unserialize(b); err != nil {
		return fmt.Errorf("decoding recovery AUM: %v", err)
	}

	if nlRevokeKeysArgs.cosign {
		aumBytes, err := localClient.NetworkLockCosignRecoveryAUM(ctx, recoveryAUM)
		if err != nil {
			return fmt.Errorf("co-signing recovery AUM failed: %w", err)
		}

		fmt.Printf(`Co-signing completed successfully.

To accumulate an additional signature, run the following command on another machine with a trusted tailnet lock key:
	%s lock revoke-keys --cosign %X

Alternatively if you are done with co-signing, complete recovery by running the following command:
	%s lock revoke-keys --finish %X
`, os.Args[0], aumBytes, os.Args[0], aumBytes)
	}

	if nlRevokeKeysArgs.finish {
		if err := localClient.NetworkLockSubmitRecoveryAUM(ctx, recoveryAUM); err != nil {
			return fmt.Errorf("submitting recovery AUM failed: %w", err)
		}
		fmt.Println("Recovery completed.")
	}

	return nil
}
