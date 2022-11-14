// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
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
	},
	Exec: runNetworkLockStatus,
}

var nlInitCmd = &ffcli.Command{
	Name:       "init",
	ShortUsage: "init <public-key>...",
	ShortHelp:  "Initialize the tailnet key authority",
	Exec:       runNetworkLockInit,
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

	status, err := localClient.NetworkLockInit(ctx, keys, disablementValues)
	if err != nil {
		return err
	}

	fmt.Printf("Status: %+v\n\n", status)
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
		fmt.Println("Network-lock is ENABLED.")
	} else {
		fmt.Println("Network-lock is NOT enabled.")
	}
	fmt.Println()

	if st.Enabled && st.NodeKey != nil {
		if st.NodeKeySigned {
			fmt.Println("This node is trusted by network-lock.")
		} else {
			fmt.Println("This node IS NOT trusted by network-lock, and action is required to establish connectivity.")
			fmt.Printf("Run the following command on a node with a network-lock key:\n\ttailscale lock sign %v\n", st.NodeKey)
		}
		fmt.Println()
	}

	if !st.PublicKey.IsZero() {
		p, err := st.PublicKey.MarshalText()
		if err != nil {
			return err
		}
		fmt.Printf("This node's public-key: %s\n", p)
		fmt.Println()
	}

	if st.Enabled && len(st.TrustedKeys) > 0 {
		fmt.Println("Keys trusted to make changes to network-lock:")
		for _, k := range st.TrustedKeys {
			key, err := k.Key.MarshalText()
			if err != nil {
				return err
			}

			var line strings.Builder
			line.WriteString("\t")
			line.WriteString(string(key))
			line.WriteString("\t")
			line.WriteString(fmt.Sprint(k.Votes))
			line.WriteString("\t")
			if k.Key == st.PublicKey {
				line.WriteString("(us)")
			}
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
		return errors.New("network-lock is not enabled")
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
	ShortHelp:  "Consumes a disablement secret to shut down network-lock across the tailnet",
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

var nlDisablementKDFCmd = &ffcli.Command{
	Name:       "disablement-kdf",
	ShortUsage: "disablement-kdf <hex-encoded-disablement-secret>",
	ShortHelp:  "Computes a disablement value from a disablement secret",
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
