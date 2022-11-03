// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"bytes"
	"context"
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

	// Parse the set of initially-trusted keys.
	keys, err := parseNLKeyArgs(args)
	if err != nil {
		return err
	}

	// TODO(tom): Implement specification of disablement values from the command line.
	disablementValues := [][]byte{bytes.Repeat([]byte{0xa5}, 32)}

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

	p, err := st.PublicKey.MarshalText()
	if err != nil {
		return err
	}
	fmt.Printf("This node's public-key: %s\n", p)
	fmt.Println()

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

// parseNLKeyArgs converts a slice of strings into a slice of tka.Key. The keys
// should be specified using their key.NLPublic.MarshalText representation with
// an optional '?<votes>' suffix. If any of the keys encounters an error, a nil
// slice is returned along with an appropriate error.
func parseNLKeyArgs(args []string) ([]tka.Key, error) {
	var keys []tka.Key
	for i, a := range args {
		var nlpk key.NLPublic
		spl := strings.SplitN(a, "?", 2)
		if err := nlpk.UnmarshalText([]byte(spl[0])); err != nil {
			return nil, fmt.Errorf("parsing key %d: %v", i+1, err)
		}

		k := tka.Key{
			Kind:   tka.Key25519,
			Public: nlpk.Verifier(),
			Votes:  1,
		}
		if len(spl) > 1 {
			votes, err := strconv.Atoi(spl[1])
			if err != nil {
				return nil, fmt.Errorf("parsing key %d votes: %v", i+1, err)
			}
			k.Votes = uint(votes)
		}
		keys = append(keys, k)
	}
	return keys, nil
}

func runNetworkLockModify(ctx context.Context, addArgs, removeArgs []string) error {
	st, err := localClient.NetworkLockStatus(ctx)
	if err != nil {
		return fixTailscaledConnectError(err)
	}
	if !st.Enabled {
		return errors.New("network-lock is not enabled")
	}

	addKeys, err := parseNLKeyArgs(addArgs)
	if err != nil {
		return err
	}
	removeKeys, err := parseNLKeyArgs(removeArgs)
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
	ShortUsage: "sign <node-key>",
	ShortHelp:  "Signs a node-key and transmits that signature to the control plane",
	Exec:       runNetworkLockSign,
}

// TODO(tom): Implement specifying the rotation key for the signature.
func runNetworkLockSign(ctx context.Context, args []string) error {
	switch len(args) {
	case 0:
		return errors.New("expected node-key as second argument")
	case 1:
		var nodeKey key.NodePublic
		if err := nodeKey.UnmarshalText([]byte(args[0])); err != nil {
			return fmt.Errorf("decoding node-key: %w", err)
		}

		return localClient.NetworkLockSign(ctx, nodeKey, nil)
	default:
		return errors.New("expected a single node-key as only argument")
	}
}
