// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Program tl-longchain prints commands to re-sign Tailscale nodes that have
// long rotation signature chains.
//
// There is an implicit limit on the number of rotation signatures that can
// be chained before the signature becomes too long. This program helps
// tailnet admins to identify nodes that have signatures with long chains and
// prints commands to re-sign those node keys with a fresh direct signature.
// Commands are printed to stdout, while log messages are printed to stderr.
//
// Note that the Tailscale client this command is executed on must have
// ACL visibility to all other nodes to be able to see their signatures.
// https://tailscale.com/kb/1087/device-visibility
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"tailscale.com/client/tailscale"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tka"
	"tailscale.com/types/key"
)

var (
	flagSocket   = flag.String("socket", "", "custom path to tailscaled socket")
	maxRotations = flag.Int("rotations", 10, "number of rotation signatures before re-signing (max 16)")
	showFiltered = flag.Bool("show-filtered", false, "include nodes with invalid signatures")
)

func main() {
	flag.Parse()

	lc := tailscale.LocalClient{Socket: *flagSocket}
	if lc.Socket != "" {
		lc.UseSocketOnly = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	st, err := lc.NetworkLockStatus(ctx)
	if err != nil {
		log.Fatalf("could not get Tailnet Lock status: %v", err)
	}
	if !st.Enabled {
		log.Print("Tailnet Lock is not enabled")
		return
	}
	print("Self", *st.NodeKey, *st.NodeKeySignature)
	if len(st.VisiblePeers) > 0 {
		log.Print("Visible peers with valid signatures:")
		for _, peer := range st.VisiblePeers {
			print(peerInfo(peer), peer.NodeKey, peer.NodeKeySignature)
		}
	}
	if *showFiltered && len(st.FilteredPeers) > 0 {
		log.Print("Visible peers with invalid signatures:")
		for _, peer := range st.FilteredPeers {
			print(peerInfo(peer), peer.NodeKey, peer.NodeKeySignature)
		}
	}
}

// peerInfo returns a string with information about a peer.
func peerInfo(peer *ipnstate.TKAPeer) string {
	return fmt.Sprintf("Peer %s (%s) nodeid=%s, current signature kind=%v", peer.Name, peer.TailscaleIPs[0], peer.StableID, peer.NodeKeySignature.SigKind)
}

// print prints a message about a node key signature and a re-signing command if needed.
func print(info string, nodeKey key.NodePublic, sig tka.NodeKeySignature) {
	if l := chainLength(sig); l > *maxRotations {
		log.Printf("%s: chain length %d, printing command to re-sign", info, l)
		wrapping, _ := sig.UnverifiedWrappingPublic()
		fmt.Printf("tailscale lock sign %s %s\n", nodeKey, key.NLPublicFromEd25519Unsafe(wrapping).CLIString())
	} else {
		log.Printf("%s: does not need re-signing", info)
	}
}

// chainLength returns the length of the rotation signature chain.
func chainLength(sig tka.NodeKeySignature) int {
	if sig.SigKind != tka.SigRotation {
		return 1
	}
	return 1 + chainLength(*sig.Nested)
}
