// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_wakeonelan

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/atomicfile"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

func init() {
	maybeWakeOnLANCmd = func() *ffcli.Command { return wakeOnLANCmd }
}

// Cache file top-level structure
type wolTopology struct {
	Timestamp time.Time              `json:"timestamp"`
	Probers   map[string]*proberInfo `json:"probers"` // key is string(nodeID)
}

// Information about a node that was probed
type proberInfo struct {
	NodeID       tailcfg.StableNodeID `json:"nodeID"`
	NodeName     string               `json:"nodeName"`
	TailscaleIP  string               `json:"tailscaleIP"`
	MacAddresses []string             `json:"macAddresses"`
	CanSee       []peerInfo           `json:"canSee"`
}

// Information about a peer visible on local network
type peerInfo struct {
	NodeID         tailcfg.StableNodeID `json:"nodeID"`
	NodeName       string               `json:"nodeName"`
	TailscaleIP    string               `json:"tailscaleIP"`
	Endpoint       string               `json:"endpoint"`
	LatencySeconds float64              `json:"latencySeconds"`
}

// Response from /v0/check-direct endpoint
type checkDirectResponse struct {
	Nodes            []directNodeInfo `json:"nodes"`
	SelfMacAddresses []string         `json:"self_mac_addresses"`
}

type directNodeInfo struct {
	NodeID         tailcfg.StableNodeID `json:"nodeID"`
	NodeName       string               `json:"nodeName,omitempty"`
	Endpoint       string               `json:"endpoint"`
	OnSameSubnet   bool                 `json:"onSameSubnet"`
	LatencySeconds float64              `json:"latencySeconds"`
}

// Response from /v0/wol endpoint
type wolResponse struct {
	SentTo []string `json:"SentTo"`
	Errors []string `json:"Errors"`
}

// Get cache file path (default or from args)
func getWoLCacheFile(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	return getDefaultCacheFile()
}

func getDefaultCacheFile() string {
	configDir, err := os.UserConfigDir()
	if err != nil {
		configDir = os.Getenv("HOME")
	}
	return filepath.Join(configDir, "tailscale", "wol-topology.json")
}

// Call /v0/check-direct on a peer
func callCheckDirect(ctx context.Context, peerAPIURL string) (*checkDirectResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", peerAPIURL+"/v0/check-direct", nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
	}

	var result checkDirectResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("unable to decode result: %w", err)
	}

	return &result, nil
}

// Send WoL packet via /v0/wol
func sendWoL(ctx context.Context, peerAPIURL, mac string) (*wolResponse, error) {
	data := url.Values{"mac": {mac}}
	req, err := http.NewRequestWithContext(ctx, "POST", peerAPIURL+"/v0/wol",
		strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
	}

	var result wolResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// Save topology to file
func saveTopology(path string, topology *wolTopology) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	// Encode to JSON
	data, err := json.MarshalIndent(topology, "", "  ")
	if err != nil {
		return err
	}

	// Use atomic file write
	return atomicfile.WriteFile(path, data, 0o644)
}

// Load topology from file
func loadTopology(path string) (*wolTopology, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var topology wolTopology
	if err := json.Unmarshal(data, &topology); err != nil {
		return nil, err
	}

	return &topology, nil
}

// Find node in topology by name or IP
func findNodeInTopology(topology *wolTopology, search string) *proberInfo {
	for _, prober := range topology.Probers {
		if strings.Contains(prober.NodeName, search) ||
			prober.TailscaleIP == search ||
			fmt.Sprint(prober.NodeID) == search {
			return prober
		}
	}
	return nil
}

// Enrich topology with Tailscale IPs from status
func enrichTopologyWithIPs(topology *wolTopology, st *ipnstate.Status) {
	// Build a map from StableNodeID to PeerStatus for quick lookup
	idToPeer := make(map[tailcfg.StableNodeID]*ipnstate.PeerStatus)
	for _, peer := range st.Peer {
		idToPeer[peer.ID] = peer
	}

	for _, prober := range topology.Probers {
		for i := range prober.CanSee {
			peer := &prober.CanSee[i]
			if statusPeer, ok := idToPeer[peer.NodeID]; ok && len(statusPeer.TailscaleIPs) > 0 {
				peer.TailscaleIP = statusPeer.TailscaleIPs[0].String()
			}
		}
	}
}

var wolProbeCmd = &ffcli.Command{
	Name:       "probe",
	ShortUsage: "tailscale wakeonlan probe [cache-file]",
	ShortHelp:  "Probe network topology for Wake-on-LAN",
	LongHelp:   "Discovers which nodes can wake which other nodes by probing all peers on the network.",
	Exec:       runWakeOnLANProbe,
}

func runWakeOnLANProbe(ctx context.Context, args []string) error {
	cacheFile := getWoLCacheFile(args)

	st, err := localClient.Status(ctx)
	if err != nil {
		return fmt.Errorf("failed to get status: %w", err)
	}

	printf("Probing network topology...\n")
	topology := &wolTopology{
		Timestamp: time.Now(),
		Probers:   make(map[string]*proberInfo),
	}

	for _, peer := range st.Peer {
		// Skip nodes not online and mullvad nodes.
		if !peer.Online || strings.Contains(peer.DNSName, "mullvad.ts.net") {
			continue
		}

		// Skip peers without PeerAPI
		if peer.PeerAPIURL == nil || len(peer.PeerAPIURL) == 0 {
			printf("⊘ %s: no PeerAPI available\n", peer.DNSName)
			continue
		}

		// Call /v0/check-direct on this peer
		resp, err := callCheckDirect(ctx, peer.PeerAPIURL[0])
		if err != nil {
			printf("✗ %s: %v\n", peer.DNSName, err)
			continue
		}

		info := &proberInfo{
			NodeID:       peer.ID,
			NodeName:     peer.DNSName,
			TailscaleIP:  peer.TailscaleIPs[0].String(),
			MacAddresses: resp.SelfMacAddresses,
			CanSee:       make([]peerInfo, 0, len(resp.Nodes)),
		}

		for _, node := range resp.Nodes {
			info.CanSee = append(info.CanSee, peerInfo{
				NodeID:         node.NodeID,
				NodeName:       node.NodeName,
				TailscaleIP:    "", // Need to look up from status
				Endpoint:       node.Endpoint,
				LatencySeconds: node.LatencySeconds,
			})
		}

		topology.Probers[fmt.Sprint(peer.ID)] = info
		printf("✓ %s: found %d local peers\n", peer.DNSName, len(info.CanSee))
	}

	enrichTopologyWithIPs(topology, st)

	if err := saveTopology(cacheFile, topology); err != nil {
		return err
	}

	printf("\nTopology saved to %s\n", cacheFile)
	return nil
}

var wolListCmd = &ffcli.Command{
	Name:       "list",
	ShortUsage: "tailscale wakeonlan list [cache-file]",
	ShortHelp:  "List nodes that can be woken via Wake-on-LAN",
	LongHelp:   "Displays cached topology showing which nodes can wake which other nodes.",
	Exec:       runWakeOnLANList,
}

func runWakeOnLANList(ctx context.Context, args []string) error {
	cacheFile := getWoLCacheFile(args)
	topology, err := loadTopology(cacheFile)
	if err != nil {
		return fmt.Errorf("failed to load topology: %w (try running 'tailscale wakeonlan probe' first)", err)
	}

	// 2. Build reverse map: target -> list of probers that can wake it
	wakeMap := make(map[tailcfg.StableNodeID][]*proberInfo)
	for _, prober := range topology.Probers {
		for _, peer := range prober.CanSee {
			wakeMap[peer.NodeID] = append(wakeMap[peer.NodeID], prober)
		}
	}

	// 3. Display formatted output
	printf("Wake-on-LAN Topology (cached from %s)\n\n",
		topology.Timestamp.Format("2006-01-02 15:04:05"))

	if len(wakeMap) == 0 {
		printf("No nodes found that can be woken.\n")
		printf("Run 'tailscale wakeonlan probe' to discover topology.\n")
		return nil
	}

	printf("Nodes that can be woken:\n")

	for nodeID, wakers := range wakeMap {
		// Find node info (need MAC addresses)
		var nodeInfo *proberInfo
		for _, p := range topology.Probers {
			if p.NodeID == nodeID {
				nodeInfo = p
				break
			}
		}

		if nodeInfo == nil || len(nodeInfo.MacAddresses) == 0 {
			continue // Can't wake nodes without MAC addresses
		}

		printf("  %s (%s)\n", nodeInfo.NodeName, nodeInfo.TailscaleIP)
		printf("    MAC: %s\n", strings.Join(nodeInfo.MacAddresses, ", "))

		wakeNames := make([]string, 0, len(wakers))
		for _, w := range wakers {
			wakeNames = append(wakeNames, strings.TrimSuffix(w.NodeName, "."))
		}
		printf("    Can be woken by: %s\n\n", strings.Join(wakeNames, ", "))
	}

	printf("Run 'tailscale wakeonlan probe' to refresh topology.\n")
	return nil
}

var wolWakeupCmd = &ffcli.Command{
	Name:       "wakeup",
	ShortUsage: "tailscale wakeonlan wakeup [cache-file] <target-node>",
	ShortHelp:  "Wake up a node using Wake-on-LAN",
	LongHelp:   "Sends Wake-on-LAN packets to wake up a specific node on the network.",
	Exec:       runWakeOnLANWakeup,
}

func runWakeOnLANWakeup(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return errors.New("missing target node")
	}

	var cacheFile string
	var targetNode string
	if len(args) == 1 {
		cacheFile = getDefaultCacheFile()
		targetNode = args[0]
	} else {
		cacheFile = args[0]
		targetNode = args[1]
	}

	topology, err := loadTopology(cacheFile)
	if err != nil {
		return fmt.Errorf("failed to load topology: %w (try running 'tailscale wakeonlan probe' first)", err)
	}

	target := findNodeInTopology(topology, targetNode)
	if target == nil {
		return fmt.Errorf("target node %q not found in topology", targetNode)
	}

	if len(target.MacAddresses) == 0 {
		return fmt.Errorf("no MAC addresses found for %s", target.NodeName)
	}

	var wakers []*proberInfo
	for _, prober := range topology.Probers {
		for _, peer := range prober.CanSee {
			if peer.NodeID == target.NodeID {
				wakers = append(wakers, prober)
				break
			}
		}
	}

	if len(wakers) == 0 {
		return fmt.Errorf("no nodes found that can wake %s", target.NodeName)
	}

	printf("Waking up %s...\n\n", target.NodeName)

	// Get current status to find PeerAPI URL
	st, err := localClient.Status(ctx)
	if err != nil {
		return fmt.Errorf("Failed to get localClient status: %v", err)
	}

	successCount := 0
	for _, waker := range wakers {
		// Find peer by StableNodeID
		var peer *ipnstate.PeerStatus
		for _, p := range st.Peer {
			if p.ID == waker.NodeID {
				peer = p
				break
			}
		}

		if peer == nil || !peer.Online || len(peer.PeerAPIURL) == 0 {
			continue
		}

		printf("Sending WoL from %s...\n", waker.NodeName)

		// Call /v0/wol for each MAC address
		for _, mac := range target.MacAddresses {
			resp, err := sendWoL(ctx, peer.PeerAPIURL[0], mac)
			if err != nil {
				printf("  ✗ Failed: %v\n", err)
				continue
			}

			if len(resp.Errors) > 0 {
				for _, e := range resp.Errors {
					printf("  ✗ Error: %s\n", e)
				}
			}

			if len(resp.SentTo) > 0 {
				for _, iface := range resp.SentTo {
					printf("  ✓ Sent on interface %s\n", iface)
				}
				successCount++
			}
		}
	}

	if successCount > 0 {
		printf("\nWake-on-LAN packets sent successfully from %d peers.\n", successCount)
		return nil
	}

	return errors.New("failed to send any WoL packets")
}

var wakeOnLANCmd = &ffcli.Command{
	Name:       "wakeonlan",
	ShortUsage: "tailscale wakeonlan <probe|list|wakeup> [flags]",
	ShortHelp:  "Wake-on-LAN network discovery and control",
	LongHelp:   "Discover network topology and wake up nodes on the same LAN.",
	Subcommands: []*ffcli.Command{
		wolProbeCmd,
		wolListCmd,
		wolWakeupCmd,
	},
	Exec: runWakeOnLANNoSubcommand,
}

func runWakeOnLANNoSubcommand(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("unknown subcommand: %s", args[0])
	}
	return errors.New("wakeonlan requires a subcommand: probe, list, or wakeup")
}
