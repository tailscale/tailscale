// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/client/local"
	"tailscale.com/cmd/tailscale/cli/ffcomplete"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tailperf"
)

var perfCmd = &ffcli.Command{
	Name:       "perf",
	ShortUsage: "tailscale perf -s [--port=<port>] | tailscale perf -c <hostname-or-IP> [flags]",
	ShortHelp:  "Run a Tailperf node-to-node performance test",
	LongHelp: strings.TrimSpace(`
Tailperf runs a Tailscale-integrated performance test between this node and
another node in the tailnet.

Manual server mode:

  tailscale perf -s

Client mode:

  tailscale perf -c node-a --duration=10s --cap=100mbit

By default client mode attempts grant-authorized remote setup when the peer
supports it, then runs the test against the configured or default port.
`),
	Exec: runPerf,
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("perf")
		fs.BoolVar(&perfArgs.server, "s", false, "run in server mode")
		fs.StringVar(&perfArgs.client, "c", "", "run in client mode against hostname, MagicDNS name, or Tailscale IP")
		fs.UintVar(&perfArgs.port, "port", uint(tailperf.DefaultPort), "tailperf listen/connect port")
		fs.StringVar(&perfArgs.proto, "proto", string(tailperf.ProtoTCP), "protocol: tcp or udp")
		fs.DurationVar(&perfArgs.duration, "duration", tailperf.DefaultDuration, "test duration")
		fs.StringVar(&perfArgs.cap, "cap", "", "bandwidth cap, such as 100mbit; empty or 0 means unlimited")
		fs.BoolVar(&perfArgs.reverse, "reverse", false, "run traffic from server to client")
		fs.BoolVar(&perfArgs.bothDirections, "both-directions", false, "run forward and reverse tests")
		fs.BoolVar(&perfArgs.noTUN, "no-tun", false, "use tailscaled userspace dialing instead of the OS TUN path for TCP client tests")
		fs.BoolVar(&perfArgs.noLog, "no-log", false, "do not emit Tailperf result records to internal Tailperf result logging")
		fs.BoolVar(&perfArgs.noMagic, "no-magic", false, hidden+"skip grant-authorized remote server setup")
		return fs
	})(),
}

func init() {
	ffcomplete.Args(perfCmd, func(args []string) ([]string, ffcomplete.ShellCompDirective, error) {
		if len(args) > 0 {
			return nil, ffcomplete.ShellCompDirectiveNoFileComp, nil
		}
		return completeHostOrIP(ffcomplete.LastArg(args))
	})
}

var perfArgs struct {
	server         bool
	client         string
	port           uint
	proto          string
	duration       time.Duration
	cap            string
	reverse        bool
	bothDirections bool
	noTUN          bool
	noLog          bool
	noMagic        bool
}

func runPerf(ctx context.Context, args []string) error {
	if len(args) == 1 && perfArgs.client == "" && !perfArgs.server {
		perfArgs.client = args[0]
		args = nil
	}
	if len(args) != 0 {
		return errors.New("usage: tailscale perf -s | tailscale perf -c <hostname-or-IP>")
	}
	if perfArgs.server == (perfArgs.client != "") {
		return errors.New("specify exactly one of -s or -c")
	}
	if perfArgs.port == 0 || perfArgs.port > 65535 {
		return fmt.Errorf("invalid tailperf port %d", perfArgs.port)
	}
	proto := tailperf.Protocol(strings.ToLower(perfArgs.proto))
	if !proto.Valid() {
		return fmt.Errorf("unsupported tailperf protocol %q", perfArgs.proto)
	}
	if perfArgs.server {
		fmt.Fprintf(Stderr, "Tailperf listening on %s port %d\n", proto, perfArgs.port)
		return tailperf.RunServer(ctx, tailperf.ServerConfig{
			Port:     uint16(perfArgs.port),
			Protocol: proto,
		})
	}

	st, err := localClient.Status(ctx)
	if err != nil {
		return fixTailscaledConnectError(err)
	}
	description, ok := isRunningOrStarting(st)
	if !ok {
		printf("%s\n", description)
		os.Exit(1)
	}

	capBits, err := tailperf.ParseBandwidth(perfArgs.cap)
	if err != nil {
		return err
	}
	dir := tailperf.DirectionForward
	if perfArgs.reverse {
		dir = tailperf.DirectionReverse
	}
	if perfArgs.bothDirections {
		dir = tailperf.DirectionBoth
	}
	cfg := tailperf.ClientConfig{
		Host:             perfArgs.client,
		Port:             uint16(perfArgs.port),
		Protocol:         proto,
		Duration:         perfArgs.duration,
		CapBitsPerSecond: capBits,
		Direction:        dir,
		TUNMode:          tailperf.TUNModeDefault,
		NoLog:            perfArgs.noLog,
		SourceNode:       localNodeName(st),
		DestinationNode:  strings.TrimSuffix(perfArgs.client, "."),
		PathProvider:     pathProvider(ctx, perfArgs.client),
	}
	if perfArgs.noTUN {
		cfg.TUNMode = tailperf.TUNModeUserspace
		if proto == tailperf.ProtoTCP {
			cfg.DialTCP = localClient.DialTCP
		}
	}
	if !perfArgs.noMagic {
		if startedPort, err := maybeStartRemoteTailperf(ctx, perfArgs.client, cfg); err != nil {
			return err
		} else if startedPort != 0 {
			cfg.Port = startedPort
		}
	}
	r, err := tailperf.RunClient(ctx, cfg)
	if err != nil {
		return err
	}
	return tailperf.WriteTextReport(Stdout, perfArgs.client, r)
}

func localNodeName(st *ipnstate.Status) string {
	if st == nil || st.Self == nil {
		return ""
	}
	if st.Self.DNSName != "" {
		return strings.TrimSuffix(st.Self.DNSName, ".")
	}
	return st.Self.HostName
}

func pathProvider(ctx context.Context, target string) tailperf.PathProvider {
	ip, self, err := tailscaleIPFromArg(ctx, target)
	if err != nil || self {
		return func(context.Context) tailperf.PathMetadata { return tailperf.PathMetadata{Type: tailperf.PathUnknown} }
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return func(context.Context) tailperf.PathMetadata { return tailperf.PathMetadata{Type: tailperf.PathUnknown} }
	}
	return func(context.Context) tailperf.PathMetadata {
		pctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		pr, err := localClient.PingWithOpts(pctx, addr, tailcfg.PingDisco, local.PingOpts{})
		if err != nil || pr == nil || pr.Err != "" {
			return tailperf.PathMetadata{Type: tailperf.PathUnknown}
		}
		return pathFromPing(pr)
	}
}

func pathFromPing(pr *ipnstate.PingResult) tailperf.PathMetadata {
	switch {
	case pr.PeerRelay != "":
		return tailperf.PathMetadata{Type: tailperf.PathPeerRelay, PeerRelay: pr.PeerRelay}.Normalized()
	case pr.DERPRegionID != 0 || pr.DERPRegionCode != "":
		return tailperf.PathMetadata{Type: tailperf.PathDERP, DERPRegionID: pr.DERPRegionID, DERPRegionCode: pr.DERPRegionCode}
	case pr.Endpoint != "":
		return tailperf.PathMetadata{Type: tailperf.PathDirect, Endpoint: pr.Endpoint}
	default:
		return tailperf.PathMetadata{Type: tailperf.PathUnknown}
	}
}

type tailperfStartResponse struct {
	Port uint16 `json:"port"`
}

func maybeStartRemoteTailperf(ctx context.Context, target string, cfg tailperf.ClientConfig) (uint16, error) {
	if cfg.Protocol != tailperf.ProtoTCP {
		return 0, nil
	}
	ip, self, err := tailscaleIPFromArg(ctx, target)
	if err != nil || self {
		return 0, nil
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return 0, nil
	}
	pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	pr, err := localClient.PingWithOpts(pctx, addr, tailcfg.PingPeerAPI, local.PingOpts{})
	if err != nil || pr == nil || pr.PeerAPIURL == "" {
		return 0, nil
	}
	body, _ := json.Marshal(map[string]any{
		"protocol":       cfg.Protocol,
		"durationMillis": cfg.Duration.Milliseconds(),
		"port":           cfg.Port,
		"noTun":          cfg.TUNMode == tailperf.TUNModeUserspace,
		"noLog":          cfg.NoLog,
	})
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(pr.PeerAPIURL, "/")+"/v0/tailperf/start", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound || res.StatusCode == http.StatusNotImplemented || res.StatusCode == http.StatusMethodNotAllowed {
		return 0, nil
	}
	if res.StatusCode != http.StatusOK {
		var b bytes.Buffer
		_, _ = b.ReadFrom(res.Body)
		return 0, fmt.Errorf("%s", strings.TrimSpace(b.String()))
	}
	var sr tailperfStartResponse
	if err := json.NewDecoder(res.Body).Decode(&sr); err != nil {
		return 0, err
	}
	return sr.Port, nil
}
