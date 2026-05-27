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
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/client/local"
	"tailscale.com/cmd/tailscale/cli/ffcomplete"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/paths"
	"tailscale.com/tailcfg"
	"tailscale.com/tailperf"
)

var perfCmd = &ffcli.Command{
	Name:       "perf",
	ShortUsage: "tailscale perf list [--all] | tailscale perf -s [--port=<port>] | tailscale perf -c <hostname-or-IP> [flags] | tailscale perf --history",
	ShortHelp:  "Run a Tailperf node-to-node performance test",
	LongHelp: strings.TrimSpace(`
Tailperf runs a Tailscale-integrated performance test between this node and
another node in the tailnet.

List usable targets:

  tailscale perf list
  tailscale perf list --all

Manual server mode:

  tailscale perf -s

Client mode:

  tailscale perf -c node-a --duration=10s --cap=100mbit

By default client mode attempts grant-authorized remote setup and uses the
target's Tailperf grant-configured port unless --port is set.

Local history:

  tailscale perf --history
  tailscale perf --export-support=tailperf-support.json
`),
	Exec: runPerf,
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("perf")
		fs.BoolVar(&perfArgs.server, "s", false, "run in server mode")
		fs.StringVar(&perfArgs.client, "c", "", "run in client mode against hostname, MagicDNS name, or Tailscale IP")
		perfArgs.port = uint(tailperf.DefaultPort)
		fs.Var(tailperfPortFlag{dst: &perfArgs.port, explicit: &perfArgs.portSet}, "port", "tailperf listen/connect port")
		fs.StringVar(&perfArgs.proto, "proto", string(tailperf.ProtoTCP), "protocol: tcp or udp")
		fs.DurationVar(&perfArgs.duration, "duration", tailperf.DefaultDuration, "test duration")
		fs.StringVar(&perfArgs.cap, "cap", "", "bandwidth cap, such as 100mbit; empty or 0 means unlimited")
		fs.BoolVar(&perfArgs.reverse, "reverse", false, "run traffic from server to client")
		fs.BoolVar(&perfArgs.bothDirections, "both-directions", false, "run forward and reverse tests")
		fs.BoolVar(&perfArgs.noTUN, "no-tun", false, "use tailscaled userspace dialing instead of the OS TUN path for TCP client tests")
		fs.BoolVar(&perfArgs.noLog, "no-log", false, "do not emit Tailperf result records to internal Tailperf result logging")
		fs.StringVar(&perfArgs.logFile, "log-file", "", "write Tailperf result records to this JSONL file")
		fs.BoolVar(&perfArgs.history, "history", false, "show local Tailperf result history")
		fs.IntVar(&perfArgs.historyLimit, "history-limit", 10, "maximum Tailperf history records to show; zero shows all")
		fs.BoolVar(&perfArgs.baseline, "baseline", false, "compare the result with matching local Tailperf history")
		fs.StringVar(&perfArgs.exportSupport, "export-support", "", "write redacted Tailperf history support data to this path; use - for stdout")
		fs.BoolVar(&perfArgs.noMagic, "no-magic", false, "skip grant-authorized remote server setup and use a manually started server")
		fs.BoolVar(&perfArgs.listAll, "all", false, "with 'perf list', show all peers instead of truncating")
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
	portSet        bool
	proto          string
	duration       time.Duration
	cap            string
	reverse        bool
	bothDirections bool
	noTUN          bool
	noLog          bool
	logFile        string
	history        bool
	historyLimit   int
	baseline       bool
	exportSupport  string
	noMagic        bool
	listAll        bool
}

const (
	tailperfListDefaultLimit     = 20
	tailperfListProbeTimeout     = 1500 * time.Millisecond
	tailperfListProbeConcurrency = 8
)

type tailperfPortFlag struct {
	dst      *uint
	explicit *bool
}

func (f tailperfPortFlag) String() string {
	if f.dst == nil {
		return ""
	}
	return strconv.FormatUint(uint64(*f.dst), 10)
}

func (f tailperfPortFlag) Set(s string) error {
	if f.dst == nil || f.explicit == nil {
		return errors.New("missing tailperf port flag storage")
	}
	v, err := strconv.ParseUint(s, 10, 0)
	if err != nil {
		return err
	}
	*f.dst = uint(v)
	*f.explicit = true
	return nil
}

func parseTailperfListArgs(args []string, flagAll bool) (list bool, all bool, rest []string, err error) {
	if len(args) == 0 || args[0] != "list" {
		return false, flagAll, args, nil
	}
	all = flagAll
	for _, arg := range args[1:] {
		switch arg {
		case "--all":
			all = true
		default:
			return true, all, nil, errors.New("usage: tailscale perf list [--all]")
		}
	}
	return true, all, nil, nil
}

type tailperfRemoteStatus struct {
	Busy  bool                      `json:"busy"`
	Rules []tailcfg.TailperfCapRule `json:"rules,omitempty"`
}

type tailperfListPeer struct {
	Name       string
	IP         string
	OS         string
	State      string
	Path       string
	Reachable  bool
	PeerAPIURL string
	Status     *tailperfRemoteStatus
	StatusErr  string
}

type tailperfListOptions struct {
	All           bool
	Limit         int
	CommandPrefix []string
}

func runPerf(ctx context.Context, args []string) error {
	list, listAll, _, err := parseTailperfListArgs(args, perfArgs.listAll)
	if err != nil {
		return err
	}
	if list {
		if perfArgs.server || perfArgs.client != "" || perfArgs.history || perfArgs.exportSupport != "" {
			return errors.New("specify 'tailscale perf list' without -s, -c, --history, or --export-support")
		}
		return runPerfList(ctx, listAll)
	}
	if perfArgs.listAll {
		return errors.New("--all is only valid with 'tailscale perf list'")
	}
	if len(args) == 1 && perfArgs.client == "" && !perfArgs.server {
		perfArgs.client = args[0]
		args = nil
	}
	if len(args) != 0 {
		return errors.New("usage: tailscale perf -s | tailscale perf -c <hostname-or-IP>")
	}
	if perfArgs.history || perfArgs.exportSupport != "" {
		if perfArgs.server || perfArgs.client != "" {
			return errors.New("specify --history or --export-support without -s or -c")
		}
		if perfArgs.history && perfArgs.exportSupport != "" {
			return errors.New("specify at most one of --history or --export-support")
		}
		logPath, err := tailperfLogPathForConfig(perfArgs.logFile)
		if err != nil {
			return err
		}
		if perfArgs.history {
			rs, err := (tailperf.HistoryStore{Path: logPath}).Load(ctx)
			if err != nil {
				return err
			}
			return writeTailperfHistoryReport(Stdout, rs, perfArgs.historyLimit)
		}
		return exportTailperfSupportHistory(ctx, logPath, perfArgs.exportSupport, Stdout)
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
	logPath, logSink, err := tailperfLogSinkForConfig(perfArgs.logFile, perfArgs.noLog)
	if err != nil {
		return err
	}
	cfg.LogSink = logSink
	var prior []tailperf.Result
	if perfArgs.baseline {
		historyPath := logPath
		if historyPath == "" {
			historyPath, err = tailperfLogPathForConfig(perfArgs.logFile)
			if err != nil {
				return err
			}
		}
		prior, err = (tailperf.HistoryStore{Path: historyPath}).Load(ctx)
		if err != nil {
			return err
		}
	}
	if perfArgs.noTUN {
		cfg.TUNMode = tailperf.TUNModeUserspace
		if proto == tailperf.ProtoTCP {
			cfg.DialTCP = localClient.DialTCP
		}
	}
	if !perfArgs.noMagic {
		if startedPort, err := maybeStartRemoteTailperf(ctx, perfArgs.client, cfg, perfArgs.portSet); err != nil {
			return err
		} else if startedPort != 0 {
			cfg.Port = startedPort
		}
	}
	r, err := tailperf.RunClient(ctx, cfg)
	if err != nil {
		return err
	}
	if err := tailperf.WriteTextReport(Stdout, perfArgs.client, r); err != nil {
		return err
	}
	if logPath != "" {
		fmt.Fprintf(Stdout, "Tailperf result logged to %s\n", logPath)
	}
	if perfArgs.baseline {
		if err := writeTailperfBaselineReport(Stdout, tailperf.BuildNodePairInsight(r, prior)); err != nil {
			return err
		}
	}
	return nil
}

func runPerfList(ctx context.Context, all bool) error {
	st, err := localClient.Status(ctx)
	if err != nil {
		return fixTailscaledConnectError(err)
	}
	description, ok := isRunningOrStarting(st)
	if !ok {
		printf("%s\n", description)
		os.Exit(1)
	}
	peers := tailperfListPeersFromStatus(st, all)
	toProbe := peers
	if !all && len(toProbe) > tailperfListDefaultLimit {
		toProbe = toProbe[:tailperfListDefaultLimit]
	}
	probeTailperfListPeers(ctx, toProbe)
	return writeTailperfListReport(Stdout, peers, tailperfListOptions{
		All:           all,
		Limit:         tailperfListDefaultLimit,
		CommandPrefix: tailperfListCommandPrefix(),
	})
}

func tailperfListPeersFromStatus(st *ipnstate.Status, all bool) []tailperfListPeer {
	if st == nil {
		return nil
	}
	peers := make([]tailperfListPeer, 0, len(st.Peer))
	for _, ps := range st.Peer {
		if ps == nil {
			continue
		}
		reachable := ps.Active || ps.Online
		if !all && !reachable {
			continue
		}
		ip, ok := preferredTailscaleIP(ps.TailscaleIPs)
		if !ok {
			continue
		}
		var peerAPIURL string
		if len(ps.PeerAPIURL) > 0 {
			peerAPIURL = ps.PeerAPIURL[0]
		}
		peers = append(peers, tailperfListPeer{
			Name:       tailperfListPeerName(st, ps),
			IP:         ip.String(),
			OS:         ps.OS,
			State:      tailperfListState(ps),
			Path:       tailperfListPath(ps),
			Reachable:  reachable,
			PeerAPIURL: peerAPIURL,
		})
	}
	sort.SliceStable(peers, func(i, j int) bool {
		if peers[i].Reachable != peers[j].Reachable {
			return peers[i].Reachable
		}
		if peers[i].State != peers[j].State {
			return peers[i].State < peers[j].State
		}
		return strings.ToLower(peers[i].Name) < strings.ToLower(peers[j].Name)
	})
	return peers
}

func preferredTailscaleIP(ips []netip.Addr) (netip.Addr, bool) {
	for _, ip := range ips {
		if ip.Is4() {
			return ip, true
		}
	}
	if len(ips) == 0 {
		return netip.Addr{}, false
	}
	return ips[0], true
}

func tailperfListPeerName(st *ipnstate.Status, ps *ipnstate.PeerStatus) string {
	if ps.DNSName != "" || ps.HostName != "" {
		return dnsOrQuoteHostname(st, ps)
	}
	if len(ps.TailscaleIPs) > 0 {
		return ps.TailscaleIPs[0].String()
	}
	return "-"
}

func tailperfListState(ps *ipnstate.PeerStatus) string {
	switch {
	case ps.Active:
		return "active"
	case ps.Online:
		return "online"
	case !ps.LastSeen.IsZero():
		return "offline"
	default:
		return "unknown"
	}
}

func tailperfListPath(ps *ipnstate.PeerStatus) string {
	switch {
	case ps.CurAddr != "":
		return "direct " + ps.CurAddr
	case ps.PeerRelay != "":
		return "peer relay " + ps.PeerRelay
	case ps.Relay != "":
		return "derp " + ps.Relay
	default:
		return ""
	}
}

func probeTailperfListPeers(ctx context.Context, peers []tailperfListPeer) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, tailperfListProbeConcurrency)
	for i := range peers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				peers[i].StatusErr = ctx.Err().Error()
				return
			}
			probeTailperfListPeer(ctx, &peers[i])
		}(i)
	}
	wg.Wait()
}

func probeTailperfListPeer(ctx context.Context, p *tailperfListPeer) {
	if p.Status != nil || p.StatusErr != "" {
		return
	}
	if !p.Reachable && p.PeerAPIURL == "" {
		p.StatusErr = "peer is offline"
		return
	}
	if p.PeerAPIURL == "" {
		addr, err := netip.ParseAddr(p.IP)
		if err != nil {
			p.StatusErr = "bad Tailscale IP: " + err.Error()
			return
		}
		pctx, cancel := context.WithTimeout(ctx, tailperfListProbeTimeout)
		pr, err := localClient.PingWithOpts(pctx, addr, tailcfg.PingPeerAPI, local.PingOpts{})
		cancel()
		if err != nil {
			p.StatusErr = "PeerAPI discovery failed: " + err.Error()
			return
		}
		if pr == nil {
			p.StatusErr = "PeerAPI discovery failed: no response"
			return
		}
		if pr.PeerAPIURL == "" {
			if pr.Err != "" {
				p.StatusErr = "PeerAPI discovery failed: " + pr.Err
			} else {
				p.StatusErr = "PeerAPI discovery failed: no PeerAPI URL"
			}
			return
		}
		p.PeerAPIURL = pr.PeerAPIURL
	}
	pctx, cancel := context.WithTimeout(ctx, tailperfListProbeTimeout)
	status, err := getRemoteTailperfStatus(pctx, p.PeerAPIURL)
	cancel()
	if err != nil {
		p.StatusErr = err.Error()
		return
	}
	p.Status = &status
}

func getRemoteTailperfStatus(ctx context.Context, peerAPIURL string) (tailperfRemoteStatus, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(peerAPIURL, "/")+"/v0/tailperf/status", nil)
	if err != nil {
		return tailperfRemoteStatus{}, err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return tailperfRemoteStatus{}, fmt.Errorf("Tailperf status failed: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound || res.StatusCode == http.StatusNotImplemented || res.StatusCode == http.StatusMethodNotAllowed {
		return tailperfRemoteStatus{}, errors.New("Tailperf status unavailable: target build does not support Magic Perf status; update the target or try 'tailscale perf -c <ip>'")
	}
	if res.StatusCode != http.StatusOK {
		var b bytes.Buffer
		_, _ = b.ReadFrom(res.Body)
		msg := strings.TrimSpace(b.String())
		if msg == "" {
			msg = res.Status
		}
		return tailperfRemoteStatus{}, fmt.Errorf("%s", msg)
	}
	var st tailperfRemoteStatus
	if err := json.NewDecoder(res.Body).Decode(&st); err != nil {
		return tailperfRemoteStatus{}, err
	}
	return st, nil
}

func writeTailperfListReport(w io.Writer, peers []tailperfListPeer, opts tailperfListOptions) error {
	if opts.Limit == 0 {
		opts.Limit = tailperfListDefaultLimit
	}
	if len(opts.CommandPrefix) == 0 {
		opts.CommandPrefix = []string{"tailscale"}
	}
	total := len(peers)
	shown := total
	if !opts.All && opts.Limit > 0 && len(peers) > opts.Limit {
		peers = peers[:opts.Limit]
		shown = opts.Limit
	}
	if _, err := fmt.Fprintln(w, "Tailperf targets"); err != nil {
		return err
	}
	if total == 0 {
		_, err := fmt.Fprintln(w, "No reachable peers found.")
		return err
	}
	if shown != total {
		if _, err := fmt.Fprintf(w, "showing %d of %d peers; use 'tailscale perf list --all' to show every peer\n", shown, total); err != nil {
			return err
		}
	}

	var active, candidates, unavailable []tailperfListPeer
	for _, p := range peers {
		if p.Status != nil && len(tailperfListCommands(opts.CommandPrefix, p, true)) > 0 && p.Status.Busy {
			active = append(active, p)
			continue
		}
		if p.Status != nil && len(tailperfListCommands(opts.CommandPrefix, p, false)) > 0 {
			candidates = append(candidates, p)
			continue
		}
		unavailable = append(unavailable, p)
	}
	if len(active) > 0 {
		if err := writeTailperfListSection(w, "Active Tailperf listeners", active, opts.CommandPrefix, true); err != nil {
			return err
		}
	}
	if len(candidates) > 0 {
		if err := writeTailperfListSection(w, "Magic Perf candidates", candidates, opts.CommandPrefix, false); err != nil {
			return err
		}
	}
	if len(active) == 0 && len(candidates) == 0 {
		if _, err := fmt.Fprintln(w, "No grant-authorized Magic Perf candidates found in the displayed peers."); err != nil {
			return err
		}
	}
	if len(unavailable) > 0 {
		if err := writeTailperfUnavailableSection(w, unavailable, opts.CommandPrefix); err != nil {
			return err
		}
	}
	return nil
}

func writeTailperfListSection(w io.Writer, title string, peers []tailperfListPeer, commandPrefix []string, noMagic bool) error {
	if _, err := fmt.Fprintln(w, title); err != nil {
		return err
	}
	for _, p := range peers {
		if err := writeTailperfListPeerLine(w, p); err != nil {
			return err
		}
		for _, cmd := range tailperfListCommands(commandPrefix, p, noMagic) {
			if _, err := fmt.Fprintf(w, "  %s: %s\n", cmd.Label, cmd.Command); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeTailperfUnavailableSection(w io.Writer, peers []tailperfListPeer, commandPrefix []string) error {
	if _, err := fmt.Fprintln(w, "Peers without usable Magic Perf setup"); err != nil {
		return err
	}
	for _, p := range peers {
		if err := writeTailperfListPeerLine(w, p); err != nil {
			return err
		}
		reason := p.StatusErr
		if reason == "" {
			reason = "no configured Tailperf listen ports returned"
		}
		if _, err := fmt.Fprintf(w, "  Reason: %s\n", reason); err != nil {
			return err
		}
		if p.IP != "" {
			if _, err := fmt.Fprintf(w, "  PeerAPI check: %s\n", shellJoin(append(append([]string{}, commandPrefix...), "ping", "--peerapi", p.IP))); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeTailperfListPeerLine(w io.Writer, p tailperfListPeer) error {
	var attrs []string
	if p.IP != "" {
		attrs = append(attrs, p.IP)
	}
	if p.OS != "" {
		attrs = append(attrs, p.OS)
	}
	if p.State != "" {
		attrs = append(attrs, p.State)
	}
	if p.Path != "" {
		attrs = append(attrs, p.Path)
	}
	if len(attrs) == 0 {
		_, err := fmt.Fprintf(w, "- %s\n", p.Name)
		return err
	}
	_, err := fmt.Fprintf(w, "- %s (%s)\n", p.Name, strings.Join(attrs, ", "))
	return err
}

type tailperfListCommand struct {
	Label   string
	Command string
}

func tailperfListCommands(commandPrefix []string, p tailperfListPeer, noMagic bool) []tailperfListCommand {
	if p.Status == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []tailperfListCommand
	for _, rule := range p.Status.Rules {
		if rule.TUNListenPort != 0 {
			key := fmt.Sprintf("tun:%d", rule.TUNListenPort)
			if !seen[key] {
				seen[key] = true
				out = append(out, tailperfListCommand{
					Label:   "TUN",
					Command: formatTailperfRunCommand(commandPrefix, p.IP, false, noMagic, rule.TUNListenPort),
				})
			}
		}
		if rule.UserspaceListenPort != 0 {
			key := fmt.Sprintf("userspace:%d", rule.UserspaceListenPort)
			if !seen[key] {
				seen[key] = true
				out = append(out, tailperfListCommand{
					Label:   "userspace",
					Command: formatTailperfRunCommand(commandPrefix, p.IP, true, noMagic, rule.UserspaceListenPort),
				})
			}
		}
	}
	return out
}

func formatTailperfRunCommand(commandPrefix []string, ip string, noTUN, noMagic bool, port uint16) string {
	args := append([]string{}, commandPrefix...)
	args = append(args, "perf", "-c", ip)
	if noTUN {
		args = append(args, "--no-tun")
	}
	if noMagic {
		args = append(args, "--no-magic")
	}
	if port != 0 {
		args = append(args, fmt.Sprintf("--port=%d", port))
	}
	return shellJoin(args)
}

func tailperfListCommandPrefix() []string {
	cmd := "tailscale"
	if len(os.Args) > 0 && os.Args[0] != "" {
		cmd = os.Args[0]
	}
	args := []string{cmd}
	if localClient.Socket != "" && localClient.Socket != paths.DefaultTailscaledSocket() {
		args = append(args, "--socket="+localClient.Socket)
	}
	return args
}

func shellJoin(args []string) string {
	quoted := make([]string, len(args))
	for i, arg := range args {
		quoted[i] = shellQuoteArg(arg)
	}
	return strings.Join(quoted, " ")
}

func shellQuoteArg(s string) string {
	if s == "" {
		return "''"
	}
	for _, r := range s {
		if !isShellSafeRune(r) {
			return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
		}
	}
	return s
}

func isShellSafeRune(r rune) bool {
	return r >= 'a' && r <= 'z' ||
		r >= 'A' && r <= 'Z' ||
		r >= '0' && r <= '9' ||
		strings.ContainsRune("@%_+=:,./-", r)
}

func tailperfLogPathFromCacheDir(cacheDir string) string {
	return filepath.Join(cacheDir, "tailscale", "tailperf.jsonl")
}

func tailperfLogPathForConfig(logFile string) (string, error) {
	if logFile != "" {
		return logFile, nil
	}
	return defaultTailperfLogPath()
}

func defaultTailperfLogPath() (string, error) {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("getting user cache dir for tailperf log: %w", err)
	}
	return tailperfLogPathFromCacheDir(cacheDir), nil
}

func tailperfLogSinkForConfig(logFile string, noLog bool) (string, tailperf.LogSink, error) {
	if noLog {
		return "", nil, nil
	}
	logFile, err := tailperfLogPathForConfig(logFile)
	if err != nil {
		return "", nil, err
	}
	return logFile, tailperfLogSinkForPath(logFile), nil
}

func tailperfLogSinkForPath(path string) tailperf.LogSink {
	return tailperfCLIHistorySink{store: tailperf.HistoryStore{Path: path}}
}

type tailperfCLIHistorySink struct {
	store tailperf.HistoryStore
}

func (s tailperfCLIHistorySink) LogTailperfResult(ctx context.Context, r tailperf.Result) error {
	if err := os.MkdirAll(filepath.Dir(s.store.Path), 0700); err != nil {
		return fmt.Errorf("creating tailperf log directory: %w", err)
	}
	return s.store.Append(ctx, r)
}

func writeTailperfHistoryReport(w io.Writer, rs []tailperf.Result, limit int) error {
	if len(rs) == 0 {
		_, err := fmt.Fprintln(w, "No Tailperf history found.")
		return err
	}
	if limit < 0 {
		return fmt.Errorf("tailperf history limit must be non-negative")
	}
	rs = append([]tailperf.Result(nil), rs...)
	sort.SliceStable(rs, func(i, j int) bool {
		return rs[i].Started.After(rs[j].Started)
	})
	if limit > 0 && limit < len(rs) {
		rs = rs[:limit]
	}
	if _, err := fmt.Fprintln(w, "Tailperf history (newest first)"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "Started                 Source -> Destination       Proto  Dir      Transfer     Bitrate        Path"); err != nil {
		return err
	}
	for _, r := range rs {
		if _, err := fmt.Fprintf(w, "%-23s %-26s %-5s  %-7s  %10s  %13s  %s\n",
			formatTailperfStarted(r.Started),
			formatTailperfPair(r),
			r.Protocol,
			r.Direction,
			formatTailperfBytes(r.TransferBytes),
			formatTailperfBitrate(r.BitrateBitsPerSecond),
			r.Path.String()); err != nil {
			return err
		}
	}
	return nil
}

func writeTailperfBaselineReport(w io.Writer, ins tailperf.NodePairInsight) error {
	if _, err := fmt.Fprintln(w, "Baseline"); err != nil {
		return err
	}
	if ins.Baseline.Available {
		if _, err := fmt.Fprintf(w, "Current:  %s\nBaseline: %s\n",
			formatTailperfBitrate(ins.Baseline.NewBitsPerSec),
			formatTailperfBitrate(ins.Baseline.BaselineBitsPerSec)); err != nil {
			return err
		}
	} else if _, err := fmt.Fprintf(w, "Current:  %s\nBaseline: unavailable (%d matching samples)\n",
		formatTailperfBitrate(ins.Baseline.NewBitsPerSec),
		ins.Baseline.SampleCount); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Path:     %s\n", ins.PathSummary); err != nil {
		return err
	}
	for _, msg := range ins.Baseline.Messages {
		if _, err := fmt.Fprintf(w, "- %s\n", msg); err != nil {
			return err
		}
	}
	if ins.RecommendedNextAction != "" {
		if _, err := fmt.Fprintf(w, "Recommendation: %s\n", ins.RecommendedNextAction); err != nil {
			return err
		}
	}
	return nil
}

func exportTailperfSupportHistory(ctx context.Context, logPath, outPath string, stdout io.Writer) error {
	if outPath == "" {
		return errors.New("missing Tailperf support export path")
	}
	b, err := (tailperf.HistoryStore{Path: logPath}).ExportSupport(ctx, tailperf.RedactionOptions{
		HideUserIdentity: true,
		HideTailnetName:  true,
		HideNodeNames:    true,
		HidePrivateIPs:   true,
		HidePublicIPs:    true,
		HideDNSAnswers:   true,
		HideURLs:         true,
		HideRelayNames:   true,
	})
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if outPath == "-" {
		_, err := stdout.Write(b)
		return err
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0700); err != nil {
		return fmt.Errorf("creating Tailperf support export directory: %w", err)
	}
	return os.WriteFile(outPath, b, 0600)
}

func formatTailperfStarted(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04:05")
}

func formatTailperfPair(r tailperf.Result) string {
	src := r.SourceNode
	if src == "" {
		src = "source"
	}
	dst := r.DestinationNode
	if dst == "" {
		dst = "destination"
	}
	return src + " -> " + dst
}

func formatTailperfBytes(n int64) string {
	v := float64(n)
	for _, unit := range []string{"Bytes", "KBytes", "MBytes", "GBytes", "TBytes"} {
		if v < 1024 || unit == "TBytes" {
			if unit == "Bytes" {
				return fmt.Sprintf("%d %s", n, unit)
			}
			return fmt.Sprintf("%.2f %s", v, unit)
		}
		v /= 1024
	}
	return fmt.Sprintf("%d Bytes", n)
}

func formatTailperfBitrate(bitsPerSecond float64) string {
	v := bitsPerSecond
	for _, unit := range []string{"bits/sec", "Kbits/sec", "Mbits/sec", "Gbits/sec", "Tbits/sec"} {
		if v < 1000 || unit == "Tbits/sec" {
			return fmt.Sprintf("%.2f %s", v, unit)
		}
		v /= 1000
	}
	return fmt.Sprintf("%.2f bits/sec", bitsPerSecond)
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

type tailperfStartRequest struct {
	Protocol       tailperf.Protocol `json:"protocol"`
	DurationMillis int64             `json:"durationMillis"`
	Port           uint16            `json:"port,omitempty"`
	NoTUN          bool              `json:"noTun,omitempty"`
	NoLog          bool              `json:"noLog,omitempty"`
}

func remoteTailperfStartRequest(cfg tailperf.ClientConfig, explicitPort bool) tailperfStartRequest {
	var port uint16
	if explicitPort {
		port = cfg.Port
	}
	return tailperfStartRequest{
		Protocol:       cfg.Protocol,
		DurationMillis: cfg.Duration.Milliseconds(),
		Port:           port,
		NoTUN:          cfg.TUNMode == tailperf.TUNModeUserspace,
		NoLog:          cfg.NoLog,
	}
}

func maybeStartRemoteTailperf(ctx context.Context, target string, cfg tailperf.ClientConfig, explicitPort bool) (uint16, error) {
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
	if err != nil {
		return 0, fmt.Errorf("Tailperf remote setup discovery failed: %w", err)
	}
	if pr == nil || pr.PeerAPIURL == "" {
		return 0, errors.New("Tailperf target does not advertise PeerAPI remote setup; make sure the target is running a build with Magic Perf support, or run 'tailscale perf -s' on the target and retry with --no-magic")
	}
	return postRemoteTailperfStart(ctx, pr.PeerAPIURL, remoteTailperfStartRequest(cfg, explicitPort))
}

func postRemoteTailperfStart(ctx context.Context, peerAPIURL string, start tailperfStartRequest) (uint16, error) {
	body, _ := json.Marshal(start)
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(peerAPIURL, "/")+"/v0/tailperf/start", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("Tailperf remote setup failed: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound || res.StatusCode == http.StatusNotImplemented || res.StatusCode == http.StatusMethodNotAllowed {
		return 0, errors.New("Tailperf target does not support Magic Perf remote setup; make sure the target is running a build with Magic Perf support, or run 'tailscale perf -s' on the target and retry with --no-magic")
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
	if sr.Port == 0 {
		return 0, errors.New("Tailperf target returned no remote listen port")
	}
	return sr.Port, nil
}
