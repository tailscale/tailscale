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
	ShortUsage: "tailscale perf -s [--port=<port>] | tailscale perf -c <hostname-or-IP> [flags] | tailscale perf --history",
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

Local history:

  tailscale perf --history
  tailscale perf --export-support=tailperf-support.json
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
		fs.StringVar(&perfArgs.logFile, "log-file", "", "write Tailperf result records to this JSONL file")
		fs.BoolVar(&perfArgs.history, "history", false, "show local Tailperf result history")
		fs.IntVar(&perfArgs.historyLimit, "history-limit", 10, "maximum Tailperf history records to show; zero shows all")
		fs.BoolVar(&perfArgs.baseline, "baseline", false, "compare the result with matching local Tailperf history")
		fs.StringVar(&perfArgs.exportSupport, "export-support", "", "write redacted Tailperf history support data to this path; use - for stdout")
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
	logFile        string
	history        bool
	historyLimit   int
	baseline       bool
	exportSupport  string
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
