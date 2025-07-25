// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/peterbourgon/ff/v3/ffcli"
	"golang.org/x/net/http/httpproxy"
	"golang.org/x/net/http2"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/control/controlhttp"
	"tailscale.com/hostinfo"
	"tailscale.com/internal/noiseconn"
	"tailscale.com/ipn"
	"tailscale.com/net/ace"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tshttpproxy"
	"tailscale.com/paths"
	"tailscale.com/safesocket"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/must"
)

var (
	debugCaptureCmd   func() *ffcli.Command // or nil
	debugPortmapCmd   func() *ffcli.Command // or nil
	debugPeerRelayCmd func() *ffcli.Command // or nil
)

func debugCmd() *ffcli.Command {
	return &ffcli.Command{
		Name:       "debug",
		Exec:       runDebug,
		ShortUsage: "tailscale debug <debug-flags | subcommand>",
		ShortHelp:  "Debug commands",
		LongHelp:   hidden + `"tailscale debug" contains misc debug facilities; it is not a stable interface.`,
		FlagSet: (func() *flag.FlagSet {
			fs := newFlagSet("debug")
			fs.StringVar(&debugArgs.file, "file", "", "get, delete:NAME, or NAME")
			fs.StringVar(&debugArgs.cpuFile, "cpu-profile", "", "if non-empty, grab a CPU profile for --profile-seconds seconds and write it to this file; - for stdout")
			fs.StringVar(&debugArgs.memFile, "mem-profile", "", "if non-empty, grab a memory profile and write it to this file; - for stdout")
			fs.IntVar(&debugArgs.cpuSec, "profile-seconds", 15, "number of seconds to run a CPU profile for, when --cpu-profile is non-empty")
			return fs
		})(),
		Subcommands: nonNilCmds([]*ffcli.Command{
			{
				Name:       "derp-map",
				ShortUsage: "tailscale debug derp-map",
				Exec:       runDERPMap,
				ShortHelp:  "Print DERP map",
			},
			{
				Name:       "component-logs",
				ShortUsage: "tailscale debug component-logs [" + strings.Join(ipn.DebuggableComponents, "|") + "]",
				Exec:       runDebugComponentLogs,
				ShortHelp:  "Enable/disable debug logs for a component",
				FlagSet: (func() *flag.FlagSet {
					fs := newFlagSet("component-logs")
					fs.DurationVar(&debugComponentLogsArgs.forDur, "for", time.Hour, "how long to enable debug logs for; zero or negative means to disable")
					return fs
				})(),
			},
			{
				Name:       "daemon-goroutines",
				ShortUsage: "tailscale debug daemon-goroutines",
				Exec:       runDaemonGoroutines,
				ShortHelp:  "Print tailscaled's goroutines",
			},
			{
				Name:       "daemon-logs",
				ShortUsage: "tailscale debug daemon-logs",
				Exec:       runDaemonLogs,
				ShortHelp:  "Watch tailscaled's server logs",
				FlagSet: (func() *flag.FlagSet {
					fs := newFlagSet("daemon-logs")
					fs.IntVar(&daemonLogsArgs.verbose, "verbose", 0, "verbosity level")
					fs.BoolVar(&daemonLogsArgs.time, "time", false, "include client time")
					return fs
				})(),
			},
			{
				Name:       "daemon-bus-events",
				ShortUsage: "tailscale debug daemon-bus-events",
				Exec:       runDaemonBusEvents,
				ShortHelp:  "Watch events on the tailscaled bus",
			},
			{
				Name:       "daemon-bus-graph",
				ShortUsage: "tailscale debug daemon-bus-graph",
				Exec:       runDaemonBusGraph,
				ShortHelp:  "Print graph for the tailscaled bus",
				FlagSet: (func() *flag.FlagSet {
					fs := newFlagSet("debug-bus-graph")
					fs.StringVar(&daemonBusGraphArgs.format, "format", "json", "output format [json/dot]")
					return fs
				})(),
			},
			{
				Name:       "metrics",
				ShortUsage: "tailscale debug metrics",
				Exec:       runDaemonMetrics,
				ShortHelp:  "Print tailscaled's metrics",
				FlagSet: (func() *flag.FlagSet {
					fs := newFlagSet("metrics")
					fs.BoolVar(&metricsArgs.watch, "watch", false, "print JSON dump of delta values")
					return fs
				})(),
			},
			{
				Name:       "env",
				ShortUsage: "tailscale debug env",
				Exec:       runEnv,
				ShortHelp:  "Print cmd/tailscale environment",
			},
			{
				Name:       "stat",
				ShortUsage: "tailscale debug stat <files...>",
				Exec:       runStat,
				ShortHelp:  "Stat a file",
			},
			{
				Name:       "hostinfo",
				ShortUsage: "tailscale debug hostinfo",
				Exec:       runHostinfo,
				ShortHelp:  "Print hostinfo",
			},
			{
				Name:       "local-creds",
				ShortUsage: "tailscale debug local-creds",
				Exec:       runLocalCreds,
				ShortHelp:  "Print how to access Tailscale LocalAPI",
			},
			{
				Name:       "localapi",
				ShortUsage: "tailscale debug localapi [<method>] <path> [<body| \"-\">]",
				Exec:       runLocalAPI,
				ShortHelp:  "Call a LocalAPI method directly",
				FlagSet: (func() *flag.FlagSet {
					fs := newFlagSet("localapi")
					fs.BoolVar(&localAPIFlags.verbose, "v", false, "verbose; dump HTTP headers")
					return fs
				})(),
			},
			{
				Name:       "restun",
				ShortUsage: "tailscale debug restun",
				Exec:       localAPIAction("restun"),
				ShortHelp:  "Force a magicsock restun",
			},
			{
				Name:       "rebind",
				ShortUsage: "tailscale debug rebind",
				Exec:       localAPIAction("rebind"),
				ShortHelp:  "Force a magicsock rebind",
			},
			{
				Name:       "derp-set-on-demand",
				ShortUsage: "tailscale debug derp-set-on-demand",
				Exec:       localAPIAction("derp-set-homeless"),
				ShortHelp:  "Enable DERP on-demand mode (breaks reachability)",
			},
			{
				Name:       "derp-unset-on-demand",
				ShortUsage: "tailscale debug derp-unset-on-demand",
				Exec:       localAPIAction("derp-unset-homeless"),
				ShortHelp:  "Disable DERP on-demand mode",
			},
			{
				Name:       "break-tcp-conns",
				ShortUsage: "tailscale debug break-tcp-conns",
				Exec:       localAPIAction("break-tcp-conns"),
				ShortHelp:  "Break any open TCP connections from the daemon",
			},
			{
				Name:       "break-derp-conns",
				ShortUsage: "tailscale debug break-derp-conns",
				Exec:       localAPIAction("break-derp-conns"),
				ShortHelp:  "Break any open DERP connections from the daemon",
			},
			{
				Name:       "pick-new-derp",
				ShortUsage: "tailscale debug pick-new-derp",
				Exec:       localAPIAction("pick-new-derp"),
				ShortHelp:  "Switch to some other random DERP home region for a short time",
			},
			{
				Name:       "force-prefer-derp",
				ShortUsage: "tailscale debug force-prefer-derp",
				Exec:       forcePreferDERP,
				ShortHelp:  "Prefer the given region ID if reachable (until restart, or 0 to clear)",
			},
			{
				Name:       "force-netmap-update",
				ShortUsage: "tailscale debug force-netmap-update",
				Exec:       localAPIAction("force-netmap-update"),
				ShortHelp:  "Force a full no-op netmap update (for load testing)",
			},
			{
				// TODO(bradfitz,maisem): eventually promote this out of debug
				Name:       "reload-config",
				ShortUsage: "tailscale debug reload-config",
				Exec:       reloadConfig,
				ShortHelp:  "Reload config",
			},
			{
				Name:       "control-knobs",
				ShortUsage: "tailscale debug control-knobs",
				Exec:       debugControlKnobs,
				ShortHelp:  "See current control knobs",
			},
			{
				Name:       "prefs",
				ShortUsage: "tailscale debug prefs",
				Exec:       runPrefs,
				ShortHelp:  "Print prefs",
				FlagSet: (func() *flag.FlagSet {
					fs := newFlagSet("prefs")
					fs.BoolVar(&prefsArgs.pretty, "pretty", false, "If true, pretty-print output")
					return fs
				})(),
			},
			{
				Name:       "watch-ipn",
				ShortUsage: "tailscale debug watch-ipn",
				Exec:       runWatchIPN,
				ShortHelp:  "Subscribe to IPN message bus",
				FlagSet: (func() *flag.FlagSet {
					fs := newFlagSet("watch-ipn")
					fs.BoolVar(&watchIPNArgs.netmap, "netmap", true, "include netmap in messages")
					fs.BoolVar(&watchIPNArgs.initial, "initial", false, "include initial status")
					fs.BoolVar(&watchIPNArgs.rateLimit, "rate-limit", true, "rate limit messags")
					fs.BoolVar(&watchIPNArgs.showPrivateKey, "show-private-key", false, "include node private key in printed netmap")
					fs.IntVar(&watchIPNArgs.count, "count", 0, "exit after printing this many statuses, or 0 to keep going forever")
					return fs
				})(),
			},
			{
				Name:       "netmap",
				ShortUsage: "tailscale debug netmap",
				Exec:       runNetmap,
				ShortHelp:  "Print the current network map",
				FlagSet: (func() *flag.FlagSet {
					fs := newFlagSet("netmap")
					fs.BoolVar(&netmapArgs.showPrivateKey, "show-private-key", false, "include node private key in printed netmap")
					return fs
				})(),
			},
			{
				Name: "via",
				ShortUsage: "tailscale debug via <site-id> <v4-cidr>\n" +
					"tailscale debug via <v6-route>",
				Exec:      runVia,
				ShortHelp: "Convert between site-specific IPv4 CIDRs and IPv6 'via' routes",
			},
			{
				Name:       "ts2021",
				ShortUsage: "tailscale debug ts2021",
				Exec:       runTS2021,
				ShortHelp:  "Debug ts2021 protocol connectivity",
				FlagSet: (func() *flag.FlagSet {
					fs := newFlagSet("ts2021")
					fs.StringVar(&ts2021Args.host, "host", "controlplane.tailscale.com", "hostname of control plane")
					fs.IntVar(&ts2021Args.version, "version", int(tailcfg.CurrentCapabilityVersion), "protocol version")
					fs.BoolVar(&ts2021Args.verbose, "verbose", false, "be extra verbose")
					fs.StringVar(&ts2021Args.aceHost, "ace", "", "if non-empty, use this ACE server IP/hostname as a candidate path")
					fs.StringVar(&ts2021Args.dialPlanJSONFile, "dial-plan", "", "if non-empty, use this JSON file to configure the dial plan")
					return fs
				})(),
			},
			{
				Name:       "set-expire",
				ShortUsage: "tailscale debug set-expire --in=1m",
				Exec:       runSetExpire,
				ShortHelp:  "Manipulate node key expiry for testing",
				FlagSet: (func() *flag.FlagSet {
					fs := newFlagSet("set-expire")
					fs.DurationVar(&setExpireArgs.in, "in", 0, "if non-zero, set node key to expire this duration from now")
					return fs
				})(),
			},
			{
				Name:       "dev-store-set",
				ShortUsage: "tailscale debug dev-store-set",
				Exec:       runDevStoreSet,
				ShortHelp:  "Set a key/value pair during development",
				FlagSet: (func() *flag.FlagSet {
					fs := newFlagSet("store-set")
					fs.BoolVar(&devStoreSetArgs.danger, "danger", false, "accept danger")
					return fs
				})(),
			},
			{
				Name:       "derp",
				ShortUsage: "tailscale debug derp",
				Exec:       runDebugDERP,
				ShortHelp:  "Test a DERP configuration",
			},
			ccall(debugCaptureCmd),
			ccall(debugPortmapCmd),
			{
				Name:       "peer-endpoint-changes",
				ShortUsage: "tailscale debug peer-endpoint-changes <hostname-or-IP>",
				Exec:       runPeerEndpointChanges,
				ShortHelp:  "Print debug information about a peer's endpoint changes",
			},
			{
				Name:       "dial-types",
				ShortUsage: "tailscale debug dial-types <hostname-or-IP> <port>",
				Exec:       runDebugDialTypes,
				ShortHelp:  "Print debug information about connecting to a given host or IP",
				FlagSet: (func() *flag.FlagSet {
					fs := newFlagSet("dial-types")
					fs.StringVar(&debugDialTypesArgs.network, "network", "tcp", `network type to dial ("tcp", "udp", etc.)`)
					return fs
				})(),
			},
			{
				Name:       "resolve",
				ShortUsage: "tailscale debug resolve <hostname>",
				Exec:       runDebugResolve,
				ShortHelp:  "Does a DNS lookup",
				FlagSet: (func() *flag.FlagSet {
					fs := newFlagSet("resolve")
					fs.StringVar(&resolveArgs.net, "net", "ip", "network type to resolve (ip, ip4, ip6)")
					return fs
				})(),
			},
			{
				Name:       "go-buildinfo",
				ShortUsage: "tailscale debug go-buildinfo",
				ShortHelp:  "Print Go's runtime/debug.BuildInfo",
				Exec:       runGoBuildInfo,
			},
			{
				Name:       "peer-relay-servers",
				ShortUsage: "tailscale debug peer-relay-servers",
				ShortHelp:  "Print the current set of candidate peer relay servers",
				Exec:       runPeerRelayServers,
			},
			{
				Name:       "test-risk",
				ShortUsage: "tailscale debug test-risk",
				ShortHelp:  "Do a fake risky action",
				Exec:       runTestRisk,
				FlagSet: (func() *flag.FlagSet {
					fs := newFlagSet("test-risk")
					fs.StringVar(&testRiskArgs.acceptedRisk, "accept-risk", "", "comma-separated list of accepted risks")
					return fs
				})(),
			},
			ccall(debugPeerRelayCmd),
		}...),
	}
}

func runGoBuildInfo(ctx context.Context, args []string) error {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return errors.New("no Go build info")
	}
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "\t")
	return e.Encode(bi)
}

var debugArgs struct {
	file    string
	cpuSec  int
	cpuFile string
	memFile string
}

func writeProfile(dst string, v []byte) error {
	if dst == "-" {
		_, err := Stdout.Write(v)
		return err
	}
	return os.WriteFile(dst, v, 0600)
}

func outName(dst string) string {
	if dst == "-" {
		return "stdout"
	}
	if runtime.GOOS == "darwin" {
		return fmt.Sprintf("%s (warning: sandboxed macOS binaries write to Library/Containers; use - to write to stdout and redirect to file instead)", dst)
	}
	return dst
}

func runDebug(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("tailscale debug: unknown subcommand: %s", args[0])
	}
	var usedFlag bool
	if out := debugArgs.cpuFile; out != "" {
		usedFlag = true // TODO(bradfitz): add "pprof" subcommand
		log.Printf("Capturing CPU profile for %v seconds ...", debugArgs.cpuSec)
		if v, err := localClient.Pprof(ctx, "profile", debugArgs.cpuSec); err != nil {
			return err
		} else {
			if err := writeProfile(out, v); err != nil {
				return err
			}
			log.Printf("CPU profile written to %s", outName(out))
		}
	}
	if out := debugArgs.memFile; out != "" {
		usedFlag = true // TODO(bradfitz): add "pprof" subcommand
		log.Printf("Capturing memory profile ...")
		if v, err := localClient.Pprof(ctx, "heap", 0); err != nil {
			return err
		} else {
			if err := writeProfile(out, v); err != nil {
				return err
			}
			log.Printf("Memory profile written to %s", outName(out))
		}
	}
	if debugArgs.file != "" {
		usedFlag = true // TODO(bradfitz): add "file" subcommand
		if debugArgs.file == "get" {
			wfs, err := localClient.WaitingFiles(ctx)
			if err != nil {
				fatalf("%v\n", err)
			}
			e := json.NewEncoder(Stdout)
			e.SetIndent("", "\t")
			e.Encode(wfs)
			return nil
		}
		if name, ok := strings.CutPrefix(debugArgs.file, "delete:"); ok {
			return localClient.DeleteWaitingFile(ctx, name)
		}
		rc, size, err := localClient.GetWaitingFile(ctx, debugArgs.file)
		if err != nil {
			return err
		}
		log.Printf("Size: %v\n", size)
		io.Copy(Stdout, rc)
		return nil
	}
	if usedFlag {
		// TODO(bradfitz): delete this path when all debug flags are migrated
		// to subcommands.
		return nil
	}
	return errors.New("tailscale debug: subcommand or flag required")
}

func runLocalCreds(ctx context.Context, args []string) error {
	port, token, err := safesocket.LocalTCPPortAndToken()
	if err == nil {
		printf("curl -u:%s http://localhost:%d/localapi/v0/status\n", token, port)
		return nil
	}
	if runtime.GOOS == "windows" {
		runLocalAPIProxy()
		return nil
	}
	printf("curl --unix-socket %s http://local-tailscaled.sock/localapi/v0/status\n", paths.DefaultTailscaledSocket())
	return nil
}

func looksLikeHTTPMethod(s string) bool {
	if len(s) > len("OPTIONS") {
		return false
	}
	for _, r := range s {
		if r < 'A' || r > 'Z' {
			return false
		}
	}
	return true
}

var localAPIFlags struct {
	verbose bool
}

func runLocalAPI(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("expected at least one argument")
	}
	method := "GET"
	if looksLikeHTTPMethod(args[0]) {
		method = args[0]
		args = args[1:]
		if len(args) == 0 {
			return errors.New("expected at least one argument after method")
		}
	}
	path := args[0]
	if !strings.HasPrefix(path, "/localapi/") {
		if !strings.Contains(path, "/") {
			path = "/localapi/v0/" + path
		} else {
			path = "/localapi/" + path
		}
	}

	var body io.Reader
	if len(args) > 1 {
		if args[1] == "-" {
			fmt.Fprintf(Stderr, "# reading request body from stdin...\n")
			all, err := io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("reading Stdin: %q", err)
			}
			body = bytes.NewReader(all)
		} else {
			body = strings.NewReader(args[1])
		}
	}
	req, err := http.NewRequest(method, "http://local-tailscaled.sock"+path, body)
	if err != nil {
		return err
	}
	fmt.Fprintf(Stderr, "# doing request %s %s\n", method, path)

	res, err := localClient.DoLocalRequest(req)
	if err != nil {
		return err
	}
	is2xx := res.StatusCode >= 200 && res.StatusCode <= 299
	if localAPIFlags.verbose {
		res.Write(Stdout)
	} else {
		if !is2xx {
			fmt.Fprintf(Stderr, "# Response status %s\n", res.Status)
		}
		io.Copy(Stdout, res.Body)
	}
	if is2xx {
		return nil
	}
	return errors.New(res.Status)
}

type localClientRoundTripper struct{}

func (localClientRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return localClient.DoLocalRequest(req)
}

func runLocalAPIProxy() {
	rp := httputil.NewSingleHostReverseProxy(&url.URL{
		Scheme: "http",
		Host:   apitype.LocalAPIHost,
		Path:   "/",
	})
	dir := rp.Director
	rp.Director = func(req *http.Request) {
		dir(req)
		req.Host = ""
		req.RequestURI = ""
	}
	rp.Transport = localClientRoundTripper{}
	lc, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Serving LocalAPI proxy on http://%s\n", lc.Addr())
	fmt.Printf("curl.exe http://%v/localapi/v0/status\n", lc.Addr())
	fmt.Printf("Ctrl+C to stop")
	http.Serve(lc, rp)
}

var prefsArgs struct {
	pretty bool
}

func runPrefs(ctx context.Context, args []string) error {
	prefs, err := localClient.GetPrefs(ctx)
	if err != nil {
		return err
	}
	if prefsArgs.pretty {
		outln(prefs.Pretty())
	} else {
		j, _ := json.MarshalIndent(prefs, "", "\t")
		outln(string(j))
	}
	return nil
}

var watchIPNArgs struct {
	netmap         bool
	initial        bool
	showPrivateKey bool
	rateLimit      bool
	count          int
}

func runWatchIPN(ctx context.Context, args []string) error {
	var mask ipn.NotifyWatchOpt
	if watchIPNArgs.initial {
		mask = ipn.NotifyInitialState | ipn.NotifyInitialPrefs | ipn.NotifyInitialNetMap
	}
	if !watchIPNArgs.showPrivateKey {
		mask |= ipn.NotifyNoPrivateKeys
	}
	if watchIPNArgs.rateLimit {
		mask |= ipn.NotifyRateLimit
	}
	watcher, err := localClient.WatchIPNBus(ctx, mask)
	if err != nil {
		return err
	}
	defer watcher.Close()
	fmt.Fprintf(Stderr, "Connected.\n")
	for seen := 0; watchIPNArgs.count == 0 || seen < watchIPNArgs.count; seen++ {
		n, err := watcher.Next()
		if err != nil {
			return err
		}
		if !watchIPNArgs.netmap {
			n.NetMap = nil
		}
		j, _ := json.MarshalIndent(n, "", "\t")
		fmt.Printf("%s\n", j)
	}
	return nil
}

var netmapArgs struct {
	showPrivateKey bool
}

func runNetmap(ctx context.Context, args []string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var mask ipn.NotifyWatchOpt = ipn.NotifyInitialNetMap
	if !netmapArgs.showPrivateKey {
		mask |= ipn.NotifyNoPrivateKeys
	}
	watcher, err := localClient.WatchIPNBus(ctx, mask)
	if err != nil {
		return err
	}
	defer watcher.Close()

	n, err := watcher.Next()
	if err != nil {
		return err
	}
	j, _ := json.MarshalIndent(n.NetMap, "", "\t")
	fmt.Printf("%s\n", j)
	return nil
}

func runDERPMap(ctx context.Context, args []string) error {
	dm, err := localClient.CurrentDERPMap(ctx)
	if err != nil {
		return fmt.Errorf(
			"failed to get local derp map, instead `curl %s/derpmap/default`: %w", ipn.DefaultControlURL, err,
		)
	}
	enc := json.NewEncoder(Stdout)
	enc.SetIndent("", "\t")
	enc.Encode(dm)
	return nil
}

func forcePreferDERP(ctx context.Context, args []string) error {
	var n int
	if len(args) != 1 {
		return errors.New("expected exactly one integer argument")
	}
	n, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("expected exactly one integer argument: %w", err)
	}
	b, err := json.Marshal(n)
	if err != nil {
		return fmt.Errorf("failed to marshal DERP region: %w", err)
	}
	if err := localClient.DebugActionBody(ctx, "force-prefer-derp", bytes.NewReader(b)); err != nil {
		return fmt.Errorf("failed to force preferred DERP: %w", err)
	}
	return nil
}

func localAPIAction(action string) func(context.Context, []string) error {
	return func(ctx context.Context, args []string) error {
		if len(args) > 0 {
			return errors.New("unexpected arguments")
		}
		return localClient.DebugAction(ctx, action)
	}
}

func reloadConfig(ctx context.Context, args []string) error {
	ok, err := localClient.ReloadConfig(ctx)
	if err != nil {
		return err
	}
	if ok {
		printf("config reloaded\n")
		return nil
	}
	printf("config mode not in use\n")
	os.Exit(1)
	panic("unreachable")
}

func runEnv(ctx context.Context, args []string) error {
	for _, e := range os.Environ() {
		outln(e)
	}
	return nil
}

func runStat(ctx context.Context, args []string) error {
	for _, a := range args {
		fi, err := os.Lstat(a)
		if err != nil {
			printf("%s: %v\n", a, err)
			continue
		}
		printf("%s: %v, %v\n", a, fi.Mode(), fi.Size())
		if fi.IsDir() {
			ents, _ := os.ReadDir(a)
			for i, ent := range ents {
				if i == 25 {
					printf("  ...\n")
					break
				}
				printf("  - %s\n", ent.Name())
			}
		}
	}
	return nil
}

func runHostinfo(ctx context.Context, args []string) error {
	hi := hostinfo.New()
	j, _ := json.MarshalIndent(hi, "", "  ")
	Stdout.Write(j)
	return nil
}

func runDaemonGoroutines(ctx context.Context, args []string) error {
	goroutines, err := localClient.Goroutines(ctx)
	if err != nil {
		return err
	}
	Stdout.Write(goroutines)
	return nil
}

var daemonLogsArgs struct {
	verbose int
	time    bool
}

func runDaemonLogs(ctx context.Context, args []string) error {
	logs, err := localClient.TailDaemonLogs(ctx)
	if err != nil {
		return err
	}
	d := json.NewDecoder(logs)
	for {
		var line struct {
			Text    string `json:"text"`
			Verbose int    `json:"v"`
			Time    string `json:"client_time"`
		}
		err := d.Decode(&line)
		if err != nil {
			return err
		}
		line.Text = strings.TrimSpace(line.Text)
		if line.Text == "" || line.Verbose > daemonLogsArgs.verbose {
			continue
		}
		if daemonLogsArgs.time {
			fmt.Printf("%s %s\n", line.Time, line.Text)
		} else {
			fmt.Println(line.Text)
		}
	}
}

func runDaemonBusEvents(ctx context.Context, args []string) error {
	for line, err := range localClient.StreamBusEvents(ctx) {
		if err != nil {
			return err
		}
		fmt.Printf("[%d][%q][from: %q][to: %q] %s\n", line.Count, line.Type,
			line.From, line.To, line.Event)
	}
	return nil
}

var daemonBusGraphArgs struct {
	format string
}

func runDaemonBusGraph(ctx context.Context, args []string) error {
	graph, err := localClient.EventBusGraph(ctx)
	if err != nil {
		return err
	}
	if format := daemonBusGraphArgs.format; format != "json" && format != "dot" {
		return fmt.Errorf("unrecognized output format %q", format)
	}
	if daemonBusGraphArgs.format == "dot" {
		var topics eventbus.DebugTopics
		if err := json.Unmarshal(graph, &topics); err != nil {
			return fmt.Errorf("unable to parse json: %w", err)
		}
		fmt.Print(generateDOTGraph(topics.Topics))
	} else {
		fmt.Print(string(graph))
	}
	return nil
}

// generateDOTGraph generates the DOT graph format based on the events
func generateDOTGraph(topics []eventbus.DebugTopic) string {
	var sb strings.Builder
	sb.WriteString("digraph event_bus {\n")

	for _, topic := range topics {
		// If no subscribers, still ensure the topic is drawn
		if len(topic.Subscribers) == 0 {
			topic.Subscribers = append(topic.Subscribers, "no-subscribers")
		}
		for _, subscriber := range topic.Subscribers {
			fmt.Fprintf(&sb, "\t%q -> %q [label=%q];\n",
				topic.Publisher, subscriber, cmp.Or(topic.Name, "???"))
		}
	}

	sb.WriteString("}\n")
	return sb.String()
}

var metricsArgs struct {
	watch bool
}

func runDaemonMetrics(ctx context.Context, args []string) error {
	last := map[string]int64{}
	for {
		out, err := localClient.DaemonMetrics(ctx)
		if err != nil {
			return err
		}
		if !metricsArgs.watch {
			Stdout.Write(out)
			return nil
		}
		bs := bufio.NewScanner(bytes.NewReader(out))
		type change struct {
			name     string
			from, to int64
		}
		var changes []change
		var maxNameLen int
		for bs.Scan() {
			line := bytes.TrimSpace(bs.Bytes())
			if len(line) == 0 || line[0] == '#' {
				continue
			}
			f := strings.Fields(string(line))
			if len(f) != 2 {
				continue
			}
			name := f[0]
			n, _ := strconv.ParseInt(f[1], 10, 64)
			prev, ok := last[name]
			if ok && prev == n {
				continue
			}
			last[name] = n
			if !ok {
				continue
			}
			changes = append(changes, change{name, prev, n})
			if len(name) > maxNameLen {
				maxNameLen = len(name)
			}
		}
		if len(changes) > 0 {
			format := fmt.Sprintf("%%-%ds %%+5d => %%v\n", maxNameLen)
			for _, c := range changes {
				fmt.Fprintf(Stdout, format, c.name, c.to-c.from, c.to)
			}
			io.WriteString(Stdout, "\n")
		}
		time.Sleep(time.Second)
	}
}

func runVia(ctx context.Context, args []string) error {
	switch len(args) {
	default:
		return errors.New("expect either <site-id> <v4-cidr> or <v6-route>")
	case 1:
		ipp, err := netip.ParsePrefix(args[0])
		if err != nil {
			return err
		}
		if !ipp.Addr().Is6() {
			return errors.New("with one argument, expect an IPv6 CIDR")
		}
		if !tsaddr.TailscaleViaRange().Contains(ipp.Addr()) {
			return errors.New("not a via route")
		}
		if ipp.Bits() < 96 {
			return errors.New("short length, want /96 or more")
		}
		v4 := tsaddr.UnmapVia(ipp.Addr())
		a := ipp.Addr().As16()
		siteID := binary.BigEndian.Uint32(a[8:12])
		printf("site %v (0x%x), %v\n", siteID, siteID, netip.PrefixFrom(v4, ipp.Bits()-96))
	case 2:
		siteID, err := strconv.ParseUint(args[0], 0, 32)
		if err != nil {
			return fmt.Errorf("invalid site-id %q; must be decimal or hex with 0x prefix", args[0])
		}
		if siteID > 0xffff {
			return fmt.Errorf("site-id values over 65535 are currently reserved")
		}
		ipp, err := netip.ParsePrefix(args[1])
		if err != nil {
			return err
		}
		via, err := tsaddr.MapVia(uint32(siteID), ipp)
		if err != nil {
			return err
		}
		outln(via)
	}
	return nil
}

var ts2021Args struct {
	host    string // "controlplane.tailscale.com"
	version int    // 27 or whatever
	verbose bool
	aceHost string // if non-empty, FQDN of https ACE server to use ("ace.example.com")

	dialPlanJSONFile string // if non-empty, path to JSON file [tailcfg.ControlDialPlan] JSON
}

func runTS2021(ctx context.Context, args []string) error {
	log.SetOutput(Stdout)
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	keysURL := "https://" + ts2021Args.host + "/key?v=" + strconv.Itoa(ts2021Args.version)

	keyTransport := http.DefaultTransport.(*http.Transport).Clone()
	if ts2021Args.aceHost != "" {
		log.Printf("using ACE server %q", ts2021Args.aceHost)
		keyTransport.Proxy = nil
		keyTransport.DialContext = (&ace.Dialer{ACEHost: ts2021Args.aceHost}).Dial
	}

	if ts2021Args.verbose {
		u, err := url.Parse(keysURL)
		if err != nil {
			return err
		}
		envConf := httpproxy.FromEnvironment()
		if *envConf == (httpproxy.Config{}) {
			log.Printf("HTTP proxy env: (none)")
		} else {
			log.Printf("HTTP proxy env: %+v", envConf)
		}
		proxy, err := tshttpproxy.ProxyFromEnvironment(&http.Request{URL: u})
		log.Printf("tshttpproxy.ProxyFromEnvironment = (%v, %v)", proxy, err)
	}
	machinePrivate := key.NewMachine()
	var dialer net.Dialer

	var keys struct {
		PublicKey key.MachinePublic
	}
	log.Printf("Fetching keys from %s ...", keysURL)
	req, err := http.NewRequestWithContext(ctx, "GET", keysURL, nil)
	if err != nil {
		return err
	}
	res, err := keyTransport.RoundTrip(req)
	if err != nil {
		log.Printf("Do: %v", err)
		return err
	}
	if res.StatusCode != 200 {
		log.Printf("Status: %v", res.Status)
		return errors.New(res.Status)
	}
	if err := json.NewDecoder(res.Body).Decode(&keys); err != nil {
		log.Printf("JSON: %v", err)
		return fmt.Errorf("decoding /keys JSON: %w", err)
	}
	res.Body.Close()
	if ts2021Args.verbose {
		log.Printf("got public key: %v", keys.PublicKey)
	}

	dialFunc := func(ctx context.Context, network, address string) (net.Conn, error) {
		log.Printf("Dial(%q, %q) ...", network, address)
		c, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			// skip logging context cancellation errors
			if !errors.Is(err, context.Canceled) {
				log.Printf("Dial(%q, %q) = %v", network, address, err)
			}
		} else {
			log.Printf("Dial(%q, %q) = %v / %v", network, address, c.LocalAddr(), c.RemoteAddr())
		}
		return c, err
	}
	var logf logger.Logf
	if ts2021Args.verbose {
		logf = log.Printf
	}

	bus := eventbus.New()
	defer bus.Close()

	netMon, err := netmon.New(bus, logger.WithPrefix(logf, "netmon: "))
	if err != nil {
		return fmt.Errorf("creating netmon: %w", err)
	}

	var dialPlan *tailcfg.ControlDialPlan
	if ts2021Args.dialPlanJSONFile != "" {
		b, err := os.ReadFile(ts2021Args.dialPlanJSONFile)
		if err != nil {
			return fmt.Errorf("reading dial plan JSON file: %w", err)
		}
		dialPlan = new(tailcfg.ControlDialPlan)
		if err := json.Unmarshal(b, dialPlan); err != nil {
			return fmt.Errorf("unmarshaling dial plan JSON file: %w", err)
		}
	}

	noiseDialer := &controlhttp.Dialer{
		Hostname:        ts2021Args.host,
		HTTPPort:        "80",
		HTTPSPort:       "443",
		MachineKey:      machinePrivate,
		ControlKey:      keys.PublicKey,
		ProtocolVersion: uint16(ts2021Args.version),
		DialPlan:        dialPlan,
		Dialer:          dialFunc,
		Logf:            logf,
		NetMon:          netMon,
	}
	if ts2021Args.aceHost != "" {
		noiseDialer.DialPlan = &tailcfg.ControlDialPlan{
			Candidates: []tailcfg.ControlIPCandidate{
				{
					ACEHost:        ts2021Args.aceHost,
					DialTimeoutSec: 10,
				},
			},
		}
	}
	const tries = 2
	for i := range tries {
		err := tryConnect(ctx, keys.PublicKey, noiseDialer)
		if err != nil {
			log.Printf("error on attempt %d/%d: %v", i+1, tries, err)
			continue
		}
		break
	}
	return nil
}

func tryConnect(ctx context.Context, controlPublic key.MachinePublic, noiseDialer *controlhttp.Dialer) error {
	conn, err := noiseDialer.Dial(ctx)
	log.Printf("controlhttp.Dial = %p, %v", conn, err)
	if err != nil {
		return err
	}
	log.Printf("did noise handshake")

	gotPeer := conn.Peer()
	if gotPeer != controlPublic {
		log.Printf("peer = %v, want %v", gotPeer, controlPublic)
		return errors.New("key mismatch")
	}

	log.Printf("final underlying conn: %v / %v", conn.LocalAddr(), conn.RemoteAddr())

	h2Transport, err := http2.ConfigureTransports(&http.Transport{
		IdleConnTimeout: time.Second,
	})
	if err != nil {
		return fmt.Errorf("http2.ConfigureTransports: %w", err)
	}

	// Now, create a Noise conn over the existing conn.
	nc, err := noiseconn.New(conn.Conn, h2Transport, 0, nil)
	if err != nil {
		return fmt.Errorf("noiseconn.New: %w", err)
	}
	defer nc.Close()

	// Reserve a RoundTrip for the whoami request.
	ok, _, err := nc.ReserveNewRequest(ctx)
	if err != nil {
		return fmt.Errorf("ReserveNewRequest: %w", err)
	}
	if !ok {
		return errors.New("ReserveNewRequest failed")
	}

	// Make a /whoami request to the server to verify that we can actually
	// communicate over the newly-established connection.
	whoamiURL := "http://" + ts2021Args.host + "/machine/whoami"
	req, err := http.NewRequestWithContext(ctx, "GET", whoamiURL, nil)
	if err != nil {
		return err
	}
	resp, err := nc.RoundTrip(req)
	if err != nil {
		return fmt.Errorf("RoundTrip whoami request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("whoami request returned status %v", resp.Status)
	} else {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("reading whoami response: %w", err)
		}
		log.Printf("whoami response: %q", body)
	}
	return nil
}

var debugComponentLogsArgs struct {
	forDur time.Duration
}

func runDebugComponentLogs(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: tailscale debug component-logs [" + strings.Join(ipn.DebuggableComponents, "|") + "]")
	}
	component := args[0]
	dur := debugComponentLogsArgs.forDur

	err := localClient.SetComponentDebugLogging(ctx, component, dur)
	if err != nil {
		return err
	}
	if debugComponentLogsArgs.forDur <= 0 {
		fmt.Printf("Disabled debug logs for component %q\n", component)
	} else {
		fmt.Printf("Enabled debug logs for component %q for %v\n", component, dur)
	}
	return nil
}

var devStoreSetArgs struct {
	danger bool
}

func runDevStoreSet(ctx context.Context, args []string) error {
	if len(args) != 2 {
		return errors.New("usage: tailscale debug dev-store-set --danger <key> <value>")
	}
	if !devStoreSetArgs.danger {
		return errors.New("this command is dangerous; use --danger to proceed")
	}
	key, val := args[0], args[1]
	if val == "-" {
		valb, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		val = string(valb)
	}
	return localClient.SetDevStoreKeyValue(ctx, key, val)
}

func runDebugDERP(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: tailscale debug derp <region>")
	}
	st, err := localClient.DebugDERPRegion(ctx, args[0])
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", must.Get(json.MarshalIndent(st, "", " ")))
	return nil
}

var setExpireArgs struct {
	in time.Duration
}

func runSetExpire(ctx context.Context, args []string) error {
	if len(args) != 0 || setExpireArgs.in == 0 {
		return errors.New("usage: tailscale debug set-expire --in=<duration>")
	}
	return localClient.DebugSetExpireIn(ctx, setExpireArgs.in)
}

func runPeerEndpointChanges(ctx context.Context, args []string) error {
	st, err := localClient.Status(ctx)
	if err != nil {
		return fixTailscaledConnectError(err)
	}
	description, ok := isRunningOrStarting(st)
	if !ok {
		printf("%s\n", description)
		os.Exit(1)
	}

	if len(args) != 1 || args[0] == "" {
		return errors.New("usage: tailscale debug peer-endpoint-changes <hostname-or-IP>")
	}
	var ip string

	hostOrIP := args[0]
	ip, self, err := tailscaleIPFromArg(ctx, hostOrIP)
	if err != nil {
		return err
	}
	if self {
		printf("%v is local Tailscale IP\n", ip)
		return nil
	}

	if ip != hostOrIP {
		log.Printf("lookup %q => %q", hostOrIP, ip)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "http://local-tailscaled.sock/localapi/v0/debug-peer-endpoint-changes?ip="+ip, nil)
	if err != nil {
		return err
	}

	resp, err := localClient.DoLocalRequest(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var dst bytes.Buffer
	if err := json.Indent(&dst, body, "", "  "); err != nil {
		return fmt.Errorf("indenting returned JSON: %w", err)
	}

	if ss := dst.String(); !strings.HasSuffix(ss, "\n") {
		dst.WriteByte('\n')
	}
	fmt.Printf("%s", dst.String())
	return nil
}

func debugControlKnobs(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return errors.New("unexpected arguments")
	}
	v, err := localClient.DebugResultJSON(ctx, "control-knobs")
	if err != nil {
		return err
	}
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	e.Encode(v)
	return nil
}

var debugDialTypesArgs struct {
	network string
}

func runDebugDialTypes(ctx context.Context, args []string) error {
	st, err := localClient.Status(ctx)
	if err != nil {
		return fixTailscaledConnectError(err)
	}
	description, ok := isRunningOrStarting(st)
	if !ok {
		printf("%s\n", description)
		os.Exit(1)
	}

	if len(args) != 2 || args[0] == "" || args[1] == "" {
		return errors.New("usage: tailscale debug dial-types <hostname-or-IP> <port>")
	}

	port, err := strconv.ParseUint(args[1], 10, 16)
	if err != nil {
		return fmt.Errorf("invalid port %q: %w", args[1], err)
	}

	hostOrIP := args[0]
	ip, _, err := tailscaleIPFromArg(ctx, hostOrIP)
	if err != nil {
		return err
	}
	if ip != hostOrIP {
		log.Printf("lookup %q => %q", hostOrIP, ip)
	}

	qparams := make(url.Values)
	qparams.Set("ip", ip)
	qparams.Set("port", strconv.FormatUint(port, 10))
	qparams.Set("network", debugDialTypesArgs.network)

	req, err := http.NewRequestWithContext(ctx, "POST", "http://local-tailscaled.sock/localapi/v0/debug-dial-types?"+qparams.Encode(), nil)
	if err != nil {
		return err
	}

	resp, err := localClient.DoLocalRequest(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	fmt.Printf("%s", body)
	return nil
}

var resolveArgs struct {
	net string // "ip", "ip4", "ip6""
}

func runDebugResolve(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: tailscale debug resolve <hostname>")
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	host := args[0]
	ips, err := net.DefaultResolver.LookupIP(ctx, resolveArgs.net, host)
	if err != nil {
		return err
	}
	for _, ip := range ips {
		fmt.Printf("%s\n", ip)
	}
	return nil
}

func runPeerRelayServers(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return errors.New("unexpected arguments")
	}
	v, err := localClient.DebugResultJSON(ctx, "peer-relay-servers")
	if err != nil {
		return err
	}
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	e.Encode(v)
	return nil
}

var testRiskArgs struct {
	acceptedRisk string
}

func runTestRisk(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return errors.New("unexpected arguments")
	}
	if err := presentRiskToUser("test-risk", "This is a test risky action.", testRiskArgs.acceptedRisk); err != nil {
		return err
	}
	fmt.Println("did-test-risky-action")
	return nil
}
