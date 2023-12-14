// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bufio"
	"bytes"
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
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/peterbourgon/ff/v3/ffcli"
	"golang.org/x/net/http/httpproxy"
	"tailscale.com/client/tailscale"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/control/controlhttp"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tshttpproxy"
	"tailscale.com/paths"
	"tailscale.com/safesocket"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/must"
	"tailscale.com/wgengine/capture"
)

var debugCmd = &ffcli.Command{
	Name:     "debug",
	Exec:     runDebug,
	LongHelp: `"tailscale debug" contains misc debug facilities; it is not a stable interface.`,
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("debug")
		fs.StringVar(&debugArgs.file, "file", "", "get, delete:NAME, or NAME")
		fs.StringVar(&debugArgs.cpuFile, "cpu-profile", "", "if non-empty, grab a CPU profile for --profile-seconds seconds and write it to this file; - for stdout")
		fs.StringVar(&debugArgs.memFile, "mem-profile", "", "if non-empty, grab a memory profile and write it to this file; - for stdout")
		fs.IntVar(&debugArgs.cpuSec, "profile-seconds", 15, "number of seconds to run a CPU profile for, when --cpu-profile is non-empty")
		return fs
	})(),
	Subcommands: []*ffcli.Command{
		{
			Name:      "derp-map",
			Exec:      runDERPMap,
			ShortHelp: "print DERP map",
		},
		{
			Name:       "component-logs",
			Exec:       runDebugComponentLogs,
			ShortHelp:  "enable/disable debug logs for a component",
			ShortUsage: "tailscale debug component-logs [" + strings.Join(ipn.DebuggableComponents, "|") + "]",
			FlagSet: (func() *flag.FlagSet {
				fs := newFlagSet("component-logs")
				fs.DurationVar(&debugComponentLogsArgs.forDur, "for", time.Hour, "how long to enable debug logs for; zero or negative means to disable")
				return fs
			})(),
		},
		{
			Name:      "daemon-goroutines",
			Exec:      runDaemonGoroutines,
			ShortHelp: "print tailscaled's goroutines",
		},
		{
			Name:      "daemon-logs",
			Exec:      runDaemonLogs,
			ShortHelp: "watch tailscaled's server logs",
			FlagSet: (func() *flag.FlagSet {
				fs := newFlagSet("daemon-logs")
				fs.IntVar(&daemonLogsArgs.verbose, "verbose", 0, "verbosity level")
				fs.BoolVar(&daemonLogsArgs.time, "time", false, "include client time")
				return fs
			})(),
		},
		{
			Name:      "metrics",
			Exec:      runDaemonMetrics,
			ShortHelp: "print tailscaled's metrics",
			FlagSet: (func() *flag.FlagSet {
				fs := newFlagSet("metrics")
				fs.BoolVar(&metricsArgs.watch, "watch", false, "print JSON dump of delta values")
				return fs
			})(),
		},
		{
			Name:      "env",
			Exec:      runEnv,
			ShortHelp: "print cmd/tailscale environment",
		},
		{
			Name:      "stat",
			Exec:      runStat,
			ShortHelp: "stat a file",
		},
		{
			Name:      "hostinfo",
			Exec:      runHostinfo,
			ShortHelp: "print hostinfo",
		},
		{
			Name:      "local-creds",
			Exec:      runLocalCreds,
			ShortHelp: "print how to access Tailscale LocalAPI",
		},
		{
			Name:      "restun",
			Exec:      localAPIAction("restun"),
			ShortHelp: "force a magicsock restun",
		},
		{
			Name:      "rebind",
			Exec:      localAPIAction("rebind"),
			ShortHelp: "force a magicsock rebind",
		},
		{
			Name:      "derp-set-homeless",
			Exec:      localAPIAction("derp-set-homeless"),
			ShortHelp: "enable DERP homeless mode (breaks reachablility)",
		},
		{
			Name:      "derp-unset-homeless",
			Exec:      localAPIAction("derp-unset-homeless"),
			ShortHelp: "disable DERP homeless mode",
		},
		{
			Name:      "break-tcp-conns",
			Exec:      localAPIAction("break-tcp-conns"),
			ShortHelp: "break any open TCP connections from the daemon",
		},
		{
			Name:      "break-derp-conns",
			Exec:      localAPIAction("break-derp-conns"),
			ShortHelp: "break any open DERP connections from the daemon",
		},
		{
			Name:      "pick-new-derp",
			Exec:      localAPIAction("pick-new-derp"),
			ShortHelp: "switch to some other random DERP home region for a short time",
		},
		{
			Name:      "force-netmap-update",
			Exec:      localAPIAction("force-netmap-update"),
			ShortHelp: "force a full no-op netmap update (for load testing)",
		},
		{
			// TODO(bradfitz,maisem): eventually promote this out of debug
			Name:      "reload-config",
			Exec:      reloadConfig,
			ShortHelp: "reload config",
		},
		{
			Name:      "control-knobs",
			Exec:      debugControlKnobs,
			ShortHelp: "see current control knobs",
		},
		{
			Name:      "prefs",
			Exec:      runPrefs,
			ShortHelp: "print prefs",
			FlagSet: (func() *flag.FlagSet {
				fs := newFlagSet("prefs")
				fs.BoolVar(&prefsArgs.pretty, "pretty", false, "If true, pretty-print output")
				return fs
			})(),
		},
		{
			Name:      "watch-ipn",
			Exec:      runWatchIPN,
			ShortHelp: "subscribe to IPN message bus",
			FlagSet: (func() *flag.FlagSet {
				fs := newFlagSet("watch-ipn")
				fs.BoolVar(&watchIPNArgs.netmap, "netmap", true, "include netmap in messages")
				fs.BoolVar(&watchIPNArgs.initial, "initial", false, "include initial status")
				fs.BoolVar(&watchIPNArgs.showPrivateKey, "show-private-key", false, "include node private key in printed netmap")
				fs.IntVar(&watchIPNArgs.count, "count", 0, "exit after printing this many statuses, or 0 to keep going forever")
				return fs
			})(),
		},
		{
			Name:      "netmap",
			Exec:      runNetmap,
			ShortHelp: "print the current network map",
			FlagSet: (func() *flag.FlagSet {
				fs := newFlagSet("netmap")
				fs.BoolVar(&netmapArgs.showPrivateKey, "show-private-key", false, "include node private key in printed netmap")
				return fs
			})(),
		},
		{
			Name:      "via",
			Exec:      runVia,
			ShortHelp: "convert between site-specific IPv4 CIDRs and IPv6 'via' routes",
		},
		{
			Name:      "ts2021",
			Exec:      runTS2021,
			ShortHelp: "debug ts2021 protocol connectivity",
			FlagSet: (func() *flag.FlagSet {
				fs := newFlagSet("ts2021")
				fs.StringVar(&ts2021Args.host, "host", "controlplane.tailscale.com", "hostname of control plane")
				fs.IntVar(&ts2021Args.version, "version", int(tailcfg.CurrentCapabilityVersion), "protocol version")
				fs.BoolVar(&ts2021Args.verbose, "verbose", false, "be extra verbose")
				return fs
			})(),
		},
		{
			Name:      "set-expire",
			Exec:      runSetExpire,
			ShortHelp: "manipulate node key expiry for testing",
			FlagSet: (func() *flag.FlagSet {
				fs := newFlagSet("set-expire")
				fs.DurationVar(&setExpireArgs.in, "in", 0, "if non-zero, set node key to expire this duration from now")
				return fs
			})(),
		},
		{
			Name:      "dev-store-set",
			Exec:      runDevStoreSet,
			ShortHelp: "set a key/value pair during development",
			FlagSet: (func() *flag.FlagSet {
				fs := newFlagSet("store-set")
				fs.BoolVar(&devStoreSetArgs.danger, "danger", false, "accept danger")
				return fs
			})(),
		},
		{
			Name:      "derp",
			Exec:      runDebugDERP,
			ShortHelp: "test a DERP configuration",
		},
		{
			Name:      "capture",
			Exec:      runCapture,
			ShortHelp: "streams pcaps for debugging",
			FlagSet: (func() *flag.FlagSet {
				fs := newFlagSet("capture")
				fs.StringVar(&captureArgs.outFile, "o", "", "path to stream the pcap (or - for stdout), leave empty to start wireshark")
				return fs
			})(),
		},
		{
			Name:      "portmap",
			Exec:      debugPortmap,
			ShortHelp: "run portmap debugging debugging",
			FlagSet: (func() *flag.FlagSet {
				fs := newFlagSet("portmap")
				fs.DurationVar(&debugPortmapArgs.duration, "duration", 5*time.Second, "timeout for port mapping")
				fs.StringVar(&debugPortmapArgs.ty, "type", "", `portmap debug type (one of "", "pmp", "pcp", or "upnp")`)
				fs.StringVar(&debugPortmapArgs.gatewayAddr, "gateway-addr", "", `override gateway IP (must also pass --self-addr)`)
				fs.StringVar(&debugPortmapArgs.selfAddr, "self-addr", "", `override self IP (must also pass --gateway-addr)`)
				fs.BoolVar(&debugPortmapArgs.logHTTP, "log-http", false, `print all HTTP requests and responses to the log`)
				return fs
			})(),
		},
		{
			Name:      "peer-endpoint-changes",
			Exec:      runPeerEndpointChanges,
			ShortHelp: "prints debug information about a peer's endpoint changes",
		},
	},
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
		return errors.New("unknown arguments")
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
	return errors.New("see 'tailscale debug --help")
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
	watcher, err := localClient.WatchIPNBus(ctx, mask)
	if err != nil {
		return err
	}
	defer watcher.Close()
	fmt.Fprintf(os.Stderr, "Connected.\n")
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
	os.Stdout.Write(j)
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
		if siteID > 0xff {
			return fmt.Errorf("site-id values over 255 are currently reserved")
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
}

func runTS2021(ctx context.Context, args []string) error {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	keysURL := "https://" + ts2021Args.host + "/key?v=" + strconv.Itoa(ts2021Args.version)

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
	res, err := http.DefaultClient.Do(req)
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
			log.Printf("Dial(%q, %q) = %v", network, address, err)
		} else {
			log.Printf("Dial(%q, %q) = %v / %v", network, address, c.LocalAddr(), c.RemoteAddr())
		}
		return c, err
	}
	var logf logger.Logf
	if ts2021Args.verbose {
		logf = log.Printf
	}
	conn, err := (&controlhttp.Dialer{
		Hostname:        ts2021Args.host,
		HTTPPort:        "80",
		HTTPSPort:       "443",
		MachineKey:      machinePrivate,
		ControlKey:      keys.PublicKey,
		ProtocolVersion: uint16(ts2021Args.version),
		Dialer:          dialFunc,
		Logf:            logf,
	}).Dial(ctx)
	log.Printf("controlhttp.Dial = %p, %v", conn, err)
	if err != nil {
		return err
	}
	log.Printf("did noise handshake")

	gotPeer := conn.Peer()
	if gotPeer != keys.PublicKey {
		log.Printf("peer = %v, want %v", gotPeer, keys.PublicKey)
		return errors.New("key mismatch")
	}

	log.Printf("final underlying conn: %v / %v", conn.LocalAddr(), conn.RemoteAddr())
	return nil
}

var debugComponentLogsArgs struct {
	forDur time.Duration
}

func runDebugComponentLogs(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: debug component-logs [" + strings.Join(ipn.DebuggableComponents, "|") + "]")
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
		return errors.New("usage: dev-store-set --danger <key> <value>")
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
		return errors.New("usage: debug derp <region>")
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
		return errors.New("usage --in=<duration>")
	}
	return localClient.DebugSetExpireIn(ctx, setExpireArgs.in)
}

var captureArgs struct {
	outFile string
}

func runCapture(ctx context.Context, args []string) error {
	stream, err := localClient.StreamDebugCapture(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()

	switch captureArgs.outFile {
	case "-":
		fmt.Fprintln(os.Stderr, "Press Ctrl-C to stop the capture.")
		_, err = io.Copy(os.Stdout, stream)
		return err
	case "":
		lua, err := os.CreateTemp("", "ts-dissector")
		if err != nil {
			return err
		}
		defer os.Remove(lua.Name())
		lua.Write([]byte(capture.DissectorLua))
		if err := lua.Close(); err != nil {
			return err
		}

		wireshark := exec.CommandContext(ctx, "wireshark", "-X", "lua_script:"+lua.Name(), "-k", "-i", "-")
		wireshark.Stdin = stream
		wireshark.Stdout = os.Stdout
		wireshark.Stderr = os.Stderr
		return wireshark.Run()
	}

	f, err := os.OpenFile(captureArgs.outFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	fmt.Fprintln(os.Stderr, "Press Ctrl-C to stop the capture.")
	_, err = io.Copy(f, stream)
	return err
}

var debugPortmapArgs struct {
	duration    time.Duration
	gatewayAddr string
	selfAddr    string
	ty          string
	logHTTP     bool
}

func debugPortmap(ctx context.Context, args []string) error {
	opts := &tailscale.DebugPortmapOpts{
		Duration: debugPortmapArgs.duration,
		Type:     debugPortmapArgs.ty,
		LogHTTP:  debugPortmapArgs.logHTTP,
	}
	if (debugPortmapArgs.gatewayAddr != "") != (debugPortmapArgs.selfAddr != "") {
		return fmt.Errorf("if one of --gateway-addr and --self-addr is provided, the other must be as well")
	}
	if debugPortmapArgs.gatewayAddr != "" {
		var err error
		opts.GatewayAddr, err = netip.ParseAddr(debugPortmapArgs.gatewayAddr)
		if err != nil {
			return fmt.Errorf("invalid --gateway-addr: %w", err)
		}
		opts.SelfAddr, err = netip.ParseAddr(debugPortmapArgs.selfAddr)
		if err != nil {
			return fmt.Errorf("invalid --self-addr: %w", err)
		}
	}
	rc, err := localClient.DebugPortmap(ctx, opts)
	if err != nil {
		return err
	}
	defer rc.Close()

	_, err = io.Copy(os.Stdout, rc)
	return err
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
		return errors.New("usage: peer-status <hostname-or-IP>")
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
