// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"golang.org/x/exp/slices"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/util/mak"
	"tailscale.com/version"
)

var serveCmd = newServeCommand(&serveEnv{})

// newServeCommand returns a new "serve" subcommand using e as its environmment.
func newServeCommand(e *serveEnv) *ffcli.Command {
	return &ffcli.Command{
		Name:      "serve",
		ShortHelp: "[ALPHA] Serve from your Tailscale node",
		ShortUsage: strings.TrimSpace(`
  serve [flags] <mount-point> {proxy|path|text} <arg>
  serve [flags] <sub-command> [sub-flags] <args>`),
		LongHelp: strings.TrimSpace(`
*** ALPHA; all of this is subject to change ***

The 'tailscale serve' set of commands allows you to serve
content and local servers from your Tailscale node to
your tailnet. 

You can also choose to enable the Tailscale Funnel with:
'tailscale serve funnel on'. Funnel allows you to publish
a 'tailscale serve' server publicly, open to the entire
internet. See https://tailscale.com/funnel.

EXAMPLES
  - To proxy requests to a web server at 127.0.0.1:3000:
    $ tailscale serve / proxy 3000

  - To serve a single file or a directory of files:
    $ tailscale serve / path /home/alice/blog/index.html
    $ tailscale serve /images/ path /home/alice/blog/images

  - To serve simple static text:
    $ tailscale serve / text "Hello, world!"
`),
		Exec: e.runServe,
		FlagSet: e.newFlags("serve", func(fs *flag.FlagSet) {
			fs.BoolVar(&e.remove, "remove", false, "remove an existing serve config")
			fs.UintVar(&e.servePort, "serve-port", 443, "port to serve on (443, 8443 or 10000)")
		}),
		UsageFunc: usageFunc,
		Subcommands: []*ffcli.Command{
			{
				Name:      "status",
				Exec:      e.runServeStatus,
				ShortHelp: "show current serve status",
				FlagSet: e.newFlags("serve-status", func(fs *flag.FlagSet) {
					fs.BoolVar(&e.json, "json", false, "output JSON")
				}),
				UsageFunc: usageFunc,
			},
			{
				Name:      "tcp",
				Exec:      e.runServeTCP,
				ShortHelp: "add or remove a TCP port forward",
				LongHelp: strings.Join([]string{
					"EXAMPLES",
					"  - Forward TLS over TCP to a local TCP server on port 5432:",
					"    $ tailscale serve tcp 5432",
					"",
					"  - Forward raw, TLS-terminated TCP packets to a local TCP server on port 5432:",
					"    $ tailscale serve --terminate-tls tcp 5432",
				}, "\n"),
				FlagSet: e.newFlags("serve-tcp", func(fs *flag.FlagSet) {
					fs.BoolVar(&e.terminateTLS, "terminate-tls", false, "terminate TLS before forwarding TCP connection")
				}),
				UsageFunc: usageFunc,
			},
			{
				Name:       "funnel",
				Exec:       e.runServeFunnel,
				ShortUsage: "funnel [flags] {on|off}",
				ShortHelp:  "turn Tailscale Funnel on or off",
				LongHelp: strings.Join([]string{
					"Funnel allows you to publish a 'tailscale serve'",
					"server publicly, open to the entire internet.",
					"",
					"Turning off Funnel only turns off serving to the internet.",
					"It does not affect serving to your tailnet.",
				}, "\n"),
				UsageFunc: usageFunc,
			},
		},
	}
}

func (e *serveEnv) newFlags(name string, setup func(fs *flag.FlagSet)) *flag.FlagSet {
	onError, out := flag.ExitOnError, Stderr
	if e.testFlagOut != nil {
		onError, out = flag.ContinueOnError, e.testFlagOut
	}
	fs := flag.NewFlagSet(name, onError)
	fs.SetOutput(out)
	if setup != nil {
		setup(fs)
	}
	return fs
}

// serveEnv is the environment the serve command runs within. All I/O should be
// done via serveEnv methods so that it can be faked out for tests.
//
// It also contains the flags, as registered with newServeCommand.
type serveEnv struct {
	// flags
	servePort    uint // Port to serve on. Defaults to 443.
	terminateTLS bool
	remove       bool // remove a serve config
	json         bool // output JSON (status only for now)

	// optional stuff for tests:
	testFlagOut              io.Writer
	testGetServeConfig       func(context.Context) (*ipn.ServeConfig, error)
	testSetServeConfig       func(context.Context, *ipn.ServeConfig) error
	testGetLocalClientStatus func(context.Context) (*ipnstate.Status, error)
	testStdout               io.Writer
}

// getSelfDNSName returns the DNS name of the current node.
// The trailing dot is removed.
// Returns an error if local client status fails.
func (e *serveEnv) getSelfDNSName(ctx context.Context) (string, error) {
	st, err := e.getLocalClientStatus(ctx)
	if err != nil {
		return "", fmt.Errorf("getting client status: %w", err)
	}
	return strings.TrimSuffix(st.Self.DNSName, "."), nil
}

// getLocalClientStatus calls LocalClient.Status, checks if
// Status is ready.
// Returns error if unable to reach tailscaled or if self node is nil.
// Exits if status is not running or starting.
func (e *serveEnv) getLocalClientStatus(ctx context.Context) (*ipnstate.Status, error) {
	if e.testGetLocalClientStatus != nil {
		return e.testGetLocalClientStatus(ctx)
	}
	st, err := localClient.Status(ctx)
	if err != nil {
		return nil, fixTailscaledConnectError(err)
	}
	description, ok := isRunningOrStarting(st)
	if !ok {
		fmt.Fprintf(os.Stderr, "%s\n", description)
		os.Exit(1)
	}
	if st.Self == nil {
		return nil, errors.New("no self node")
	}
	return st, nil
}

func (e *serveEnv) getServeConfig(ctx context.Context) (*ipn.ServeConfig, error) {
	if e.testGetServeConfig != nil {
		return e.testGetServeConfig(ctx)
	}
	return localClient.GetServeConfig(ctx)
}

func (e *serveEnv) setServeConfig(ctx context.Context, c *ipn.ServeConfig) error {
	if e.testSetServeConfig != nil {
		return e.testSetServeConfig(ctx, c)
	}
	return localClient.SetServeConfig(ctx, c)
}

// validateServePort returns --serve-port flag value,
// or an error if the port is not a valid port to serve on.
func (e *serveEnv) validateServePort() (port uint16, err error) {
	// make sure e.servePort is uint16
	port = uint16(e.servePort)
	if uint(port) != e.servePort {
		return 0, fmt.Errorf("serve-port %d is out of range", e.servePort)
	}
	// make sure e.servePort is 443, 8443 or 10000
	if port != 443 && port != 8443 && port != 10000 {
		return 0, fmt.Errorf("serve-port %d is invalid; must be 443, 8443 or 10000", e.servePort)
	}
	return port, nil
}

// runServe is the entry point for the "serve" subcommand, managing Web
// serve config types like proxy, path, and text.
//
// Examples:
// - tailscale serve / proxy 3000
// - tailscale serve /images/ path /var/www/images/
// - tailscale --serve-port=10000 serve /motd.txt text "Hello, world!"
func (e *serveEnv) runServe(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return flag.ErrHelp
	}

	// Undocumented debug command (not using ffcli subcommands) to set raw
	// configs from stdin for now (2022-11-13).
	if len(args) == 1 && args[0] == "set-raw" {
		valb, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		sc := new(ipn.ServeConfig)
		if err := json.Unmarshal(valb, sc); err != nil {
			return fmt.Errorf("invalid JSON: %w", err)
		}
		return localClient.SetServeConfig(ctx, sc)
	}

	if !(len(args) == 3 || (e.remove && len(args) >= 1)) {
		fmt.Fprintf(os.Stderr, "error: invalid number of arguments\n\n")
		return flag.ErrHelp
	}

	srvPort, err := e.validateServePort()
	if err != nil {
		return err
	}
	srvPortStr := strconv.Itoa(int(srvPort))

	mount, err := cleanMountPoint(args[0])
	if err != nil {
		return err
	}

	if e.remove {
		return e.handleWebServeRemove(ctx, mount)
	}

	h := new(ipn.HTTPHandler)

	switch args[1] {
	case "path":
		if version.IsSandboxedMacOS() {
			// don't allow path serving for now on macOS (2022-11-15)
			return fmt.Errorf("path serving is not supported if sandboxed on macOS")
		}
		if !filepath.IsAbs(args[2]) {
			fmt.Fprintf(os.Stderr, "error: path must be absolute\n\n")
			return flag.ErrHelp
		}
		fi, err := os.Stat(args[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: invalid path: %v\n\n", err)
			return flag.ErrHelp
		}
		if fi.IsDir() && !strings.HasSuffix(mount, "/") {
			// dir mount points must end in /
			// for relative file links to work
			mount += "/"
		}
		h.Path = args[2]
	case "proxy":
		t, err := expandProxyTarget(args[2])
		if err != nil {
			return err
		}
		h.Proxy = t
	case "text":
		if args[2] == "" {
			return errors.New("unable to serve; text cannot be an empty string")
		}
		h.Text = args[2]
	default:
		fmt.Fprintf(os.Stderr, "error: unknown serve type %q\n\n", args[1])
		return flag.ErrHelp
	}

	cursc, err := e.getServeConfig(ctx)
	if err != nil {
		return err
	}
	sc := cursc.Clone() // nil if no config
	if sc == nil {
		sc = new(ipn.ServeConfig)
	}
	dnsName, err := e.getSelfDNSName(ctx)
	if err != nil {
		return err
	}
	hp := ipn.HostPort(net.JoinHostPort(dnsName, srvPortStr))

	if sc.IsTCPForwardingOnPort(srvPort) {
		fmt.Fprintf(os.Stderr, "error: cannot serve web; already serving TCP\n")
		return flag.ErrHelp
	}

	mak.Set(&sc.TCP, srvPort, &ipn.TCPPortHandler{HTTPS: true})

	if _, ok := sc.Web[hp]; !ok {
		mak.Set(&sc.Web, hp, new(ipn.WebServerConfig))
	}
	mak.Set(&sc.Web[hp].Handlers, mount, h)

	for k, v := range sc.Web[hp].Handlers {
		if v == h {
			continue
		}
		// If the new mount point ends in / and another mount point
		// shares the same prefix, remove the other handler.
		// (e.g. /foo/ overwrites /foo)
		// The opposite example is also handled.
		m1 := strings.TrimSuffix(mount, "/")
		m2 := strings.TrimSuffix(k, "/")
		if m1 == m2 {
			delete(sc.Web[hp].Handlers, k)
			continue
		}
	}

	if !reflect.DeepEqual(cursc, sc) {
		if err := e.setServeConfig(ctx, sc); err != nil {
			return err
		}
	}

	return nil
}

func (e *serveEnv) handleWebServeRemove(ctx context.Context, mount string) error {
	srvPort, err := e.validateServePort()
	if err != nil {
		return err
	}
	srvPortStr := strconv.Itoa(int(srvPort))
	sc, err := e.getServeConfig(ctx)
	if err != nil {
		return err
	}
	if sc == nil {
		return errors.New("error: serve config does not exist")
	}
	dnsName, err := e.getSelfDNSName(ctx)
	if err != nil {
		return err
	}
	if sc.IsTCPForwardingOnPort(srvPort) {
		return errors.New("cannot remove web handler; currently serving TCP")
	}
	hp := ipn.HostPort(net.JoinHostPort(dnsName, srvPortStr))
	if !sc.WebHandlerExists(hp, mount) {
		return errors.New("error: serve config does not exist")
	}
	// delete existing handler, then cascade delete if empty
	delete(sc.Web[hp].Handlers, mount)
	if len(sc.Web[hp].Handlers) == 0 {
		delete(sc.Web, hp)
		delete(sc.TCP, srvPort)
	}
	// clear empty maps mostly for testing
	if len(sc.Web) == 0 {
		sc.Web = nil
	}
	if len(sc.TCP) == 0 {
		sc.TCP = nil
	}
	if err := e.setServeConfig(ctx, sc); err != nil {
		return err
	}
	return nil
}

func cleanMountPoint(mount string) (string, error) {
	if mount == "" {
		return "", errors.New("mount point cannot be empty")
	}
	if !strings.HasPrefix(mount, "/") {
		mount = "/" + mount
	}
	c := path.Clean(mount)
	if mount == c || mount == c+"/" {
		return mount, nil
	}
	return "", fmt.Errorf("invalid mount point %q", mount)
}

func expandProxyTarget(target string) (string, error) {
	if allNumeric(target) {
		p, err := strconv.ParseUint(target, 10, 16)
		if p == 0 || err != nil {
			return "", fmt.Errorf("invalid port %q", target)
		}
		return "http://127.0.0.1:" + target, nil
	}
	if !strings.Contains(target, "://") {
		target = "http://" + target
	}
	u, err := url.ParseRequestURI(target)
	if err != nil {
		return "", fmt.Errorf("parsing url: %w", err)
	}
	switch u.Scheme {
	case "http", "https", "https+insecure":
		// ok
	default:
		return "", fmt.Errorf("must be a URL starting with http://, https://, or https+insecure://")
	}
	host := u.Hostname()
	switch host {
	// TODO(shayne,bradfitz): do we want to do this?
	case "localhost", "127.0.0.1":
		host = "127.0.0.1"
	default:
		return "", fmt.Errorf("only localhost or 127.0.0.1 proxies are currently supported")
	}
	url := u.Scheme + "://" + host
	if u.Port() != "" {
		url += ":" + u.Port()
	}
	return url, nil
}

func allNumeric(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// runServeStatus prints the current serve config.
//
// Examples:
//   - tailscale status
//   - tailscale status --json
func (e *serveEnv) runServeStatus(ctx context.Context, args []string) error {
	sc, err := e.getServeConfig(ctx)
	if err != nil {
		return err
	}
	if e.json {
		j, err := json.MarshalIndent(sc, "", "  ")
		if err != nil {
			return err
		}
		j = append(j, '\n')
		e.stdout().Write(j)
		return nil
	}
	if sc == nil || (len(sc.TCP) == 0 && len(sc.Web) == 0 && len(sc.AllowFunnel) == 0) {
		printf("No serve config\n")
		return nil
	}
	st, err := e.getLocalClientStatus(ctx)
	if err != nil {
		return err
	}
	if sc.IsTCPForwardingAny() {
		if err := printTCPStatusTree(ctx, sc, st); err != nil {
			return err
		}
		printf("\n")
	}
	for hp := range sc.Web {
		printWebStatusTree(sc, hp)
		printf("\n")
	}
	// warn when funnel on without handlers
	for hp, a := range sc.AllowFunnel {
		if !a {
			continue
		}
		_, portStr, _ := net.SplitHostPort(string(hp))
		p, _ := strconv.ParseUint(portStr, 10, 16)
		if _, ok := sc.TCP[uint16(p)]; !ok {
			printf("WARNING: funnel=on for %s, but no serve config\n", hp)
		}
	}
	return nil
}

func (e *serveEnv) stdout() io.Writer {
	if e.testStdout != nil {
		return e.testStdout
	}
	return os.Stdout
}

func printTCPStatusTree(ctx context.Context, sc *ipn.ServeConfig, st *ipnstate.Status) error {
	dnsName := strings.TrimSuffix(st.Self.DNSName, ".")
	for p, h := range sc.TCP {
		if h.TCPForward == "" {
			continue
		}
		hp := ipn.HostPort(net.JoinHostPort(dnsName, strconv.Itoa(int(p))))
		tlsStatus := "TLS over TCP"
		if h.TerminateTLS != "" {
			tlsStatus = "TLS terminated"
		}
		fStatus := "tailnet only"
		if sc.IsFunnelOn(hp) {
			fStatus = "Funnel on"
		}
		printf("|-- tcp://%s (%s, %s)\n", hp, tlsStatus, fStatus)
		for _, a := range st.TailscaleIPs {
			ipp := net.JoinHostPort(a.String(), strconv.Itoa(int(p)))
			printf("|-- tcp://%s\n", ipp)
		}
		printf("|--> tcp://%s\n", h.TCPForward)
	}
	return nil
}

func printWebStatusTree(sc *ipn.ServeConfig, hp ipn.HostPort) {
	if sc == nil {
		return
	}
	fStatus := "tailnet only"
	if sc.IsFunnelOn(hp) {
		fStatus = "Funnel on"
	}
	host, portStr, _ := net.SplitHostPort(string(hp))
	if portStr == "443" {
		printf("https://%s (%s)\n", host, fStatus)
	} else {
		printf("https://%s:%s (%s)\n", host, portStr, fStatus)
	}
	srvTypeAndDesc := func(h *ipn.HTTPHandler) (string, string) {
		switch {
		case h.Path != "":
			return "path", h.Path
		case h.Proxy != "":
			return "proxy", h.Proxy
		case h.Text != "":
			return "text", "\"" + elipticallyTruncate(h.Text, 20) + "\""
		}
		return "", ""
	}

	var mounts []string
	for k := range sc.Web[hp].Handlers {
		mounts = append(mounts, k)
	}
	sort.Slice(mounts, func(i, j int) bool {
		return len(mounts[i]) < len(mounts[j])
	})
	maxLen := len(mounts[len(mounts)-1])

	for _, m := range mounts {
		h := sc.Web[hp].Handlers[m]
		t, d := srvTypeAndDesc(h)
		printf("%s %s%s %-5s %s\n", "|--", m, strings.Repeat(" ", maxLen-len(m)), t, d)
	}
}

func elipticallyTruncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

// runServeTCP is the entry point for the "serve tcp" subcommand and
// manages the serve config for TCP forwarding.
//
// Examples:
//   - tailscale serve tcp 5432
//   - tailscale --serve-port=8443 tcp 4430
//   - tailscale --serve-port=10000 --terminate-tls tcp 8080
func (e *serveEnv) runServeTCP(ctx context.Context, args []string) error {
	if len(args) != 1 {
		fmt.Fprintf(os.Stderr, "error: invalid number of arguments\n\n")
		return flag.ErrHelp
	}

	srvPort, err := e.validateServePort()
	if err != nil {
		return err
	}

	portStr := args[0]
	p, err := strconv.ParseUint(portStr, 10, 16)
	if p == 0 || err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid port %q\n\n", portStr)
	}

	cursc, err := e.getServeConfig(ctx)
	if err != nil {
		return err
	}
	sc := cursc.Clone() // nil if no config
	if sc == nil {
		sc = new(ipn.ServeConfig)
	}

	fwdAddr := "127.0.0.1:" + portStr

	if sc.IsServingWeb(srvPort) {
		if e.remove {
			return fmt.Errorf("unable to remove; serving web, not TCP forwarding on serve port %d", srvPort)
		}
		return fmt.Errorf("cannot serve TCP; already serving web on %d", srvPort)
	}

	if e.remove {
		if ph := sc.GetTCPPortHandler(srvPort); ph != nil && ph.TCPForward == fwdAddr {
			delete(sc.TCP, srvPort)
			// clear map mostly for testing
			if len(sc.TCP) == 0 {
				sc.TCP = nil
			}
			return e.setServeConfig(ctx, sc)
		}
		return errors.New("error: serve config does not exist")
	}

	mak.Set(&sc.TCP, srvPort, &ipn.TCPPortHandler{TCPForward: fwdAddr})

	dnsName, err := e.getSelfDNSName(ctx)
	if err != nil {
		return err
	}
	if e.terminateTLS {
		sc.TCP[srvPort].TerminateTLS = dnsName
	}

	if !reflect.DeepEqual(cursc, sc) {
		if err := e.setServeConfig(ctx, sc); err != nil {
			return err
		}
	}

	return nil
}

// runServeFunnel is the entry point for the "serve funnel" subcommand and
// manages turning on/off funnel. Funnel is off by default.
//
// Note: funnel is only supported on single DNS name for now. (2022-11-15)
func (e *serveEnv) runServeFunnel(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return flag.ErrHelp
	}

	srvPort, err := e.validateServePort()
	if err != nil {
		return err
	}
	srvPortStr := strconv.Itoa(int(srvPort))

	var on bool
	switch args[0] {
	case "on", "off":
		on = args[0] == "on"
	default:
		return flag.ErrHelp
	}
	sc, err := e.getServeConfig(ctx)
	if err != nil {
		return err
	}
	if sc == nil {
		sc = new(ipn.ServeConfig)
	}
	st, err := e.getLocalClientStatus(ctx)
	if err != nil {
		return fmt.Errorf("getting client status: %w", err)
	}
	if !slices.Contains(st.Self.Capabilities, tailcfg.NodeAttrFunnel) {
		return errors.New("Funnel not available. See https://tailscale.com/s/no-funnel")
	}
	dnsName := strings.TrimSuffix(st.Self.DNSName, ".")
	hp := ipn.HostPort(dnsName + ":" + srvPortStr)
	isFun := sc.IsFunnelOn(hp)
	if on && isFun || !on && !isFun {
		// Nothing to do.
		return nil
	}
	if on {
		mak.Set(&sc.AllowFunnel, hp, true)
	} else {
		delete(sc.AllowFunnel, hp)
		// clear map mostly for testing
		if len(sc.AllowFunnel) == 0 {
			sc.AllowFunnel = nil
		}
	}
	if err := e.setServeConfig(ctx, sc); err != nil {
		return err
	}
	return nil
}
