// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

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
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/util/mak"
	"tailscale.com/version"
)

var serveCmd = newServeCommand(&serveEnv{lc: &localClient})

// newServeCommand returns a new "serve" subcommand using e as its environment.
func newServeCommand(e *serveEnv) *ffcli.Command {
	return &ffcli.Command{
		Name:      "serve",
		ShortHelp: "[BETA] Serve from your Tailscale node",
		ShortUsage: strings.TrimSpace(`
serve https:<port> <mount-point> <source> [off]
  serve tcp:<port> tcp://localhost:<local-port> [off]
  serve tls-terminated-tcp:<port> tcp://localhost:<local-port> [off]
  serve status [--json]
`),
		LongHelp: strings.TrimSpace(`
*** BETA; all of this is subject to change ***

The 'tailscale serve' set of commands allows you to serve
content and local servers from your Tailscale node to
your tailnet.

You can also choose to enable the Tailscale Funnel with:
'tailscale funnel on'. Funnel allows you to publish
a 'tailscale serve' server publicly, open to the entire
internet. See https://tailscale.com/funnel.

EXAMPLES
  - To proxy requests to a web server at 127.0.0.1:3000:
    $ tailscale serve https:443 / http://127.0.0.1:3000

	Or, using the default port:
	$ tailscale serve https / http://127.0.0.1:3000

  - To serve a single file or a directory of files:
    $ tailscale serve https / /home/alice/blog/index.html
    $ tailscale serve https /images/ /home/alice/blog/images

  - To serve simple static text:
    $ tailscale serve https:8080 / text:"Hello, world!"

  - To forward incoming TCP connections on port 2222 to a local TCP server on
    port 22 (e.g. to run OpenSSH in parallel with Tailscale SSH):
    $ tailscale serve tcp:2222 tcp://localhost:22

  - To accept TCP TLS connections (terminated within tailscaled) proxied to a
    local plaintext server on port 80:
    $ tailscale serve tls-terminated-tcp:443 tcp://localhost:80
`),
		Exec:      e.runServe,
		UsageFunc: usageFunc,
		Subcommands: []*ffcli.Command{
			{
				Name:      "status",
				Exec:      e.runServeStatus,
				ShortHelp: "show current serve/funnel status",
				FlagSet: e.newFlags("serve-status", func(fs *flag.FlagSet) {
					fs.BoolVar(&e.json, "json", false, "output JSON")
				}),
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

// localServeClient is an interface conforming to the subset of
// tailscale.LocalClient. It includes only the methods used by the
// serve command.
//
// The purpose of this interface is to allow tests to provide a mock.
type localServeClient interface {
	Status(context.Context) (*ipnstate.Status, error)
	GetServeConfig(context.Context) (*ipn.ServeConfig, error)
	SetServeConfig(context.Context, *ipn.ServeConfig) error
}

// serveEnv is the environment the serve command runs within. All I/O should be
// done via serveEnv methods so that it can be faked out for tests.
// Calls to localClient should be done via the lc field, which is an interface
// that can be faked out for tests.
//
// It also contains the flags, as registered with newServeCommand.
type serveEnv struct {
	// flags
	json bool // output JSON (status only for now)

	lc localServeClient // localClient interface, specific to serve

	// optional stuff for tests:
	testFlagOut io.Writer
	testStdout  io.Writer
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

// getLocalClientStatus returns the Status of the local client.
// Returns error if unable to reach tailscaled or if self node is nil.
//
// Exits if status is not running or starting.
func (e *serveEnv) getLocalClientStatus(ctx context.Context) (*ipnstate.Status, error) {
	st, err := e.lc.Status(ctx)
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

// runServe is the entry point for the "serve" subcommand, managing Web
// serve config types like proxy, path, and text.
//
// Examples:
// - tailscale serve https / http://localhost:3000
// - tailscale serve https /images/ /var/www/images/
// - tailscale serve https:10000 /motd.txt text:"Hello, world!"
// - tailscale serve tcp:2222 tcp://localhost:22
// - tailscale serve tls-terminated-tcp:443 tcp://localhost:80
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
		return e.lc.SetServeConfig(ctx, sc)
	}

	parsePort := func(portStr string) (uint16, error) {
		port64, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return 0, err
		}
		return uint16(port64), nil
	}

	srcType, srcPortStr, found := strings.Cut(args[0], ":")
	if !found {
		if srcType == "https" && srcPortStr == "" {
			// Default https port to 443.
			srcPortStr = "443"
		} else {
			return flag.ErrHelp
		}
	}

	turnOff := "off" == args[len(args)-1]

	if len(args) < 2 || (srcType == "https" && !turnOff && len(args) < 3) {
		fmt.Fprintf(os.Stderr, "error: invalid number of arguments\n\n")
		return flag.ErrHelp
	}

	srcPort, err := parsePort(srcPortStr)
	if err != nil {
		return err
	}

	switch srcType {
	case "https":
		mount, err := cleanMountPoint(args[1])
		if err != nil {
			return err
		}
		if turnOff {
			return e.handleWebServeRemove(ctx, srcPort, mount)
		}
		return e.handleWebServe(ctx, srcPort, mount, args[2])
	case "tcp", "tls-terminated-tcp":
		if turnOff {
			return e.handleTCPServeRemove(ctx, srcPort)
		}
		return e.handleTCPServe(ctx, srcType, srcPort, args[1])
	default:
		fmt.Fprintf(os.Stderr, "error: invalid serve type %q\n", srcType)
		fmt.Fprint(os.Stderr, "must be one of: https:<port>, tcp:<port> or tls-terminated-tcp:<port>\n\n", srcType)
		return flag.ErrHelp
	}
}

// handleWebServe handles the "tailscale serve https:..." subcommand.
// It configures the serve config to forward HTTPS connections to the
// given source.
//
// Examples:
//   - tailscale serve https / http://localhost:3000
//   - tailscale serve https:8443 /files/ /home/alice/shared-files/
//   - tailscale serve https:10000 /motd.txt text:"Hello, world!"
func (e *serveEnv) handleWebServe(ctx context.Context, srvPort uint16, mount, source string) error {
	h := new(ipn.HTTPHandler)

	ts, _, _ := strings.Cut(source, ":")
	switch {
	case ts == "text":
		text := strings.TrimPrefix(source, "text:")
		if text == "" {
			return errors.New("unable to serve; text cannot be an empty string")
		}
		h.Text = text
	case isProxyTarget(source):
		t, err := expandProxyTarget(source)
		if err != nil {
			return err
		}
		h.Proxy = t
	default: // assume path
		if version.IsSandboxedMacOS() {
			// don't allow path serving for now on macOS (2022-11-15)
			return fmt.Errorf("path serving is not supported if sandboxed on macOS")
		}
		if !filepath.IsAbs(source) {
			fmt.Fprintf(os.Stderr, "error: path must be absolute\n\n")
			return flag.ErrHelp
		}
		source = filepath.Clean(source)
		fi, err := os.Stat(source)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: invalid path: %v\n\n", err)
			return flag.ErrHelp
		}
		if fi.IsDir() && !strings.HasSuffix(mount, "/") {
			// dir mount points must end in /
			// for relative file links to work
			mount += "/"
		}
		h.Path = source
	}

	cursc, err := e.lc.GetServeConfig(ctx)
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
	hp := ipn.HostPort(net.JoinHostPort(dnsName, strconv.Itoa(int(srvPort))))

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
		if err := e.lc.SetServeConfig(ctx, sc); err != nil {
			return err
		}
	}

	return nil
}

// isProxyTarget reports whether source is a valid proxy target.
func isProxyTarget(source string) bool {
	if strings.HasPrefix(source, "http://") ||
		strings.HasPrefix(source, "https://") ||
		strings.HasPrefix(source, "https+insecure://") {
		return true
	}
	// support "localhost:3000", for example
	_, portStr, ok := strings.Cut(source, ":")
	if ok && allNumeric(portStr) {
		return true
	}
	return false
}

// allNumeric reports whether s only comprises of digits
// and has at least one digit.
func allNumeric(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// handleWebServeRemove removes a web handler from the serve config.
// The srvPort argument is the serving port and the mount argument is
// the mount point or registered path to remove.
func (e *serveEnv) handleWebServeRemove(ctx context.Context, srvPort uint16, mount string) error {
	sc, err := e.lc.GetServeConfig(ctx)
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
	hp := ipn.HostPort(net.JoinHostPort(dnsName, strconv.Itoa(int(srvPort))))
	if !sc.WebHandlerExists(hp, mount) {
		return errors.New("error: handler does not exist")
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
	if err := e.lc.SetServeConfig(ctx, sc); err != nil {
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

func expandProxyTarget(source string) (string, error) {
	if !strings.Contains(source, "://") {
		source = "http://" + source
	}
	u, err := url.ParseRequestURI(source)
	if err != nil {
		return "", fmt.Errorf("parsing url: %w", err)
	}
	switch u.Scheme {
	case "http", "https", "https+insecure":
		// ok
	default:
		return "", fmt.Errorf("must be a URL starting with http://, https://, or https+insecure://")
	}

	port, err := strconv.ParseUint(u.Port(), 10, 16)
	if port == 0 || err != nil {
		return "", fmt.Errorf("invalid port %q: %w", u.Port(), err)
	}

	host := u.Hostname()
	switch host {
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

// handleTCPServe handles the "tailscale serve tls-terminated-tcp:..." subcommand.
// It configures the serve config to forward TCP connections to the
// given source.
//
// Examples:
//   - tailscale serve tcp:2222 tcp://localhost:22
//   - tailscale serve tls-terminated-tcp:8443 tcp://localhost:8080
func (e *serveEnv) handleTCPServe(ctx context.Context, srcType string, srcPort uint16, dest string) error {
	var terminateTLS bool
	switch srcType {
	case "tcp":
		terminateTLS = false
	case "tls-terminated-tcp":
		terminateTLS = true
	default:
		fmt.Fprintf(os.Stderr, "error: invalid TCP source %q\n\n", dest)
		return flag.ErrHelp
	}

	dstURL, err := url.Parse(dest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid TCP source %q: %v\n\n", dest, err)
		return flag.ErrHelp
	}
	host, dstPortStr, err := net.SplitHostPort(dstURL.Host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid TCP source %q: %v\n\n", dest, err)
		return flag.ErrHelp
	}

	switch host {
	case "localhost", "127.0.0.1":
		// ok
	default:
		fmt.Fprintf(os.Stderr, "error: invalid TCP source %q\n", dest)
		fmt.Fprint(os.Stderr, "must be one of: localhost or 127.0.0.1\n\n", dest)
		return flag.ErrHelp
	}

	if p, err := strconv.ParseUint(dstPortStr, 10, 16); p == 0 || err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid port %q\n\n", dstPortStr)
		return flag.ErrHelp
	}

	cursc, err := e.lc.GetServeConfig(ctx)
	if err != nil {
		return err
	}
	sc := cursc.Clone() // nil if no config
	if sc == nil {
		sc = new(ipn.ServeConfig)
	}

	fwdAddr := "127.0.0.1:" + dstPortStr

	if sc.IsServingWeb(srcPort) {
		return fmt.Errorf("cannot serve TCP; already serving web on %d", srcPort)
	}

	mak.Set(&sc.TCP, srcPort, &ipn.TCPPortHandler{TCPForward: fwdAddr})

	dnsName, err := e.getSelfDNSName(ctx)
	if err != nil {
		return err
	}
	if terminateTLS {
		sc.TCP[srcPort].TerminateTLS = dnsName
	}

	if !reflect.DeepEqual(cursc, sc) {
		if err := e.lc.SetServeConfig(ctx, sc); err != nil {
			return err
		}
	}

	return nil
}

// handleTCPServeRemove removes the TCP forwarding configuration for the
// given srvPort, or serving port.
func (e *serveEnv) handleTCPServeRemove(ctx context.Context, src uint16) error {
	cursc, err := e.lc.GetServeConfig(ctx)
	if err != nil {
		return err
	}
	sc := cursc.Clone() // nil if no config
	if sc == nil {
		sc = new(ipn.ServeConfig)
	}
	if sc.IsServingWeb(src) {
		return fmt.Errorf("unable to remove; serving web, not TCP forwarding on serve port %d", src)
	}
	if ph := sc.GetTCPPortHandler(src); ph != nil {
		delete(sc.TCP, src)
		// clear map mostly for testing
		if len(sc.TCP) == 0 {
			sc.TCP = nil
		}
		return e.lc.SetServeConfig(ctx, sc)
	}
	return errors.New("error: serve config does not exist")
}

// runServeStatus is the entry point for the "serve status"
// subcommand and prints the current serve config.
//
// Examples:
//   - tailscale status
//   - tailscale status --json
func (e *serveEnv) runServeStatus(ctx context.Context, args []string) error {
	sc, err := e.lc.GetServeConfig(ctx)
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
	printFunnelStatus(ctx)
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
	printFunnelWarning(sc)
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
		if sc.AllowFunnel[hp] {
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
	if sc.AllowFunnel[hp] {
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
