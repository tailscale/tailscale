// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"tailscale.com/util/httpm"
	"time"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/client/local"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/paths"
	"tailscale.com/tailcfg"
)

// Command definiton

var doctorCmd = &ffcli.Command{
	Name:       "doctor",
	ShortHelp:  "Run diagnostics on tailnet",
	ShortUsage: "tailscale doctor [flags]",
	LongHelp: strings.TrimSpace(`
Run a suite of pre-flight diagnostic checks and print a pass/warn/fail summary.

Checks performed:
  daemon    tailscaled is running and reachable
  auth      authentication / login state
  net       control plane and DERP reachability
  expiry    auth key expiry warning
  dns       MagicDNS resolution
  acl       peer reachability (auto-detected, or via --peer for a specific target)
  routes    subnet route advertising
  exitnode  exit node configuration
  version   client version
  clockskew system clock vs control plane time
  cacert    control plane CA certificate validity

Examples:
  tailscale doctor
  tailscale doctor --verbose
  tailscale doctor --json
  tailscale doctor --peer 100.64.0.2
  tailscale doctor --peer db-prod:5432
  tailscale doctor --check acl
`),
	FlagSet: doctorFlagSet(),
	Exec:    runDoctor,
}

var doctorArgs struct {
	verbose bool
	jsonOut bool
	peer    string
	check   string
}

func doctorFlagSet() *flag.FlagSet {
	fs := newFlagSet("doctor")
	fs.BoolVar(&doctorArgs.verbose, "verbose", false, "show full detail for each check")
	fs.BoolVar(&doctorArgs.verbose, "v", false, "shorthand for --verbose")
	fs.BoolVar(&doctorArgs.jsonOut, "json", false, "output results as JSON")
	fs.StringVar(&doctorArgs.peer, "peer", "", "check ACL reachability to a specific peer IP, hostname, or host:port")
	fs.StringVar(&doctorArgs.check, "check", "", "run only one check: daemon|auth|net|expiry|dns|acl|routes|exitnode|version|clockskew|cacert")
	return fs
}

type checkStatus string

const (
	statusPass checkStatus = "pass"
	statusWarn checkStatus = "warn"
	statusFail checkStatus = "fail"
	statusSkip checkStatus = "skip"
)

type checkResult struct {
	Name    string      `json:"name"`
	Status  checkStatus `json:"status"`
	Message string      `json:"message"`
	Detail  string      `json:"detail,omitempty"`
	Fix     string      `json:"fix,omitempty"`
}

func (r checkResult) icon() string {
	switch r.Status {
	case statusPass:
		return "OK  "
	case statusWarn:
		return "WARN"
	case statusFail:
		return "FAIL"
	case statusSkip:
		return "SKIP"
	}
	return "    "
}

// initial entry point
func runDoctor(ctx context.Context, args []string) error {
	// ignore versions for now
	local.SetVersionMismatchHandler(func(_, _ string) {})

	// Enforce a 5-second total budget across all checks.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Fetch status once; all checks share it. If the daemon is unreachable,
	// statusErr is non-nil and each check degrades gracefully.
	st, statusErr := localClient.Status(ctx)

	results := runAllChecks(ctx, st, statusErr)

	if doctorArgs.jsonOut {
		return printDoctorJSON(results)
	}
	printDoctorTable(results)
	return nil
}

type namedCheck struct {
	id string
	fn func() checkResult
}

func runAllChecks(ctx context.Context, st *ipnstate.Status, statusErr error) []checkResult {
	checks := []namedCheck{
		{"daemon", func() checkResult { return checkDaemon(statusErr) }},
		{"auth", func() checkResult { return checkAuth(st, statusErr) }},
		{"net", func() checkResult { return checkNetwork(ctx, statusErr) }},
		{"expiry", func() checkResult { return checkKeyExpiry(st, statusErr) }},
		{"dns", func() checkResult { return checkDNS(ctx, st, statusErr) }},
		{"acl", func() checkResult { return checkACL(ctx, st, statusErr) }},
		{"routes", func() checkResult { return checkSubnetRoutes(st, statusErr) }},
		{"exitnode", func() checkResult { return checkExitNode(st, statusErr) }},
		{"version", func() checkResult { return checkVersion(st, statusErr) }},
		{"clockskew", func() checkResult { return checkClockSkew(ctx, statusErr) }},
		{"cacert", func() checkResult { return checkCACert(ctx) }},
	}

	// Single-check mode via --check flag.
	if doctorArgs.check != "" {
		for _, c := range checks {
			if c.id == doctorArgs.check {
				return []checkResult{c.fn()}
			}
		}
		return []checkResult{{
			Name:    doctorArgs.check,
			Status:  statusFail,
			Message: fmt.Sprintf("unknown check %q — valid: daemon, auth, net, expiry, dns, acl, routes, exitnode, version, clockskew, cacert", doctorArgs.check),
		}}
	}

	// Run all checks concurrently; preserve output order.
	results := make([]checkResult, len(checks))
	var wg sync.WaitGroup
	for i, c := range checks {
		wg.Add(1)
		go func(idx int, fn func() checkResult) {
			defer wg.Done()
			results[idx] = fn()
		}(i, c.fn)
	}
	wg.Wait()
	return results
}

// Individual checks

func checkDERPTor(ctx context.Context, statusErr error) checkResult {
	name := "DERP/Tor"
	if statusErr != nil {
		return checkResult{Name: name, Status: statusSkip, Message: "skipped (daemon unreachable)"}
	}

	st, err := localClient.DebugDERPRegion(ctx, "tor")
	if err != nil {
		return checkResult{
			Name:    name,
			Status:  statusFail,
			Message: "DERP tor region unreachable",
			Detail:  err.Error(),
		}
	}
	_ = st // inspect st fields as needed
	return checkResult{Name: name, Status: statusPass, Message: "DERP tor region reachable"}
}

// checkDaemon verifies tailscaled is running and reachable via the local API.
func checkDaemon(statusErr error) checkResult {
	name := "Daemon"
	if statusErr == nil {
		return checkResult{Name: name, Status: statusPass, Message: "tailscaled is running"}
	}
	fix := "Start the daemon: sudo tailscaled"
	if strings.Contains(statusErr.Error(), "permission denied") {
		fix = "Permission denied — try running as root or check socket permissions"
	}
	return checkResult{
		Name:    name,
		Status:  statusFail,
		Message: "Cannot reach tailscaled",
		Detail:  statusErr.Error(),
		Fix:     fix,
	}
}

// checkAuth verifies the user is logged in and the backend is in a healthy state.
func checkAuth(st *ipnstate.Status, statusErr error) checkResult {
	name := "Auth"
	if statusErr != nil || st == nil {
		return checkResult{Name: name, Status: statusSkip, Message: "skipped (daemon unreachable)"}
	}
	switch st.BackendState {
	case "Running":
		msg := "Logged in"
		if st.Self != nil && st.Self.Tags != nil && st.Self.Tags.Len() > 0 {
			msg += fmt.Sprintf(" (tags: %s)", strings.Join(st.Self.Tags.AsSlice(), ", "))
		}
		return checkResult{Name: name, Status: statusPass, Message: msg}
	case "NeedsLogin":
		return checkResult{
			Name:    name,
			Status:  statusFail,
			Message: "Not logged in",
			Fix:     "Run: tailscale up",
		}
	case "Stopped":
		return checkResult{
			Name:    name,
			Status:  statusFail,
			Message: "Tailscale is stopped",
			Fix:     "Run: tailscale up",
		}
	default:
		return checkResult{
			Name:    name,
			Status:  statusWarn,
			Message: fmt.Sprintf("Unexpected backend state: %s", st.BackendState),
		}
	}
}

// checkNetwork verifies the daemon can reach the Tailscale control plane by
// fetching the DERP map. Run 'tailscale netcheck' for detailed latency info.
func checkNetwork(ctx context.Context, statusErr error) checkResult {
	name := "Network"
	if statusErr != nil {
		return checkResult{Name: name, Status: statusSkip, Message: "skipped (daemon unreachable)"}
	}

	dm, err := localClient.CurrentDERPMap(ctx)
	if err != nil || dm == nil || len(dm.Regions) == 0 {
		detail := ""
		if err != nil {
			detail = err.Error()
		}
		return checkResult{
			Name:    name,
			Status:  statusWarn,
			Message: "Cannot reach Tailscale control plane",
			Detail:  detail,
			Fix:     "Check your internet connection; run 'tailscale netcheck' for details",
		}
	}

	return checkResult{
		Name:    name,
		Status:  statusPass,
		Message: fmt.Sprintf("Control plane reachable (%d DERP regions)", len(dm.Regions)),
		Detail:  "Run 'tailscale netcheck' for DERP latency details",
	}
}

// checkKeyExpiry warns when the node key is close to expiring.
func checkKeyExpiry(st *ipnstate.Status, statusErr error) checkResult {
	name := "Key expiry"
	if statusErr != nil || st == nil || st.Self == nil {
		return checkResult{Name: name, Status: statusSkip, Message: "skipped (daemon unreachable)"}
	}

	expiry := st.Self.KeyExpiry
	if expiry == nil || expiry.IsZero() {
		return checkResult{Name: name, Status: statusPass, Message: "Key does not expire (tagged device or expiry disabled)"}
	}

	daysLeft := time.Until(*expiry).Hours() / 24
	switch {
	case daysLeft < 0:
		return checkResult{
			Name:    name,
			Status:  statusFail,
			Message: fmt.Sprintf("Key expired %s ago", doctorFormatDuration(time.Since(*expiry))),
			Fix:     "Run: tailscale up --auth-key=<new-key>",
		}
	case daysLeft < 3:
		return checkResult{
			Name:    name,
			Status:  statusFail,
			Message: fmt.Sprintf("Key expires in %.0f days — renew immediately", daysLeft),
			Fix:     "Run: tailscale up  (or enable key auto-renewal in the admin console)",
		}
	case daysLeft < 14:
		return checkResult{
			Name:    name,
			Status:  statusWarn,
			Message: fmt.Sprintf("Key expires in %.0f days", daysLeft),
			Detail:  fmt.Sprintf("Expiry: %s", expiry.Format(time.RFC1123)),
			Fix:     "Run: tailscale up  (or enable key auto-renewal in the admin console)",
		}
	default:
		return checkResult{
			Name:    name,
			Status:  statusPass,
			Message: fmt.Sprintf("%.0f days remaining", daysLeft),
			Detail:  fmt.Sprintf("Expiry: %s", expiry.Format(time.RFC1123)),
		}
	}
}

// checkDNS verifies MagicDNS can resolve the node's own hostname.
func checkDNS(ctx context.Context, st *ipnstate.Status, statusErr error) checkResult {
	name := "MagicDNS"
	if statusErr != nil || st == nil {
		return checkResult{Name: name, Status: statusSkip, Message: "skipped (daemon unreachable)"}
	}
	if st.CurrentTailnet.MagicDNSSuffix == "" {
		return checkResult{Name: name, Status: statusSkip, Message: "MagicDNS not enabled on this tailnet"}
	}
	if st.Self == nil || st.Self.DNSName == "" {
		return checkResult{Name: name, Status: statusSkip, Message: "No DNS name available to test"}
	}

	hostname := strings.TrimSuffix(st.Self.DNSName, ".")
	dnsCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupHost(dnsCtx, hostname)
	if err != nil {
		return checkResult{
			Name:    name,
			Status:  statusFail,
			Message: fmt.Sprintf("Cannot resolve %s", hostname),
			Detail:  err.Error(),
			Fix:     "Run: tailscale up --accept-dns=true",
		}
	}

	return checkResult{
		Name:    name,
		Status:  statusPass,
		Message: fmt.Sprintf("Resolving %s -> %s", hostname, strings.Join(addrs, ", ")),
	}
}

// checkACL checks peer reachability.
// With --peer: TCP probe to the specified host:port.
// Without --peer: disco-ping all online peers (up to maxACLPeers).
func checkACL(ctx context.Context, st *ipnstate.Status, statusErr error) checkResult {
	name := "ACL"
	if statusErr != nil || st == nil {
		return checkResult{Name: name, Status: statusSkip, Message: "skipped (daemon unreachable)"}
	}

	if doctorArgs.peer != "" {
		return checkACLPeer(ctx, name, doctorArgs.peer)
	}
	return checkACLAutoDetect(ctx, name, st)
}

// checkACLPeer does a TCP probe to a specific peer (--peer flag).
// "connection refused" counts as reachable — ACLs allow the traffic,
// the service is just not listening on that port.
func checkACLPeer(ctx context.Context, name, peer string) checkResult {
	addr := peer
	if !strings.Contains(addr, ":") {
		addr = net.JoinHostPort(peer, "80")
	}

	dialCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "connection refused") {
			return checkResult{
				Name:    name,
				Status:  statusPass,
				Message: fmt.Sprintf("Host reachable (port refused at %s)", addr),
				Detail:  "Connection refused means ACLs allow the traffic; the service is just not listening on that port",
			}
		}
		return checkResult{
			Name:    name,
			Status:  statusFail,
			Message: fmt.Sprintf("Cannot reach %s", addr),
			Detail:  errStr,
			Fix:     "Check ACL rules — this peer may be blocked from your node",
		}
	}
	conn.Close()
	return checkResult{
		Name:    name,
		Status:  statusPass,
		Message: fmt.Sprintf("Reachable at %s", addr),
	}
}

// maxACLPeers caps the number of peers probed during auto-detection.
const maxACLPeers = 10

// checkACLAutoDetect probes up to maxACLPeers online peers via Tailscale disco ping.
func checkACLAutoDetect(ctx context.Context, name string, st *ipnstate.Status) checkResult {
	type peerTarget struct {
		label string
		ip    netip.Addr
	}

	var targets []peerTarget
	for _, ps := range st.Peer {
		if ps.Online && len(ps.TailscaleIPs) > 0 {
			label := ps.HostName
			if label == "" {
				label = ps.TailscaleIPs[0].String()
			}
			targets = append(targets, peerTarget{label: label, ip: ps.TailscaleIPs[0]})
			if len(targets) >= maxACLPeers {
				break
			}
		}
	}
	// If the control plane hasn't reported any peer's online status, fall back
	// to all peers with IPs. The disco ping determines actual reachability.
	if len(targets) == 0 {
		for _, ps := range st.Peer {
			if len(ps.TailscaleIPs) == 0 {
				continue
			}
			label := ps.HostName
			if label == "" {
				label = ps.TailscaleIPs[0].String()
			}
			targets = append(targets, peerTarget{label: label, ip: ps.TailscaleIPs[0]})
			if len(targets) >= maxACLPeers {
				break
			}
		}
	}

	if len(targets) == 0 {
		return checkResult{Name: name, Status: statusSkip, Message: "No peers to check"}
	}

	type result struct {
		label string
		ok    bool
		err   string
	}
	results := make([]result, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(idx int, target peerTarget) {
			defer wg.Done()
			pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			pr, err := localClient.Ping(pingCtx, target.ip, tailcfg.PingDisco)
			if err != nil || (pr != nil && pr.Err != "") {
				msg := ""
				if err != nil {
					msg = err.Error()
				} else {
					msg = pr.Err
				}
				results[idx] = result{label: target.label, ok: false, err: msg}
			} else {
				results[idx] = result{label: target.label, ok: true}
			}
		}(i, t)
	}
	wg.Wait()

	var failed []string
	for _, r := range results {
		if !r.ok {
			failed = append(failed, r.label)
		}
	}

	total := len(targets)
	reachable := total - len(failed)

	if len(failed) == 0 {
		return checkResult{
			Name:    name,
			Status:  statusPass,
			Message: fmt.Sprintf("%d/%d peers reachable", reachable, total),
		}
	}
	if len(failed) == total {
		return checkResult{
			Name:    name,
			Status:  statusFail,
			Message: fmt.Sprintf("0/%d peers reachable", total),
			Detail:  fmt.Sprintf("Unreachable: %s", strings.Join(failed, ", ")),
			Fix:     "Check ACL rules — no peers are reachable from this node",
		}
	}
	return checkResult{
		Name:    name,
		Status:  statusWarn,
		Message: fmt.Sprintf("%d/%d peers reachable", reachable, total),
		Detail:  fmt.Sprintf("Unreachable: %s", strings.Join(failed, ", ")),
		Fix:     "Some peers unreachable — check ACL rules or use --peer <host:port> for details",
	}
}

// checkSubnetRoutes verifies this node is advertising any configured subnet routes.
func checkSubnetRoutes(st *ipnstate.Status, statusErr error) checkResult {
	name := "Subnet routes"
	if statusErr != nil || st == nil || st.Self == nil {
		return checkResult{Name: name, Status: statusSkip, Message: "skipped (daemon unreachable)"}
	}

	routes := st.Self.PrimaryRoutes
	if routes == nil || len(routes.AsSlice()) == 0 {
		return checkResult{Name: name, Status: statusSkip, Message: "No subnet routes configured on this node"}
	}

	prefixes := routes.AsSlice()
	strs := make([]string, len(prefixes))
	for i, p := range prefixes {
		strs[i] = p.String()
	}

	return checkResult{
		Name:    name,
		Status:  statusPass,
		Message: fmt.Sprintf("%d route(s) advertised", len(prefixes)),
		Detail:  fmt.Sprintf("Routes: %s", strings.Join(strs, ", ")),
	}
}

// checkExitNode reports whether an exit node is currently active.
func checkExitNode(st *ipnstate.Status, statusErr error) checkResult {
	name := "Exit node"
	if statusErr != nil || st == nil {
		return checkResult{Name: name, Status: statusSkip, Message: "skipped (daemon unreachable)"}
	}

	for _, peer := range st.Peer {
		if peer.ExitNode {
			ip := ""
			if len(peer.TailscaleIPs) > 0 {
				ip = fmt.Sprintf(" (%s)", peer.TailscaleIPs[0])
			}
			return checkResult{
				Name:    name,
				Status:  statusPass,
				Message: fmt.Sprintf("Active: %s%s", peer.HostName, ip),
			}
		}
	}

	return checkResult{
		Name:    name,
		Status:  statusPass,
		Message: "Not configured (OK)",
	}
}

// checkVersion reports the running daemon version.
func checkVersion(st *ipnstate.Status, statusErr error) checkResult {
	name := "Version"
	if statusErr != nil {
		return checkResult{Name: name, Status: statusSkip, Message: "skipped (daemon unreachable)"}
	}
	if st != nil && st.Version != "" {
		return checkResult{
			Name:    name,
			Status:  statusPass,
			Message: fmt.Sprintf("v%s", st.Version),
			Detail:  fmt.Sprintf("OS: %s/%s", runtime.GOOS, runtime.GOARCH),
		}
	}
	return checkResult{Name: name, Status: statusSkip, Message: "version unknown"}
}

// checkClockSkew compares local time against the Tailscale control plane's
// Date response header. WireGuard rejects handshakes outside a ~3-minute
// window, so significant skew causes silent connectivity failures.
func checkClockSkew(ctx context.Context, statusErr error) checkResult {
	name := "Clock skew"
	if statusErr != nil {
		return checkResult{Name: name, Status: statusSkip, Message: "skipped (daemon unreachable)"}
	}

	reqCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(reqCtx, httpm.HEAD, "https://controlplane.tailscale.com", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return checkResult{Name: name, Status: statusSkip, Message: "skipped (cannot reach control plane)", Detail: err.Error()}
	}
	resp.Body.Close()

	dateStr := resp.Header.Get("Date")
	if dateStr == "" {
		return checkResult{Name: name, Status: statusSkip, Message: "skipped (no Date header in response)"}
	}

	serverTime, err := http.ParseTime(dateStr)
	if err != nil {
		return checkResult{Name: name, Status: statusSkip, Message: "skipped (unparseable Date header)"}
	}

	skew := time.Since(serverTime)
	if skew < 0 {
		skew = -skew
	}

	switch {
	case skew > 2*time.Minute:
		return checkResult{
			Name:    name,
			Status:  statusFail,
			Message: fmt.Sprintf("Clock skew: %s", skew.Round(time.Second)),
			Detail:  fmt.Sprintf("Local: %s  Server: %s", time.Now().UTC().Format(time.RFC3339), serverTime.UTC().Format(time.RFC3339)),
			Fix:     "Sync your system clock: sudo systemctl restart systemd-timesyncd (or ntpd/chrony)",
		}
	case skew > 30*time.Second:
		return checkResult{
			Name:    name,
			Status:  statusWarn,
			Message: fmt.Sprintf("Clock skew: %s", skew.Round(time.Second)),
			Detail:  fmt.Sprintf("Local: %s  Server: %s", time.Now().UTC().Format(time.RFC3339), serverTime.UTC().Format(time.RFC3339)),
			Fix:     "Consider syncing your system clock",
		}
	default:
		return checkResult{
			Name:    name,
			Status:  statusPass,
			Message: fmt.Sprintf("Clock in sync (skew: %s)", skew.Round(time.Millisecond)),
		}
	}
}

// checkCACert verifies the stored control plane CA certificate still validates
// the live server. It reads the PEM file written by "tailscale debug download-cert",
// builds a cert pool from it, and performs a TLS handshake against
// controlplane.tailscale.com using that pool as the only trusted root.
func checkCACert(ctx context.Context) checkResult {
	name := "CA cert"
	certPath := filepath.Join(paths.DefaultTailscaledStateDir(), "control-ca.pem")

	data, err := os.ReadFile(certPath)
	if err != nil {
		return checkResult{
			Name:    name,
			Status:  statusFail,
			Message: "No stored CA certificate found",
			Detail:  certPath,
			Fix:     "Run: tailscale debug download-cert",
		}
	}

	pool := x509.NewCertPool()
	var certCount int
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		pool.AddCert(cert)
		certCount++
	}
	if certCount == 0 {
		return checkResult{
			Name:    name,
			Status:  statusFail,
			Message: "Stored file contains no valid certificates",
			Detail:  certPath,
			Fix:     "Run: tailscale debug download-cert to re-download",
		}
	}

	const host = "controlplane.tailscale.com"
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	conn, err := (&tls.Dialer{
		Config: &tls.Config{
			ServerName: host,
			RootCAs:    pool,
		},
	}).DialContext(dialCtx, "tcp", host+":443")
	if err != nil {
		return checkResult{
			Name:    name,
			Status:  statusFail,
			Message: "Stored certificate does not validate the control server",
			Detail:  err.Error(),
			Fix:     "Run: tailscale debug download-cert to refresh the stored certificate",
		}
	}
	conn.Close()

	return checkResult{
		Name:    name,
		Status:  statusPass,
		Message: fmt.Sprintf("Stored certificate validates %s (%d cert(s) in chain)", host, certCount),
		Detail:  certPath,
	}
}

// Formatting

func printDoctorTable(results []checkResult) {
	errs, warns := 0, 0
	for _, r := range results {
		switch r.Status {
		case statusFail:
			errs++
		case statusWarn:
			warns++
		}
	}

	const nameWidth = 14
	fmt.Println()
	for _, r := range results {
		fmt.Printf("  [%s]  %-*s  %s\n", r.icon(), nameWidth, r.Name, r.Message)
		if r.Fix != "" {
			fmt.Printf("          %-*s  Fix: %s\n", nameWidth, "", r.Fix)
		}
		if doctorArgs.verbose && r.Detail != "" {
			fmt.Printf("          %-*s  %s\n", nameWidth, "", r.Detail)
		}
	}
	fmt.Println()

	switch {
	case errs > 0 && warns > 0:
		fmt.Printf("  %d error(s), %d warning(s). Run with --verbose for full details.\n\n", errs, warns)
	case errs > 0:
		fmt.Printf("  %d error(s). Run with --verbose for full details.\n\n", errs)
	case warns > 0:
		fmt.Printf("  %d warning(s). Run with --verbose for full details.\n\n", warns)
	default:
		fmt.Println("  All checks passed.")
	}
}

func printDoctorJSON(results []checkResult) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"os":        runtime.GOOS,
		"arch":      runtime.GOARCH,
		"checks":    results,
	})
}

func doctorFormatDuration(d time.Duration) string {
	d = d.Round(time.Minute)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h >= 24 {
		return fmt.Sprintf("%d days", h/24)
	}
	if h > 0 {
		return fmt.Sprintf("%dh%dm", h, m)
	}
	return fmt.Sprintf("%dm", m)
}
