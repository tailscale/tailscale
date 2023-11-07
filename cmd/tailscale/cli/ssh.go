// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/envknob"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/tsaddr"
	"tailscale.com/paths"
	"tailscale.com/version"
)

var sshCmd = &ffcli.Command{
	Name:       "ssh",
	ShortUsage: "ssh [user@]<host> [args...]",
	ShortHelp:  "SSH to a Tailscale machine",
	LongHelp: strings.TrimSpace(`

The 'tailscale ssh' command is an optional wrapper around the system 'ssh'
command that's useful in some cases. Tailscale SSH does not require its use;
most users running the Tailscale SSH server will prefer to just use the normal
'ssh' command or their normal SSH client.

The 'tailscale ssh' wrapper adds a few things:

* It resolves the destination server name in its arguments using MagicDNS,
  even if --accept-dns=false.
* It works in userspace-networking mode, by supplying a ProxyCommand to the
  system 'ssh' command that connects via a pipe through tailscaled.
* It automatically checks the destination server's SSH host key against the
  node's SSH host key as advertised via the Tailscale coordination server.

Tailscale can also be integrated with the system 'ssh' and related commands
by using the --config flag. This will output an SSH config snippet that can 
be added to your ~/.ssh/config file to enable Tailscale for all SSH connections.
`),
	Exec: runSSH,
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("ssh")
		fs.BoolVar(&sshArgs.config, "config", false, "output an SSH config snippet to integrate with standard ssh")
		fs.StringVar(&sshArgs.check, "check", "", "check if host SSH is managed by Tailscale")
		return fs
	})(),
}

var sshArgs struct {
	check  string // Check if host SSH is managed by Tailscale
	config bool   // Output an SSH config snippet to integrate with standard ssh
}

func runSSH(ctx context.Context, args []string) error {
	tailscaleBin, err := os.Executable()
	if err != nil {
		return err
	}
	st, err := localClient.Status(ctx)
	if err != nil {
		return err
	}
	knownHostsFile, err := writeKnownHosts(st)
	if err != nil {
		return err
	}
	if sshArgs.check != "" {
		if isSSHHost(st, sshArgs.check) {
			return nil
		} else {
			return errors.New("host ssh is not managed by Tailscale")
		}
	}
	if sshArgs.config {
		fmt.Printf(`
# Tailscale ssh config
Match exec "%s ssh --check %%h"
  UserKnownHostsFile %s
`, tailscaleBin, knownHostsFile)
		return nil
	}
	if runtime.GOOS == "darwin" && version.IsSandboxedMacOS() && !envknob.UseWIPCode() {
		return errors.New("The 'tailscale ssh' wrapper subcommand is not available on sandboxed macOS builds.\nUse the regular 'ssh' client instead.")
	}
	if len(args) == 0 {
		return errors.New("usage: ssh [user@]<host>")
	}
	arg, argRest := args[0], args[1:]
	username, host, ok := strings.Cut(arg, "@")
	if !ok {
		host = arg
		lu, err := user.Current()
		if err != nil {
			return nil
		}
		username = lu.Username
	}

	// hostForSSH is the hostname we'll tell OpenSSH we're
	// connecting to, so we have to maintain fewer entries in the
	// known_hosts files.
	hostForSSH := host
	if v, ok := nodeDNSNameFromArg(st, host); ok {
		hostForSSH = v
	}
	ssh, err := findSSH()
	if err != nil {
		// TODO(bradfitz): use Go's crypto/ssh client instead
		// of failing. But for now:
		return fmt.Errorf("no system 'ssh' command found: %w", err)
	}

	argv := []string{ssh}

	if envknob.Bool("TS_DEBUG_SSH_EXEC") {
		argv = append(argv, "-vvv")
	}
	argv = append(argv,
		// Only trust SSH hosts that we know about.
		"-o", fmt.Sprintf("UserKnownHostsFile %q", knownHostsFile),
		"-o", "UpdateHostKeys no",
		"-o", "StrictHostKeyChecking yes",
	)

	// TODO(bradfitz): nc is currently broken on macOS:
	// https://github.com/tailscale/tailscale/issues/4529
	// So don't use it for now. MagicDNS is usually working on macOS anyway
	// and they're not in userspace mode, so 'nc' isn't very useful.
	if runtime.GOOS != "darwin" {
		socketArg := ""
		if rootArgs.socket != "" && rootArgs.socket != paths.DefaultTailscaledSocket() {
			socketArg = fmt.Sprintf("--socket=%q", rootArgs.socket)
		}

		argv = append(argv,
			"-o", fmt.Sprintf("ProxyCommand %q %s nc %%h %%p",
				tailscaleBin,
				socketArg,
			))
	}

	// Explicitly rebuild the user@host argument rather than
	// passing it through.  In general, the use of OpenSSH's ssh
	// binary is a crutch for now.  We don't want to be
	// Hyrum-locked into passing through all OpenSSH flags to the
	// OpenSSH client forever. We try to make our flags and args
	// be compatible, but only a subset. The "tailscale ssh"
	// command should be a simple and portable one. If they want
	// to use a different one, we'll later be making stock ssh
	// work well by default too. (doing things like automatically
	// setting known_hosts, etc)
	argv = append(argv, username+"@"+hostForSSH)

	argv = append(argv, argRest...)

	if envknob.Bool("TS_DEBUG_SSH_EXEC") {
		log.Printf("Running: %q, %q ...", ssh, argv)
	}

	return execSSH(ssh, argv)
}

func writeKnownHosts(st *ipnstate.Status) (knownHostsFile string, err error) {
	confDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	tsConfDir := filepath.Join(confDir, "tailscale")
	if err := os.MkdirAll(tsConfDir, 0700); err != nil {
		return "", err
	}
	knownHostsFile = filepath.Join(tsConfDir, "ssh_known_hosts")
	want := genKnownHosts(st)
	if cur, err := os.ReadFile(knownHostsFile); err != nil || !bytes.Equal(cur, want) {
		if err := os.WriteFile(knownHostsFile, want, 0644); err != nil {
			return "", err
		}
	}
	return knownHostsFile, nil
}

func genKnownHosts(st *ipnstate.Status) []byte {
	var buf bytes.Buffer
	for _, k := range st.Peers() {
		ps := st.Peer[k]
		for _, hk := range ps.SSH_HostKeys {
			hostKey := strings.TrimSpace(hk)
			if strings.ContainsAny(hostKey, "\n\r") { // invalid
				continue
			}
			// Join all ps.TailscaleIPs as strings separated by commas.
			ips := make([]string, len(ps.TailscaleIPs))
			for i, ip := range ps.TailscaleIPs {
				ips[i] = ip.String()
			}
			// Generate comma separated string of all possible names for the host.
			n := strings.Join(append(ips, ps.DNSName, strings.TrimSuffix(ps.DNSName, "."), strings.Split(ps.DNSName, ".")[0]), ",")
			fmt.Fprintf(&buf, "%s %s\n", n, hostKey)
		}
	}
	return buf.Bytes()
}

// nodeFromArg returns the PeerStatus value from a peer in st that matches the input arg
// which can be a base name, full DNS name, or an IP.
func nodeFromArg(st *ipnstate.Status, arg string) (ps *ipnstate.PeerStatus, ok bool) {
	if arg == "" {
		return
	}
	argIP, _ := netip.ParseAddr(arg)
	for _, ps = range st.Peer {
		if argIP.IsValid() {
			for _, ip := range ps.TailscaleIPs {
				if ip == argIP {
					return ps, true
				}
			}
			continue
		}
		if strings.EqualFold(strings.TrimSuffix(arg, "."), strings.TrimSuffix(ps.DNSName, ".")) {
			return ps, true
		}
		if base, _, ok := strings.Cut(ps.DNSName, "."); ok && strings.EqualFold(base, arg) {
			return ps, true
		}
	}
	return nil, false
}

// nodeDNSNameFromArg returns the PeerStatus.DNSName value from a peer
// in st that matches the input arg which can be a base name, full
// DNS name, or an IP.
func nodeDNSNameFromArg(st *ipnstate.Status, arg string) (dnsName string, ok bool) {
	ps, ok := nodeFromArg(st, arg)
	if !ok {
		return "", false
	}
	return ps.DNSName, true
}

// getSSHClientEnvVar returns the "SSH_CLIENT" environment variable
// for the current process group, if any.
var getSSHClientEnvVar = func() string {
	return ""
}

// isSSHOverTailscale checks if the invocation is in a SSH session over Tailscale.
// It is used to detect if the user is about to take an action that might result in them
// disconnecting from the machine (e.g. disabling SSH)
func isSSHOverTailscale() bool {
	sshClient := getSSHClientEnvVar()
	if sshClient == "" {
		return false
	}
	ipStr, _, ok := strings.Cut(sshClient, " ")
	if !ok {
		return false
	}
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}
	return tsaddr.IsTailscaleIP(ip)
}

// isSSHHost checks if the node's ssh is managed by Tailscale.
func isSSHHost(st *ipnstate.Status, arg string) bool {
	ps, ok := nodeFromArg(st, arg)
	if !ok {
		return false
	}
	if len(ps.SSH_HostKeys) == 0 {
		return false
	}
	return true
}
