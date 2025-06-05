// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows && !plan9

package vms

import (
	"context"
	"testing"
	"time"

	"github.com/pkg/sftp"
	expect "github.com/tailscale/goexpect"
)

func TestRunUbuntu2404(t *testing.T) {
	testOneDistribution(t, 0, Distros[0])
}

func TestRunNixos2505(t *testing.T) {
	t.Parallel()
	testOneDistribution(t, 1, Distros[1])
}

// TestMITMProxy is a smoke test for derphttp through a MITM proxy.
// Encountering such proxies is unfortunately commonplace in more
// traditional enterprise networks.
//
// We invoke tailscale netcheck because the networking check is done
// by tailscale rather than tailscaled, making it easier to configure
// the proxy.
//
// To provide the actual MITM server, we use squid.
func TestMITMProxy(t *testing.T) {
	t.Parallel()
	setupTests(t)
	distro := Distros[1] // nixos-25.05

	ctx, done := context.WithCancel(context.Background())
	t.Cleanup(done)

	h := newHarness(t)

	err := ramsem.sem.Acquire(ctx, int64(distro.MemoryMegs))
	if err != nil {
		t.Fatalf("can't acquire ram semaphore: %v", err)
	}
	t.Cleanup(func() { ramsem.sem.Release(int64(distro.MemoryMegs)) })

	vm := h.mkVM(t, 2, distro, h.pubKey, h.loginServerURL, t.TempDir())
	vm.waitStartup(t)

	ipm := h.waitForIPMap(t, vm, distro)
	_, cli := h.setupSSHShell(t, distro, ipm)

	sftpCli, err := sftp.NewClient(cli)
	if err != nil {
		t.Fatalf("can't connect over sftp to copy binaries: %v", err)
	}
	defer sftpCli.Close()

	// Initialize a squid installation.
	//
	// A few things of note here:
	// - The first thing we do is append the nsslcrtd_program stanza to the config.
	//   This must be an absolute path and is based on the nix path of the squid derivation,
	//   so we compute and write it out here.
	// - Squid expects a pre-initialized directory layout, so we create that in /tmp/squid then
	//   invoke squid with -z to have it fill in the rest.
	// - Doing a meddler-in-the-middle attack requires using some fake keys, so we create
	//   them using openssl and then use the security_file_certgen tool to setup squids' ssl_db.
	// - There were some perms issues, so i yeeted 0777. Its only a test anyway
	copyFile(t, sftpCli, "squid.conf", "/tmp/squid.conf")
	runTestCommands(t, 30*time.Second, cli, []expect.Batcher{
		&expect.BSnd{S: "echo -e \"\\nsslcrtd_program $(nix eval --raw nixpkgs.squid)/libexec/security_file_certgen -s /tmp/squid/ssl_db -M 4MB\\n\" >> /tmp/squid.conf\n"},
		&expect.BSnd{S: "mkdir -p /tmp/squid/{cache,core}\n"},
		&expect.BSnd{S: "openssl req -batch -new -newkey rsa:4096 -sha256 -days 3650 -nodes -x509 -keyout /tmp/squid/myca-mitm.pem -out /tmp/squid/myca-mitm.pem\n"},
		&expect.BExp{R: `writing new private key to '/tmp/squid/myca-mitm.pem'`},
		&expect.BSnd{S: "$(nix eval --raw nixpkgs.squid)/libexec/security_file_certgen -c -s /tmp/squid/ssl_db -M 4MB\n"},
		&expect.BExp{R: `Done`},
		&expect.BSnd{S: "sudo chmod -R 0777 /tmp/squid\n"},
		&expect.BSnd{S: "squid --foreground -YCs -z -f /tmp/squid.conf\n"},
		&expect.BSnd{S: "echo Success.\n"},
		&expect.BExp{R: `Success.`},
	})

	// Start the squid server.
	runTestCommands(t, 10*time.Second, cli, []expect.Batcher{
		&expect.BSnd{S: "daemonize -v -c /tmp/squid $(nix eval --raw nixpkgs.squid)/bin/squid --foreground -YCs -f /tmp/squid.conf\n"}, // start daemon
		// NOTE(tom): Writing to /dev/tcp/* is bash magic, not a file. This
		//            eldritchian incantation lets us wait till squid is up.
		&expect.BSnd{S: "while ! timeout 5 bash -c 'echo > /dev/tcp/localhost/3128'; do sleep 1; done\n"},
		&expect.BSnd{S: "echo Success.\n"},
		&expect.BExp{R: `Success.`},
	})

	// Uncomment to help debugging this test if it fails.
	//
	// runTestCommands(t, 30 * time.Second, cli, []expect.Batcher{
	// 	&expect.BSnd{S: "sudo ifconfig\n"},
	// 	&expect.BSnd{S: "sudo ip link\n"},
	// 	&expect.BSnd{S: "sudo ip route\n"},
	// 	&expect.BSnd{S: "ps -aux\n"},
	// 	&expect.BSnd{S: "netstat -a\n"},
	// 	&expect.BSnd{S: "cat /tmp/squid/access.log && cat /tmp/squid/cache.log && cat /tmp/squid.conf && echo Success.\n"},
	// 	&expect.BExp{R: `Success.`},
	// })

	runTestCommands(t, 30*time.Second, cli, []expect.Batcher{
		&expect.BSnd{S: "SSL_CERT_FILE=/tmp/squid/myca-mitm.pem HTTPS_PROXY=http://127.0.0.1:3128 tailscale netcheck\n"},
		&expect.BExp{R: `IPv4: yes`},
	})
}
