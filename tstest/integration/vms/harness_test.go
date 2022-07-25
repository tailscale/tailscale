// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !windows
// +build !windows

package vms

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
	"tailscale.com/net/netaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/dnstype"
)

type Harness struct {
	testerDialer   proxy.Dialer
	testerDir      string
	binaryDir      string
	cli            string
	daemon         string
	pubKey         string
	signer         ssh.Signer
	cs             *testcontrol.Server
	loginServerURL string
	testerV4       netaddr.IP
	ipMu           *sync.Mutex
	ipMap          map[string]ipMapping
}

func newHarness(t *testing.T) *Harness {
	dir := t.TempDir()
	bindHost := deriveBindhost(t)
	ln, err := net.Listen("tcp", net.JoinHostPort(bindHost, "0"))
	if err != nil {
		t.Fatalf("can't make TCP listener: %v", err)
	}
	t.Cleanup(func() {
		ln.Close()
	})
	t.Logf("host:port: %s", ln.Addr())

	cs := &testcontrol.Server{
		DNSConfig: &tailcfg.DNSConfig{
			// TODO: this is wrong.
			// It is also only one of many configurations.
			// Figure out how to scale it up.
			Resolvers:    []*dnstype.Resolver{{Addr: "100.100.100.100"}, {Addr: "8.8.8.8"}},
			Domains:      []string{"record"},
			Proxied:      true,
			ExtraRecords: []tailcfg.DNSRecord{{Name: "extratest.record", Type: "A", Value: "1.2.3.4"}},
		},
	}

	derpMap := integration.RunDERPAndSTUN(t, t.Logf, bindHost)
	cs.DERPMap = derpMap

	var (
		ipMu  sync.Mutex
		ipMap = map[string]ipMapping{}
	)

	mux := http.NewServeMux()
	mux.Handle("/", cs)

	lc := &integration.LogCatcher{}
	if *verboseLogcatcher {
		lc.UseLogf(t.Logf)
		t.Cleanup(func() {
			lc.UseLogf(nil) // do not log after test is complete
		})
	}
	mux.Handle("/c/", lc)

	// This handler will let the virtual machines tell the host information about that VM.
	// This is used to maintain a list of port->IP address mappings that are known to be
	// working. This allows later steps to connect over SSH. This returns no response to
	// clients because no response is needed.
	mux.HandleFunc("/myip/", func(w http.ResponseWriter, r *http.Request) {
		ipMu.Lock()
		defer ipMu.Unlock()

		name := path.Base(r.URL.Path)
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		port, err := strconv.Atoi(name)
		if err != nil {
			log.Panicf("bad port: %v", port)
		}
		distro := r.UserAgent()
		ipMap[distro] = ipMapping{distro, port, host}
		t.Logf("%s: %v", name, host)
	})

	hs := &http.Server{Handler: mux}
	go hs.Serve(ln)

	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-f", "machinekey", "-N", "")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v, %s", err, out)
	}
	pubkey, err := os.ReadFile(filepath.Join(dir, "machinekey.pub"))
	if err != nil {
		t.Fatalf("can't read ssh key: %v", err)
	}

	privateKey, err := os.ReadFile(filepath.Join(dir, "machinekey"))
	if err != nil {
		t.Fatalf("can't read ssh private key: %v", err)
	}

	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		t.Fatalf("can't parse private key: %v", err)
	}

	loginServer := fmt.Sprintf("http://%s", ln.Addr())
	t.Logf("loginServer: %s", loginServer)

	h := &Harness{
		pubKey:         string(pubkey),
		binaryDir:      integration.BinaryDir(t),
		cli:            integration.TailscaleBinary(t),
		daemon:         integration.TailscaledBinary(t),
		signer:         signer,
		loginServerURL: loginServer,
		cs:             cs,
		ipMu:           &ipMu,
		ipMap:          ipMap,
	}

	h.makeTestNode(t, loginServer)

	return h
}

func (h *Harness) Tailscale(t *testing.T, args ...string) []byte {
	t.Helper()

	args = append([]string{"--socket=" + filepath.Join(h.testerDir, "sock")}, args...)

	cmd := exec.Command(h.cli, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}

	return out
}

// makeTestNode creates a userspace tailscaled running in netstack mode that
// enables us to make connections to and from the tailscale network being
// tested. This mutates the Harness to allow tests to dial into the tailscale
// network as well as control the tester's tailscaled.
func (h *Harness) makeTestNode(t *testing.T, controlURL string) {
	dir := t.TempDir()
	h.testerDir = dir

	port, err := getProbablyFreePortNumber()
	if err != nil {
		t.Fatalf("can't get free port: %v", err)
	}

	cmd := exec.Command(
		h.daemon,
		"--tun=userspace-networking",
		"--state="+filepath.Join(dir, "state.json"),
		"--socket="+filepath.Join(dir, "sock"),
		fmt.Sprintf("--socks5-server=localhost:%d", port),
	)

	cmd.Env = append(
		os.Environ(),
		"NOTIFY_SOCKET="+filepath.Join(dir, "notify_socket"),
		"TS_LOG_TARGET="+h.loginServerURL,
	)

	err = cmd.Start()
	if err != nil {
		t.Fatalf("can't start tailscaled: %v", err)
	}

	t.Cleanup(func() {
		cmd.Process.Kill()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)

outer:
	for {
		select {
		case <-ctx.Done():
			t.Fatal("timed out waiting for tailscaled to come up")
			return
		case <-ticker.C:
			conn, err := net.Dial("unix", filepath.Join(dir, "sock"))
			if err != nil {
				continue
			}

			conn.Close()
			break outer
		}
	}

	run(t, dir, h.cli,
		"--socket="+filepath.Join(dir, "sock"),
		"up",
		"--login-server="+controlURL,
		"--hostname=tester",
	)

	dialer, err := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), nil, &net.Dialer{})
	if err != nil {
		t.Fatalf("can't make netstack proxy dialer: %v", err)
	}
	h.testerDialer = dialer
	h.testerV4 = bytes2Netaddr(h.Tailscale(t, "ip", "-4"))
}

func bytes2Netaddr(inp []byte) netaddr.IP {
	return netaddr.MustParseIP(string(bytes.TrimSpace(inp)))
}
