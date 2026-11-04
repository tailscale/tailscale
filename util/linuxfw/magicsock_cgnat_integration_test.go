// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && cgnat_integration && !ts_omit_iptables

package linuxfw

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/coreos/go-iptables/iptables"
)

// Run only inside the two disposable namespaces made by the CI harness. This
// exercises real kernel packet filtering, not a source-text/order assertion.
func TestCGNATTransportKernel(t *testing.T) {
	mode := os.Getenv("TS_CGNAT_TEST_FIREWALL")
	if mode == "" {
		t.Skip("requires isolated cgnat-host/cgnat-peer namespaces")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root in disposable namespace")
	}
	// Upstream unit tests replace this process-global predicate with a fake
	// string matcher. Use the real classifier only for this isolated kernel test.
	oldClassifier := isNotExistError
	isNotExistError = func(err error) bool {
		var iptErr *iptables.Error
		return errors.As(err, &iptErr) && iptErr.IsNotExist()
	}
	t.Cleanup(func() { isNotExistError = oldClassifier })

	if _, err := net.InterfaceByName("cghost"); err != nil {
		t.Fatal("refusing to change firewall outside test namespace")
	}
	var runner NetfilterRunner
	var err error
	switch mode {
	case "iptables":
		runner, err = newIPTablesRunner(t.Logf)
	case "nftables":
		runner, err = newNfTablesRunner(t.Logf)
	default:
		t.Fatalf("unsupported test firewall %q", mode)
	}
	if err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(runner.AddChains())
	t.Cleanup(func() {
		if err := runner.DelHooks(t.Logf); err != nil {
			t.Error(err)
		}
		if err := runner.DelChains(); err != nil {
			t.Error(err)
		}
	})
	must(runner.AddHooks())
	must(runner.AddBase("tailscale0"))
	// Current upstream installs CGNAT policy separately from the base chains.
	must(runner.AddExternalCGNATRules(CGNATModeDrop, "tailscale0"))
	listen := func(port int) *net.UDPConn {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("100.64.50.2"), Port: port})
		must(err)
		t.Cleanup(func() { c.Close() })
		return c
	}
	first, second := listen(41641), listen(41642)
	probe := func(c *net.UDPConn, accepted bool) {
		t.Helper()
		code := `import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(("100.64.50.1",0)); s.settimeout(1)
s.sendto(b"cgnat-regression",("100.64.50.2",int(sys.argv[1])))
try: ok=s.recv(128)==b"cgnat-regression"
except socket.timeout: ok=False
sys.exit(0 if ok==(sys.argv[2]=="true") else 1)`
		cmd := exec.Command("ip", "netns", "exec", "cgnat-peer", "python3", "-c", code, strconv.Itoa(c.LocalAddr().(*net.UDPAddr).Port), strconv.FormatBool(accepted))
		var output bytes.Buffer
		cmd.Stdout = &output
		cmd.Stderr = &output
		must(c.SetReadDeadline(time.Now().Add(1500 * time.Millisecond)))
		must(cmd.Start())
		buf := make([]byte, 128)
		n, peer, readErr := c.ReadFromUDP(buf)
		if readErr == nil {
			_, err = c.WriteToUDP(buf[:n], peer)
			must(err)
		}
		commandErr := cmd.Wait()
		if accepted != (readErr == nil) {
			t.Fatalf("accepted=%v, read=%v", accepted, readErr)
		}
		if readErr != nil {
			if ne, ok := readErr.(net.Error); !ok || !ne.Timeout() {
				t.Fatal(readErr)
			}
		}
		if commandErr != nil {
			t.Fatalf("peer probe: %v: %s", commandErr, output.String())
		}
		t.Logf("%s UDP/%d accepted=%v", mode, c.LocalAddr().(*net.UDPAddr).Port, accepted)
	}
	probe(first, false)
	must(runner.AddMagicsockPortRule(41641, "udp4"))
	probe(first, true)
	probe(second, false)
	tcp, err := net.Listen("tcp4", "100.64.50.2:41641")
	must(err)
	defer tcp.Close()
	code := `import socket,sys
s=socket.socket(); s.settimeout(0.5)
sys.exit(1 if s.connect_ex(("100.64.50.2",41641))==0 else 0)`
	if out, err := exec.Command("ip", "netns", "exec", "cgnat-peer", "python3", "-c", code).CombinedOutput(); err != nil {
		t.Fatal(fmt.Errorf("non-UDP spoof protection: %w: %s", err, out))
	}
	must(runner.DelMagicsockPortRule(41641, "udp4"))
	must(runner.AddMagicsockPortRule(41642, "udp4"))
	probe(first, false)
	probe(second, true)
	must(runner.DelMagicsockPortRule(41642, "udp4"))
	probe(second, false)
}
