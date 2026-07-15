// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
	"tailscale.com/types/dnstype"
)

// TestDNSExtraRecordsSearchDomains verifies that control-plane DNS config
// makes it all the way into an Ubuntu guest's OS resolver: an ExtraRecords
// entry ("extratest.record" → 1.2.3.4) resolves via libc (getent), and the
// "record" search domain lets the bare name "extratest" resolve too. That
// requires tailscaled to have plumbed MagicDNS routes and search domains
// into systemd-resolved.
func TestDNSExtraRecordsSearchDomains(t *testing.T) {
	env := vmtest.New(t, vmtest.ControlDNS("tailnet.test", &tailcfg.DNSConfig{
		Proxied: true,
		Domains: []string{"record"},
		Routes:  map[string][]*dnstype.Resolver{"record": nil},
		ExtraRecords: []tailcfg.DNSRecord{
			{Name: "extratest.record", Type: "A", Value: "1.2.3.4"},
		},
	}))
	node := env.AddNode("node",
		env.AddNetwork("2.1.1.1", "192.168.1.1/24", vnet.EasyNAT),
		vmtest.OS(vmtest.Ubuntu2404))
	env.Start()

	for _, name := range []string{"extratest.record", "extratest"} {
		// Retry for a bit: tailscaled applies the DNS config to
		// systemd-resolved asynchronously after coming up.
		if err := tstest.WaitFor(30*time.Second, func() error {
			out, err := env.SSHExec(node, "getent hosts "+name)
			if err != nil {
				return fmt.Errorf("getent hosts %s: %v (%s)", name, err, strings.TrimSpace(out))
			}
			if !strings.Contains(out, "1.2.3.4") {
				return fmt.Errorf("getent hosts %s = %q, want it to contain 1.2.3.4", name, strings.TrimSpace(out))
			}
			return nil
		}); err != nil {
			out, _ := env.SSHExec(node, "resolvectl status; cat /etc/resolv.conf")
			t.Fatalf("%v\nresolver state:\n%s", err, out)
		}
	}
}
