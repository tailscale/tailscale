// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"math/rand"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"inet.af/netaddr"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/winutil"
)

func TestManagerWindows(t *testing.T) {
	if !winutil.IsCurrentProcessElevated() {
		t.Skipf("test requires running as elevated user")
	}

	logf := func(format string, args ...any) {
		t.Logf(format, args...)
	}

	fakeInterface, err := windows.GenerateGUID()
	if err != nil {
		t.Fatalf("windows.GenerateGUID: %v\n", err)
	}

	cfg, err := NewOSConfigurator(logf, fakeInterface.String())
	if err != nil {
		t.Fatalf("NewOSConfigurator: %v\n", err)
	}
	mgr := cfg.(windowsManager)

	// Upon initialization of cfg, we should not have any NRPT rules
	ensureNoRules(t)

	resolvers := []netaddr.IP{netaddr.MustParseIP("1.1.1.1")}

	domains := make([]dnsname.FQDN, 0, 2*nrptMaxDomainsPerRule+1)

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	const charset = "abcdefghijklmnopqrstuvwxyz"

	// Just generate a bunch of random subdomains
	for len(domains) < cap(domains) {
		l := r.Intn(19) + 1
		b := make([]byte, l)
		for i, _ := range b {
			b[i] = charset[r.Intn(len(charset))]
		}
		d := string(b) + ".example.com"
		fqdn, err := dnsname.ToFQDN(d)
		if err != nil {
			t.Fatalf("dnsname.ToFQDN: %v\n", err)
		}
		domains = append(domains, fqdn)
	}

	cases := []int{
		1,
		50,
		51,
		100,
		101,
		100,
		50,
		1,
		51,
	}

	for _, n := range cases {
		t.Logf("Test case: %d domains\n", n)
		caseDomains := domains[:n]
		err := mgr.setSplitDNS(resolvers, caseDomains)
		if err != nil {
			t.Fatalf("setSplitDNS: %v\n", err)
		}
		validateRegistry(t, caseDomains)
	}

	t.Logf("Test case: nil resolver\n")
	err = mgr.setSplitDNS(nil, domains)
	if err != nil {
		t.Fatalf("setSplitDNS: %v\n", err)
	}
	ensureNoRules(t)
}

func ensureNoRules(t *testing.T) {
	ruleIDs := winutil.GetRegStrings(nrptRuleIDValueName, nil)
	if ruleIDs != nil {
		t.Errorf("%s: %v, want nil\n", nrptRuleIDValueName, ruleIDs)
	}

	legacyKeyPath := nrptBase + nrptSingleRuleID
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, legacyKeyPath, registry.READ)
	if err == nil {
		key.Close()
	}
	if err != registry.ErrNotExist {
		t.Errorf("%s: %q, want %q\n", legacyKeyPath, err, registry.ErrNotExist)
	}
}

func validateRegistry(t *testing.T, domains []dnsname.FQDN) {
	q := len(domains) / nrptMaxDomainsPerRule
	r := len(domains) % nrptMaxDomainsPerRule
	numRules := q
	if r > 0 {
		numRules++
	}

	ruleIDs := winutil.GetRegStrings(nrptRuleIDValueName, nil)
	if ruleIDs == nil {
		ruleIDs = []string{nrptSingleRuleID}
	} else if len(ruleIDs) != numRules {
		t.Errorf("%s for %d domains: %d, want %d\n", nrptRuleIDValueName, len(domains), len(ruleIDs), numRules)
	}

	for i, ruleID := range ruleIDs {
		savedDomains, err := getSavedDomainsForRule(ruleID)
		if err != nil {
			t.Fatalf("getSavedDomainsForRule(%q): %v\n", ruleID, err)
		}

		start := i * nrptMaxDomainsPerRule
		end := start + nrptMaxDomainsPerRule
		if i == len(ruleIDs)-1 && r > 0 {
			end = start + r
		}

		checkDomains := domains[start:end]
		if len(checkDomains) != len(savedDomains) {
			t.Errorf("len(checkDomains) != len(savedDomains): %d, want %d\n", len(savedDomains), len(checkDomains))
		}
		for j, cd := range checkDomains {
			sd := strings.TrimPrefix(savedDomains[j], ".")
			if string(cd.WithoutTrailingDot()) != sd {
				t.Errorf("checkDomain differs savedDomain: %s, want %s\n", sd, cd.WithoutTrailingDot())
			}
		}
	}
}

func getSavedDomainsForRule(ruleID string) ([]string, error) {
	keyPath := nrptBase + ruleID
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.READ)
	if err != nil {
		return nil, err
	}
	defer key.Close()
	result, _, err := key.GetStringsValue("Name")
	return result, err
}
