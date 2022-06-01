// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"fmt"
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

const testGPRuleID = "{7B1B6151-84E6-41A3-8967-62F7F7B45687}"

var (
	procRegisterGPNotification   = libUserenv.NewProc("RegisterGPNotification")
	procUnregisterGPNotification = libUserenv.NewProc("UnregisterGPNotification")
)

func TestManagerWindowsLocal(t *testing.T) {
	if !isWindows10OrBetter() || !winutil.IsCurrentProcessElevated() {
		t.Skipf("test requires running as elevated user on Windows 10+")
	}

	runTest(t, true)
}

func TestManagerWindowsGP(t *testing.T) {
	if !isWindows10OrBetter() || !winutil.IsCurrentProcessElevated() {
		t.Skipf("test requires running as elevated user on Windows 10+")
	}

	checkGPNotificationsWork(t)

	// Make sure group policy is refreshed before this test exits but after we've
	// cleaned everything else up.
	defer procRefreshPolicyEx.Call(uintptr(1), uintptr(_RP_FORCE))

	err := createFakeGPKey()
	if err != nil {
		t.Fatalf("Creating fake GP key: %v\n", err)
	}
	defer deleteFakeGPKey(t)

	runTest(t, false)
}

func checkGPNotificationsWork(t *testing.T) {
	// Test to ensure that RegisterGPNotification work on this machine,
	// otherwise this test will fail.
	trk, err := newGPNotificationTracker()
	if err != nil {
		t.Skipf("newGPNotificationTracker error: %v\n", err)
	}
	defer trk.Close()

	r, _, err := procRefreshPolicyEx.Call(uintptr(1), uintptr(_RP_FORCE))
	if r == 0 {
		t.Fatalf("RefreshPolicyEx error: %v\n", err)
	}

	timeout := uint32(10000) // Milliseconds
	if !trk.DidRefreshTimeout(timeout) {
		t.Skipf("GP notifications are not working on this machine\n")
	}
}

func runTest(t *testing.T, isLocal bool) {
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

	usingGP := mgr.nrptDB.writeAsGP
	if isLocal == usingGP {
		t.Fatalf("usingGP %v, want %v\n", usingGP, !usingGP)
	}

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

	var regBaseValidate string
	var regBaseEnsure string
	if isLocal {
		regBaseValidate = nrptBaseLocal
		regBaseEnsure = nrptBaseGP
	} else {
		regBaseValidate = nrptBaseGP
		regBaseEnsure = nrptBaseLocal
	}

	var trk *gpNotificationTracker
	if isLocal {
		// (dblohm7) When isLocal == true, we keep trk active through the entire
		// sequence of test cases, and then we verify that no policy notifications
		// occurred. Because policy notifications are scoped to the entire computer,
		// this check could potentially fail if another process concurrently modifies
		// group policies while this test is running. I don't expect this to be an
		// issue on any computer on which we run this test, but something to keep in
		// mind if we start seeing flakiness around these GP notifications.
		trk, err = newGPNotificationTracker()
		if err != nil {
			t.Fatalf("newGPNotificationTracker: %v\n", err)
		}
		defer trk.Close()
	}

	runCase := func(n int) {
		t.Logf("Test case: %d domains\n", n)
		if !isLocal {
			// When !isLocal, we want to check that a GP notification occured for
			// every single test case.
			trk, err = newGPNotificationTracker()
			if err != nil {
				t.Fatalf("newGPNotificationTracker: %v\n", err)
			}
			defer trk.Close()
		}
		caseDomains := domains[:n]
		err = mgr.setSplitDNS(resolvers, caseDomains)
		if err != nil {
			t.Fatalf("setSplitDNS: %v\n", err)
		}
		validateRegistry(t, regBaseValidate, caseDomains)
		ensureNoRulesInSubkey(t, regBaseEnsure)
		if !isLocal && !trk.DidRefresh(true) {
			t.Fatalf("DidRefresh false, want true\n")
		}
	}

	for _, n := range cases {
		runCase(n)
	}

	if isLocal && trk.DidRefresh(false) {
		t.Errorf("DidRefresh true, want false\n")
	}

	t.Logf("Test case: nil resolver\n")
	err = mgr.setSplitDNS(nil, domains)
	if err != nil {
		t.Fatalf("setSplitDNS: %v\n", err)
	}
	ensureNoRules(t)
}

func createFakeGPKey() error {
	keyStr := nrptBaseGP + `\` + testGPRuleID
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, keyStr, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("opening %s: %w", keyStr, err)
	}
	defer key.Close()
	if err := key.SetDWordValue("Version", 1); err != nil {
		return err
	}
	if err := key.SetStringsValue("Name", []string{"._setbygp_.example.com"}); err != nil {
		return err
	}
	if err := key.SetStringValue("GenericDNSServers", "1.1.1.1"); err != nil {
		return err
	}
	if err := key.SetDWordValue("ConfigOptions", nrptOverrideDNS); err != nil {
		return err
	}
	return nil
}

func deleteFakeGPKey(t *testing.T) {
	keyName := nrptBaseGP + `\` + testGPRuleID
	if err := registry.DeleteKey(registry.LOCAL_MACHINE, keyName); err != nil && err != registry.ErrNotExist {
		t.Fatalf("Error deleting NRPT rule key %q: %v\n", keyName, err)
	}

	isEmpty, err := isPolicyConfigSubkeyEmpty()
	if err != nil {
		t.Fatalf("isPolicyConfigSubkeyEmpty: %v", err)
	}

	if !isEmpty {
		return
	}

	if err := registry.DeleteKey(registry.LOCAL_MACHINE, nrptBaseGP); err != nil {
		t.Fatalf("Deleting DnsPolicyKey Subkey: %v", err)
	}
}

func ensureNoRules(t *testing.T) {
	ruleIDs := winutil.GetRegStrings(nrptRuleIDValueName, nil)
	if ruleIDs != nil {
		t.Errorf("%s: %v, want nil\n", nrptRuleIDValueName, ruleIDs)
	}

	for _, base := range []string{nrptBaseLocal, nrptBaseGP} {
		ensureNoSingleRule(t, base)
	}
}

func ensureNoRulesInSubkey(t *testing.T, base string) {
	ruleIDs := winutil.GetRegStrings(nrptRuleIDValueName, nil)
	if ruleIDs == nil {
		for _, base := range []string{nrptBaseLocal, nrptBaseGP} {
			ensureNoSingleRule(t, base)
		}
		return
	}

	for _, ruleID := range ruleIDs {
		keyName := base + `\` + ruleID
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyName, registry.READ)
		if err == nil {
			key.Close()
		}
		if err != registry.ErrNotExist {
			t.Fatalf("%s: %q, want %q\n", keyName, err, registry.ErrNotExist)
		}
	}
}

func ensureNoSingleRule(t *testing.T, base string) {
	singleKeyPath := base + `\` + nrptSingleRuleID
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, singleKeyPath, registry.READ)
	if err == nil {
		key.Close()
	}
	if err != registry.ErrNotExist {
		t.Fatalf("%s: %q, want %q\n", singleKeyPath, err, registry.ErrNotExist)
	}
}

func validateRegistry(t *testing.T, nrptBase string, domains []dnsname.FQDN) {
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
		savedDomains, err := getSavedDomainsForRule(nrptBase, ruleID)
		if err != nil {
			t.Fatalf("getSavedDomainsForRule(%q, %q): %v\n", nrptBase, ruleID, err)
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

func getSavedDomainsForRule(base, ruleID string) ([]string, error) {
	keyPath := base + `\` + ruleID
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.READ)
	if err != nil {
		return nil, err
	}
	defer key.Close()
	result, _, err := key.GetStringsValue("Name")
	return result, err
}

// gpNotificationTracker registers with the Windows policy engine and receives
// notifications when policy refreshes occur.
type gpNotificationTracker struct {
	event windows.Handle
}

func newGPNotificationTracker() (*gpNotificationTracker, error) {
	var err error
	evt, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			windows.CloseHandle(evt)
		}
	}()

	ok, _, e := procRegisterGPNotification.Call(
		uintptr(evt),
		uintptr(1), // We want computer policy changes, not user policy changes.
	)
	if ok == 0 {
		err = e
		return nil, err
	}

	return &gpNotificationTracker{evt}, nil
}

func (trk *gpNotificationTracker) DidRefresh(isExpected bool) bool {
	// If we're not expecting a refresh event, then we need to use a timeout.
	timeout := uint32(1000) // 1 second (in milliseconds)
	if isExpected {
		// Otherwise, since it is imperative that we see an event, we wait infinitely.
		timeout = windows.INFINITE
	}

	return trk.DidRefreshTimeout(timeout)
}

func (trk *gpNotificationTracker) DidRefreshTimeout(timeout uint32) bool {
	waitCode, _ := windows.WaitForSingleObject(trk.event, timeout)
	return waitCode == windows.WAIT_OBJECT_0
}

func (trk *gpNotificationTracker) Close() error {
	procUnregisterGPNotification.Call(uintptr(trk.event))
	windows.CloseHandle(trk.event)
	trk.event = 0
	return nil
}
