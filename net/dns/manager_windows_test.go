// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"tailscale.com/types/logger"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/syspolicy/policyclient"
	"tailscale.com/util/winutil"
	"tailscale.com/util/winutil/gp"
)

const testGPRuleID = "{7B1B6151-84E6-41A3-8967-62F7F7B45687}"

func TestHostFileNewLines(t *testing.T) {
	in := []byte("#foo\r\n#bar\n#baz\n")
	want := []byte("#foo\r\n#bar\r\n#baz\r\n# TailscaleHostsSectionStart\r\n# This section contains MagicDNS entries for Tailscale.\r\n# Do not edit this section manually.\r\n\r\n192.168.1.1 aaron\r\n\r\n# TailscaleHostsSectionEnd\r\n")

	he := []*HostEntry{
		&HostEntry{
			Addr:  netip.MustParseAddr("192.168.1.1"),
			Hosts: []string{"aaron"},
		},
	}
	got, err := setTailscaleHosts(logger.Discard, in, he)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q\n", got, want)
	}
}

func TestHostFileUnchanged(t *testing.T) {
	in := []byte("#foo\r\n#bar\r\n#baz\r\n# TailscaleHostsSectionStart\r\n# This section contains MagicDNS entries for Tailscale.\r\n# Do not edit this section manually.\r\n\r\n192.168.1.1 aaron\r\n\r\n# TailscaleHostsSectionEnd\r\n")

	he := []*HostEntry{
		&HostEntry{
			Addr:  netip.MustParseAddr("192.168.1.1"),
			Hosts: []string{"aaron"},
		},
	}
	got, err := setTailscaleHosts(logger.Discard, in, he)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("got %q, want nil\n", got)
	}
}

func TestHostFileChanged(t *testing.T) {
	in := []byte("#foo\r\n#bar\r\n#baz\r\n# TailscaleHostsSectionStart\r\n# This section contains MagicDNS entries for Tailscale.\r\n# Do not edit this section manually.\r\n\r\n192.168.1.1 aaron1\r\n\r\n# TailscaleHostsSectionEnd\r\n")
	want := []byte("#foo\r\n#bar\r\n#baz\r\n# TailscaleHostsSectionStart\r\n# This section contains MagicDNS entries for Tailscale.\r\n# Do not edit this section manually.\r\n\r\n192.168.1.1 aaron1\r\n192.168.1.2 aaron2\r\n\r\n# TailscaleHostsSectionEnd\r\n")

	he := []*HostEntry{
		&HostEntry{
			Addr:  netip.MustParseAddr("192.168.1.1"),
			Hosts: []string{"aaron1"},
		},
		&HostEntry{
			Addr:  netip.MustParseAddr("192.168.1.2"),
			Hosts: []string{"aaron2"},
		},
	}
	got, err := setTailscaleHosts(logger.Discard, in, he)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q\n", got, want)
	}
}

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
	defer gp.RefreshMachinePolicy(true)

	err := createFakeGPKey()
	if err != nil {
		t.Fatalf("Creating fake GP key: %v\n", err)
	}
	defer deleteFakeGPKey(t)

	runTest(t, false)
}

func TestManagerWindowsGPCopy(t *testing.T) {
	if !isWindows10OrBetter() || !winutil.IsCurrentProcessElevated() {
		t.Skipf("test requires running as elevated user on Windows 10+")
	}

	checkGPNotificationsWork(t)

	logf := func(format string, args ...any) {
		t.Logf(format, args...)
	}

	fakeInterface, err := windows.GenerateGUID()
	if err != nil {
		t.Fatalf("windows.GenerateGUID: %v\n", err)
	}

	delIfKey, err := createFakeInterfaceKey(t, fakeInterface)
	if err != nil {
		t.Fatalf("createFakeInterfaceKey: %v\n", err)
	}
	defer delIfKey()

	cfg, err := NewOSConfigurator(logf, nil, policyclient.NoPolicyClient{}, nil, fakeInterface.String())
	if err != nil {
		t.Fatalf("NewOSConfigurator: %v\n", err)
	}
	mgr := cfg.(*windowsManager)
	defer mgr.Close()

	usingGP := mgr.nrptDB.writeAsGP
	if usingGP {
		t.Fatalf("usingGP %v, want %v\n", usingGP, false)
	}

	regWatcher, err := newRegKeyWatcher()
	if err != nil {
		t.Fatalf("newRegKeyWatcher error %v\n", err)
	}

	// Upon initialization of cfg, we should not have any NRPT rules
	ensureNoRules(t)

	resolvers := []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	domains := genRandomSubdomains(t, 1)

	// 1. Populate local NRPT
	err = mgr.setSplitDNS(resolvers, domains)
	if err != nil {
		t.Fatalf("setSplitDNS: %v\n", err)
	}

	t.Logf("Validating that local NRPT is populated...\n")
	validateRegistry(t, nrptBaseLocal, domains)
	ensureNoRulesInSubkey(t, nrptBaseGP)

	// 2. Create fake GP key and refresh
	t.Logf("Creating fake group policy key and refreshing...\n")
	err = createFakeGPKey()
	if err != nil {
		t.Fatalf("createFakeGPKey: %v\n", err)
	}

	err = regWatcher.watch()
	if err != nil {
		t.Fatalf("regWatcher.watch: %v\n", err)
	}

	err = gp.RefreshMachinePolicy(true)
	if err != nil {
		t.Fatalf("testDoRefresh: %v\n", err)
	}

	err = regWatcher.wait()
	if err != nil {
		t.Fatalf("regWatcher.wait: %v\n", err)
	}

	// 3. Check that both local NRPT and GP NRPT are populated
	t.Logf("Validating that group policy NRPT is populated...\n")
	validateRegistry(t, nrptBaseLocal, domains)
	validateRegistry(t, nrptBaseGP, domains)

	// 4. Delete fake GP key and refresh
	t.Logf("Deleting fake group policy key and refreshing...\n")
	deleteFakeGPKey(t)

	err = regWatcher.watch()
	if err != nil {
		t.Fatalf("regWatcher.watch: %v\n", err)
	}

	err = gp.RefreshMachinePolicy(true)
	if err != nil {
		t.Fatalf("testDoRefresh: %v\n", err)
	}

	err = regWatcher.wait()
	if err != nil {
		t.Fatalf("regWatcher.wait: %v\n", err)
	}

	// 5. Check that local NRPT is populated and GP is empty
	t.Logf("Validating that local NRPT is populated...\n")
	validateRegistry(t, nrptBaseLocal, domains)
	ensureNoRulesInSubkey(t, nrptBaseGP)

	// 6. Cleanup
	t.Logf("Cleaning up...\n")
	err = mgr.setSplitDNS(nil, domains)
	if err != nil {
		t.Fatalf("setSplitDNS: %v\n", err)
	}
	ensureNoRules(t)
}

func checkGPNotificationsWork(t *testing.T) {
	// Test to ensure that RegisterGPNotification work on this machine,
	// otherwise this test will fail.
	trk, err := newGPNotificationTracker()
	if err != nil {
		t.Skipf("newGPNotificationTracker error: %v\n", err)
	}
	defer trk.Close()

	err = gp.RefreshMachinePolicy(true)
	if err != nil {
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

	delIfKey, err := createFakeInterfaceKey(t, fakeInterface)
	if err != nil {
		t.Fatalf("createFakeInterfaceKey: %v\n", err)
	}
	defer delIfKey()

	cfg, err := NewOSConfigurator(logf, nil, policyclient.NoPolicyClient{}, nil, fakeInterface.String())
	if err != nil {
		t.Fatalf("NewOSConfigurator: %v\n", err)
	}
	mgr := cfg.(*windowsManager)
	defer mgr.Close()

	usingGP := mgr.nrptDB.writeAsGP
	if isLocal == usingGP {
		t.Fatalf("usingGP %v, want %v\n", usingGP, !usingGP)
	}

	// Upon initialization of cfg, we should not have any NRPT rules
	ensureNoRules(t)

	resolvers := []netip.Addr{netip.MustParseAddr("1.1.1.1")}

	domains := genRandomSubdomains(t, 2*nrptMaxDomainsPerRule+1)

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
			// When !isLocal, we want to check that a GP notification occurred for
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

func createFakeInterfaceKey(t *testing.T, guid windows.GUID) (func(), error) {
	basePaths := []winutil.RegistryPathPrefix{winutil.IPv4TCPIPInterfacePrefix, winutil.IPv6TCPIPInterfacePrefix}
	keyPaths := make([]string, 0, len(basePaths))

	guidStr := guid.String()
	for _, basePath := range basePaths {
		keyPath := string(basePath.WithSuffix(guidStr))
		key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, keyPath, registry.SET_VALUE)
		if err != nil {
			return nil, err
		}
		key.Close()

		keyPaths = append(keyPaths, keyPath)
	}

	result := func() {
		for _, keyPath := range keyPaths {
			if err := registry.DeleteKey(registry.LOCAL_MACHINE, keyPath); err != nil {
				t.Fatalf("deleting fake interface key \"%s\": %v\n", keyPath, err)
			}
		}
	}

	return result, nil
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
		} else if err != registry.ErrNotExist {
			t.Fatalf("%s: %q, want %q\n", keyName, err, registry.ErrNotExist)
		}
	}

	if base == nrptBaseGP {
		// When dealing with the group policy subkey, we want the base key to
		// also be absent.
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, base, registry.READ)
		if err == nil {
			key.Close()

			isEmpty, err := isPolicyConfigSubkeyEmpty()
			if err != nil {
				t.Fatalf("isPolicyConfigSubkeyEmpty: %v", err)
			}
			if isEmpty {
				t.Errorf("Unexpectedly found group policy key\n")
			}
		} else if err != registry.ErrNotExist {
			t.Errorf("Group policy key error: %q, want %q\n", err, registry.ErrNotExist)
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

func genRandomSubdomains(t *testing.T, n int) []dnsname.FQDN {
	domains := make([]dnsname.FQDN, 0, n)

	seed := time.Now().UnixNano()
	t.Logf("genRandomSubdomains(%d) seed: %v\n", n, seed)

	r := rand.New(rand.NewSource(seed))
	const charset = "abcdefghijklmnopqrstuvwxyz"

	for len(domains) < cap(domains) {
		l := r.Intn(19) + 1
		b := make([]byte, l)
		for i := range b {
			b[i] = charset[r.Intn(len(charset))]
		}
		d := string(b) + ".example.com"
		fqdn, err := dnsname.ToFQDN(d)
		if err != nil {
			t.Fatalf("dnsname.ToFQDN: %v\n", err)
		}
		domains = append(domains, fqdn)
	}

	return domains
}

var (
	libUserenv                   = windows.NewLazySystemDLL("userenv.dll")
	procRegisterGPNotification   = libUserenv.NewProc("RegisterGPNotification")
	procUnregisterGPNotification = libUserenv.NewProc("UnregisterGPNotification")
)

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

type regKeyWatcher struct {
	keyGP registry.Key
	evtGP windows.Handle
}

func newRegKeyWatcher() (result *regKeyWatcher, err error) {
	// Monitor dnsBaseGP instead of nrptBaseGP, since the latter will be
	// repeatedly created and destroyed throughout the course of the test.
	keyGP, _, err := registry.CreateKey(registry.LOCAL_MACHINE, dnsBaseGP, registry.READ)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			keyGP.Close()
		}
	}()

	evtGP, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return nil, err
	}

	return &regKeyWatcher{
		keyGP: keyGP,
		evtGP: evtGP,
	}, nil
}

func (rw *regKeyWatcher) watch() error {
	// We can make these waits thread-agnostic because the tests that use this code must already run on Windows 10+
	return windows.RegNotifyChangeKeyValue(windows.Handle(rw.keyGP), true,
		windows.REG_NOTIFY_CHANGE_NAME|windows.REG_NOTIFY_THREAD_AGNOSTIC, rw.evtGP, true)
}

func (rw *regKeyWatcher) wait() error {
	waitCode, err := windows.WaitForSingleObject(
		rw.evtGP,
		10000, // 10 seconds (as milliseconds)
	)

	switch waitCode {
	case uint32(windows.WAIT_TIMEOUT):
		return context.DeadlineExceeded
	case windows.WAIT_FAILED:
		return err
	default:
		return nil
	}
}

func (rw *regKeyWatcher) Close() error {
	rw.keyGP.Close()
	windows.CloseHandle(rw.evtGP)
	return nil
}
