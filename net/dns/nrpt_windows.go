// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"tailscale.com/types/logger"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/set"
	"tailscale.com/util/winutil"
)

const (
	dnsBaseGP     = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`
	nrptBaseLocal = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`
	nrptBaseGP    = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`

	nrptOverrideDNS = 0x8 // bitmask value for "use the provided override DNS resolvers"

	// Apparently NRPT rules cannot handle > 50 domains.
	nrptMaxDomainsPerRule = 50

	// This is the legacy rule ID that previous versions used when we supported
	// only a single rule. Now that we support multiple rules are required, we
	// generate their GUIDs and store them under the Tailscale registry key.
	nrptSingleRuleID = `{5abe529b-675b-4486-8459-25a634dacc23}`

	// This is the name of the registry value we use to save Rule IDs under
	// the Tailscale registry key.
	nrptRuleIDValueName = `NRPTRuleIDs`

	// This is the name of the registry value the NRPT uses for storing a rule's version number.
	nrptRuleVersionName = `Version`

	// This is the name of the registry value the NRPT uses for storing a rule's list of domains.
	nrptRuleDomsName = `Name`

	// This is the name of the registry value the NRPT uses for storing a rule's list of DNS servers.
	nrptRuleServersName = `GenericDNSServers`

	// This is the name of the registry value the NRPT uses for storing a rule's flags.
	nrptRuleFlagsName = `ConfigOptions`
)

var (
	libUserenv                   = windows.NewLazySystemDLL("userenv.dll")
	procRefreshPolicyEx          = libUserenv.NewProc("RefreshPolicyEx")
	procRegisterGPNotification   = libUserenv.NewProc("RegisterGPNotification")
	procUnregisterGPNotification = libUserenv.NewProc("UnregisterGPNotification")
)

const _RP_FORCE = 1 // Flag for RefreshPolicyEx

// nrptRuleDatabase encapsulates access to the Windows Name Resolution Policy
// Table (NRPT).
type nrptRuleDatabase struct {
	logf               logger.Logf
	watcher            *gpNotificationWatcher
	isGPRefreshPending atomic.Bool
	mu                 sync.Mutex // protects the fields below
	ruleIDs            []string
	isGPDirty          bool
	writeAsGP          bool
}

func newNRPTRuleDatabase(logf logger.Logf) *nrptRuleDatabase {
	ret := &nrptRuleDatabase{logf: logf}
	ret.loadRuleSubkeyNames()
	ret.detectWriteAsGP()
	ret.watchForGPChanges()
	// Best-effort: if our NRPT rule exists, try to delete it. Unlike
	// per-interface configuration, NRPT rules survive the unclean
	// termination of the Tailscale process, and depending on the
	// rule, it may prevent us from reaching login.tailscale.com to
	// boot up. The bootstrap resolver logic will save us, but it
	// slows down start-up a bunch.
	ret.DelAllRuleKeys()
	return ret
}

func (db *nrptRuleDatabase) loadRuleSubkeyNames() {
	// Use the legacy rule ID if none are specified in our registry key
	db.ruleIDs = winutil.GetRegStrings(nrptRuleIDValueName, []string{nrptSingleRuleID})
}

// detectWriteAsGP determines which registry path should be used for writing
// NRPT rules. If there are rules in the GP path that don't belong to us, then
// we should use the GP path. When detectWriteAsGP determines that the desired
// path has changed, it moves the NRPT policies as appropriate.
func (db *nrptRuleDatabase) detectWriteAsGP() {
	db.mu.Lock()
	defer db.mu.Unlock()

	writeAsGP := false
	var err error

	defer func() {
		if err != nil {
			return
		}
		prev := db.writeAsGP
		db.writeAsGP = writeAsGP
		db.logf("nrptRuleDatabase using group policy: %v, was %v\n", writeAsGP, prev)
		// When db.watcher == nil, prev != writeAsGP because we're initializing, not
		// because anything has changed. We do not invoke
		// db.updateGroupPoliciesLocked in that case.
		if db.watcher != nil && prev != writeAsGP {
			db.updateGroupPoliciesLocked(writeAsGP)
		}
	}()

	// Get a list of all the NRPT rules under the GP subkey.
	nrptKey, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptBaseGP, registry.READ)
	if err != nil {
		if err != registry.ErrNotExist {
			db.logf("Failed to open key %q with error: %v\n", nrptBaseGP, err)
		}
		// If this subkey does not exist then we definitely don't need to use the GP key.
		return
	}
	defer nrptKey.Close()

	gpSubkeyNames, err := nrptKey.ReadSubKeyNames(0)
	if err != nil {
		db.logf("Failed to list subkeys under %q with error: %v\n", nrptBaseGP, err)
		return
	}

	// Add *all* rules from the GP subkey into a set.
	gpSubkeyMap := make(set.Set[string], len(gpSubkeyNames))
	for _, gpSubkey := range gpSubkeyNames {
		gpSubkeyMap.Add(strings.ToUpper(gpSubkey))
	}

	// Remove *our* rules from the set.
	for _, ourRuleID := range db.ruleIDs {
		gpSubkeyMap.Delete(strings.ToUpper(ourRuleID))
	}

	// Any leftover rules do not belong to us. When group policy is being used
	// by something else, we must also use the GP path.
	writeAsGP = len(gpSubkeyMap) > 0
}

// DelAllRuleKeys removes any and all NRPT rules that are owned by Tailscale.
func (db *nrptRuleDatabase) DelAllRuleKeys() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if err := db.delRuleKeys(db.ruleIDs); err != nil {
		return err
	}
	if err := winutil.DeleteRegValue(nrptRuleIDValueName); err != nil {
		db.logf("Error deleting registry value %q: %v", nrptRuleIDValueName, err)
		return err
	}
	db.ruleIDs = nil
	return nil
}

// delRuleKeys removes the NRPT rules specified by nrptRuleIDs from the
// Windows registry. It attempts to remove the rules from both possible registry
// keys: the local key and the group policy key.
func (db *nrptRuleDatabase) delRuleKeys(nrptRuleIDs []string) error {
	for _, rid := range nrptRuleIDs {
		keyNameLocal := nrptBaseLocal + `\` + rid
		if err := registry.DeleteKey(registry.LOCAL_MACHINE, keyNameLocal); err != nil && err != registry.ErrNotExist {
			db.logf("Error deleting NRPT rule key %q: %v", keyNameLocal, err)
			return err
		}

		keyNameGP := nrptBaseGP + `\` + rid
		err := registry.DeleteKey(registry.LOCAL_MACHINE, keyNameGP)
		if err == nil {
			// If this deleted subkey existed under the GP key, we will need to refresh.
			db.isGPDirty = true
		} else if err != registry.ErrNotExist {
			db.logf("Error deleting NRPT rule key %q: %v", keyNameGP, err)
			return err
		}
	}

	if !db.isGPDirty {
		return nil
	}

	// If we've removed keys from the Group Policy subkey, and the DNSPolicyConfig
	// subkey is now empty, we need to remove that subkey.
	isEmpty, err := isPolicyConfigSubkeyEmpty()
	if err != nil || !isEmpty {
		return err
	}

	return registry.DeleteKey(registry.LOCAL_MACHINE, nrptBaseGP)
}

// isPolicyConfigSubkeyEmpty returns true if and only if the nrptBaseGP exists
// and does not contain any values or subkeys.
func isPolicyConfigSubkeyEmpty() (bool, error) {
	subKey, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptBaseGP, registry.READ)
	if err != nil {
		if err == registry.ErrNotExist {
			return false, nil
		}
		return false, err
	}
	defer subKey.Close()

	ki, err := subKey.Stat()
	if err != nil {
		return false, err
	}

	return (ki.ValueCount == 0 && ki.SubKeyCount == 0), nil
}

func (db *nrptRuleDatabase) WriteSplitDNSConfig(servers []string, domains []dnsname.FQDN) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	// NRPT has an undocumented restriction that each rule may only be associated
	// with a maximum of 50 domains. If we are setting rules for more domains
	// than that, we need to split domains into chunks and write out a rule per chunk.
	domainRulesLen := (len(domains) + nrptMaxDomainsPerRule - 1) / nrptMaxDomainsPerRule
	db.loadRuleSubkeyNames()

	for len(db.ruleIDs) < domainRulesLen {
		guid, err := windows.GenerateGUID()
		if err != nil {
			return err
		}
		db.ruleIDs = append(db.ruleIDs, guid.String())
	}

	// Remove any surplus rules that are no longer needed.
	ruleIDsToRemove := db.ruleIDs[domainRulesLen:]
	db.delRuleKeys(ruleIDsToRemove)

	// We need to save the list of rule IDs to our Tailscale registry key so that
	// we know which rules are ours during subsequent modifications to NRPT rules.
	ruleIDsToWrite := db.ruleIDs[:domainRulesLen]
	if len(ruleIDsToWrite) == 0 {
		if err := winutil.DeleteRegValue(nrptRuleIDValueName); err != nil {
			return err
		}
		db.ruleIDs = nil
		return nil
	}

	if err := winutil.SetRegStrings(nrptRuleIDValueName, ruleIDsToWrite); err != nil {
		return err
	}
	db.ruleIDs = ruleIDsToWrite

	curRuleID := 0
	doms := make([]string, 0, nrptMaxDomainsPerRule)

	for _, domain := range domains {
		if len(doms) == nrptMaxDomainsPerRule {
			if err := db.writeNRPTRule(db.ruleIDs[curRuleID], servers, doms); err != nil {
				return err
			}
			curRuleID++
			doms = doms[:0]
		}

		// NRPT rules must have a leading dot, which is not usual for
		// DNS search paths.
		doms = append(doms, "."+domain.WithoutTrailingDot())
	}

	if len(doms) > 0 {
		if err := db.writeNRPTRule(db.ruleIDs[curRuleID], servers, doms); err != nil {
			return err
		}
	}

	return nil
}

// Refresh notifies the Windows group policy engine when policies have changed.
func (db *nrptRuleDatabase) Refresh() {
	db.mu.Lock()
	defer db.mu.Unlock()

	db.refreshLocked()
}

func (db *nrptRuleDatabase) refreshLocked() {
	if !db.isGPDirty {
		return
	}

	// Record that we are about to initiate a refresh.
	// (*nrptRuleDatabase).watchForGPChanges() checks this value to avoid false
	// positives.
	db.isGPRefreshPending.Store(true)

	ok, _, err := procRefreshPolicyEx.Call(
		uintptr(1), // Win32 TRUE: Refresh computer policy, not user policy.
		uintptr(_RP_FORCE),
	)
	if ok == 0 {
		db.logf("RefreshPolicyEx failed: %v", err)
		return
	}

	db.isGPDirty = false
}

func (db *nrptRuleDatabase) writeNRPTRule(ruleID string, servers, doms []string) error {
	subKeys := []string{nrptBaseLocal, nrptBaseGP}
	if !db.writeAsGP {
		// We don't want to write to the GP key, so chop nrptBaseGP off of subKeys.
		subKeys = subKeys[:1]
	}

	for _, subKeyBase := range subKeys {
		subKey := strings.Join([]string{subKeyBase, ruleID}, `\`)
		key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, subKey, registry.SET_VALUE)
		if err != nil {
			return fmt.Errorf("opening %q: %w", subKey, err)
		}
		defer key.Close()

		if err := writeNRPTValues(key, strings.Join(servers, "; "), doms); err != nil {
			return err
		}
	}

	db.isGPDirty = db.writeAsGP
	return nil
}

func readNRPTValues(key registry.Key) (servers string, doms []string, err error) {
	doms, _, err = key.GetStringsValue(nrptRuleDomsName)
	if err != nil {
		return servers, doms, err
	}

	servers, _, err = key.GetStringValue(nrptRuleServersName)
	return servers, doms, err
}

func writeNRPTValues(key registry.Key, servers string, doms []string) error {
	if err := key.SetDWordValue(nrptRuleVersionName, 1); err != nil {
		return err
	}

	if err := key.SetStringsValue(nrptRuleDomsName, doms); err != nil {
		return err
	}

	if err := key.SetStringValue(nrptRuleServersName, servers); err != nil {
		return err
	}

	return key.SetDWordValue(nrptRuleFlagsName, nrptOverrideDNS)
}

func (db *nrptRuleDatabase) watchForGPChanges() {
	watchHandler := func() {
		// Do not invoke detectWriteAsGP when we ourselves were responsible for
		// initiating the group policy refresh.
		if db.isGPRefreshPending.CompareAndSwap(true, false) {
			return
		}
		db.logf("Computer group policies refreshed, reconfiguring NRPT rule database.")
		db.detectWriteAsGP()
	}

	watcher, err := newGPNotificationWatcher(watchHandler)
	if err != nil {
		return
	}

	db.watcher = watcher
}

// updateGroupPoliciesLocked updates the NRPT group policy table depending on
// the value of writeAsGP. When writeAsGP is true, each NRPT rule is copied from
// the local NRPT table to the group policy NRPT table. When writeAsGP is false,
// we remove any Tailscale NRPT rules from the group policy table and, if no
// non-Tailscale rules remain, we also delete the entire DnsPolicyConfig subkey.
// db.mu must already be locked.
func (db *nrptRuleDatabase) updateGroupPoliciesLocked(writeAsGP bool) {
	// Since we're updating the group policy NRPT table, we need
	// to refresh once this updateGroupPoliciesLocked is done.
	defer db.refreshLocked()

	for _, id := range db.ruleIDs {
		if writeAsGP {
			if err := copyNRPTRule(id); err != nil {
				db.logf("updateGroupPoliciesLocked: copyNRPTRule(%q) failed with error %v", id, err)
				return
			}
		} else {
			subKeyFrom := strings.Join([]string{nrptBaseGP, id}, `\`)
			if err := registry.DeleteKey(registry.LOCAL_MACHINE, subKeyFrom); err != nil && err != registry.ErrNotExist {
				db.logf("updateGroupPoliciesLocked: DeleteKey for rule %q failed with error %v", id, err)
				return
			}
		}

		db.isGPDirty = true
	}

	if writeAsGP {
		return
	}

	// Now that we have removed our rules from group policy subkey, it should
	// now be empty. Let's verify that.
	isEmpty, err := isPolicyConfigSubkeyEmpty()
	if err != nil {
		db.logf("updateGroupPoliciesLocked: isPolicyConfigSubkeyEmpty error %v", err)
		return
	}
	if !isEmpty {
		db.logf("updateGroupPoliciesLocked: policy config subkey should be empty, but isn't!")
		return
	}

	// Delete the subkey itself. Group policy will continue to override local
	// settings unless we do so.
	if err := registry.DeleteKey(registry.LOCAL_MACHINE, nrptBaseGP); err != nil {
		db.logf("updateGroupPoliciesLocked DeleteKey error %v", err)
	}

	db.isGPDirty = true
}

func copyNRPTRule(ruleID string) error {
	subKeyFrom := strings.Join([]string{nrptBaseLocal, ruleID}, `\`)
	subKeyTo := strings.Join([]string{nrptBaseGP, ruleID}, `\`)

	fromKey, err := registry.OpenKey(registry.LOCAL_MACHINE, subKeyFrom, registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	defer fromKey.Close()

	toKey, _, err := registry.CreateKey(registry.LOCAL_MACHINE, subKeyTo, registry.WRITE)
	if err != nil {
		return err
	}
	defer toKey.Close()

	servers, doms, err := readNRPTValues(fromKey)
	if err != nil {
		return err
	}

	return writeNRPTValues(toKey, servers, doms)
}

func (db *nrptRuleDatabase) Close() error {
	if db.watcher == nil {
		return nil
	}
	err := db.watcher.Close()
	db.watcher = nil
	return err
}

type gpNotificationWatcher struct {
	gpWaitEvents [2]windows.Handle
	handler      func()
	done         chan struct{}
}

// newGPNotificationWatcher creates an instance of gpNotificationWatcher that
// invokes handler every time Windows notifies it of a group policy change.
func newGPNotificationWatcher(handler func()) (*gpNotificationWatcher, error) {
	var err error

	// evtDone is signaled by (*gpNotificationWatcher).Close() to indicate that
	// the doWatch goroutine should exit.
	evtDone, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			windows.CloseHandle(evtDone)
		}
	}()

	// evtChanged is registered with the Windows policy engine to become
	// signalled any time group policy has been refreshed.
	evtChanged, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			windows.CloseHandle(evtChanged)
		}
	}()

	// Tell Windows to signal evtChanged whenever group policies are refreshed.
	ok, _, e := procRegisterGPNotification.Call(
		uintptr(evtChanged),
		uintptr(1), // Win32 TRUE: We want to monitor computer policy changes, not user policy changes.
	)
	if ok == 0 {
		err = e
		return nil, err
	}

	result := &gpNotificationWatcher{
		// Ordering of the event handles in gpWaitEvents is important:
		// When calling windows.WaitForMultipleObjects and multiple objects are
		// signalled simultaneously, it always returns the wait code for the
		// lowest-indexed handle in its input array. evtDone is higher priority for
		// us than evtChanged, so the former must be placed into the array ahead of
		// the latter.
		gpWaitEvents: [2]windows.Handle{
			evtDone,
			evtChanged,
		},
		handler: handler,
		done:    make(chan struct{}),
	}

	go result.doWatch()

	return result, nil
}

func (w *gpNotificationWatcher) doWatch() {
	// The wait code corresponding to the event that is signalled when a group
	// policy change occurs.
	const expectedWaitCode = windows.WAIT_OBJECT_0 + 1
	for {
		if waitCode, _ := windows.WaitForMultipleObjects(w.gpWaitEvents[:], false, windows.INFINITE); waitCode != expectedWaitCode {
			break
		}
		w.handler()
	}
	close(w.done)
}

func (w *gpNotificationWatcher) Close() error {
	// Notify doWatch that we're done and it should exit.
	if err := windows.SetEvent(w.gpWaitEvents[0]); err != nil {
		return err
	}

	procUnregisterGPNotification.Call(uintptr(w.gpWaitEvents[1]))

	// Wait for doWatch to complete.
	<-w.done

	// Now we may safely clean up all the things.
	for i, evt := range w.gpWaitEvents {
		windows.CloseHandle(evt)
		w.gpWaitEvents[i] = 0
	}

	w.handler = nil

	return nil
}
