// Copyright (c) Tailscale Inc & contributors
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
	"tailscale.com/util/winutil"
	"tailscale.com/util/winutil/gp"
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

// nrptRuleDatabase encapsulates access to the Windows Name Resolution Policy
// Table (NRPT).
type nrptRuleDatabase struct {
	logf               logger.Logf
	watcher            *gp.ChangeWatcher
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
// NRPT rules. When detectWriteAsGP determines that group policy has been
// enabled for the NRPT, it moves the NRPT policies as appropriate.
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
		if db.watcher != nil && prev != writeAsGP && writeAsGP {
			db.updateGroupPoliciesLocked()
		}
	}()

	// dnsapi simply uses the presence of this key to determine NRPT location.
	if nrptKey, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptBaseGP, registry.READ); err == nil {
		nrptKey.Close()
		writeAsGP = true
	}
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

	return nil
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

	if err := gp.RefreshMachinePolicy(true); err != nil {
		db.logf("RefreshMachinePolicy failed: %v", err)
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

		if err := writeNRPTValues(key, strings.Join(servers, ";"), doms); err != nil {
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

	watcher, err := gp.NewChangeWatcher(gp.MachinePolicy, watchHandler)
	if err != nil {
		return
	}

	db.watcher = watcher
}

// updateGroupPoliciesLocked updates the group policy NRPT. Each NRPT rule is
// copied from the local NRPT to the group policy NRPT.
// db.mu must already be locked.
func (db *nrptRuleDatabase) updateGroupPoliciesLocked() {
	// Since we're updating the group policy NRPT, we need to refresh upon return.
	defer db.refreshLocked()

	for _, id := range db.ruleIDs {
		if err := copyNRPTRule(id); err != nil {
			db.logf("updateGroupPoliciesLocked: copyNRPTRule(%q) failed with error %v", id, err)
			return
		}

		db.isGPDirty = true
	}
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
