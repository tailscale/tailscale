// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"tailscale.com/types/logger"
	"tailscale.com/util/dnsname"
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
)

var (
	libUserenv          = windows.NewLazySystemDLL("userenv.dll")
	procRefreshPolicyEx = libUserenv.NewProc("RefreshPolicyEx")
)

const _RP_FORCE = 1 // Flag for RefreshPolicyEx

// nrptRuleDatabase ensapsulates access to the Windows Name Resolution Policy
// Table (NRPT).
type nrptRuleDatabase struct {
	logf      logger.Logf
	ruleIDs   []string
	writeAsGP bool
	isGPDirty bool
}

func newNRPTRuleDatabase(logf logger.Logf) *nrptRuleDatabase {
	ret := &nrptRuleDatabase{logf: logf}
	ret.loadRuleSubkeyNames()
	ret.initWriteAsGP()
	logf("nrptRuleDatabase using group policy: %v\n", ret.writeAsGP)
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
	result := winutil.GetRegStrings(nrptRuleIDValueName, nil)
	if result == nil {
		// Use the legacy rule ID if none are specified in our registry key
		result = []string{nrptSingleRuleID}
	}
	db.ruleIDs = result
}

// initWriteAsGP determines which registry path should be used for writing
// NRPT rules. If there are rules in the GP path that don't belong to us, then
// we should use the GP path.
func (db *nrptRuleDatabase) initWriteAsGP() {
	var err error
	defer func() {
		if err != nil {
			db.writeAsGP = false
		}
	}()

	dnsKey, err := registry.OpenKey(registry.LOCAL_MACHINE, dnsBaseGP, registry.READ)
	if err != nil {
		db.logf("Failed to open key %q with error: %v\n", dnsBaseGP, err)
		return
	}
	defer dnsKey.Close()

	ki, err := dnsKey.Stat()
	if err != nil {
		db.logf("Failed to stat key %q with error: %v\n", dnsBaseGP, err)
		return
	}

	// If the dnsKey contains any values, then we need to use the GP key.
	if ki.ValueCount > 0 {
		db.writeAsGP = true
		return
	}

	if ki.SubKeyCount == 0 {
		// If dnsKey contains no values and no subkeys, then we definitely don't
		// need to use the GP key.
		db.writeAsGP = false
		return
	}

	// Get a list of all the NRPT rules under the GP subkey.
	nrptKey, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptBaseGP, registry.READ)
	if err != nil {
		db.logf("Failed to open key %q with error: %v\n", nrptBaseGP, err)
		return
	}
	defer nrptKey.Close()

	gpSubkeyNames, err := nrptKey.ReadSubKeyNames(0)
	if err != nil {
		db.logf("Failed to list subkeys under %q with error: %v\n", nrptBaseGP, err)
		return
	}

	// Add *all* rules from the GP subkey into a set.
	gpSubkeyMap := make(map[string]struct{}, len(gpSubkeyNames))
	for _, gpSubkey := range gpSubkeyNames {
		gpSubkeyMap[strings.ToUpper(gpSubkey)] = struct{}{}
	}

	// Remove *our* rules from the set.
	for _, ourRuleID := range db.ruleIDs {
		delete(gpSubkeyMap, strings.ToUpper(ourRuleID))
	}

	// Any leftover rules do not belong to us. When group policy is being used
	// by something else, we must also use the GP path.
	db.writeAsGP = len(gpSubkeyMap) > 0
}

// DelAllRuleKeys removes any and all NRPT rules that are owned by Tailscale.
func (db *nrptRuleDatabase) DelAllRuleKeys() error {
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
	// NRPT has an undocumented restriction that each rule may only be associated
	// with a maximum of 50 domains. If we are setting rules for more domains
	// than that, we need to split domains into chunks and write out a rule per chunk.
	dq := len(domains) / nrptMaxDomainsPerRule
	dr := len(domains) % nrptMaxDomainsPerRule

	domainRulesLen := dq
	if dr > 0 {
		domainRulesLen++
	}

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
	if !db.isGPDirty {
		return
	}
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
	var nrptBase string
	if db.writeAsGP {
		nrptBase = nrptBaseGP
	} else {
		nrptBase = nrptBaseLocal
	}

	keyStr := nrptBase + `\` + ruleID

	// CreateKey is actually open-or-create, which suits us fine.
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, keyStr, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("opening %s: %w", keyStr, err)
	}
	defer key.Close()
	if err := key.SetDWordValue("Version", 1); err != nil {
		return err
	}
	if err := key.SetStringsValue("Name", doms); err != nil {
		return err
	}
	if err := key.SetStringValue("GenericDNSServers", strings.Join(servers, "; ")); err != nil {
		return err
	}
	if err := key.SetDWordValue("ConfigOptions", nrptOverrideDNS); err != nil {
		return err
	}

	if db.writeAsGP {
		db.isGPDirty = true
	}

	return nil
}
