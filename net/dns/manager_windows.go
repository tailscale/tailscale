// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"inet.af/netaddr"
	"tailscale.com/types/logger"
	"tailscale.com/util/dnsname"
)

const (
	ipv4RegBase = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`
	ipv6RegBase = `SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters`

	// the GUID is randomly generated. At present, Tailscale installs
	// zero or one NRPT rules, so hardcoding a single GUID everywhere
	// is fine.
	nrptBase        = `SYSTEM\CurrentControlSet\services\Dnscache\Parameters\DnsPolicyConfig\{5abe529b-675b-4486-8459-25a634dacc23}`
	nrptOverrideDNS = 0x8 // bitmask value for "use the provided override DNS resolvers"

	versionKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
)

type windowsManager struct {
	logf      logger.Logf
	guid      string
	nrptWorks bool
}

func NewOSConfigurator(logf logger.Logf, interfaceName string) (OSConfigurator, error) {
	ret := windowsManager{
		logf:      logf,
		guid:      interfaceName,
		nrptWorks: !isWindows7(),
	}

	// Best-effort: if our NRPT rule exists, try to delete it. Unlike
	// per-interface configuration, NRPT rules survive the unclean
	// termination of the Tailscale process, and depending on the
	// rule, it may prevent us from reaching login.tailscale.com to
	// boot up. The bootstrap resolver logic will save us, but it
	// slows down start-up a bunch.
	if ret.nrptWorks {
		ret.delKey(nrptBase)
	}

	return ret, nil
}

// keyOpenTimeout is how long we wait for a registry key to
// appear. For some reason, registry keys tied to ephemeral interfaces
// can take a long while to appear after interface creation, and we
// can end up racing with that.
const keyOpenTimeout = 20 * time.Second

func (m windowsManager) openKey(path string) (registry.Key, error) {
	key, err := openKeyWait(registry.LOCAL_MACHINE, path, registry.SET_VALUE, keyOpenTimeout)
	if err != nil {
		return 0, fmt.Errorf("opening %s: %w", path, err)
	}
	return key, nil
}

func (m windowsManager) ifPath(basePath string) string {
	return fmt.Sprintf(`%s\Interfaces\%s`, basePath, m.guid)
}

func (m windowsManager) delKey(path string) error {
	if err := registry.DeleteKey(registry.LOCAL_MACHINE, path); err != nil && err != registry.ErrNotExist {
		return err
	}
	return nil
}

func delValue(key registry.Key, name string) error {
	if err := key.DeleteValue(name); err != nil && err != registry.ErrNotExist {
		return err
	}
	return nil
}

// setSplitDNS configures an NRPT (Name Resolution Policy Table) rule
// to resolve queries for domains using resolvers, rather than the
// system's "primary" resolver.
//
// If no resolvers are provided, the Tailscale NRPT rule is deleted.
func (m windowsManager) setSplitDNS(resolvers []netaddr.IP, domains []dnsname.FQDN) error {
	if len(resolvers) == 0 {
		return m.delKey(nrptBase)
	}

	servers := make([]string, 0, len(resolvers))
	for _, resolver := range resolvers {
		servers = append(servers, resolver.String())
	}
	doms := make([]string, 0, len(domains))
	for _, domain := range domains {
		// NRPT rules must have a leading dot, which is not usual for
		// DNS search paths.
		doms = append(doms, "."+domain.WithoutTrailingDot())
	}

	// CreateKey is actually open-or-create, which suits us fine.
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, nrptBase, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("opening %s: %w", nrptBase, err)
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

	return nil
}

// setPrimaryDNS sets the given resolvers and domains as the Tailscale
// interface's DNS configuration.
// If resolvers is non-empty, those resolvers become the system's
// "primary" resolvers.
// domains can be set without resolvers, which just contributes new
// paths to the global DNS search list.
func (m windowsManager) setPrimaryDNS(resolvers []netaddr.IP, domains []dnsname.FQDN) error {
	var ipsv4 []string
	var ipsv6 []string

	for _, ip := range resolvers {
		if ip.Is4() {
			ipsv4 = append(ipsv4, ip.String())
		} else {
			ipsv6 = append(ipsv6, ip.String())
		}
	}

	domStrs := make([]string, 0, len(domains))
	for _, dom := range domains {
		domStrs = append(domStrs, dom.WithoutTrailingDot())
	}

	key4, err := m.openKey(m.ifPath(ipv4RegBase))
	if err != nil {
		return err
	}
	defer key4.Close()

	if len(ipsv4) == 0 {
		if err := delValue(key4, "NameServer"); err != nil {
			return err
		}
	} else if err := key4.SetStringValue("NameServer", strings.Join(ipsv4, ",")); err != nil {
		return err
	}

	if len(domains) == 0 {
		if err := delValue(key4, "SearchList"); err != nil {
			return err
		}
	} else if err := key4.SetStringValue("SearchList", strings.Join(domStrs, ",")); err != nil {
		return err
	}

	key6, err := m.openKey(m.ifPath(ipv6RegBase))
	if err != nil {
		return err
	}
	defer key6.Close()

	if len(ipsv6) == 0 {
		if err := delValue(key6, "NameServer"); err != nil {
			return err
		}
	} else if err := key6.SetStringValue("NameServer", strings.Join(ipsv6, ",")); err != nil {
		return err
	}

	if len(domains) == 0 {
		if err := delValue(key6, "SearchList"); err != nil {
			return err
		}
	} else if err := key6.SetStringValue("SearchList", strings.Join(domStrs, ",")); err != nil {
		return err
	}

	// Disable LLMNR on the Tailscale interface. We don't do
	// multicast, and we certainly don't do LLMNR, so it's pointless
	// to make Windows try it.
	if err := key4.SetDWordValue("EnableMulticast", 0); err != nil {
		return err
	}
	if err := key6.SetDWordValue("EnableMulticast", 0); err != nil {
		return err
	}

	return nil
}

func (m windowsManager) SetDNS(cfg OSConfig) error {
	// We can configure Windows DNS in one of two ways:
	//
	//  - In primary DNS mode, we set the NameServer and SearchList
	//    registry keys on our interface. Because our interface metric
	//    is very low, this turns us into the one and only "primary"
	//    resolver for the OS, i.e. all queries flow to the
	//    resolver(s) we specify.
	//  - In split DNS mode, we set the Domain registry key on our
	//    interface (which adds that domain to the global search list,
	//    but does not contribute other DNS configuration from the
	//    interface), and configure an NRPT (Name Resolution Policy
	//    Table) rule to route queries for our suffixes to the
	//    provided resolver.
	//
	// When switching modes, we delete all the configuration related
	// to the other mode, so these two are an XOR.
	//
	// Windows actually supports much more advanced configurations as
	// well, with arbitrary routing of hosts and suffixes to arbitrary
	// resolvers. However, we use it in a "simple" split domain
	// configuration only, routing one set of things to the "split"
	// resolver and the rest to the primary.

	if len(cfg.MatchDomains) == 0 {
		if err := m.setSplitDNS(nil, nil); err != nil {
			return err
		}
		if err := m.setPrimaryDNS(cfg.Nameservers, cfg.SearchDomains); err != nil {
			return err
		}
	} else if !m.nrptWorks {
		return errors.New("cannot set per-domain resolvers on Windows 7")
	} else {
		if err := m.setSplitDNS(cfg.Nameservers, cfg.MatchDomains); err != nil {
			return err
		}
		// Still set search domains on the interface, since NRPT only
		// handles query routing and not search domain expansion.
		if err := m.setPrimaryDNS(nil, cfg.SearchDomains); err != nil {
			return err
		}
	}

	// Force DNS re-registration in Active Directory. What we actually
	// care about is that this command invokes the undocumented hidden
	// function that forces Windows to notice that adapter settings
	// have changed, which makes the DNS settings actually take
	// effect.
	//
	// This command can take a few seconds to run, so run it async, best effort.
	//
	// After re-registering DNS, also flush the DNS cache to clear out
	// any cached split-horizon queries that are no longer the correct
	// answer.
	go func() {
		t0 := time.Now()
		m.logf("running ipconfig /registerdns ...")
		cmd := exec.Command("ipconfig", "/registerdns")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		err := cmd.Run()
		d := time.Since(t0).Round(time.Millisecond)
		if err != nil {
			m.logf("error running ipconfig /registerdns after %v: %v", d, err)
		} else {
			m.logf("ran ipconfig /registerdns in %v", d)
		}

		t0 = time.Now()
		m.logf("running ipconfig /registerdns ...")
		cmd = exec.Command("ipconfig", "/flushdns")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		err = cmd.Run()
		d = time.Since(t0).Round(time.Millisecond)
		if err != nil {
			m.logf("error running ipconfig /flushdns after %v: %v", d, err)
		} else {
			m.logf("ran ipconfig /flushdns in %v", d)
		}
	}()

	return nil
}

func (m windowsManager) SupportsSplitDNS() bool {
	return m.nrptWorks
}

func (m windowsManager) Close() error {
	return m.SetDNS(OSConfig{})
}

func (m windowsManager) GetBaseConfig() (OSConfig, error) {
	resolvers, err := m.getBasePrimaryResolver()
	if err != nil {
		return OSConfig{}, err
	}
	return OSConfig{
		Nameservers: resolvers,
		// Don't return any search domains here, because even Windows
		// 7 correctly handles blending search domains from multiple
		// sources, and any search domains we add here will get tacked
		// onto the Tailscale config unnecessarily.
	}, nil
}

// getBasePrimaryResolver returns a guess of the non-Tailscale primary
// resolver on the system.
// It's used on Windows 7 to emulate split DNS by trying to figure out
// what the "previous" primary resolver was. It might be wrong, or
// incomplete.
func (m windowsManager) getBasePrimaryResolver() (resolvers []netaddr.IP, err error) {
	tsGUID, err := windows.GUIDFromString(m.guid)
	if err != nil {
		return nil, err
	}
	tsLUID, err := winipcfg.LUIDFromGUID(&tsGUID)
	if err != nil {
		return nil, err
	}
	ifrows, err := winipcfg.GetIPInterfaceTable(windows.AF_INET)
	if err == windows.ERROR_NOT_FOUND {
		// IPv4 seems disabled, try to get interface metrics from IPv6 instead.
		ifrows, err = winipcfg.GetIPInterfaceTable(windows.AF_INET6)
	}
	if err != nil {
		return nil, err
	}

	var (
		primary winipcfg.LUID
		best    = ^uint32(0)
	)
	for _, row := range ifrows {
		if !row.Connected {
			continue
		}
		if row.InterfaceLUID == tsLUID {
			continue
		}
		if row.Metric < best {
			primary = row.InterfaceLUID
			best = row.Metric
		}
	}
	if primary == 0 {
		// No resolvers set outside of Tailscale.
		return nil, nil
	}

	ips, err := primary.DNS()
	if err != nil {
		return nil, err
	}
	for _, stdip := range ips {
		if ip, ok := netaddr.FromStdIP(stdip); ok {
			resolvers = append(resolvers, ip)
		}
	}

	return resolvers, nil
}

func isWindows7() bool {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, versionKey, registry.READ)
	if err != nil {
		// Fail safe, assume Windows 7.
		return true
	}
	ver, _, err := key.GetStringValue("CurrentVersion")
	if err != nil {
		return true
	}
	// Careful to not assume anything about version numbers beyond
	// 6.3, Microsoft deprecated this registry key and locked its
	// value to what it was in Windows 8.1. We can only use this to
	// probe for versions before that. Good thing we only need Windows
	// 7 (so far).
	//
	// And yes, Windows 7 is version 6.1. Don't ask.
	return ver == "6.1"
}
