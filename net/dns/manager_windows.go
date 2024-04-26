// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"tailscale.com/atomicfile"
	"tailscale.com/envknob"
	"tailscale.com/health"
	"tailscale.com/types/logger"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/winutil"
)

const (
	versionKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
)

var configureWSL = envknob.RegisterBool("TS_DEBUG_CONFIGURE_WSL")

type windowsManager struct {
	logf       logger.Logf
	guid       string
	nrptDB     *nrptRuleDatabase
	wslManager *wslManager

	mu      sync.Mutex
	closing bool
}

func NewOSConfigurator(logf logger.Logf, health *health.Tracker, interfaceName string) (OSConfigurator, error) {
	ret := &windowsManager{
		logf:       logf,
		guid:       interfaceName,
		wslManager: newWSLManager(logf, health),
	}

	if isWindows10OrBetter() {
		ret.nrptDB = newNRPTRuleDatabase(logf)
	}

	go func() {
		// Log WSL status once at startup.
		if distros, err := wslDistros(); err != nil {
			logf("WSL: could not list distributions: %v", err)
		} else {
			logf("WSL: found %d distributions", len(distros))
		}
	}()

	return ret, nil
}

func (m *windowsManager) openInterfaceKey(pfx winutil.RegistryPathPrefix) (registry.Key, error) {
	var key registry.Key
	var err error
	path := pfx.WithSuffix(m.guid)

	m.mu.Lock()
	closing := m.closing
	m.mu.Unlock()
	if closing {
		// Do not wait for the interface key to appear if the manager is being closed.
		// If it's being closed due to the removal of the wintun adapter,
		// the key would already be gone by now and will not reappear until tailscaled is restarted.
		key, err = registry.OpenKey(registry.LOCAL_MACHINE, string(path), registry.SET_VALUE)
	} else {
		key, err = winutil.OpenKeyWait(registry.LOCAL_MACHINE, path, registry.SET_VALUE)
	}
	if err != nil {
		return 0, fmt.Errorf("opening %s: %w", path, err)
	}
	return key, nil
}

func (m *windowsManager) muteKeyNotFoundIfClosing(err error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closing || (!errors.Is(err, windows.ERROR_FILE_NOT_FOUND) && !errors.Is(err, windows.ERROR_PATH_NOT_FOUND)) {
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

// setSplitDNS configures one or more NRPT (Name Resolution Policy Table) rules
// to resolve queries for domains using resolvers, rather than the
// system's "primary" resolver.
//
// If no resolvers are provided, the Tailscale NRPT rules are deleted.
func (m *windowsManager) setSplitDNS(resolvers []netip.Addr, domains []dnsname.FQDN) error {
	if m.nrptDB == nil {
		if resolvers == nil {
			// Just a no-op in this case.
			return nil
		}
		return fmt.Errorf("Split DNS unsupported on this Windows version")
	}

	defer m.nrptDB.Refresh()
	if len(resolvers) == 0 {
		return m.nrptDB.DelAllRuleKeys()
	}

	servers := make([]string, 0, len(resolvers))
	for _, resolver := range resolvers {
		servers = append(servers, resolver.String())
	}

	return m.nrptDB.WriteSplitDNSConfig(servers, domains)
}

func setTailscaleHosts(prevHostsFile []byte, hosts []*HostEntry) ([]byte, error) {
	b := bytes.ReplaceAll(prevHostsFile, []byte("\r\n"), []byte("\n"))
	sc := bufio.NewScanner(bytes.NewReader(b))
	const (
		header = "# TailscaleHostsSectionStart"
		footer = "# TailscaleHostsSectionEnd"
	)
	var comments = []string{
		"# This section contains MagicDNS entries for Tailscale.",
		"# Do not edit this section manually.",
	}
	var out bytes.Buffer
	var inSection bool
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == header {
			inSection = true
			continue
		}
		if line == footer {
			inSection = false
			continue
		}
		if inSection {
			continue
		}
		fmt.Fprintln(&out, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(hosts) > 0 {
		fmt.Fprintln(&out, header)
		for _, c := range comments {
			fmt.Fprintln(&out, c)
		}
		fmt.Fprintln(&out)
		for _, he := range hosts {
			fmt.Fprintf(&out, "%s %s\n", he.Addr, strings.Join(he.Hosts, " "))
		}
		fmt.Fprintln(&out)
		fmt.Fprintln(&out, footer)
	}
	return bytes.ReplaceAll(out.Bytes(), []byte("\n"), []byte("\r\n")), nil
}

// setHosts sets the hosts file to contain the given host entries.
func (m *windowsManager) setHosts(hosts []*HostEntry) error {
	systemDir, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	hostsFile := filepath.Join(systemDir, "drivers", "etc", "hosts")
	b, err := os.ReadFile(hostsFile)
	if err != nil {
		return err
	}
	outB, err := setTailscaleHosts(b, hosts)
	if err != nil {
		return err
	}
	const fileMode = 0 // ignored on windows.

	// This can fail spuriously with an access denied error, so retry it a
	// few times.
	for range 5 {
		if err = atomicfile.WriteFile(hostsFile, outB, fileMode); err == nil {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return err
}

// setPrimaryDNS sets the given resolvers and domains as the Tailscale
// interface's DNS configuration.
// If resolvers is non-empty, those resolvers become the system's
// "primary" resolvers.
// domains can be set without resolvers, which just contributes new
// paths to the global DNS search list.
func (m *windowsManager) setPrimaryDNS(resolvers []netip.Addr, domains []dnsname.FQDN) error {
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

	key4, err := m.openInterfaceKey(winutil.IPv4TCPIPInterfacePrefix)
	if err != nil {
		return m.muteKeyNotFoundIfClosing(err)
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

	key6, err := m.openInterfaceKey(winutil.IPv6TCPIPInterfacePrefix)
	if err != nil {
		return m.muteKeyNotFoundIfClosing(err)
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

	// Disable LLMNR on the Tailscale interface. We don't do multicast, and we
	// certainly don't do LLMNR, so it's pointless to make Windows try it. It is
	// being deprecated.
	if err := key4.SetDWordValue("EnableMulticast", 0); err != nil {
		return err
	}
	if err := key6.SetDWordValue("EnableMulticast", 0); err != nil {
		return err
	}

	return nil
}

func (m *windowsManager) SetDNS(cfg OSConfig) error {
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

	// Unconditionally disable dynamic DNS updates and NetBIOS on our
	// interfaces.
	if err := m.disableDynamicUpdates(); err != nil {
		m.logf("disableDynamicUpdates error: %v\n", err)
	}
	if err := m.disableNetBIOS(); err != nil {
		m.logf("disableNetBIOS error: %v\n", err)
	}

	if len(cfg.MatchDomains) == 0 {
		if err := m.setSplitDNS(nil, nil); err != nil {
			return err
		}
		if err := m.setHosts(nil); err != nil {
			return err
		}
		if err := m.setPrimaryDNS(cfg.Nameservers, cfg.SearchDomains); err != nil {
			return err
		}
	} else if m.nrptDB == nil {
		return errors.New("cannot set per-domain resolvers on Windows 7")
	} else {
		if err := m.setSplitDNS(cfg.Nameservers, cfg.MatchDomains); err != nil {
			return err
		}
		// Unset the resolver on the interface to ensure that we do not become
		// the primary resolver. Although this is what we want, at the moment
		// (2022-08-13) it causes single label resolutions from the OS resolver
		// to wait for a MDNS response from the Tailscale interface.
		// See #1659 and #5366 for more details.
		//
		// Still set search domains on the interface, since NRPT only handles
		// query routing and not search domain expansion.
		if err := m.setPrimaryDNS(nil, cfg.SearchDomains); err != nil {
			return err
		}

		// As we are not the primary resolver in this setup, we need to
		// explicitly set some single name hosts to ensure that we can resolve
		// them quickly and get around the 2.3s delay that otherwise occurs due
		// to multicast timeouts.
		if err := m.setHosts(cfg.Hosts); err != nil {
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
		m.logf("running ipconfig /flushdns ...")
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

	// On initial setup of WSL, the restart caused by --shutdown is slow,
	// so we do it out-of-line.
	if configureWSL() {
		go func() {
			if err := m.wslManager.SetDNS(cfg); err != nil {
				m.logf("WSL SetDNS: %v", err) // continue
			} else {
				m.logf("WSL SetDNS: success")
			}
		}()
	}

	return nil
}

func (m *windowsManager) SupportsSplitDNS() bool {
	return m.nrptDB != nil
}

func (m *windowsManager) Close() error {
	m.mu.Lock()
	if m.closing {
		m.mu.Unlock()
		return nil
	}
	m.closing = true
	m.mu.Unlock()

	err := m.SetDNS(OSConfig{})
	if m.nrptDB != nil {
		m.nrptDB.Close()
		m.nrptDB = nil
	}
	return err
}

// disableDynamicUpdates sets the appropriate registry values to prevent the
// Windows DHCP client from sending dynamic DNS updates for our interface to
// AD domain controllers.
func (m *windowsManager) disableDynamicUpdates() error {
	prefixen := []winutil.RegistryPathPrefix{
		winutil.IPv4TCPIPInterfacePrefix,
		winutil.IPv6TCPIPInterfacePrefix,
	}

	for _, prefix := range prefixen {
		k, err := m.openInterfaceKey(prefix)
		if err != nil {
			return m.muteKeyNotFoundIfClosing(err)
		}
		defer k.Close()

		if err := k.SetDWordValue("DisableDynamicUpdate", 1); err != nil {
			return err
		}
		if err := k.SetDWordValue("MaxNumberOfAddressesToRegister", 0); err != nil {
			return err
		}
	}
	return nil
}

// setSingleDWORD opens the Registry Key in HKLM for the interface associated
// with the windowsManager and sets the "keyPrefix\value" to data.
func (m *windowsManager) setSingleDWORD(prefix winutil.RegistryPathPrefix, value string, data uint32) error {
	k, err := m.openInterfaceKey(prefix)
	if err != nil {
		return m.muteKeyNotFoundIfClosing(err)
	}
	defer k.Close()
	return k.SetDWordValue(value, data)
}

// disableNetBIOS sets the appropriate registry values to prevent Windows from
// sending NetBIOS name resolution requests for our interface which we do not
// handle nor want to. By leaving it enabled and not handling it we introduce
// short-name resolution delays in certain conditions as Windows waits for
// NetBIOS responses from our interface (#1659).
//
// Further, LLMNR and NetBIOS are being deprecated anyway in favor of MDNS.
// https://techcommunity.microsoft.com/t5/networking-blog/aligning-on-mdns-ramping-down-netbios-name-resolution-and-llmnr/ba-p/3290816
func (m *windowsManager) disableNetBIOS() error {
	return m.setSingleDWORD(winutil.NetBTInterfacePrefix, "NetbiosOptions", 2)
}

func (m *windowsManager) GetBaseConfig() (OSConfig, error) {
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
func (m *windowsManager) getBasePrimaryResolver() (resolvers []netip.Addr, err error) {
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

	type candidate struct {
		id     winipcfg.LUID
		metric uint32
	}
	var candidates []candidate
	for _, row := range ifrows {
		if !row.Connected {
			continue
		}
		if row.InterfaceLUID == tsLUID {
			continue
		}
		candidates = append(candidates, candidate{row.InterfaceLUID, row.Metric})
	}
	if len(candidates) == 0 {
		// No resolvers set outside of Tailscale.
		return nil, nil
	}

	sort.Slice(candidates, func(i, j int) bool { return candidates[i].metric < candidates[j].metric })

	for _, candidate := range candidates {
		ips, err := candidate.id.DNS()
		if err != nil {
			return nil, err
		}

	ipLoop:
		for _, ip := range ips {
			ip = ip.Unmap()
			// Skip IPv6 site-local resolvers. These are an ancient
			// and obsolete IPv6 RFC, which Windows still faithfully
			// implements. The net result is that some low-metric
			// interfaces can "have" DNS resolvers, but they're just
			// site-local resolver IPs that don't go anywhere. So, we
			// skip the site-local resolvers in order to find the
			// first interface that has real DNS servers configured.
			for _, sl := range siteLocalResolvers {
				if ip.WithZone("") == sl {
					continue ipLoop
				}
			}
			resolvers = append(resolvers, ip)
		}

		if len(resolvers) > 0 {
			// Found some resolvers, we're done.
			break
		}
	}

	return resolvers, nil
}

var siteLocalResolvers = []netip.Addr{
	netip.MustParseAddr("fec0:0:0:ffff::1"),
	netip.MustParseAddr("fec0:0:0:ffff::2"),
	netip.MustParseAddr("fec0:0:0:ffff::3"),
}

func isWindows10OrBetter() bool {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, versionKey, registry.READ)
	if err != nil {
		// Fail safe, assume old Windows.
		return false
	}
	// This key above only exists in Windows 10 and above. Its mere
	// presence is good enough.
	if _, _, err := key.GetIntegerValue("CurrentMajorVersionNumber"); err != nil {
		return false
	}
	return true
}
