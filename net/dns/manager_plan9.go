// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// TODO: man 6 ndb | grep -e 'suffix.*same line'
// to detect Russ's https://9fans.topicbox.com/groups/9fans/T9c9d81b5801a0820/ndb-suffix-specific-dns-changes

package dns

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"unicode"

	"tailscale.com/control/controlknobs"
	"tailscale.com/health"
	"tailscale.com/types/logger"
	"tailscale.com/util/set"
	"tailscale.com/util/syspolicy/policyclient"
)

func NewOSConfigurator(logf logger.Logf, ht *health.Tracker, _ policyclient.Client, knobs *controlknobs.Knobs, interfaceName string) (OSConfigurator, error) {
	return &plan9DNSManager{
		logf:  logf,
		ht:    ht,
		knobs: knobs,
	}, nil
}

type plan9DNSManager struct {
	logf  logger.Logf
	ht    *health.Tracker
	knobs *controlknobs.Knobs
}

// netNDBBytesWithoutTailscale returns raw (the contents of /net/ndb) with any
// Tailscale bits removed.
func netNDBBytesWithoutTailscale(raw []byte) ([]byte, error) {
	var ret bytes.Buffer
	bs := bufio.NewScanner(bytes.NewReader(raw))
	removeLine := set.Set[string]{}
	for bs.Scan() {
		t := bs.Text()
		if rest, ok := strings.CutPrefix(t, "#tailscaled-added-line:"); ok {
			removeLine.Add(strings.TrimSpace(rest))
			continue
		}
		trimmed := strings.TrimSpace(t)
		if removeLine.Contains(trimmed) {
			removeLine.Delete(trimmed)
			continue
		}

		// Also remove any DNS line referencing *.ts.net. This is
		// Tailscale-specific (and won't work with, say, Headscale), but
		// the Headscale case will be covered by the #tailscaled-added-line
		// logic above, assuming the user didn't delete those comments.
		if (strings.HasPrefix(trimmed, "dns=") || strings.Contains(trimmed, "dnsdomain=")) &&
			strings.HasSuffix(trimmed, ".ts.net") {
			continue
		}

		ret.WriteString(t)
		ret.WriteByte('\n')
	}
	return ret.Bytes(), bs.Err()
}

// setNDBSuffix adds lines to tsFree (the contents of /net/ndb already cleaned
// of Tailscale-added lines) to add the optional DNS search domain (e.g.
// "foo.ts.net") and DNS server to it.
func setNDBSuffix(tsFree []byte, suffix string) []byte {
	suffix = strings.TrimSuffix(suffix, ".")
	if suffix == "" {
		return tsFree
	}
	var buf bytes.Buffer
	bs := bufio.NewScanner(bytes.NewReader(tsFree))
	var added []string
	addLine := func(s string) {
		added = append(added, strings.TrimSpace(s))
		buf.WriteString(s)
	}
	for bs.Scan() {
		buf.Write(bs.Bytes())
		buf.WriteByte('\n')

		t := bs.Text()
		if suffix != "" && len(added) == 0 && strings.HasPrefix(t, "\tdns=") {
			addLine(fmt.Sprintf("\tdns=100.100.100.100 suffix=%s\n", suffix))
			addLine(fmt.Sprintf("\tdnsdomain=%s\n", suffix))
		}
	}
	bufTrim := bytes.TrimLeftFunc(buf.Bytes(), unicode.IsSpace)
	if len(added) == 0 {
		return bufTrim
	}
	var ret bytes.Buffer
	for _, s := range added {
		ret.WriteString("#tailscaled-added-line: ")
		ret.WriteString(s)
		ret.WriteString("\n")
	}
	ret.WriteString("\n")
	ret.Write(bufTrim)
	return ret.Bytes()
}

func (m *plan9DNSManager) SetDNS(c OSConfig) error {
	ndbOnDisk, err := os.ReadFile("/net/ndb")
	if err != nil {
		return err
	}

	tsFree, err := netNDBBytesWithoutTailscale(ndbOnDisk)
	if err != nil {
		return err
	}

	var suffix string
	if len(c.SearchDomains) > 0 {
		suffix = string(c.SearchDomains[0])
	}

	newBuf := setNDBSuffix(tsFree, suffix)
	if !bytes.Equal(newBuf, ndbOnDisk) {
		if err := os.WriteFile("/net/ndb", newBuf, 0644); err != nil {
			return fmt.Errorf("writing /net/ndb: %w", err)
		}
		if f, err := os.OpenFile("/net/dns", os.O_RDWR, 0); err == nil {
			if _, err := io.WriteString(f, "refresh\n"); err != nil {
				f.Close()
				return fmt.Errorf("/net/dns refresh write: %w", err)
			}
			if err := f.Close(); err != nil {
				return fmt.Errorf("/net/dns refresh close: %w", err)
			}
		}
	}

	return nil
}

func (m *plan9DNSManager) SupportsSplitDNS() bool { return false }

func (m *plan9DNSManager) Close() error {
	// TODO(bradfitz): remove the Tailscale bits from /net/ndb ideally
	return nil
}

var dnsRegex = regexp.MustCompile(`\bdns=(\d+\.\d+\.\d+\.\d+)\b`)

func (m *plan9DNSManager) GetBaseConfig() (OSConfig, error) {
	var oc OSConfig
	f, err := os.Open("/net/ndb")
	if err != nil {
		return oc, err
	}
	defer f.Close()
	bs := bufio.NewScanner(f)
	for bs.Scan() {
		m := dnsRegex.FindSubmatch(bs.Bytes())
		if m == nil {
			continue
		}
		addr, err := netip.ParseAddr(string(m[1]))
		if err != nil {
			continue
		}
		oc.Nameservers = append(oc.Nameservers, addr)
	}
	if err := bs.Err(); err != nil {
		return oc, err
	}

	return oc, nil
}
