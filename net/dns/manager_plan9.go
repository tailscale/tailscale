// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// TODO: man 6 ndb | grep -e 'suffix.*same line'
// to detect Russ's https://9fans.topicbox.com/groups/9fans/T9c9d81b5801a0820/ndb-suffix-specific-dns-changes

package dns

import (
	"bufio"
	"bytes"
	"log"
	"net/netip"
	"os"
	"regexp"

	"tailscale.com/control/controlknobs"
	"tailscale.com/health"
	"tailscale.com/types/logger"
)

func NewOSConfigurator(logf logger.Logf, ht *health.Tracker, knobs *controlknobs.Knobs, interfaceName string) (OSConfigurator, error) {
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

func (m *plan9DNSManager) SetDNS(c OSConfig) error {
	var buf bytes.Buffer
	bw := bufio.NewWriter(&buf)
	c.WriteToBufioWriter(bw)
	bw.Flush()

	log.Printf("XXX: TODO: plan9 SetDNS: %s", buf.Bytes())
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
