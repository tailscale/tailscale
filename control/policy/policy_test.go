// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package policy

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/wgengine/filter"
)

type PortRange = filter.PortRange
type IPPortRange = filter.IPPortRange

var syntax_errors = []string{
	`{ "ACLs": []! }`,

	`{ "ACLs": [
	  {"Action": "accept", "Users": [], "xPorts": ["100.122.98.50:22"]}
	]}`,

	`{ "ACLs": [
	  {"Action": "drop", "Users": [], "Ports": ["100.122.98.50:22"]}
	]}`,

	`{ "ACLs": [
	  {"Users": [], "Ports": ["100.122.98.50:22"]}
	]}`,

	`{ "ACLs": [
	  {"Action": "accept", "Users": [], "Ports": ["1.2.3.4"]}
	]}`,

	`{ "ACLs": [
	  {"Action": "accept", "Users": [], "Ports": ["1.2.3.4:0"]}
	]}`,

	`{ "ACLs": [
	  {"Action": "accept", "Users": [], "Ports": ["0.0.0.0:12"]}
	]}`,

	`{ "ACLs": [
	  {"Action": "accept", "Users": [], "Ports": ["*:0"]}
	]}`,

	`{ "ACLs": [
	  {"Action": "accept", "Users": [], "Ports": ["1.2.3.4:5:6"]}
	]}`,

	`{ "ACLs": [
	  {"Action": "accept", "Users": [], "Ports": ["1.2.3.4.5:12"]}
	]}`,

	`{ "ACLs": [
	  {"Action": "accept", "Users": [], "Ports": ["1.2.3.4::12"]}
	]}`,

	`{ "ACLs": [
	  {"Action": "accept", "Users": [], "Ports": ["1.2.3.4"]}
	]}`,

	`{ "ACLs": [
	  {"Action": "accept", "Users": [], "Ports": ["1.2.3.4:0-0"]}
	]}`,

	`{ "ACLs": [
	  {"Action": "accept", "Users": [], "Ports": ["1.2.3.4:1-10,2-"]}
	]}`,

	`{ "ACLs": [
	  {"Action": "accept", "Users": [], "Ports": ["1.2.3.4:1-10,*"]}
	]}`,

	`{ "ACLs": [
	  {"Action": "accept", "Users": [], "Ports": ["1.2.3.4,5.6.7.8:1-10"]}
	]}`,

	`{ "Hosts": {"mailserver": "not-an-ip"} }`,

	`{ "Hosts": {"mailserver": "1.2.3.4:55"} }`,

	`{ "xGroups": {
	  "bob": ["user1", "user2"]
	 }}`,
}

func TestSyntaxErrors(t *testing.T) {
	for _, s := range syntax_errors {
		_, err := Parse(s)
		if err == nil {
			t.Fatalf("Parse passed when it shouldn't. json:\n---\n%v\n---", s)
		}
	}
}

func ippr(ip IP, start, end uint16) []IPPortRange {
	return []IPPortRange{
		IPPortRange{ip, PortRange{start, end}},
	}
}

func TestPolicy(t *testing.T) {
	// Check ACL table parsing

	usermap := map[string][]IP{
		"A@b.com":    []IP{0x08010101, 0x08020202},
		"role:admin": []IP{0x02020202},
		"user1@org":  []IP{0x99010101, 0x99010102},
		// user2 is intentionally missing
		"user3@org": []IP{0x99030303},
		"user4@org": []IP{},
	}
	want := filter.Matches{
		{SrcIPs: []IP{0x08010101, 0x08020202}, DstPorts: []IPPortRange{
			IPPortRange{0x01020304, PortRange{22, 22}},
			IPPortRange{0x05060708, PortRange{23, 24}},
			IPPortRange{0x05060708, PortRange{27, 28}},
		}},
		{SrcIPs: []IP{0x02020202}, DstPorts: ippr(0x08010101, 22, 22)},
		{SrcIPs: []IP{0}, DstPorts: []IPPortRange{
			IPPortRange{0x647a6232, PortRange{0, 65535}},
			IPPortRange{0, PortRange{443, 443}},
		}},
		{SrcIPs: []IP{0x99010101, 0x99010102, 0x99030303}, DstPorts: ippr(0x01020304, 999, 999)},
	}

	p, err := Parse(`
{
    // Test comment
    "Hosts": {
    	"h1": "1.2.3.4", /* test comment */
    	"h2": "5.6.7.8"
    },
    "Groups": {
    	"group:eng": ["user1@org", "user2@org", "user3@org", "user4@org"]
    },
    "ACLs": [
	{"Action": "accept", "Users": ["a@b.com"], "Ports": ["h1:22", "h2:23-24,27-28"]},
	{"Action": "accept", "Users": ["role:Admin"], "Ports": ["8.1.1.1:22"]},
	{"Action": "accept", "Users": ["*"], "Ports": ["100.122.98.50:*", "*:443"]},
	{"Action": "accept", "Users": ["group:eng"], "Ports": ["h1:999"]},
    ]}
`)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	matches, err := p.Expand(usermap)
	if err != nil {
		t.Fatalf("Expand failed: %v", err)
	}
	if diff := cmp.Diff(want, matches); diff != "" {
		t.Fatalf("Expand mismatch (-want +got):\n%s", diff)
	}
}
