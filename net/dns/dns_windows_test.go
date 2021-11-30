// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsDNSQuery(t *testing.T) {
	/*
		DNS_TYPE_A    = 0x0001
		DNS_TYPE_AAAA    = 0x001c
		DNS_TYPE_SRV     = 0x0021
		DNS_TYPE_TEXT    = 0x0010
	*/
	var options uint32 = 0
	var qtype uint16 = windows.DNS_TYPE_AAAA
	var qrs *windows.DNSRecord
	st := windows.DnsQuery("google.com", qtype, options, nil, &qrs, nil)
	t.Logf("status = %v", st)
	if qrs != nil {
		const (
			DnsFreeFlat                = 0
			DnsFreeRecordList          = 1
			DnsFreeParsedMessageFields = 2
		)
		defer windows.DnsRecordListFree(qrs, DnsFreeRecordList)
	}
	t.Logf("qrs = %p", qrs)
	for rec := qrs; rec != nil; rec = rec.Next {
		t.Logf("rec: %+v", rec)
		name := windows.UTF16PtrToString(rec.Name)
		t.Logf("  name = %q", name)
	}
}
