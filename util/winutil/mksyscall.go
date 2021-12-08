// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package winutil

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall_windows.go mksyscall.go

// Note: DO NOT use DnsQueryExW! It *is* exported from dnsapi.dll but is an internal function!
//sys DnsQueryEx(request *DNSQueryRequest, result *DNSQueryResult, cancelHandle *DNSQueryCancel) (status error) = dnsapi.DnsQueryEx
//sys DnsCancelQuery(cancelHandle *DNSQueryCancel) (status error) = dnsapi.DnsCancelQuery
