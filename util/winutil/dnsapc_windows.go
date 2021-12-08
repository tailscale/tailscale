// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package winutil

import (
	"fmt"
	"reflect"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Technically this function returns void, but we need it to return uintptr for NewCallback to work
func dnsQueryExApc(param uintptr, results *DNSQueryResult) uintptr {
	return 0
}

type resolver struct{}

func (r resolver) GetChannel(args []reflect.Value) *APCChannel {
	return &((*invoker)(unsafe.Pointer(uintptr(args[0].Uint())))).done
}

type invoker struct {
	done   APCChannel
	req    DNSQueryRequest
	result DNSQueryResult
	cancel DNSQueryCancel
}

type DNSServerList struct {
	Family uint16
	List   []DNSAddr
}

var (
	once        sync.Once
	apcCallback uintptr
)

func newDNSInvoker(qname string, qtype uint16, qoptions uint64, srvList *DNSServerList, ifaceIdx uint32) (*invoker, error) {
	once.Do(func() {
		cbInfo := APCCallbackInfo{reflect.TypeOf(dnsQueryExApc), resolver{}}
		apcCallback = RegisterAPCCallback(cbInfo)
	})

	var name *uint16
	var err error
	if len(qname) > 0 {
		name, err = windows.UTF16PtrFromString(qname)
		if err != nil {
			return nil, err
		}
	}

	var serverList *DNSAddrArray
	if srvList != nil {
		serverList = NewDNSAddrArray(srvList.Family, srvList.List)
	}

	inv := &invoker{done: MakeAPCChannel(),
		req: DNSQueryRequest{
			Version:                 DNS_QUERY_REQUEST_VERSION1,
			QueryName:               name,
			QueryType:               qtype,
			QueryOptions:            qoptions,
			DNSServerList:           serverList,
			InterfaceIndex:          ifaceIdx,
			QueryCompletionCallback: apcCallback},
		result: DNSQueryResult{Version: DNS_QUERY_RESULTS_VERSION1}}
	inv.req.QueryContext = uintptr(unsafe.Pointer(inv))

	return inv, nil
}

func (i *invoker) Begin() *APCChannel {
	err := DnsQueryEx(&i.req, &i.result, &i.cancel)
	if err != DNS_REQUEST_PENDING {
		i.result.QueryStatus = DNSStatus(uintptr(err.(windows.Errno)))
		close(i.done)
		return nil
	}

	return &i.done
}

func (i *invoker) Wait() *DNSQueryResult {
	<-i.done
	return &i.result
}

func (i *invoker) Cancel() error {
	return DnsCancelQuery(&i.cancel)
}

type DNSResult interface {
	Wait() *DNSQueryResult
	Cancel() error
}

func DNSQuery(qname string, qtype uint16, qoptions uint64, srvList *DNSServerList, interfaceIdx uint32) (DNSResult, error) {
	inv, err := newDNSInvoker(qname, qtype, qoptions, srvList, interfaceIdx)
	if err != nil {
		return nil, fmt.Errorf("Failed creating DNS invoker: %w", err)
	}

	err = SubmitAPCWork(inv)
	if err != nil {
		return nil, fmt.Errorf("Failed submitting work: %w", err)
	}

	return inv, nil
}
