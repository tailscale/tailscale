package netmap

import "net/netip"

// IPServiceMappings maps IP addresses to service names. This is the inverse of
// [ServiceIPMappings], and is used to inform clients which services is an VIP
// address associated with. This is set to b.ipVIPServiceMap every time the
// netmap is updated. This is used to reduce the cost for looking up the service
// name for the dst IP address in the netStack packet processing workflow.
//
// This is of the form:
//
//	{
//	  "100.65.32.1": "svc:samba",
//	  "fd7a:115c:a1e0::1234": "svc:samba",
//	  "100.102.42.3": "svc:web",
//	  "fd7a:115c:a1e0::abcd": "svc:web",
//	}
type IPServiceMappings map[netip.Addr]string
