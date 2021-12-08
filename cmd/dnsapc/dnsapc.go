package main

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
	"tailscale.com/util/winutil"
)

func main() {
	result, err := winutil.DNSQuery("www.tailscale.com", windows.DNS_TYPE_A, winutil.DNS_QUERY_STANDARD, nil, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	qresult := result.Wait()
	finalStatus := qresult.QueryStatus
	fmt.Printf("Query status: %v", finalStatus)
	if finalStatus != 0 {
		fmt.Printf(" (%v)\n", windows.Errno(finalStatus))
	} else {
		fmt.Printf("\n")
	}

	count := 0
	for rec := qresult.QueryRecords; rec != nil; rec = rec.Next {
		name := windows.UTF16PtrToString(rec.Name)
		fmt.Printf("Record %d: %s, type %v", count, name, rec.Type)
		switch rec.Type {
		case windows.DNS_TYPE_A:
			rd := (*winutil.DNSAData)(unsafe.Pointer(&rec.Data[0]))
			a := rd.IPv4Address
			fmt.Printf(" (A): %v.%v.%v.%v\n", a[0], a[1], a[2], a[3])
		case windows.DNS_TYPE_CNAME:
			rd := (*windows.DNSPTRData)(unsafe.Pointer(&rec.Data[0]))
			fmt.Printf(" (CNAME): %s\n", windows.UTF16PtrToString(rd.Host))
		default:
			fmt.Printf("\n")
		}
		count++
	}

	qresult.Close()
}
