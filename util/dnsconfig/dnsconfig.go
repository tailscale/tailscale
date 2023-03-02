package dnsconfig

/*
#cgo LDFLAGS: -ldl

#include <dlfcn.h>
#include <stdlib.h>

void* call_pointer(void* addr) {
	void* (*fn)(void) = addr;
	return fn();
}

void call_arg(void* addr, void* arg) {
	void (*fn)(void*) = addr;
	fn(arg);
}
*/
import "C"

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"syscall"
	"unsafe"
)

var (
	fptrOnce                sync.Once
	dnsConfigurationCopyPtr unsafe.Pointer
	dnsConfigurationFreePtr unsafe.Pointer
)

func initPointers() {
	fptrOnce.Do(func() {
		sym := C.CString("dns_configuration_copy")
		defer C.free(unsafe.Pointer(sym))
		dnsConfigurationCopyPtr = C.dlsym(C.RTLD_DEFAULT, sym)

		sym = C.CString("dns_configuration_free")
		defer C.free(unsafe.Pointer(sym))
		dnsConfigurationFreePtr = C.dlsym(C.RTLD_DEFAULT, sym)
	})
}

var errSymbolNotFound = errors.New("symbol not found")

func dnsConfigurationCopy() (*dnsConfig, error) {
	initPointers()
	if dnsConfigurationCopyPtr == nil {
		return nil, errSymbolNotFound
	}

	// Call through cgo so that the Go runtime switches to a C stack.
	ptr := C.call_pointer(dnsConfigurationCopyPtr)
	return (*dnsConfig)(ptr), nil
}

func dnsConfigurationFree(p *dnsConfig) error {
	initPointers()
	if dnsConfigurationFreePtr == nil {
		return errSymbolNotFound
	}
	// Call through cgo so that the Go runtime switches to a C stack.
	C.call_arg(dnsConfigurationFreePtr, unsafe.Pointer(p))
	return nil
}

// DNSConfig contains DNS configuration information as returned by macOS. It is
// the Go version of the private dns_config_t type.
type DNSConfig struct {
	Resolvers                []*DNSResolver
	ScopedResolvers          []*DNSResolver
	Generation               uint64
	ServiceSpecificResolvers []*DNSResolver
	Version                  uint32
}

// DNSResolver contains DNS resolver-specific information as returned by macOS.
// It is the Go version of the private dns_resolver_t type.
type DNSResolver struct {
	Domain            string
	Nameservers       []netip.AddrPort
	Port              uint16
	Search            []string
	Options           string
	Timeout           uint32
	SearchOrder       uint32
	IfIndex           uint32
	Flags             uint32
	ReachFlags        uint32
	ServiceIdentifier uint32
	CID               string
	IfName            string

	// TODO: SortAddr []any?
}

// Get returns this system's DNS configuration, or an error.
func Get() (*DNSConfig, error) {
	config, err := dnsConfigurationCopy()
	if err != nil {
		return nil, err
	}
	defer dnsConfigurationFree(config)

	// Verify that the version is what we expect. On newer versions of
	// macOS, we could check this and only load fields that are present,
	// instead of failing outright.
	version := binary.LittleEndian.Uint32(config.data[44 : 44+4])
	if version != 20170629 {
		return nil, fmt.Errorf("version mismatch: %d != 20170629", version)
	}

	ret := &DNSConfig{
		Generation: binary.LittleEndian.Uint64(config.data[24 : 24+8]),
		Version:    version,
	}

	// Populate resolvers
	for _, resolver := range getResolvers(config.data[:], 0, 4) {
		ret.Resolvers = append(ret.Resolvers, parseResolver(resolver))
	}
	for _, resolver := range getResolvers(config.data[:], 12, 16) {
		ret.ScopedResolvers = append(ret.ScopedResolvers, parseResolver(resolver))
	}
	for _, resolver := range getResolvers(config.data[:], 32, 36) {
		ret.ServiceSpecificResolvers = append(ret.ServiceSpecificResolvers, parseResolver(resolver))
	}

	return ret, nil
}

func getResolvers(data []byte, numOff, arrOff int) []*dnsResolver {
	n := int(binary.LittleEndian.Uint32(data[numOff : numOff+4]))
	arr := unsafe.Pointer(uintptr(binary.LittleEndian.Uint64(data[arrOff : arrOff+8])))
	return unsafe.Slice((**dnsResolver)(arr), n)
}

func parseResolver(r *dnsResolver) *DNSResolver {
	ret := &DNSResolver{
		Domain:            r.readCharPtr(0),
		Port:              binary.LittleEndian.Uint16(r.data[20 : 20+2]),
		Options:           r.readCharPtr(48),
		Timeout:           r.readUint32(56),
		SearchOrder:       r.readUint32(60),
		IfIndex:           r.readUint32(64),
		Flags:             r.readUint32(68),
		ReachFlags:        r.readUint32(72),
		ServiceIdentifier: r.readUint32(76),
		CID:               r.readCharPtr(80),
		IfName:            r.readCharPtr(88),
	}

	// The actual nameservers for this DNS entry.
	nNameservers := int(binary.LittleEndian.Uint32(r.data[8 : 8+4]))
	arr := unsafe.Pointer(uintptr(binary.LittleEndian.Uint64(r.data[12 : 12+8])))
	for _, sockaddr := range unsafe.Slice((**syscall.RawSockaddr)(arr), nNameservers) {
		switch sockaddr.Family {
		case syscall.AF_INET:
			sa := (*syscall.RawSockaddrInet4)(unsafe.Pointer(sockaddr))
			ret.Nameservers = append(ret.Nameservers, netip.AddrPortFrom(
				netip.AddrFrom4(sa.Addr),
				sa.Port,
			))

		case syscall.AF_INET6:
			sa := (*syscall.RawSockaddrInet6)(unsafe.Pointer(sockaddr))
			ret.Nameservers = append(ret.Nameservers, netip.AddrPortFrom(
				netip.AddrFrom16(sa.Addr),
				sa.Port,
			))

		default:
			// Skip unknown address families
			// TODO: log?
		}
	}

	// Search domains
	nSearch := int(binary.LittleEndian.Uint32(r.data[24 : 24+4]))
	arr = unsafe.Pointer(uintptr(binary.LittleEndian.Uint64(r.data[28 : 28+8])))
	for _, ss := range unsafe.Slice((**C.char)(arr), nSearch) {
		ret.Search = append(ret.Search, C.GoString(ss))
	}

	return ret
}

// dnsConfig is the type returned from the dns_configuration_copy function. The
// C header sets #pragma pack(4), which isn't easily represented in Go; we
// instead use binary.Read to get fields from this structure.
type dnsConfig struct {
	data [48]byte
}

// dnsResolver is the dns_resolver_t type; as above, since we can't represent
// it in Go, we read fields from the structure manually.
type dnsResolver struct {
	data [96]byte
}

func (d *dnsResolver) readCharPtr(off int) string {
	ptr := unsafe.Pointer(uintptr(binary.LittleEndian.Uint64(d.data[off : off+8])))
	return C.GoString((*C.char)(ptr))
}

func (d *dnsResolver) readInt32(off int) int32 {
	return int32(binary.LittleEndian.Uint32(d.data[off : off+4]))
}

func (d *dnsResolver) readUint32(off int) uint32 {
	return binary.LittleEndian.Uint32(d.data[off : off+4])
}
