// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build cgo && darwin && !ios

package posture

// #cgo LDFLAGS: -framework CoreFoundation -framework IOKit
// #include <CoreFoundation/CoreFoundation.h>
// #include <IOKit/IOKitLib.h>
//
// #if __MAC_OS_X_VERSION_MIN_REQUIRED < 120000
// #define kIOMainPortDefault kIOMasterPortDefault
// #endif
//
// const char *
// getSerialNumber()
// {
//     CFMutableDictionaryRef matching = IOServiceMatching("IOPlatformExpertDevice");
//     if (!matching) {
//         return "err: failed to create dictionary to match IOServices";
//     }
//
//     io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, matching);
//     if (!service) {
//         return "err: failed to look up registered IOService objects that match a matching dictionary";
//     }
//
//     CFStringRef serialNumberRef = IORegistryEntryCreateCFProperty(
//         service,
//         CFSTR("IOPlatformSerialNumber"),
//         kCFAllocatorDefault,
//         0
//     );
//     if (!serialNumberRef) {
//         return "err: failed to look up serial number in IORegistry";
//     }
//
//     CFIndex length = CFStringGetLength(serialNumberRef);
//     CFIndex max_size = CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;
//     char *serialNumberBuf = (char *)malloc(max_size);
//
//     bool result = CFStringGetCString(serialNumberRef, serialNumberBuf, max_size, kCFStringEncodingUTF8);
//
//     CFRelease(serialNumberRef);
//     IOObjectRelease(service);
//
//     if (!result) {
//         free(serialNumberBuf);
//
//         return "err: failed to convert serial number reference to string";
//     }
//
//     return serialNumberBuf;
// }
import "C"
import (
	"fmt"
	"strings"

	"tailscale.com/types/logger"
)

// GetSerialNumber returns the platform serial sumber as reported by IOKit.
func GetSerialNumbers(_ logger.Logf) ([]string, error) {
	csn := C.getSerialNumber()
	serialNumber := C.GoString(csn)

	if err, ok := strings.CutPrefix(serialNumber, "err: "); ok {
		return nil, fmt.Errorf("failed to get serial number from IOKit: %s", err)
	}

	return []string{serialNumber}, nil
}
