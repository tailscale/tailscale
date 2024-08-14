// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build cgo && darwin && !ios

package hostinfo

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Foundation
#import <Foundation/Foundation.h>

const char *getHostname() {
	NSString *hostname = [[NSHost currentHost] localizedName];
    if (hostname != nil) {
        const char *hostnameCString = [hostname UTF8String];
        if (hostnameCString != NULL) {
            return strdup(hostnameCString);
        }
    }
    return NULL;
}
*/
import "C"

func GetHostname() string {
	chn := C.getHostname()
	hostname := C.GoString(chn)
	return hostname
}
