// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin && !ios

// TODO(kristoffer): MobileKeyBag is original an iOS framework, maybe it works on iOS?

package posture

import (
	/*
		#cgo CFLAGS: -x objective-c
		#cgo LDFLAGS: -framework CoreFoundation
		#cgo LDFLAGS: -framework Foundation
		#import <Foundation/Foundation.h>

		typedef struct {
			int enabled;
			int gracePeriod;
			char* message;
		} screenlockRes;

		typedef NSDictionary* MKBDeviceGetGracePeriodFunction(NSDictionary*);

		screenlockRes getScreenlock() {
			screenlockRes res = { .enabled = 0, .gracePeriod = 0, .message = NULL };

			CFURLRef bundle_url = CFURLCreateWithFileSystemPath(
				kCFAllocatorDefault,
				CFSTR("/System/Library/PrivateFrameworks/MobileKeyBag.framework"),
				kCFURLPOSIXPathStyle,
				true);

			if (bundle_url == NULL) {
				res.message = strdup("Error parsing MobileKeyBag bundle URL");
				return res;
			}

			CFBundleRef bundle = CFBundleCreate(kCFAllocatorDefault, bundle_url);
			CFRelease(bundle_url);

			if (bundle == NULL) {
				res.message = strdup("Error opening MobileKeyBag bundle");
				return res;
			}

			static MKBDeviceGetGracePeriodFunction *MKBDeviceGetGracePeriod = NULL;
			MKBDeviceGetGracePeriod = (NSDictionary * (*)(NSDictionary*)) CFBundleGetFunctionPointerForName(
							bundle, CFSTR("MKBDeviceGetGracePeriod"));
			if (MKBDeviceGetGracePeriod == NULL) {
				res.message = strdup("MKBDeviceGetGracePeriod returned null");
				CFRelease(bundle);

				return res;
			}

			// MKBDeviceGetGracePeriod requires an empty dictionary as the sole argument
			NSDictionary* durationDict = MKBDeviceGetGracePeriod(@{});
			if (![durationDict isKindOfClass:[NSDictionary class]]) {
				res.message = strdup("MKBDeviceGetGracePeriod did not return an NSDictionary");
				CFRelease(bundle);

				return res;
			}

			NSNumber* durationNumber = durationDict[@"GracePeriod"];
			if (![durationNumber isKindOfClass:[NSNumber class]]) {
				res.message = strdup("GracePeriod did not contain an NSNumber");
				CFRelease(bundle);

				return res;
			}

			int duration = durationNumber.integerValue;
			// A value of INT_MAX indicates that the lock is disabled
			res.enabled = (duration == INT_MAX) ? 0 : 1;
			// Return -1 for grace_period when the lock is not set
			res.gracePeriod = res.enabled == 0 ? -1 : duration;

			CFRelease(bundle);
			return res;
		}
	*/
	"C"
)
import (
	"fmt"
	"strconv"
	"time"
)

type Result struct {
	Enabled     bool
	GracePeriod *time.Duration
	Message     string
}

func Read() (Result, error) {
	screenlockRes := C.getScreenlock()

	mkb := Result{}

	if message := C.GoString(screenlockRes.message); message != "" {
		mkb.Message = message
		return mkb, fmt.Errorf("failed to read screenlock: %s", message)
	}

	enabled, err := strconv.ParseBool(fmt.Sprintf("%d", screenlockRes.enabled))
	if err != nil {
		return mkb, fmt.Errorf("failed to parse mobile key bag bool: %s", err)
	}

	mkb.Enabled = enabled

	gracePeriod := time.Duration(screenlockRes.gracePeriod) * time.Second
	mkb.GracePeriod = &gracePeriod

	return mkb, nil
}
