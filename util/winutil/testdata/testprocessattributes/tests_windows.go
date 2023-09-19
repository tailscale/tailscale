// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"

	"tailscale.com/util/winutil"
)

func init() {
	// registerInit("Foo", FooInit)
	// register("Foo", Foo)
	register("MitigateSelf", MitigateSelf)
}

func MitigateSelf() {
	var zero winutil.ProcessMitigationPolicies
	initialPolicies, err := winutil.CurrentProcessMitigationPolicies()
	if err != nil {
		fmt.Printf("error: CurrentProcessMitigationPolicies: %v\n", err)
		return
	}

	if initialPolicies != zero {
		fmt.Println("error: initialPolicies not zero value")
		return
	}

	setTo := winutil.ProcessMitigationPolicies{
		DisableExtensionPoints:          true,
		PreferSystem32Images:            true,
		ProhibitDynamicCode:             true,
		ProhibitLowMandatoryLabelImages: true,
		ProhibitNonMicrosoftSignedDLLs:  true,
		ProhibitRemoteImages:            true,
	}

	if err := setTo.SetOnCurrentProcess(); err != nil {
		fmt.Printf("error: SetOnCurrentProcess: %v\n", err)
		return
	}

	checkPolicies, err := winutil.CurrentProcessMitigationPolicies()
	if err != nil {
		fmt.Printf("error: CurrentProcessMitigationPolicies: %v\n", err)
		return
	}

	if checkPolicies != setTo {
		fmt.Printf("error: checkPolicies got %#v, want %#v\n", checkPolicies, setTo)
		return
	}

	fmt.Println("OK")
}
