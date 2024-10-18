// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package syspolicy

import (
	"errors"
	"fmt"
	"os/user"

	"tailscale.com/util/syspolicy/internal"
	"tailscale.com/util/syspolicy/rsop"
	"tailscale.com/util/syspolicy/setting"
	"tailscale.com/util/syspolicy/source"
	"tailscale.com/util/testenv"
)

func init() {
	// On Windows, we should automatically register the Registry-based policy
	// store for the device. If we are running in a user's security context
	// (e.g., we're the GUI), we should also register the Registry policy store for
	// the user. In the future, we should register (and unregister) user policy
	// stores whenever a user connects to (or disconnects from) the local backend.
	// This ensures the backend is aware of the user's policy settings and can send
	// them to the GUI/CLI/Web clients on demand or whenever they change.
	//
	// Other platforms, such as macOS, iOS and Android, should register their
	// platform-specific policy stores via [RegisterStore]
	// (or [RegisterHandler] until they implement the [source.Store] interface).
	//
	// External code, such as the ipnlocal package, may choose to register
	// additional policy stores, such as config files and policies received from
	// the control plane.
	internal.Init.MustDefer(func() error {
		// Do not register or use default policy stores during tests.
		// Each test should set up its own necessary configurations.
		if testenv.InTest() {
			return nil
		}
		return configureSyspolicy(nil)
	})
}

// configureSyspolicy configures syspolicy for use on Windows,
// either in test or regular builds depending on whether tb has a non-nil value.
func configureSyspolicy(tb internal.TB) error {
	const localSystemSID = "S-1-5-18"
	// Always create and register a machine policy store that reads
	// policy settings from the HKEY_LOCAL_MACHINE registry hive.
	machineStore, err := source.NewMachinePlatformPolicyStore()
	if err != nil {
		return fmt.Errorf("failed to create the machine policy store: %v", err)
	}
	if tb == nil {
		_, err = rsop.RegisterStore("Platform", setting.DeviceScope, machineStore)
	} else {
		_, err = rsop.RegisterStoreForTest(tb, "Platform", setting.DeviceScope, machineStore)
	}
	if err != nil {
		return err
	}
	// Check whether the current process is running as Local System or not.
	u, err := user.Current()
	if err != nil {
		return err
	}
	if u.Uid == localSystemSID {
		return nil
	}
	// If it's not a Local System's process (e.g., it's the GUI rather than the tailscaled service),
	// we should create and use a policy store for the current user that reads
	// policy settings from that user's registry hive (HKEY_CURRENT_USER).
	userStore, err := source.NewUserPlatformPolicyStore(0)
	if err != nil {
		return fmt.Errorf("failed to create the current user's policy store: %v", err)
	}
	if tb == nil {
		_, err = rsop.RegisterStore("Platform", setting.CurrentUserScope, userStore)
	} else {
		_, err = rsop.RegisterStoreForTest(tb, "Platform", setting.CurrentUserScope, userStore)
	}
	if err != nil {
		return err
	}
	// And also set [setting.CurrentUserScope] as the [setting.DefaultScope], so [GetString],
	// [GetVisibility] and similar functions would be returning a merged result
	// of the machine's and user's policies.
	if !setting.SetDefaultScope(setting.CurrentUserScope) {
		return errors.New("current scope already set")
	}
	return nil
}
