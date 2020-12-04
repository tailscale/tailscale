// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// The code in this file is copied from:
// Copyright (C) 2020 WireGuard LLC. All Rights Reserved.

// TODO(peske): Check the file header ^^^ to ensure appropriate copyright info.

package registry

import (
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"
)

const keyRoot = registry.CURRENT_USER
const pathRoot = "Software\\WireGuardRegistryTest"
const path = pathRoot + "\\foobar"
const pathFake = pathRoot + "\\raboof"

func Test_WaitForKey(t *testing.T) {
	registry.DeleteKey(keyRoot, path)
	registry.DeleteKey(keyRoot, pathRoot)
	go func() {
		time.Sleep(time.Second * 1)
		key, _, err := registry.CreateKey(keyRoot, pathFake, registry.QUERY_VALUE)
		if err != nil {
			t.Errorf("Error creating registry key: %v", err)
		}
		key.Close()
		registry.DeleteKey(keyRoot, pathFake)

		key, _, err = registry.CreateKey(keyRoot, path, registry.QUERY_VALUE)
		if err != nil {
			t.Errorf("Error creating registry key: %v", err)
		}
		key.Close()
	}()
	err := WaitForKey(keyRoot, path, time.Second*2)
	if err != nil {
		t.Errorf("Error waiting for registry key: %v", err)
	}
	registry.DeleteKey(keyRoot, path)
	registry.DeleteKey(keyRoot, pathRoot)

	err = WaitForKey(keyRoot, path, time.Second*1)
	if err == nil {
		t.Error("Registry key notification expected to timeout but it succeeded.")
	}
}

func Test_GetValueWait(t *testing.T) {
	registry.DeleteKey(keyRoot, path)
	registry.DeleteKey(keyRoot, pathRoot)
	go func() {
		time.Sleep(time.Second * 1)
		key, _, err := registry.CreateKey(keyRoot, path, registry.SET_VALUE)
		if err != nil {
			t.Errorf("Error creating registry key: %v", err)
		}
		time.Sleep(time.Second * 1)
		key.SetStringValue("name1", "eulav")
		key.SetExpandStringValue("name2", "value")
		time.Sleep(time.Second * 1)
		key.SetDWordValue("name3", ^uint32(123))
		key.SetDWordValue("name4", 123)
		key.Close()
	}()

	key, err := OpenKeyWait(keyRoot, path, registry.QUERY_VALUE|registry.NOTIFY, time.Second*2)
	if err != nil {
		t.Errorf("Error waiting for registry key: %v", err)
	}

	valueStr, err := GetStringValueWait(key, "name2", time.Second*2)
	if err != nil {
		t.Errorf("Error waiting for registry value: %v", err)
	}
	if valueStr != "value" {
		t.Errorf("Wrong value read: %v", valueStr)
	}

	_, err = GetStringValueWait(key, "nonexisting", time.Second*1)
	if err == nil {
		t.Error("Registry value notification expected to timeout but it succeeded.")
	}

	valueInt, err := GetIntegerValueWait(key, "name4", time.Second*2)
	if err != nil {
		t.Errorf("Error waiting for registry value: %v", err)
	}
	if valueInt != 123 {
		t.Errorf("Wrong value read: %v", valueInt)
	}

	_, err = GetIntegerValueWait(key, "nonexisting", time.Second*1)
	if err == nil {
		t.Error("Registry value notification expected to timeout but it succeeded.")
	}

	key.Close()
	registry.DeleteKey(keyRoot, path)
	registry.DeleteKey(keyRoot, pathRoot)
}
