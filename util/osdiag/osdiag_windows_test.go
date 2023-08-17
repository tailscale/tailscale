// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package osdiag

import (
	"errors"
	"fmt"
	"maps"
	"strings"
	"testing"

	"golang.org/x/sys/windows/registry"
)

func makeLongBinaryValue() []byte {
	buf := make([]byte, maxBinaryValueLen*2)
	for i, _ := range buf {
		buf[i] = byte(i % 0xFF)
	}
	return buf
}

var testData = map[string]any{
	"":                              "I am the default",
	"StringEmpty":                   "",
	"StringShort":                   "Hello",
	"StringLong":                    strings.Repeat("7", initialValueBufLen+1),
	"MultiStringEmpty":              []string{},
	"MultiStringSingle":             []string{"Foo"},
	"MultiStringSingleEmpty":        []string{""},
	"MultiString":                   []string{"Foo", "Bar", "Baz"},
	"MultiStringWithEmptyBeginning": []string{"", "Foo", "Bar"},
	"MultiStringWithEmptyMiddle":    []string{"Foo", "", "Bar"},
	"MultiStringWithEmptyEnd":       []string{"Foo", "Bar", ""},
	"DWord":                         uint32(0x12345678),
	"QWord":                         uint64(0x123456789abcdef0),
	"BinaryEmpty":                   []byte{},
	"BinaryShort":                   []byte{0x01, 0x02, 0x03, 0x04},
	"BinaryLong":                    makeLongBinaryValue(),
}

const (
	keyNameTest    = `SOFTWARE\Tailscale Test`
	subKeyNameTest = "SubKey"
)

func setValues(t *testing.T, k registry.Key) {
	for vk, v := range testData {
		var err error
		switch tv := v.(type) {
		case string:
			err = k.SetStringValue(vk, tv)
		case []string:
			err = k.SetStringsValue(vk, tv)
		case uint32:
			err = k.SetDWordValue(vk, tv)
		case uint64:
			err = k.SetQWordValue(vk, tv)
		case []byte:
			err = k.SetBinaryValue(vk, tv)
		default:
			t.Fatalf("Unknown type")
		}

		if err != nil {
			t.Fatalf("Error setting %q: %v", vk, err)
		}
	}
}

func TestRegistrySupportInfo(t *testing.T) {
	// Make sure the key doesn't exist yet
	k, err := registry.OpenKey(registry.CURRENT_USER, keyNameTest, registry.READ)
	switch {
	case err == nil:
		k.Close()
		t.Fatalf("Test key already exists")
	case !errors.Is(err, registry.ErrNotExist):
		t.Fatal(err)
	}

	func() {
		k, _, err := registry.CreateKey(registry.CURRENT_USER, keyNameTest, registry.WRITE)
		if err != nil {
			t.Fatalf("Error creating test key: %v", err)
		}
		defer k.Close()

		setValues(t, k)

		sk, _, err := registry.CreateKey(k, subKeyNameTest, registry.WRITE)
		if err != nil {
			t.Fatalf("Error creating test subkey: %v", err)
		}
		defer sk.Close()

		setValues(t, sk)
	}()

	t.Cleanup(func() {
		registry.DeleteKey(registry.CURRENT_USER, keyNameTest+"\\"+subKeyNameTest)
		registry.DeleteKey(registry.CURRENT_USER, keyNameTest)
	})

	wantValuesData := maps.Clone(testData)
	wantValuesData["BinaryLong"] = (wantValuesData["BinaryLong"].([]byte))[:maxBinaryValueLen]

	wantKeyData := make(map[string]any)
	maps.Copy(wantKeyData, wantValuesData)
	wantSubKeyData := make(map[string]any)
	maps.Copy(wantSubKeyData, wantValuesData)
	wantKeyData[subKeyNameTest] = wantSubKeyData

	wantData := map[string]any{
		"HKCU\\" + keyNameTest: wantKeyData,
	}

	gotData, err := getRegistrySupportInfo(registry.CURRENT_USER, []string{keyNameTest})
	if err != nil {
		t.Errorf("getRegistrySupportInfo error: %v", err)
	}

	want, got := fmt.Sprintf("%#v", wantData), fmt.Sprintf("%#v", gotData)
	if want != got {
		t.Errorf("Compare error: want\n%s,\ngot %s", want, got)
	}
}
