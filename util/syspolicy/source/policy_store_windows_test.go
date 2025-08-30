// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package source

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"tailscale.com/tstest"
	"tailscale.com/util/cibuild"
	"tailscale.com/util/mak"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/setting"
	"tailscale.com/util/winutil"
	"tailscale.com/util/winutil/gp"
)

// subkeyStrings is a test type indicating that a string slice should be written
// to the registry as multiple REG_SZ values under the setting's key,
// rather than as a single REG_MULTI_SZ value under the group key.
// This is the same format as ADMX use for string lists.
type subkeyStrings []string

type testPolicyValue struct {
	name  pkey.Key
	value any
}

func TestLockUnlockPolicyStore(t *testing.T) {
	// Make sure we don't leak goroutines
	tstest.ResourceCheck(t)

	store, err := NewMachinePlatformPolicyStore()
	if err != nil {
		t.Fatalf("NewMachinePolicyStore failed: %v", err)
	}

	t.Run("One-Goroutine", func(t *testing.T) {
		if err := store.Lock(); err != nil {
			t.Errorf("store.Lock(): got %v; want nil", err)
			return
		}
		if v, err := store.ReadString("NonExistingPolicySetting"); err == nil || !errors.Is(err, setting.ErrNotConfigured) {
			t.Errorf(`ReadString: got %v, %v; want "", %v`, v, err, setting.ErrNotConfigured)
		}
		store.Unlock()
	})

	// Lock the store N times from different goroutines.
	const N = 100
	var unlocked atomic.Int32
	t.Run("N-Goroutines", func(t *testing.T) {
		var wg sync.WaitGroup
		wg.Add(N)
		for range N {
			go func() {
				if err := store.Lock(); err != nil {
					t.Errorf("store.Lock(): got %v; want nil", err)
					return
				}
				if v, err := store.ReadString("NonExistingPolicySetting"); err == nil || !errors.Is(err, setting.ErrNotConfigured) {
					t.Errorf(`ReadString: got %v, %v; want "", %v`, v, err, setting.ErrNotConfigured)
				}
				wg.Done()
				time.Sleep(10 * time.Millisecond)
				unlocked.Add(1)
				store.Unlock()
			}()
		}

		// Wait until the store is locked N times.
		wg.Wait()
	})

	// Close the store. The call should wait for all held locks to be released.
	if err := store.Close(); err != nil {
		t.Fatalf("(*PolicyStore).Close failed: %v", err)
	}
	if locked := unlocked.Load(); locked != N {
		t.Errorf("locked.Load(): got %v; want %v", locked, N)
	}

	// Any further attempts to lock it should fail.
	if err = store.Lock(); err == nil || !errors.Is(err, ErrStoreClosed) {
		t.Errorf("store.Lock(): got %v; want %v", err, ErrStoreClosed)
	}
}

func TestReadPolicyStore(t *testing.T) {
	if !winutil.IsCurrentProcessElevated() {
		t.Skipf("test requires running as elevated user")
	}
	tests := []struct {
		name        pkey.Key
		newValue    any
		legacyValue any
		want        any
	}{
		{name: "LegacyPolicy", legacyValue: "LegacyValue", want: "LegacyValue"},
		{name: "StringPolicy", legacyValue: "LegacyValue", newValue: "Value", want: "Value"},
		{name: "StringPolicy_Empty", legacyValue: "LegacyValue", newValue: "", want: ""},
		{name: "BoolPolicy_True", newValue: true, want: true},
		{name: "BoolPolicy_False", newValue: false, want: false},
		{name: "UIntPolicy_1", newValue: uint32(10), want: uint64(10)}, // uint32 values should be returned as uint64
		{name: "UIntPolicy_2", newValue: uint64(1 << 37), want: uint64(1 << 37)},
		{name: "StringListPolicy", newValue: []string{"Value1", "Value2"}, want: []string{"Value1", "Value2"}},
		{name: "StringListPolicy_Empty", newValue: []string{}, want: []string{}},
		{name: "StringListPolicy_SubKey", newValue: subkeyStrings{"Value1", "Value2"}, want: []string{"Value1", "Value2"}},
		{name: "StringListPolicy_SubKey_Empty", newValue: subkeyStrings{}, want: []string{}},
	}

	runTests := func(t *testing.T, userStore bool, token windows.Token) {
		var hive registry.Key
		if userStore {
			hive = registry.CURRENT_USER
		} else {
			hive = registry.LOCAL_MACHINE
		}

		// Write policy values to the registry.
		newValues := make([]testPolicyValue, 0, len(tests))
		for _, tt := range tests {
			if tt.newValue != nil {
				newValues = append(newValues, testPolicyValue{name: tt.name, value: tt.newValue})
			}
		}
		policiesKeyName := softwareKeyName + `\` + tsPoliciesSubkey
		cleanup, err := createTestPolicyValues(hive, policiesKeyName, newValues)
		if err != nil {
			t.Fatalf("createTestPolicyValues failed: %v", err)
		}
		t.Cleanup(cleanup)

		// Write legacy policy values to the registry.
		legacyValues := make([]testPolicyValue, 0, len(tests))
		for _, tt := range tests {
			if tt.legacyValue != nil {
				legacyValues = append(legacyValues, testPolicyValue{name: tt.name, value: tt.legacyValue})
			}
		}
		legacyKeyName := softwareKeyName + `\` + tsIPNSubkey
		cleanup, err = createTestPolicyValues(hive, legacyKeyName, legacyValues)
		if err != nil {
			t.Fatalf("createTestPolicyValues failed: %v", err)
		}
		t.Cleanup(cleanup)

		var store *PlatformPolicyStore
		if userStore {
			store, err = NewUserPlatformPolicyStore(token)
		} else {
			store, err = NewMachinePlatformPolicyStore()
		}
		if err != nil {
			t.Fatalf("NewXPolicyStore failed: %v", err)
		}
		t.Cleanup(func() {
			if err := store.Close(); err != nil {
				t.Errorf("(*PolicyStore).Close failed: %v", err)
			}
		})

		// testReadValues checks that [PolicyStore] returns the same values we wrote directly to the registry.
		testReadValues := func(t *testing.T, withLocks bool) {
			for _, tt := range tests {
				t.Run(string(tt.name), func(t *testing.T) {
					if userStore && tt.newValue == nil {
						t.Skip("there is no legacy policies for users")
					}

					t.Parallel()

					if withLocks {
						if err := store.Lock(); err != nil {
							t.Errorf("failed to acquire the lock: %v", err)
						}
						defer store.Unlock()
					}

					var got any
					var err error
					switch tt.want.(type) {
					case string:
						got, err = store.ReadString(tt.name)
					case uint64:
						got, err = store.ReadUInt64(tt.name)
					case bool:
						got, err = store.ReadBoolean(tt.name)
					case []string:
						got, err = store.ReadStringArray(tt.name)
					}
					if err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(got, tt.want) {
						t.Errorf("got %v; want %v", got, tt.want)
					}
				})
			}
		}
		t.Run("NoLock", func(t *testing.T) {
			testReadValues(t, false)
		})

		t.Run("WithLock", func(t *testing.T) {
			testReadValues(t, true)
		})
	}

	t.Run("MachineStore", func(t *testing.T) {
		runTests(t, false, 0)
	})

	t.Run("CurrentUserStore", func(t *testing.T) {
		runTests(t, true, 0)
	})

	t.Run("UserStoreWithToken", func(t *testing.T) {
		var token windows.Token
		if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
			t.Fatalf("OpenProcessToken: %v", err)
		}
		defer token.Close()
		runTests(t, true, token)
	})
}

func TestPolicyStoreChangeNotifications(t *testing.T) {
	if cibuild.On() {
		t.Skipf("test requires running on a real Windows environment")
	}
	store, err := NewMachinePlatformPolicyStore()
	if err != nil {
		t.Fatalf("NewMachinePolicyStore failed: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("(*PolicyStore).Close failed: %v", err)
		}
	})

	done := make(chan struct{})
	unregister, err := store.RegisterChangeCallback(func() { close(done) })
	if err != nil {
		t.Fatalf("RegisterChangeCallback failed: %v", err)
	}
	t.Cleanup(unregister)

	// RefreshMachinePolicy is a non-blocking call.
	if err := gp.RefreshMachinePolicy(true); err != nil {
		t.Fatalf("RefreshMachinePolicy failed: %v", err)
	}

	// We should receive a policy change notification when
	// the Group Policy service completes policy processing.
	// Otherwise, the test will eventually time out.
	<-done
}

func TestSplitSettingKey(t *testing.T) {
	tests := []struct {
		name      string
		key       pkey.Key
		wantPath  string
		wantValue string
	}{
		{
			name:      "empty",
			key:       "",
			wantPath:  ``,
			wantValue: "",
		},
		{
			name:      "explicit-empty-path",
			key:       "/ValueName",
			wantPath:  ``,
			wantValue: "ValueName",
		},
		{
			name:      "empty-value",
			key:       "Root/Sub/",
			wantPath:  `Root\Sub`,
			wantValue: "",
		},
		{
			name:      "with-path",
			key:       "Root/Sub/ValueName",
			wantPath:  `Root\Sub`,
			wantValue: "ValueName",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPath, gotValue := splitSettingKey(tt.key)
			if gotPath != tt.wantPath {
				t.Errorf("Path: got %q, want %q", gotPath, tt.wantPath)
			}
			if gotValue != tt.wantValue {
				t.Errorf("Value: got %q, want %q", gotValue, tt.wantPath)
			}
		})
	}
}

func createTestPolicyValues(hive registry.Key, keyName string, values []testPolicyValue) (cleanup func(), err error) {
	key, existing, err := registry.CreateKey(hive, keyName, registry.ALL_ACCESS)
	if err != nil {
		return nil, err
	}
	var valuesToDelete map[string][]string
	doCleanup := func() {
		for path, values := range valuesToDelete {
			if len(values) == 0 {
				registry.DeleteKey(key, path)
				continue
			}
			key, err := registry.OpenKey(key, path, windows.KEY_ALL_ACCESS)
			if err != nil {
				continue
			}
			defer key.Close()
			for _, value := range values {
				key.DeleteValue(value)
			}
		}

		key.Close()
		if !existing {
			registry.DeleteKey(hive, keyName)
		}
	}
	defer func() {
		if err != nil {
			doCleanup()
		}
	}()

	for _, v := range values {
		key, existing := key, existing
		path, valueName := splitSettingKey(v.name)
		if path != "" {
			if key, existing, err = registry.CreateKey(key, valueName, windows.KEY_ALL_ACCESS); err != nil {
				return nil, err
			}
			defer key.Close()
		}
		if values, ok := valuesToDelete[path]; len(values) > 0 || (!ok && existing) {
			values = append(values, valueName)
			mak.Set(&valuesToDelete, path, values)
		} else if !ok {
			mak.Set(&valuesToDelete, path, nil)
		}

		switch value := v.value.(type) {
		case string:
			err = key.SetStringValue(valueName, value)
		case uint32:
			err = key.SetDWordValue(valueName, value)
		case uint64:
			err = key.SetQWordValue(valueName, value)
		case bool:
			if value {
				err = key.SetDWordValue(valueName, 1)
			} else {
				err = key.SetDWordValue(valueName, 0)
			}
		case []string:
			err = key.SetStringsValue(valueName, value)
		case subkeyStrings:
			key, _, err := registry.CreateKey(key, valueName, windows.KEY_ALL_ACCESS)
			if err != nil {
				return nil, err
			}
			defer key.Close()
			mak.Set(&valuesToDelete, strings.Trim(path+`\`+valueName, `\`), nil)
			for i, value := range value {
				if err := key.SetStringValue(strconv.Itoa(i), value); err != nil {
					return nil, err
				}
			}
		default:
			err = fmt.Errorf("unsupported value: %v (%T), name: %q", value, value, v.name)
		}
		if err != nil {
			return nil, err
		}
	}
	return doCleanup, nil
}
