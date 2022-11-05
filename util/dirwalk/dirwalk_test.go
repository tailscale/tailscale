// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dirwalk

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"testing"

	"go4.org/mem"
)

func TestWalkShallowOSSpecific(t *testing.T) {
	if osWalkShallow == nil {
		t.Skip("no OS-specific implementation")
	}
	testWalkShallow(t, false)
}

func TestWalkShallowPortable(t *testing.T) {
	testWalkShallow(t, true)
}

func testWalkShallow(t *testing.T, portable bool) {
	if portable {
		old := osWalkShallow
		defer func() { osWalkShallow = old }()
		osWalkShallow = nil
	}
	d := t.TempDir()

	t.Run("basics", func(t *testing.T) {
		if err := os.WriteFile(filepath.Join(d, "foo"), []byte("1"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "bar"), []byte("22"), 0400); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(d, "baz"), 0777); err != nil {
			t.Fatal(err)
		}

		var got []string
		if err := WalkShallow(mem.S(d), func(name mem.RO, de os.DirEntry) error {
			var size int64
			if fi, err := de.Info(); err != nil {
				t.Errorf("Info stat error on %q: %v", de.Name(), err)
			} else if !fi.IsDir() {
				size = fi.Size()
			}
			got = append(got, fmt.Sprintf("%q %q dir=%v type=%d size=%v", name.StringCopy(), de.Name(), de.IsDir(), de.Type(), size))
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		sort.Strings(got)
		want := []string{
			`"bar" "bar" dir=false type=0 size=2`,
			`"baz" "baz" dir=true type=2147483648 size=0`,
			`"foo" "foo" dir=false type=0 size=1`,
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("mismatch:\n got %#q\nwant %#q", got, want)
		}
	})

	t.Run("err_not_exist", func(t *testing.T) {
		err := WalkShallow(mem.S(filepath.Join(d, "not_exist")), func(name mem.RO, de os.DirEntry) error {
			return nil
		})
		if !os.IsNotExist(err) {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("allocs", func(t *testing.T) {
		allocs := int(testing.AllocsPerRun(1000, func() {
			if err := WalkShallow(mem.S(d), func(name mem.RO, de os.DirEntry) error { return nil }); err != nil {
				t.Fatal(err)
			}
		}))
		t.Logf("allocs = %v", allocs)
		if !portable && runtime.GOOS == "linux" && allocs != 0 {
			t.Errorf("unexpected allocs: got %v, want 0", allocs)
		}
	})
}
