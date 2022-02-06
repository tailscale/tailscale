// Copyright 2020 Brad Fitzpatrick. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.19
// +build go1.19

package assume_no_moving_gc

import (
	"os"
	"runtime"
	"strings"
)

func init() {
	dots := strings.SplitN(runtime.Version(), ".", 3)
	v := runtime.Version()
	if len(dots) >= 2 {
		v = dots[0] + "." + dots[1]
	}
	if os.Getenv(env) == v {
		return
	}
	panic("Something in this program imports go4.org/unsafe/assume-no-moving-gc to declare that it assumes a non-moving garbage collector, but your version of go4.org/unsafe/assume-no-moving-gc hasn't been updated to assert that it's safe against the " + v + " runtime. If you want to risk it, run with environment variable " + env + "=" + v + " set. Notably, if " + v + " adds a moving garbage collector, this program is unsafe to use.")
}
