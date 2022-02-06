// Copyright 2020 Brad Fitzpatrick. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package go4.org/unsafe/assume-no-moving-gc exists so you can depend
// on it from unsafe code that wants to declare that it assumes that
// the Go runtime does not using a moving garbage colllector.
//
// This package is then updated for new Go versions when that
// is still the case and explodes at runtime with a failure
// otherwise, unless an environment variable overrides it.
//
// To use:
//
//     import _ "go4.org/unsafe/assume-no-moving-gc"
//
// There is no API.
//
// The GitHub repo is at https://github.com/go4org/unsafe-assume-no-moving-gc
package assume_no_moving_gc

const env = "ASSUME_NO_MOVING_GC_UNSAFE_RISK_IT_WITH"
