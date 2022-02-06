//go:build windows || js

// SPDX-License-Identifier: MIT

package rwcancel

type RWCancel struct {
}

func (*RWCancel) Cancel() {}
