// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_ctxlock_checks

package ctxlock

const useCheckedImpl = false

type (
	stateImpl = unchecked
	lockState = unchecked
	_         = lockState
)

var fromContext = fromContextUnchecked

func lock[R Rank](parent stateImpl, mu *uncheckedMutex[R]) stateImpl {
	return lockUnchecked(parent, mu)
}
