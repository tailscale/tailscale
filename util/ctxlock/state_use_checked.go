// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_ctxlock_checks

package ctxlock

const useCheckedImpl = true

type (
	stateImpl = *checked
	lockState = lockCallers
	_         = lockState
)

var fromContext = fromContextChecked

func lock[R Rank](parent stateImpl, mu *checkedMutex[R]) stateImpl {
	return lockChecked(parent, mu)
}
