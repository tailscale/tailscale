// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package syspolicy

import (
	"errors"

	"tailscale.com/util/winutil"
)

type windowsHandler struct{}

func init() {
	RegisterHandler(windowsHandler{})
}

func (windowsHandler) ReadString(key string) (string, error) {
	s, err := winutil.GetPolicyString(key)
	if errors.Is(err, winutil.ErrNoValue) {
		err = ErrNoSuchKey
	}
	return s, err
}

func (windowsHandler) ReadUInt64(key string) (uint64, error) {
	value, err := winutil.GetPolicyInteger(key)
	if errors.Is(err, winutil.ErrNoValue) {
		err = ErrNoSuchKey
	}
	return value, err
}

func (windowsHandler) ReadBoolean(key string) (bool, error) {
	value, err := winutil.GetPolicyInteger(key)
	if errors.Is(err, winutil.ErrNoValue) {
		err = ErrNoSuchKey
	}
	return value != 0, err
}
