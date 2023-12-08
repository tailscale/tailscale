// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package syspolicy

import (
	"errors"
	"fmt"

	"tailscale.com/util/clientmetric"
	"tailscale.com/util/winutil"
)

var (
	windowsErrors = clientmetric.NewCounter("windows_syspolicy_errors")
	windowsAny    = clientmetric.NewGauge("windows_syspolicy_any")
)

type windowsHandler struct{}

func init() {
	RegisterHandler(NewCachingHandler(windowsHandler{}))

	keyList := []struct {
		isSet func(Key) bool
		keys  []Key
	}{
		{
			isSet: func(k Key) bool {
				_, err := handler.ReadString(string(k))
				return err == nil
			},
			keys: stringKeys,
		},
		{
			isSet: func(k Key) bool {
				_, err := handler.ReadBoolean(string(k))
				return err == nil
			},
			keys: boolKeys,
		},
		{
			isSet: func(k Key) bool {
				_, err := handler.ReadUInt64(string(k))
				return err == nil
			},
			keys: uint64Keys,
		},
	}

	var anySet bool
	for _, l := range keyList {
		for _, k := range l.keys {
			if !l.isSet(k) {
				continue
			}
			clientmetric.NewGauge(fmt.Sprintf("windows_syspolicy_%s", k)).Set(1)
			anySet = true
		}
	}
	if anySet {
		windowsAny.Set(1)
	}
}

func (windowsHandler) ReadString(key string) (string, error) {
	s, err := winutil.GetPolicyString(key)
	if errors.Is(err, winutil.ErrNoValue) {
		err = ErrNoSuchKey
	} else if err != nil {
		windowsErrors.Add(1)
	}

	return s, err
}

func (windowsHandler) ReadUInt64(key string) (uint64, error) {
	value, err := winutil.GetPolicyInteger(key)
	if errors.Is(err, winutil.ErrNoValue) {
		err = ErrNoSuchKey
	} else if err != nil {
		windowsErrors.Add(1)
	}
	return value, err
}

func (windowsHandler) ReadBoolean(key string) (bool, error) {
	value, err := winutil.GetPolicyInteger(key)
	if errors.Is(err, winutil.ErrNoValue) {
		err = ErrNoSuchKey
	} else if err != nil {
		windowsErrors.Add(1)
	}
	return value != 0, err
}
