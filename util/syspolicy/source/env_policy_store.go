// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package source

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/setting"
)

var lookupEnv = os.LookupEnv // test hook

var _ Store = (*EnvPolicyStore)(nil)

// EnvPolicyStore is a [Store] that reads policy settings from environment variables.
type EnvPolicyStore struct{}

// ReadString implements [Store].
func (s *EnvPolicyStore) ReadString(key pkey.Key) (string, error) {
	_, str, err := s.lookupSettingVariable(key)
	if err != nil {
		return "", err
	}
	return str, nil
}

// ReadUInt64 implements [Store].
func (s *EnvPolicyStore) ReadUInt64(key pkey.Key) (uint64, error) {
	name, str, err := s.lookupSettingVariable(key)
	if err != nil {
		return 0, err
	}
	if str == "" {
		return 0, setting.ErrNotConfigured
	}
	value, err := strconv.ParseUint(str, 0, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w: %q is not a valid uint64", name, setting.ErrTypeMismatch, str)
	}
	return value, nil
}

// ReadBoolean implements [Store].
func (s *EnvPolicyStore) ReadBoolean(key pkey.Key) (bool, error) {
	name, str, err := s.lookupSettingVariable(key)
	if err != nil {
		return false, err
	}
	if str == "" {
		return false, setting.ErrNotConfigured
	}
	value, err := strconv.ParseBool(str)
	if err != nil {
		return false, fmt.Errorf("%s: %w: %q is not a valid bool", name, setting.ErrTypeMismatch, str)
	}
	return value, nil
}

// ReadStringArray implements [Store].
func (s *EnvPolicyStore) ReadStringArray(key pkey.Key) ([]string, error) {
	_, str, err := s.lookupSettingVariable(key)
	if err != nil || str == "" {
		return nil, err
	}
	var dst int
	res := strings.Split(str, ",")
	for src := range res {
		res[dst] = strings.TrimSpace(res[src])
		if res[dst] != "" {
			dst++
		}
	}
	return res[0:dst], nil
}

func (s *EnvPolicyStore) lookupSettingVariable(key pkey.Key) (name, value string, err error) {
	name, err = keyToEnvVarName(key)
	if err != nil {
		return "", "", err
	}
	value, ok := lookupEnv(name)
	if !ok {
		return name, "", setting.ErrNotConfigured
	}
	return name, value, nil
}

var (
	errEmptyKey   = errors.New("key must not be empty")
	errInvalidKey = errors.New("key must consist of alphanumeric characters and slashes")
)

// keyToEnvVarName returns the environment variable name for a given policy
// setting key, or an error if the key is invalid. It converts CamelCase keys into
// underscore-separated words and prepends the variable name with the TS prefix.
// For example: AuthKey => TS_AUTH_KEY, ExitNodeAllowLANAccess => TS_EXIT_NODE_ALLOW_LAN_ACCESS, etc.
//
// It's fine to use this in [EnvPolicyStore] without caching variable names since it's not a hot path.
// [EnvPolicyStore] is not a [Changeable] policy store, so the conversion will only happen once.
func keyToEnvVarName(key pkey.Key) (string, error) {
	if len(key) == 0 {
		return "", errEmptyKey
	}

	isLower := func(c byte) bool { return 'a' <= c && c <= 'z' }
	isUpper := func(c byte) bool { return 'A' <= c && c <= 'Z' }
	isLetter := func(c byte) bool { return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') }
	isDigit := func(c byte) bool { return '0' <= c && c <= '9' }

	words := make([]string, 0, 8)
	words = append(words, "TS_DEBUGSYSPOLICY")
	var currentWord strings.Builder
	for i := 0; i < len(key); i++ {
		c := key[i]
		if c >= utf8.RuneSelf {
			return "", errInvalidKey
		}

		var split bool
		switch {
		case isLower(c):
			c -= 'a' - 'A' // make upper
			split = currentWord.Len() > 0 && !isLetter(key[i-1])
		case isUpper(c):
			if currentWord.Len() > 0 {
				prevUpper := isUpper(key[i-1])
				nextLower := i < len(key)-1 && isLower(key[i+1])
				split = !prevUpper || nextLower // split on case transition
			}
		case isDigit(c):
			split = currentWord.Len() > 0 && !isDigit(key[i-1])
		case c == pkey.KeyPathSeparator:
			words = append(words, currentWord.String())
			currentWord.Reset()
			continue
		default:
			return "", errInvalidKey
		}

		if split {
			words = append(words, currentWord.String())
			currentWord.Reset()
		}

		currentWord.WriteByte(c)
	}

	if currentWord.Len() > 0 {
		words = append(words, currentWord.String())
	}

	return strings.Join(words, "_"), nil
}
