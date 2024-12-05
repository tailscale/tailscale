// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package vms

import "regexp"

type regexValue struct {
	r *regexp.Regexp
}

func (r *regexValue) String() string {
	if r.r == nil {
		return ""
	}

	return r.r.String()
}

func (r *regexValue) Set(val string) error {
	if rex, err := regexp.Compile(val); err != nil {
		return err
	} else {
		r.r = rex
		return nil
	}
}

func (r regexValue) Unwrap() *regexp.Regexp { return r.r }
