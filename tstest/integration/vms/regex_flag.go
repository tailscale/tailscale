// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
