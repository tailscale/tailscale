// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package flagtype defines flag.Value types.
package flagtype

import (
	"errors"
	"flag"
	"fmt"
	"math"
	"strconv"
	"strings"
)

type portValue struct{ n *uint16 }

func PortValue(dst *uint16, defaultPort uint16) flag.Value {
	*dst = defaultPort
	return portValue{dst}
}

func (p portValue) String() string {
	if p.n == nil {
		return ""
	}
	return fmt.Sprint(*p.n)
}
func (p portValue) Set(v string) error {
	if v == "" {
		return errors.New("can't be the empty string")
	}
	if strings.Contains(v, ":") {
		return errors.New("expecting just a port number, without a colon")
	}
	n, err := strconv.ParseUint(v, 10, 64) // use 64 instead of 16 to return nicer error message
	if err != nil {
		return fmt.Errorf("not a valid number")
	}
	if n > math.MaxUint16 {
		return errors.New("out of range for port number")
	}
	*p.n = uint16(n)
	return nil
}
