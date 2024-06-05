// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"database/sql"
	"errors"
)

type db struct {
	*sql.DB
}

func newDB(path string) (*db, error) {
	return nil, errors.New("unsupported platform")
}
