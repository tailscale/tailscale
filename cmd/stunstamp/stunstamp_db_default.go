// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !(windows && 386)

package main

import (
	"database/sql"

	_ "modernc.org/sqlite"
)

type db struct {
	*sql.DB
}

func newDB(path string) (*db, error) {
	d, err := sql.Open("sqlite", *flagOut)
	if err != nil {
		return nil, err
	}
	return &db{
		DB: d,
	}, nil
}
