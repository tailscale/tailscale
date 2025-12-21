// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_logtail

package filch

import "os"

type Options struct {
	ReplaceStderr bool
	MaxLineSize   int
	MaxFileSize   int
}

type Filch struct {
	OrigStderr *os.File
}

func (*Filch) TryReadLine() ([]byte, error) {
	return nil, nil
}

func (*Filch) Write(b []byte) (int, error) {
	return len(b), nil
}

func (f *Filch) Close() error {
	return nil
}

func New(string, Options) (*Filch, error) {
	return new(Filch), nil
}
