// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build darwin

package ipn

import (
	"fmt"
	"regexp"
)

// AWSStore is a handler for a non-implemented store on darwin
type AWSStore struct{}

// NewAWSStore returns a new AWSStore with an hydrated cache
func NewAWSStore(ssmARN string) (*AWSStore, error) {
	return nil, fmt.Errorf("AWSStore is not supported on darwin")
}

// String returns an empty string
func (s *AWSStore) String() string { return "" }

// ReadState returns an empty state
func (s *AWSStore) ReadState(_ StateKey) (bs []byte, err error) {
	return []byte{}, nil
}

// WriteState is not implemented
func (s *AWSStore) WriteState(_ StateKey, _ []byte) (err error) {
	return nil
}
