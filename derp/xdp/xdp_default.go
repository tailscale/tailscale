// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package xdp

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

// STUNServer is unimplemented on these platforms, see xdp_linux.go.
type STUNServer struct {
}

func NewSTUNServer(config *STUNServerConfig, opts ...STUNServerOption) (*STUNServer, error) {
	return nil, errors.New("unimplemented on this GOOS")
}

func (s *STUNServer) Close() error {
	return errors.New("unimplemented on this GOOS")
}

func (s *STUNServer) Describe(descCh chan<- *prometheus.Desc) {}

func (s *STUNServer) Collect(metricCh chan<- prometheus.Metric) {}

func (s *STUNServer) SetDropSTUN(v bool) error {
	return errors.New("unimplemented on this GOOS")
}

func (s *STUNServer) GetDropSTUN() bool {
	return true
}
