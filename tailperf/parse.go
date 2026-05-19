// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailperf

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

func NormalizeClientConfig(c ClientConfig) (ClientConfig, error) {
	if c.Host == "" {
		return c, fmt.Errorf("missing tailperf target")
	}
	if c.Port == 0 {
		c.Port = DefaultPort
	}
	if c.Protocol == "" {
		c.Protocol = ProtoTCP
	}
	if !c.Protocol.Valid() {
		return c, fmt.Errorf("unsupported tailperf protocol %q", c.Protocol)
	}
	if c.Duration == 0 {
		c.Duration = DefaultDuration
	}
	if c.Duration <= 0 {
		return c, fmt.Errorf("tailperf duration must be positive")
	}
	if c.Duration > MaxDuration {
		return c, fmt.Errorf("tailperf duration %v exceeds maximum %v", c.Duration, MaxDuration)
	}
	if c.Interval == 0 {
		c.Interval = DefaultInterval
	}
	if c.Interval <= 0 {
		return c, fmt.Errorf("tailperf interval must be positive")
	}
	if c.Direction == "" {
		c.Direction = DirectionForward
	}
	switch c.Direction {
	case DirectionForward, DirectionReverse, DirectionBoth:
	default:
		return c, fmt.Errorf("unsupported tailperf direction %q", c.Direction)
	}
	if c.Protocol == ProtoUDP && c.Direction != DirectionForward {
		return c, fmt.Errorf("tailperf UDP reverse and both-directions are not supported yet")
	}
	if c.TUNMode == "" {
		c.TUNMode = TUNModeDefault
	}
	return c, nil
}

func NormalizeServerConfig(c ServerConfig) (ServerConfig, error) {
	if c.Port == 0 {
		c.Port = DefaultPort
	}
	if c.Protocol == "" {
		c.Protocol = ProtoTCP
	}
	if !c.Protocol.Valid() {
		return c, fmt.Errorf("unsupported tailperf protocol %q", c.Protocol)
	}
	return c, nil
}

func ParseBandwidth(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "0" || s == "unlimited" {
		return 0, nil
	}

	mult := float64(1)
	for _, suffix := range []struct {
		s string
		m float64
	}{
		{"gbps", 1e9}, {"gbit/s", 1e9}, {"gbit", 1e9}, {"g", 1e9},
		{"mbps", 1e6}, {"mbit/s", 1e6}, {"mbit", 1e6}, {"m", 1e6},
		{"kbps", 1e3}, {"kbit/s", 1e3}, {"kbit", 1e3}, {"k", 1e3},
		{"bps", 1}, {"bit/s", 1}, {"bit", 1}, {"b", 1},
	} {
		if strings.HasSuffix(s, suffix.s) {
			mult = suffix.m
			s = strings.TrimSpace(strings.TrimSuffix(s, suffix.s))
			break
		}
	}
	if s == "" {
		return 0, fmt.Errorf("missing bandwidth value")
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid bandwidth cap %q", s)
	}
	if v < 0 {
		return 0, fmt.Errorf("bandwidth cap must be non-negative")
	}
	return int64(v * mult), nil
}

func ParseDuration(s string) (time.Duration, error) {
	d, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, fmt.Errorf("duration must be positive")
	}
	if d > MaxDuration {
		return 0, fmt.Errorf("duration %v exceeds maximum %v", d, MaxDuration)
	}
	return d, nil
}
