// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package tailperf implements the Tailscale-integrated performance test engine
// used by the tailscale perf command and related support tooling.
package tailperf

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	DefaultPort     uint16        = 5201
	DefaultDuration time.Duration = 10 * time.Second
	MaxDuration     time.Duration = 60 * time.Second
	DefaultInterval time.Duration = time.Second

	SchemaVersion = 1
)

type Protocol string

const (
	ProtoTCP Protocol = "tcp"
	ProtoUDP Protocol = "udp"
)

func (p Protocol) Valid() bool {
	return p == ProtoTCP || p == ProtoUDP
}

type Direction string

const (
	DirectionForward Direction = "forward"
	DirectionReverse Direction = "reverse"
	DirectionBoth    Direction = "both"
)

type TUNMode string

const (
	TUNModeDefault   TUNMode = "tun"
	TUNModeUserspace TUNMode = "userspace"
)

type PathType string

const (
	PathUnknown   PathType = "unknown"
	PathDirect    PathType = "direct"
	PathDERP      PathType = "derp"
	PathPeerRelay PathType = "peer-relay"
)

type PathMetadata struct {
	Type           PathType `json:"type"`
	Endpoint       string   `json:"endpoint,omitempty"`
	DERPRegionID   int      `json:"derpRegionID,omitempty"`
	DERPRegionCode string   `json:"derpRegionCode,omitempty"`
	DERPRegionName string   `json:"derpRegionName,omitempty"`
	PeerRelay      string   `json:"peerRelay,omitempty"`
	VNI            string   `json:"vni,omitempty"`
}

func (p PathMetadata) IsZero() bool {
	return p.Type == "" &&
		p.Endpoint == "" &&
		p.DERPRegionID == 0 &&
		p.DERPRegionCode == "" &&
		p.DERPRegionName == "" &&
		p.PeerRelay == "" &&
		p.VNI == ""
}

func (p PathMetadata) Normalized() PathMetadata {
	if p.Type == "" {
		p.Type = PathUnknown
	}
	switch p.Type {
	case PathDirect, PathDERP, PathPeerRelay, PathUnknown:
	default:
		p.Type = PathUnknown
	}
	if p.VNI == "" && p.PeerRelay != "" {
		if before, after, ok := strings.Cut(p.PeerRelay, ":vni:"); ok {
			p.PeerRelay = before
			p.VNI = after
		}
	}
	return p
}

func (p PathMetadata) String() string {
	p = p.Normalized()
	switch p.Type {
	case PathDirect:
		return "direct"
	case PathDERP:
		region := p.DERPRegionCode
		if region == "" {
			region = p.DERPRegionName
		}
		if region == "" && p.DERPRegionID != 0 {
			region = fmt.Sprintf("%d", p.DERPRegionID)
		}
		if region == "" {
			return "DERP"
		}
		if p.VNI != "" {
			return fmt.Sprintf("DERP (%s) vni:%s", region, p.VNI)
		}
		return fmt.Sprintf("DERP (%s)", region)
	case PathPeerRelay:
		s := "peer relay"
		if p.PeerRelay != "" {
			s += " (" + p.PeerRelay + ")"
		}
		if p.VNI != "" {
			s += " vni:" + p.VNI
		}
		return s
	default:
		return "unknown"
	}
}

type PathProvider func(context.Context) PathMetadata

type ClientConfig struct {
	Host             string
	Port             uint16
	Protocol         Protocol
	Duration         time.Duration
	Interval         time.Duration
	CapBitsPerSecond int64
	Direction        Direction
	TUNMode          TUNMode
	NoLog            bool
	SourceNode       string
	DestinationNode  string
	PathProvider     PathProvider
	DialTCP          func(context.Context, string, uint16) (net.Conn, error)
	DialUDP          func(context.Context, string, uint16) (net.Conn, error)
	LogSink          LogSink
}

type ServerConfig struct {
	Addr     string
	Port     uint16
	Protocol Protocol
}

type IntervalResult struct {
	StartSeconds         float64      `json:"startSeconds"`
	EndSeconds           float64      `json:"endSeconds"`
	TransferBytes        int64        `json:"transferBytes"`
	BitrateBitsPerSecond float64      `json:"bitrateBitsPerSecond"`
	Path                 PathMetadata `json:"path"`
}

type PathChange struct {
	AtSeconds float64      `json:"atSeconds"`
	From      PathMetadata `json:"from"`
	To        PathMetadata `json:"to"`
}

type Result struct {
	SchemaVersion        int              `json:"schemaVersion"`
	Started              time.Time        `json:"started"`
	Ended                time.Time        `json:"ended"`
	SourceNode           string           `json:"sourceNode,omitempty"`
	DestinationNode      string           `json:"destinationNode,omitempty"`
	Direction            Direction        `json:"direction"`
	Protocol             Protocol         `json:"protocol"`
	DurationMillis       int64            `json:"durationMillis"`
	CapBitsPerSecond     int64            `json:"capBitsPerSecond,omitempty"`
	TUNMode              TUNMode          `json:"tunMode,omitempty"`
	TransferBytes        int64            `json:"transferBytes"`
	BitrateBitsPerSecond float64          `json:"bitrateBitsPerSecond"`
	LatencyMillis        *float64         `json:"latencyMillis,omitempty"`
	Retransmits          *int64           `json:"retransmits,omitempty"`
	LossPercent          *float64         `json:"lossPercent,omitempty"`
	Path                 PathMetadata     `json:"path"`
	PathChanges          []PathChange     `json:"pathChanges,omitempty"`
	Intervals            []IntervalResult `json:"intervals,omitempty"`
	LoggingDisabled      bool             `json:"loggingDisabled,omitempty"`
	Redacted             bool             `json:"redacted,omitempty"`
	Error                string           `json:"error,omitempty"`
}

type LogSink interface {
	LogTailperfResult(context.Context, Result) error
}

type LogSinkFunc func(context.Context, Result) error

func (f LogSinkFunc) LogTailperfResult(ctx context.Context, r Result) error {
	return f(ctx, r)
}

type RedactionOptions struct {
	HideUserIdentity bool `json:"hideUserIdentity,omitempty"`
	HideTailnetName  bool `json:"hideTailnetName,omitempty"`
	HideNodeNames    bool `json:"hideNodeNames,omitempty"`
	HidePrivateIPs   bool `json:"hidePrivateIPs,omitempty"`
	HidePublicIPs    bool `json:"hidePublicIPs,omitempty"`
	HideDNSAnswers   bool `json:"hideDNSAnswers,omitempty"`
	HideURLs         bool `json:"hideURLs,omitempty"`
	HideRelayNames   bool `json:"hideRelayNames,omitempty"`
}
