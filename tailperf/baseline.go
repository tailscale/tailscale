// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailperf

import (
	"encoding/json"
	"fmt"
	"time"
)

type BaselineOptions struct {
	MinSamples         int
	DegradedFraction   float64
	ImprovedFraction   float64
	NormalVarianceFrac float64
}

type BaselineSummary struct {
	Available          bool     `json:"available"`
	SampleCount        int      `json:"sampleCount"`
	BaselineBitsPerSec float64  `json:"baselineBitsPerSecond,omitempty"`
	NewBitsPerSec      float64  `json:"newBitsPerSecond,omitempty"`
	Degraded           bool     `json:"degraded,omitempty"`
	Improved           bool     `json:"improved,omitempty"`
	PathChanged        bool     `json:"pathChanged,omitempty"`
	Messages           []string `json:"messages,omitempty"`
}

func CompareBaseline(newResult Result, prior []Result, opts BaselineOptions) BaselineSummary {
	if opts.MinSamples == 0 {
		opts.MinSamples = 3
	}
	if opts.DegradedFraction == 0 {
		opts.DegradedFraction = 0.75
	}
	if opts.ImprovedFraction == 0 {
		opts.ImprovedFraction = 1.25
	}
	if opts.NormalVarianceFrac == 0 {
		opts.NormalVarianceFrac = 0.15
	}

	var samples []Result
	for _, r := range prior {
		if r.Error != "" {
			continue
		}
		if r.SourceNode != newResult.SourceNode || r.DestinationNode != newResult.DestinationNode {
			continue
		}
		if r.Protocol != newResult.Protocol || r.Direction != newResult.Direction {
			continue
		}
		if r.Path.Normalized().Type != newResult.Path.Normalized().Type {
			continue
		}
		samples = append(samples, r)
	}
	s := BaselineSummary{SampleCount: len(samples), NewBitsPerSec: newResult.BitrateBitsPerSecond}
	if last, ok := lastSuccessfulResult(prior); ok && last.Path.Normalized().Type != newResult.Path.Normalized().Type {
		s.PathChanged = true
		s.Messages = append(s.Messages, fmt.Sprintf("Path changed from %s to %s since last successful test.", last.Path.String(), newResult.Path.String()))
	}
	if len(samples) < opts.MinSamples {
		s.Messages = append(s.Messages, "No baseline available: insufficient samples.")
		return s
	}
	var total float64
	for _, r := range samples {
		total += r.BitrateBitsPerSecond
	}
	s.Available = true
	s.BaselineBitsPerSec = total / float64(len(samples))
	if s.BaselineBitsPerSec > 0 {
		ratio := newResult.BitrateBitsPerSecond / s.BaselineBitsPerSec
		switch {
		case ratio < opts.DegradedFraction:
			s.Degraded = true
			s.Messages = append(s.Messages, fmt.Sprintf("Throughput is %.0f%% below recent baseline.", (1-ratio)*100))
		case ratio > opts.ImprovedFraction:
			s.Improved = true
			s.Messages = append(s.Messages, fmt.Sprintf("Throughput is %.0f%% above recent baseline.", (ratio-1)*100))
		case ratio >= 1-opts.NormalVarianceFrac && ratio <= 1+opts.NormalVarianceFrac:
			s.Messages = append(s.Messages, "Throughput is within historical range.")
		default:
			s.Messages = append(s.Messages, "Throughput is outside normal variance but not degraded enough to flag.")
		}
	}

	return s
}

type NodePairInsight struct {
	Latest                Result          `json:"latest"`
	Baseline              BaselineSummary `json:"baseline"`
	PathSummary           string          `json:"pathSummary"`
	Degraded              bool            `json:"degraded"`
	RecommendedNextAction string          `json:"recommendedNextAction,omitempty"`
}

func lastSuccessfulResult(results []Result) (Result, bool) {
	for i := len(results) - 1; i >= 0; i-- {
		if results[i].Error == "" {
			return results[i], true
		}
	}
	return Result{}, false
}

func BuildNodePairInsight(latest Result, prior []Result) NodePairInsight {
	b := CompareBaseline(latest, prior, BaselineOptions{})
	ins := NodePairInsight{
		Latest:      latest,
		Baseline:    b,
		PathSummary: latest.Path.String(),
		Degraded:    b.Degraded || b.PathChanged,
	}
	switch {
	case latest.Error != "":
		ins.RecommendedNextAction = "Check Tailperf permission, reachability, and listener state."
	case b.PathChanged:
		ins.RecommendedNextAction = "Compare path metadata with recent successful tests."
	case b.Degraded:
		ins.RecommendedNextAction = "Run a follow-up test and check whether the path is direct, DERP, or peer relay."
	default:
		ins.RecommendedNextAction = "No immediate Tailperf action recommended."
	}
	return ins
}

type ScheduleConfig struct {
	Enabled       bool         `json:"enabled"`
	Frequency     DurationJSON `json:"frequency"`
	TestDuration  DurationJSON `json:"testDuration"`
	MaxConcurrent int          `json:"maxConcurrent"`
	NoLog         bool         `json:"noLog,omitempty"`
}

func (c ScheduleConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.Frequency.Duration < 15*time.Minute {
		return fmt.Errorf("tailperf schedule frequency must be at least 15m")
	}
	if c.TestDuration.Duration <= 0 || c.TestDuration.Duration > MaxDuration {
		return fmt.Errorf("tailperf scheduled test duration must be between 1ns and %v", MaxDuration)
	}
	if c.MaxConcurrent == 0 {
		return nil
	}
	if c.MaxConcurrent != 1 {
		return fmt.Errorf("tailperf scheduled tests allow only one active test per node")
	}
	return nil
}

// DurationJSON marshals a duration as a Go duration string.
type DurationJSON struct {
	time.Duration
}

func (d DurationJSON) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

func (d *DurationJSON) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = parsed
	return nil
}
