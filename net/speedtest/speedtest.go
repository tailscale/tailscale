// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package speedtest contains both server and client code for
// running speedtests between tailscale nodes.
package speedtest

import (
	"time"
)

const (
	blockSize       = 2 * 1024 * 1024       // size of the block of data to send
	MinDuration     = 5 * time.Second       // minimum duration for a test
	DefaultDuration = MinDuration           // default duration for a test
	MaxDuration     = 30 * time.Second      // maximum duration for a test
	version         = 2                     // value used when comparing client and server versions
	increment       = time.Second           // increment to display results for, in seconds
	minInterval     = 10 * time.Millisecond // minimum interval length for a result to be included
	DefaultPort     = 20333
)

// config is the initial message sent to the server, that contains information on how to
// conduct the test.
type config struct {
	Version      int           `json:"version"`
	TestDuration time.Duration `json:"time,format:nano"`
	Direction    Direction     `json:"direction"`
}

// configResponse is the response to the testConfig message. If the server has an
// error with the config, the Error variable will hold that error value.
type configResponse struct {
	Error string `json:"error,omitempty"`
}

// This represents the Result of a speedtest within a specific interval
type Result struct {
	Bytes         int       // number of bytes sent/received during the interval
	IntervalStart time.Time // start of the interval
	IntervalEnd   time.Time // end of the interval
	Total         bool      // if true, this result struct represents the entire test, rather than a segment of the test
}

func (r Result) MBitsPerSecond() float64 {
	return r.MegaBits() / r.IntervalEnd.Sub(r.IntervalStart).Seconds()
}

func (r Result) MegaBytes() float64 {
	return float64(r.Bytes) / 1000000.0
}

func (r Result) MegaBits() float64 {
	return r.MegaBytes() * 8.0
}

func (r Result) Interval() time.Duration {
	return r.IntervalEnd.Sub(r.IntervalStart)
}

type Direction int

const (
	Download Direction = iota
	Upload
)

func (d Direction) String() string {
	switch d {
	case Upload:
		return "upload"
	case Download:
		return "download"
	default:
		return ""
	}
}

func (d *Direction) Reverse() {
	switch *d {
	case Upload:
		*d = Download
	case Download:
		*d = Upload
	default:
	}
}
