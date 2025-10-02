// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_clientmetrics

package clientmetric

type Metric struct{}

func (*Metric) Add(int64)              {}
func (*Metric) Set(int64)              {}
func (*Metric) Value() int64           { return 0 }
func (*Metric) Register(expvarInt any) {}
func (*Metric) UnregisterAll()         {}

func HasPublished(string) bool            { panic("unreachable") }
func EncodeLogTailMetricsDelta() string   { return "" }
func WritePrometheusExpositionFormat(any) {}

var zeroMetric Metric

func NewCounter(string) *Metric          { return &zeroMetric }
func NewGauge(string) *Metric            { return &zeroMetric }
func NewAggregateCounter(string) *Metric { return &zeroMetric }
