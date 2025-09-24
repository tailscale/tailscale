// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package usermetric provides a container and handler
// for user-facing metrics.
package usermetric

import (
	"io"
	"net/http"
)

// Registry tracks user-facing metrics of various Tailscale subsystems.
type Registry struct{}

type noop struct{}

type MultiLabelMap[T comparable] struct{}

func (*MultiLabelMap[T]) Add(T, int64) {}
func (*MultiLabelMap[T]) Set(T, any)   {}

// NewMultiLabelMapWithRegistry creates and register a new
// MultiLabelMap[T] variable with the given name and returns it.
// The variable is registered with the userfacing metrics package.
//
// Note that usermetric are not protected against duplicate
// metrics name. It is the caller's responsibility to ensure that
// the name is unique.
func NewMultiLabelMapWithRegistry[T comparable](m *Registry, name string, promType, helpText string) *MultiLabelMap[T] {
	return &MultiLabelMap[T]{}
}

// Gauge is a gauge metric with no labels.
type Gauge struct{}

var noopGauge = &Gauge{}

// NewGauge creates and register a new gauge metric with the given name and help text.
func (r *Registry) NewGauge(name, help string) *Gauge { return noopGauge }

func (g *Gauge) Add(v float64) {}
func (g *Gauge) Set(v float64) {}

// Set sets the gauge to the given value.
func (noop) Set(v float64) {}

// WritePrometheus writes the gauge metric in Prometheus format to the given writer.
// This satisfies the varz.PrometheusWriter interface.
func (g *Gauge) WritePrometheus(w io.Writer, name string) {
	panic("")
}

// Handler returns a varz.Handler that serves the userfacing expvar contained
// in this package.
func (r *Registry) Handler(w http.ResponseWriter, req *http.Request) {
	http.NotFound(w, req)
}

// Metrics returns the name of all the metrics in the registry.
func (r *Registry) MetricNames() []string {
	return nil
}
