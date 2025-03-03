package controlclient

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	loginLatencies = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "controlclient_login_latency_seconds",
		Help: "Control login time",
		// 15 buckets from 10ms to 1m.
		Buckets: prometheus.ExponentialBucketsRange(0.01, 60, 15)},
	)
	dialLatencies = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "controlclient_dial_latency_seconds",
		Help: "Control dial time",
		// 15 buckets from 10ms to 1m.
		Buckets: prometheus.ExponentialBucketsRange(0.01, 60, 15)},
	)
	initialMapRequestLatencies = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "controlclient_initial_map_request_latency_seconds",
		Help: "Initial map request/response time",
		// 15 buckets from 10ms to 1m.
		Buckets: prometheus.ExponentialBucketsRange(0.01, 60, 15)},
	)
	updateHealthLatencies = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "controlclient_update_health_latency_seconds",
		Help: "Update health request/response time",
		// 15 buckets from 10ms to 1m.
		Buckets: prometheus.ExponentialBucketsRange(0.01, 60, 15)},
	)
	answerPingLatencies = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "controlclient_answer_ping_latency_seconds",
		Help: "Answer ping request/response time",
		// 15 buckets from 10ms to 1m.
		Buckets: prometheus.ExponentialBucketsRange(0.01, 60, 15)},
	)
)
