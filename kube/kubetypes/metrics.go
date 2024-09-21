// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package kubetypes

const (
	// Hostinfo App values for the Tailscale Kubernetes Operator components.
	AppOperator        = "k8s-operator"
	AppAPIServerProxy  = "k8s-operator-proxy"
	AppIngressProxy    = "k8s-operator-ingress-proxy"
	AppIngressResource = "k8s-operator-ingress-resource"
	AppEgressProxy     = "k8s-operator-egress-proxy"
	AppConnector       = "k8s-operator-connector-resource"

	// Clientmetrics for Tailscale Kubernetes Operator components
	MetricIngressProxyCount              = "k8s_ingress_proxies"   // L3
	MetricIngressResourceCount           = "k8s_ingress_resources" // L7
	MetricEgressProxyCount               = "k8s_egress_proxies"
	MetricConnectorResourceCount         = "k8s_connector_resources"
	MetricConnectorWithSubnetRouterCount = "k8s_connector_subnetrouter_resources"
	MetricConnectorWithExitNodeCount     = "k8s_connector_exitnode_resources"
	MetricNameserverCount                = "k8s_nameserver_resources"
	MetricRecorderCount                  = "k8s_recorder_resources"
)
