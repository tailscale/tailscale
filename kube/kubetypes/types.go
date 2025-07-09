// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package kubetypes

const (
	// Hostinfo App values for the Tailscale Kubernetes Operator components.
	AppOperator          = "k8s-operator"
	AppAPIServerProxy    = "k8s-operator-proxy"
	AppIngressProxy      = "k8s-operator-ingress-proxy"
	AppIngressResource   = "k8s-operator-ingress-resource"
	AppEgressProxy       = "k8s-operator-egress-proxy"
	AppConnector         = "k8s-operator-connector-resource"
	AppProxyGroupEgress  = "k8s-operator-proxygroup-egress"
	AppProxyGroupIngress = "k8s-operator-proxygroup-ingress"

	// Clientmetrics for Tailscale Kubernetes Operator components
	MetricIngressProxyCount              = "k8s_ingress_proxies"      // L3
	MetricIngressResourceCount           = "k8s_ingress_resources"    // L7
	MetricIngressPGResourceCount         = "k8s_ingress_pg_resources" // L7 on ProxyGroup
	MetricServicePGResourceCount         = "k8s_service_pg_resources" // L3 on ProxyGroup
	MetricEgressProxyCount               = "k8s_egress_proxies"
	MetricConnectorResourceCount         = "k8s_connector_resources"
	MetricConnectorWithSubnetRouterCount = "k8s_connector_subnetrouter_resources"
	MetricConnectorWithExitNodeCount     = "k8s_connector_exitnode_resources"
	MetricConnectorWithAppConnectorCount = "k8s_connector_appconnector_resources"
	MetricNameserverCount                = "k8s_nameserver_resources"
	MetricRecorderCount                  = "k8s_recorder_resources"
	MetricEgressServiceCount             = "k8s_egress_service_resources"
	MetricProxyGroupEgressCount          = "k8s_proxygroup_egress_resources"
	MetricProxyGroupIngressCount         = "k8s_proxygroup_ingress_resources"

	// Keys that containerboot writes to state file that can be used to determine its state.
	// fields set in Tailscale state Secret. These are mostly used by the Tailscale Kubernetes operator to determine
	// the state of this tailscale device.
	KeyDeviceID       = "device_id"        // node stable ID of the device
	KeyDeviceFQDN     = "device_fqdn"      // device's tailnet hostname
	KeyDeviceIPs      = "device_ips"       // device's tailnet IPs
	KeyPodUID         = "pod_uid"          // Pod UID
	KeyCapVer         = "tailscale_capver" // tailcfg.CurrentCapabilityVersion of this proxy instance.
	KeyReissueAuthkey = "reissue_authkey"  // Proxies will set this to the authkey that failed, or "no-authkey", if they can't log in.
	// KeyHTTPSEndpoint is a name of a field that can be set to the value of any HTTPS endpoint currently exposed by
	// this device to the tailnet. This is used by the Kubernetes operator Ingress proxy to communicate to the operator
	// that cluster workloads behind the Ingress can now be accessed via the given DNS name over HTTPS.
	KeyHTTPSEndpoint = "https_endpoint"
	ValueNoHTTPS     = "no-https"

	// Pod's IPv4 address header key as returned by containerboot health check endpoint.
	PodIPv4Header string = "Pod-IPv4"

	EgessServicesPreshutdownEP = "/internal-egress-services-preshutdown"

	LabelManaged    = "tailscale.com/managed"
	LabelSecretType = "tailscale.com/secret-type" // "config", "state" "certs"
)
