// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var ProxyClassKind = "ProxyClass"

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=`.status.conditions[?(@.type == "ProxyClassReady")].reason`,description="Status of the ProxyClass."

// ProxyClass describes a set of configuration parameters that can be applied to
// proxy resources created by the Tailscale Kubernetes operator.
// To apply a given ProxyClass to resources created for a tailscale Ingress or
// Service, use tailscale.com/proxy-class=<proxyclass-name> label. To apply a
// given ProxyClass to resources created for a Connector, use
// connector.spec.proxyClass field.
// ProxyClass is a cluster scoped resource.
// More info:
// https://tailscale.com/kb/1445/kubernetes-operator-customization#cluster-resource-customization-using-proxyclass-custom-resource
type ProxyClass struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired state of the ProxyClass resource.
	// https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
	Spec ProxyClassSpec `json:"spec"`

	// +optional
	// Status of the ProxyClass. This is set and managed automatically.
	// https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
	Status ProxyClassStatus `json:"status"`
}

// +kubebuilder:object:root=true
type ProxyClassList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []ProxyClass `json:"items"`
}

type ProxyClassSpec struct {
	// Configuration parameters for the proxy's StatefulSet. Tailscale
	// Kubernetes operator deploys a StatefulSet for each of the user
	// configured proxies (Tailscale Ingress, Tailscale Service, Connector).
	// +optional
	StatefulSet *StatefulSet `json:"statefulSet"`
	// Configuration for proxy metrics. Metrics are currently not supported
	// for egress proxies and for Ingress proxies that have been configured
	// with tailscale.com/experimental-forward-cluster-traffic-via-ingress
	// annotation. Note that the metrics are currently considered unstable
	// and will likely change in breaking ways in the future - we only
	// recommend that you use those for debugging purposes.
	// +optional
	Metrics *Metrics `json:"metrics,omitempty"`
	// TailscaleConfig contains options to configure the tailscale-specific
	// parameters of proxies.
	// +optional
	TailscaleConfig *TailscaleConfig `json:"tailscale,omitempty"`
}

type TailscaleConfig struct {
	// AcceptRoutes can be set to true to make the proxy instance accept
	// routes advertized by other nodes on the tailnet, such as subnet
	// routes.
	// This is equivalent of passing --accept-routes flag to a tailscale Linux client.
	// https://tailscale.com/kb/1019/subnets#use-your-subnet-routes-from-other-devices
	// Defaults to false.
	AcceptRoutes bool `json:"acceptRoutes,omitempty"`
}

type StatefulSet struct {
	// Labels that will be added to the StatefulSet created for the proxy.
	// Any labels specified here will be merged with the default labels
	// applied to the StatefulSet by the Tailscale Kubernetes operator as
	// well as any other labels that might have been applied by other
	// actors.
	// Label keys and values must be valid Kubernetes label keys and values.
	// https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#syntax-and-character-set
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
	// Annotations that will be added to the StatefulSet created for the proxy.
	// Any Annotations specified here will be merged with the default annotations
	// applied to the StatefulSet by the Tailscale Kubernetes operator as
	// well as any other annotations that might have been applied by other
	// actors.
	// Annotations must be valid Kubernetes annotations.
	// https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/#syntax-and-character-set
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
	// Configuration for the proxy Pod.
	// +optional
	Pod *Pod `json:"pod,omitempty"`
}

type Pod struct {
	// Labels that will be added to the proxy Pod.
	// Any labels specified here will be merged with the default labels
	// applied to the Pod by the Tailscale Kubernetes operator.
	// Label keys and values must be valid Kubernetes label keys and values.
	// https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#syntax-and-character-set
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
	// Annotations that will be added to the proxy Pod.
	// Any annotations specified here will be merged with the default
	// annotations applied to the Pod by the Tailscale Kubernetes operator.
	// Annotations must be valid Kubernetes annotations.
	// https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/#syntax-and-character-set
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
	// Proxy Pod's affinity rules.
	// By default, the Tailscale Kubernetes operator does not apply any affinity rules.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#affinity
	// +optional
	Affinity *corev1.Affinity `json:"affinity,omitempty"`
	// Configuration for the proxy container running tailscale.
	// +optional
	TailscaleContainer *Container `json:"tailscaleContainer,omitempty"`
	// Configuration for the proxy init container that enables forwarding.
	// +optional
	TailscaleInitContainer *Container `json:"tailscaleInitContainer,omitempty"`
	// Proxy Pod's security context.
	// By default Tailscale Kubernetes operator does not apply any Pod
	// security context.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#security-context-2
	// +optional
	SecurityContext *corev1.PodSecurityContext `json:"securityContext,omitempty"`
	// Proxy Pod's image pull Secrets.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#PodSpec
	// +optional
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`
	// Proxy Pod's node name.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#scheduling
	// +optional
	NodeName string `json:"nodeName,omitempty"`
	// Proxy Pod's node selector.
	// By default Tailscale Kubernetes operator does not apply any node
	// selector.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#scheduling
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Proxy Pod's tolerations.
	// By default Tailscale Kubernetes operator does not apply any
	// tolerations.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#scheduling
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
	// Proxy Pod's topology spread constraints.
	// By default Tailscale Kubernetes operator does not apply any topology spread constraints.
	// https://kubernetes.io/docs/concepts/scheduling-eviction/topology-spread-constraints/
	// +optional
	TopologySpreadConstraints []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="!(has(self.serviceMonitor) && self.serviceMonitor.enable  && !self.enable)",message="ServiceMonitor can only be enabled if metrics are enabled"
type Metrics struct {
	// Setting enable to true will make the proxy serve Tailscale metrics
	// at <pod-ip>:9002/metrics.
	// A metrics Service named <proxy-statefulset>-metrics will also be created in the operator's namespace and will
	// serve the metrics at <service-ip>:9002/metrics.
	//
	// In 1.78.x and 1.80.x, this field also serves as the default value for
	// .spec.statefulSet.pod.tailscaleContainer.debug.enable. From 1.82.0, both
	// fields will independently default to false.
	//
	// Defaults to false.
	Enable bool `json:"enable"`
	// Enable to create a Prometheus ServiceMonitor for scraping the proxy's Tailscale metrics.
	// The ServiceMonitor will select the metrics Service that gets created when metrics are enabled.
	// The ingested metrics for each Service monitor will have labels to identify the proxy:
	// ts_proxy_type: ingress_service|ingress_resource|connector|proxygroup
	// ts_proxy_parent_name: name of the parent resource (i.e name of the Connector, Tailscale Ingress, Tailscale Service or ProxyGroup)
	// ts_proxy_parent_namespace: namespace of the parent resource (if the parent resource is not cluster scoped)
	// job: ts_<proxy type>_[<parent namespace>]_<parent_name>
	// +optional
	ServiceMonitor *ServiceMonitor `json:"serviceMonitor"`
}

type ServiceMonitor struct {
	// If Enable is set to true, a Prometheus ServiceMonitor will be created. Enable can only be set to true if metrics are enabled.
	Enable bool `json:"enable"`
}

type Container struct {
	// List of environment variables to set in the container.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#environment-variables
	// Note that environment variables provided here will take precedence
	// over Tailscale-specific environment variables set by the operator,
	// however running proxies with custom values for Tailscale environment
	// variables (i.e TS_USERSPACE) is not recommended and might break in
	// the future.
	// +optional
	Env []Env `json:"env,omitempty"`
	// Container image name. By default images are pulled from
	// docker.io/tailscale/tailscale, but the official images are also
	// available at ghcr.io/tailscale/tailscale. Specifying image name here
	// will override any proxy image values specified via the Kubernetes
	// operator's Helm chart values or PROXY_IMAGE env var in the operator
	// Deployment.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#image
	// +optional
	Image string `json:"image,omitempty"`
	// Image pull policy. One of Always, Never, IfNotPresent. Defaults to Always.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#image
	// +kubebuilder:validation:Enum=Always;Never;IfNotPresent
	// +optional
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy,omitempty"`
	// Container resource requirements.
	// By default Tailscale Kubernetes operator does not apply any resource
	// requirements. The amount of resources required wil depend on the
	// amount of resources the operator needs to parse, usage patterns and
	// cluster size.
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#resources
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
	// Container security context.
	// Security context specified here will override the security context set by the operator.
	// By default the operator sets the Tailscale container and the Tailscale init container to privileged
	// for proxies created for Tailscale ingress and egress Service, Connector and ProxyGroup.
	// You can reduce the permissions of the Tailscale container to cap NET_ADMIN by
	// installing device plugin in your cluster and configuring the proxies tun device to be created
	// by the device plugin, see  https://github.com/tailscale/tailscale/issues/10814#issuecomment-2479977752
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#security-context
	// +optional
	SecurityContext *corev1.SecurityContext `json:"securityContext,omitempty"`
	// Configuration for enabling extra debug information in the container.
	// Not recommended for production use.
	// +optional
	Debug *Debug `json:"debug,omitempty"`
}

type Debug struct {
	// Enable tailscaled's HTTP pprof endpoints at <pod-ip>:9001/debug/pprof/
	// and internal debug metrics endpoint at <pod-ip>:9001/debug/metrics, where
	// 9001 is a container port named "debug". The endpoints and their responses
	// may change in backwards incompatible ways in the future, and should not
	// be considered stable.
	//
	// In 1.78.x and 1.80.x, this setting will default to the value of
	// .spec.metrics.enable, and requests to the "metrics" port matching the
	// mux pattern /debug/ will be forwarded to the "debug" port. In 1.82.x,
	// this setting will default to false, and no requests will be proxied.
	//
	// +optional
	Enable bool `json:"enable"`
}

type Env struct {
	// Name of the environment variable. Must be a C_IDENTIFIER.
	Name Name `json:"name"`
	// Variable references $(VAR_NAME) are expanded using the previously defined
	//  environment variables in the container and any service environment
	// variables. If a variable cannot be resolved, the reference in the input
	// string will be unchanged. Double $$ are reduced to a single $, which
	// allows for escaping the $(VAR_NAME) syntax: i.e. "$$(VAR_NAME)" will
	// produce the string literal "$(VAR_NAME)". Escaped references will never
	// be expanded, regardless of whether the variable exists or not. Defaults
	// to "".
	// +optional
	Value string `json:"value,omitempty"`
}

// +kubebuilder:validation:Type=string
// +kubebuilder:validation:Pattern=`^[-._a-zA-Z][-._a-zA-Z0-9]*$`
type Name string

type ProxyClassStatus struct {
	// List of status conditions to indicate the status of the ProxyClass.
	// Known condition types are `ProxyClassReady`.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}
