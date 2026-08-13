// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package peerrelay

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler"
	"tailscale.com/k8s-operator/reconciler/tailscaled"
)

const (
	// labelReplicaIndex stores the replica index of a managed Service so it can be matched back to a specific
	// peer relay instance.
	labelReplicaIndex = "tailscale.com/peer-relay-replica"

	// parentTypePeerRelay is the value used for reconciler.LabelParentType on PeerRelay-managed resources.
	parentTypePeerRelay = "peerrelay"

	// servicePortName names the UDP port exposed by each Service. Mostly cosmetic, but Kubernetes requires a name
	// once a Service has more than one port; using a stable name keeps the door open for that.
	servicePortName = "peerrelay"

	// servicePort is the UDP port that each peer relay container will listen on and that the LoadBalancer Service
	// exposes externally.
	servicePort = 41641

	annotationEIPAllocations = "service.beta.kubernetes.io/aws-load-balancer-eip-allocations"
	annotationSubnets        = "service.beta.kubernetes.io/aws-load-balancer-subnets"
	annotationLBAttributes   = "service.beta.kubernetes.io/aws-load-balancer-attributes"
)

// cloudAnnotations are the cloud-provider-specific annotations applied to every generated LoadBalancer Service to
// ensure the Service is provisioned with a publicly addressable IP rather than a DNS name.
var cloudAnnotations = map[string]string{
	// AWS: provision an internet-facing NLB in IP target mode via the AWS Load Balancer Controller.
	"service.beta.kubernetes.io/aws-load-balancer-type":            "external",
	"service.beta.kubernetes.io/aws-load-balancer-nlb-target-type": "ip",
	"service.beta.kubernetes.io/aws-load-balancer-scheme":          "internet-facing",
	"service.beta.kubernetes.io/aws-load-balancer-ip-address-type": "ipv4",

	// AWS: health check the pod over HTTP against containerboot's /healthz rather than the port the Service
	// forwards. A peer relay listens only on UDP, so the default TCP check against the traffic port can never
	// succeed and every target reports unhealthy even while relaying fine. /healthz returns 200 once the device
	// has tailnet addresses, which is the condition that actually matters.
	"service.beta.kubernetes.io/aws-load-balancer-healthcheck-protocol": "http",
	"service.beta.kubernetes.io/aws-load-balancer-healthcheck-port":     strconv.Itoa(tailscaled.HealthCheckPort),
	"service.beta.kubernetes.io/aws-load-balancer-healthcheck-path":     "/healthz",

	// Azure: pin the LB to external.
	"service.beta.kubernetes.io/azure-load-balancer-internal": "false",
}

func peerRelayLabels(prName string) map[string]string {
	return reconciler.Labels(parentTypePeerRelay, prName, "")
}

func peerRelayServiceLabels(prName string, idx int32) map[string]string {
	labels := peerRelayLabels(prName)
	labels[labelReplicaIndex] = strconv.FormatInt(int64(idx), 10)
	return labels
}

func resourceName(prName string) string {
	return "peerrelay-" + prName
}

func replicaName(prName string, idx int32) string {
	return fmt.Sprintf("%s-%d", resourceName(prName), idx)
}

func peerRelayServiceAnnotations(pr *tsapi.PeerRelay, idx int32) map[string]string {
	annotations := make(map[string]string, len(cloudAnnotations))

	if pr.Spec.Service != nil {
		maps.Copy(annotations, pr.Spec.Service.Annotations)
	}

	maps.Copy(annotations, cloudAnnotations)

	// Unless the user has taken control of the load balancer attributes themselves, default cross-zone on. When no
	// subnet is pinned the AWS Load Balancer Controller spreads the load balancer over every zone it discovers,
	// and cross-zone is what lets all of those addresses reach the replica's pod regardless of the zone the
	// scheduler placed it in. It is inert when spec.aws.elasticIPs pins a subnet, since only one zone is enabled
	// on that load balancer, so there is no need to special case it.
	if _, ok := annotations[annotationLBAttributes]; !ok {
		annotations[annotationLBAttributes] = "load_balancing.cross_zone.enabled=true"
	}

	// Per-replica AWS pinning always wins over anything in spec.service.annotations or the cloud defaults so users
	// can rely on spec.aws.elasticIPs being the single source of truth for each replica's EIP + subnet.
	if pr.Spec.AWS != nil && int(idx) < len(pr.Spec.AWS.ElasticIPs) {
		eip := pr.Spec.AWS.ElasticIPs[idx]
		annotations[annotationEIPAllocations] = eip.AllocationID
		annotations[annotationSubnets] = eip.SubnetID
	}

	return annotations
}

func (r *Reconciler) peerRelayService(pr *tsapi.PeerRelay, idx int32) *corev1.Service {
	name := replicaName(pr.Name, idx)

	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Service",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   r.tailscaleNamespace,
			Labels:      peerRelayServiceLabels(pr.Name, idx),
			Annotations: peerRelayServiceAnnotations(pr, idx),
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeLoadBalancer,
			// The Service targets the specific StatefulSet pod for this replica. The StatefulSet controller
			// automatically sets this label on each pod.
			Selector: map[string]string{
				"statefulset.kubernetes.io/pod-name": name,
			},
			Ports: []corev1.ServicePort{
				{
					Name:       servicePortName,
					Protocol:   corev1.ProtocolUDP,
					Port:       servicePort,
					TargetPort: intstr.FromInt32(servicePort),
				},
			},
		},
	}
}

func replicaIndexFromLabels(labels map[string]string) (int32, bool) {
	raw, ok := labels[labelReplicaIndex]
	if !ok {
		return 0, false
	}

	n, err := strconv.ParseInt(raw, 10, 32)
	if err != nil {
		return 0, false
	}

	return int32(n), true
}

// peerRelayEndpoints returns one endpoint per public address the Service's load balancer answers on. A load
// balancer confined to a single subnet has one, while one the cloud spread over several availability zones has an
// address in each, and every one of them reaches the replica. Advertising all of them means a peer can still get
// through when a zone becomes unreachable, and means the user is not paying for addresses nothing uses.
//
// prev is the set of endpoints last published for this replica, returned unchanged when a lookup fails so a
// transient DNS error doesn't empty status.endpoints.
func (r *Reconciler) peerRelayEndpoints(ctx context.Context, logger *zap.SugaredLogger, svc *corev1.Service, prev []tsapi.PeerRelayEndpoint) []tsapi.PeerRelayEndpoint {
	idx, ok := replicaIndexFromLabels(svc.Labels)
	if !ok {
		return nil
	}

	var endpoints []tsapi.PeerRelayEndpoint
	for _, ing := range svc.Status.LoadBalancer.Ingress {
		if ing.IP != "" {
			endpoints = append(endpoints, tsapi.PeerRelayEndpoint{Replica: idx, Address: ing.IP, Port: servicePort})
		}
	}
	if len(endpoints) > 0 {
		return endpoints
	}

	// No IP was assigned, so fall back to resolving the hostname. This is primarily for AWS, where NLB-backed
	// Service resources are only ever given hostnames. The addresses behind such a hostname belong to the load
	// balancer and are fixed for its lifetime, whether they came from spec.aws.elasticIPs or were assigned by
	// AWS, so we resolve it here rather than making the user supply the address themselves.
	for _, ing := range svc.Status.LoadBalancer.Ingress {
		if ing.Hostname == "" {
			continue
		}

		resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		addrs, err := r.resolver(resolveCtx, "ip4", ing.Hostname)
		if err != nil || len(addrs) == 0 {
			logger.Debugf("failed to resolve LoadBalancer hostname %q for Service %q: %v", ing.Hostname, svc.Name, err)
			// Preserve the previously-known endpoints (if any) so that a failure here doesn't erase
			// status.endpoints.
			if len(prev) > 0 {
				return prev
			}

			continue
		}

		slices.SortFunc(addrs, netip.Addr.Compare)
		for _, addr := range addrs {
			endpoints = append(endpoints, tsapi.PeerRelayEndpoint{Replica: idx, Address: addr.String(), Port: servicePort})
		}

		return endpoints
	}

	return nil
}
