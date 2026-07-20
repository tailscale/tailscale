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
)

// cloudAnnotations are the cloud-provider-specific annotations applied to every generated LoadBalancer Service to
// ensure the Service is provisioned with a publicly addressable IP rather than a DNS name.
var cloudAnnotations = map[string]string{
	// AWS: provision an internet-facing NLB in IP target mode via the AWS Load Balancer Controller.
	"service.beta.kubernetes.io/aws-load-balancer-type":            "external",
	"service.beta.kubernetes.io/aws-load-balancer-nlb-target-type": "ip",
	"service.beta.kubernetes.io/aws-load-balancer-scheme":          "internet-facing",
	"service.beta.kubernetes.io/aws-load-balancer-ip-address-type": "ipv4",

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

func (r *Reconciler) peerRelayEndpoint(ctx context.Context, logger *zap.SugaredLogger, svc *corev1.Service, prev *tsapi.PeerRelayEndpoint) *tsapi.PeerRelayEndpoint {
	idx, ok := replicaIndexFromLabels(svc.Labels)
	if !ok {
		return nil
	}

	for _, ing := range svc.Status.LoadBalancer.Ingress {
		if ing.IP != "" {
			return &tsapi.PeerRelayEndpoint{Replica: idx, Address: ing.IP, Port: servicePort}
		}
	}

	// Just return nil if we're not dealing with AWS fun.
	if _, ok = svc.Annotations[annotationEIPAllocations]; !ok {
		return nil
	}

	// If we were not able to obtain an IP address, we fall back to an IPv4 lookup. This is specifically for the case
	// of AWS where NLB-backed Service resources are only ever given hostnames. We expect users to also provide
	// an annotation with their elastic IP allocations so that there is only ever 1 IP address behind the hostname, so
	// we perform a lookup so that the user doesn't also need to provide that IP address.
	for _, ing := range svc.Status.LoadBalancer.Ingress {
		if ing.Hostname == "" {
			continue
		}

		resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		addrs, err := r.resolver(resolveCtx, "ip4", ing.Hostname)
		if err != nil || len(addrs) == 0 {
			logger.Warnf("failed to resolve LoadBalancer hostname %q for Service %q: %v", ing.Hostname, svc.Name, err)
			// Preserve the previously-known endpoint (if any) so that a failure here doesn't erase status.endpoints.
			if prev != nil {
				return prev
			}

			continue
		}

		slices.SortFunc(addrs, netip.Addr.Compare)
		return &tsapi.PeerRelayEndpoint{Replica: idx, Address: addrs[0].String(), Port: servicePort}
	}

	return nil
}
