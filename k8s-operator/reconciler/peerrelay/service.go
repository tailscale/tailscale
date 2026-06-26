// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package peerrelay

import (
	"fmt"
	"maps"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
)

const (
	// labelParentType identifies which Tailscale CRD owns a managed resource. It mirrors the
	// "tailscale.com/parent-resource-type" label used by other reconcilers.
	labelParentType = "tailscale.com/parent-resource-type"

	// labelParentName identifies the name of the owning Tailscale CRD. It mirrors the
	// "tailscale.com/parent-resource" label used by other reconcilers.
	labelParentName = "tailscale.com/parent-resource"

	// labelReplicaIndex stores the replica index of a managed Service so it can be matched back to a specific
	// peer relay instance.
	labelReplicaIndex = "tailscale.com/peer-relay-replica"

	// parentTypePeerRelay is the value used for labelParentType on PeerRelay-managed resources.
	parentTypePeerRelay = "peerrelay"

	// servicePortName names the UDP port exposed by each Service. Mostly cosmetic, but Kubernetes requires a name
	// once a Service has more than one port; using a stable name keeps the door open for that.
	servicePortName = "peerrelay"

	// servicePort is the UDP port that each peer relay container will listen on and that the LoadBalancer Service
	// exposes externally.
	servicePort = 41641
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
	return map[string]string{
		kubetypes.LabelManaged: "true",
		labelParentType:        parentTypePeerRelay,
		labelParentName:        prName,
	}
}

func peerRelayServiceLabels(prName string, idx int32) map[string]string {
	labels := peerRelayLabels(prName)
	labels[labelReplicaIndex] = strconv.FormatInt(int64(idx), 10)
	return labels
}

func peerRelayServiceAnnotations(pr *tsapi.PeerRelay) map[string]string {
	annotations := make(map[string]string, len(cloudAnnotations))

	if pr.Spec.Service != nil {
		maps.Copy(annotations, pr.Spec.Service.Annotations)
	}

	maps.Copy(annotations, cloudAnnotations)

	return annotations
}

func (r *Reconciler) peerRelayService(pr *tsapi.PeerRelay, idx int32) *corev1.Service {
	name := fmt.Sprintf("%s-%d", pr.Name, idx)

	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   r.tailscaleNamespace,
			Labels:      peerRelayServiceLabels(pr.Name, idx),
			Annotations: peerRelayServiceAnnotations(pr),
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

func replicaIndexFromService(svc *corev1.Service) (int32, bool) {
	raw, ok := svc.Labels[labelReplicaIndex]
	if !ok {
		return 0, false
	}

	n, err := strconv.ParseInt(raw, 10, 32)
	if err != nil {
		return 0, false
	}

	return int32(n), true
}
