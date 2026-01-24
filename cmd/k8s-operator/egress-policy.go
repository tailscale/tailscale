package main

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"go.uber.org/zap"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tstime"
	"tailscale.com/util/set"
)

// import (
// 	"context"
// 	"fmt"
// 	"slices"
// 	"strings"
// 	"sync"

// 	dockerref "github.com/distribution/reference"
// 	"go.uber.org/zap"
// 	corev1 "k8s.io/api/core/v1"
// 	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
// 	apiequality "k8s.io/apimachinery/pkg/api/equality"
// 	apierrors "k8s.io/apimachinery/pkg/api/errors"
// 	apivalidation "k8s.io/apimachinery/pkg/api/validation"
// 	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
// 	metavalidation "k8s.io/apimachinery/pkg/apis/meta/v1/validation"
// 	"k8s.io/apimachinery/pkg/types"
// 	"k8s.io/apimachinery/pkg/util/validation/field"
// 	"k8s.io/client-go/tools/record"
// 	"sigs.k8s.io/controller-runtime/pkg/client"
// 	"sigs.k8s.io/controller-runtime/pkg/reconcile"
// 	tsoperator "tailscale.com/k8s-operator"
// 	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
// 	"tailscale.com/tstime"
// 	"tailscale.com/util/clientmetric"
// 	"tailscale.com/util/set"
// )

type EgressPolicyReconciler struct {
	client.Client

	recorder    record.EventRecorder
	logger      *zap.SugaredLogger
	clock       tstime.Clock
	tsNamespace string

	mu sync.Mutex // protects following

	// managedEgressPolicies is a set of all EgressPolicy resources that we're currently
	// managing. This is only used for metrics.
	managedEgressPolicies set.Slice[types.UID]
}

func (epr *EgressPolicyReconciler) Reconcile(ctx context.Context, req reconcile.Request) (res reconcile.Result, err error) {
	logger := epr.logger.With("EgressPolicy", req.Name)
	logger.Debugf("starting reconcile")

	ep := new(tsapi.EgressPolicy)
	err = epr.Get(ctx, req.NamespacedName, ep)
	if apierrors.IsNotFound(err) {
		logger.Debugf("EgressPolicy not found, assuming it was deleted")
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get tailscale.com EgressPolicy: %w", err)
	}

	epsList := &discoveryv1.EndpointSliceList{}
	if err := epr.List(ctx, epsList,
		client.InNamespace(epr.tsNamespace),
		client.HasLabels([]string{labelProxyGroup, labelEgressPolicy}),
		client.MatchingLabels(map[string]string{
			kubetypes.LabelManaged: "true",
			LabelParentType:        "svc",
			labelEgressPolicy:      ep.Name,
			labelSvcType:           typeEgress,
		})); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to list endpoint slices: %w", err)
	}

	// Group EndpointSlices by proxy group as there could be multiple
	// proxy groups backing services that are using the same EgressPolicy.
	pgNameToPortsMap := make(map[string][]discoveryv1.EndpointPort)
	for _, eps := range epsList.Items {
		pgName := eps.Labels[AnnotationProxyGroup]
		if _, exists := pgNameToPortsMap[pgName]; !exists {
			pgNameToPortsMap[pgName] = append(pgNameToPortsMap[pgName], eps.Ports...)
		}
	}

	logger.Debugf("EgressPolicy not found, assuming it was deleted")

	// Get all the network policies that are using this egress policy.
	npList := &networkingv1.NetworkPolicyList{}
	if err := epr.List(ctx, npList,
		client.InNamespace(epr.tsNamespace),
		client.MatchingLabels(map[string]string{
			kubetypes.LabelManaged: "true",
			LabelParentType:        "egress-policy",
			LabelParentName:        ep.Name,
		})); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to list endpoint slices: %w", err)
	}

	// Delete any NetworkPolicies that currently exists which no longer have any EndpointSlices to manage access to.
	for _, np := range npList.Items {
		pgName := strings.Replace(np.Name, fmt.Sprintf("%s-", ep.Name), "", -1)
		if _, exists := pgNameToPortsMap[pgName]; !exists {
			policyToDelete := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      np.Name,
					Namespace: np.Namespace,
				},
			}
			if err := epr.Delete(ctx, policyToDelete); err != nil {
				logger.Debugf(fmt.Sprintf("failed to delete NetworkPolicy: %w", err))
			}
		}
	}

	// Ensure a network policy exists for every proxy group -> port mapping.
	for pgName, ports := range pgNameToPortsMap {

		// Get NetworkPolicyPort's Ports from EndpointSlice's Ports
		npPorts := make([]networkingv1.NetworkPolicyPort, 0)
		for _, epsPort := range ports {
			if *epsPort.Name != tsHealthCheckPortName {
				port := intstr.FromInt32(*epsPort.Port)
				npPorts = append(npPorts, networkingv1.NetworkPolicyPort{Protocol: epsPort.Protocol, Port: &port})
			}
		}
		np := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:            fmt.Sprintf("%s-%s", ep.Name, pgName),
				Namespace:       epr.tsNamespace,
				OwnerReferences: epOwnerReference(ep),
				Labels:          npLabels(ep.Name),
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						kubetypes.LabelManaged: "true",
						LabelParentName:        pgName,
						LabelParentType:        "proxygroup"},
				},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						Ports: npPorts,
						From:  ep.Spec,
					},
				},
			},
		}
		_, err = createOrUpdate(ctx, epr.Client, epr.tsNamespace, np, func(n *networkingv1.NetworkPolicy) {
			n.Spec.Ingress[0].Ports = npPorts
			n.Spec.Ingress[0].From = ep.Spec
		})
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to create or update NetworkPolicy: %w", err)
		}
	}
	return reconcile.Result{}, nil
}

func epOwnerReference(owner *tsapi.EgressPolicy) []metav1.OwnerReference {
	return []metav1.OwnerReference{*metav1.NewControllerRef(owner, tsapi.SchemeGroupVersion.WithKind("EgressPolicy"))}
}

func npLabels(epName string) map[string]string {
	return map[string]string{
		kubetypes.LabelManaged: "true",
		LabelParentName:        epName,
		LabelParentType:        "egress-policy",
	}
}
