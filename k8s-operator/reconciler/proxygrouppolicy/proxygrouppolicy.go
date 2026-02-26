// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package proxygrouppolicy provides reconciliation logic for the ProxyGroupPolicy custom resource definition. It is
// responsible for generating ValidatingAdmissionPolicy resources that limit users to a set number of ProxyGroup
// names that can be used within Service and Ingress resources via the "tailscale.com/proxy-group" annotation.
package proxygrouppolicy

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	admr "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/types/ptr"
	"tailscale.com/util/set"
)

type (
	// The Reconciler type is a reconcile.TypedReconciler implementation used to manage the reconciliation of
	// ProxyGroupPolicy custom resources.
	Reconciler struct {
		client.Client
	}

	// The ReconcilerOptions type contains configuration values for the Reconciler.
	ReconcilerOptions struct {
		// The client for interacting with the Kubernetes API.
		Client client.Client
	}
)

const reconcilerName = "proxygrouppolicy-reconciler"

// NewReconciler returns a new instance of the Reconciler type. It watches specifically for changes to ProxyGroupPolicy
// custom resources. The ReconcilerOptions can be used to modify the behaviour of the Reconciler.
func NewReconciler(options ReconcilerOptions) *Reconciler {
	return &Reconciler{
		Client: options.Client,
	}
}

// Register the Reconciler onto the given manager.Manager implementation.
func (r *Reconciler) Register(mgr manager.Manager) error {
	return builder.
		ControllerManagedBy(mgr).
		For(&tsapi.ProxyGroupPolicy{}).
		Named(reconcilerName).
		Complete(r)
}

func (r *Reconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	// Rather than working on a single ProxyGroupPolicy resource, we list all that exist within the
	// same namespace as the one we're reconciling so that we can merge them into a single pair of
	// ValidatingAdmissionPolicy resources.
	var policies tsapi.ProxyGroupPolicyList
	if err := r.List(ctx, &policies, client.InNamespace(req.Namespace)); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to list ProxyGroupPolicy resources %q: %w", req.NamespacedName, err)
	}

	if len(policies.Items) == 0 {
		// If we've got no items in the list, we go and delete any policies and bindings that
		// may exist.
		return r.delete(ctx, req.Namespace)
	}

	return r.createOrUpdate(ctx, req.Namespace, policies)
}

func (r *Reconciler) delete(ctx context.Context, namespace string) (reconcile.Result, error) {
	ingress := "ts-ingress-" + namespace
	egress := "ts-egress-" + namespace

	objects := []client.Object{
		&admr.ValidatingAdmissionPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: ingress,
			},
		},
		&admr.ValidatingAdmissionPolicyBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: ingress,
			},
		},
		&admr.ValidatingAdmissionPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: egress,
			},
		},
		&admr.ValidatingAdmissionPolicyBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: egress,
			},
		},
	}

	for _, obj := range objects {
		err := r.Delete(ctx, obj)
		switch {
		case apierrors.IsNotFound(err):
			// A resource may have already been deleted in a previous reconciliation that failed for
			// some reason, so we'll ignore it if it doesn't exist.
			continue
		case err != nil:
			return reconcile.Result{}, fmt.Errorf("failed to delete %s %q: %w", obj.GetObjectKind().GroupVersionKind().Kind, obj.GetName(), err)
		}
	}

	return reconcile.Result{}, nil
}

func (r *Reconciler) createOrUpdate(ctx context.Context, namespace string, policies tsapi.ProxyGroupPolicyList) (reconcile.Result, error) {
	ingressNames := set.Set[string]{}
	egressNames := set.Set[string]{}

	// If this namespace has multiple ProxyGroupPolicy resources, we'll reduce them down to just their distinct
	// egress/ingress names.
	for _, policy := range policies.Items {
		ingressNames.AddSlice(policy.Spec.Ingress)
		egressNames.AddSlice(policy.Spec.Egress)
	}

	ingress, err := r.generateIngressPolicy(ctx, namespace, ingressNames)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to generate ingress policy: %w", err)
	}

	ingressBinding, err := r.generatePolicyBinding(ctx, namespace, ingress)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to generate ingress policy binding: %w", err)
	}

	egress, err := r.generateEgressPolicy(ctx, namespace, egressNames)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to generate egress policy: %w", err)
	}

	egressBinding, err := r.generatePolicyBinding(ctx, namespace, egress)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to generate egress policy binding: %w", err)
	}

	objects := []client.Object{
		ingress,
		ingressBinding,
		egress,
		egressBinding,
	}

	for _, obj := range objects {
		// Attempt to perform an update first as we'll only create these once and continually update them, so it's
		// more likely that an update is needed instead of creation. If the resource does not exist, we'll
		// create it.
		err = r.Update(ctx, obj)
		switch {
		case apierrors.IsNotFound(err):
			if err = r.Create(ctx, obj); err != nil {
				return reconcile.Result{}, fmt.Errorf("failed to create %s %q: %w", obj.GetObjectKind().GroupVersionKind().Kind, obj.GetName(), err)
			}
		case err != nil:
			return reconcile.Result{}, fmt.Errorf("failed to update %s %q: %w", obj.GetObjectKind().GroupVersionKind().Kind, obj.GetName(), err)
		}
	}

	return reconcile.Result{}, nil
}

const (
	// ingressCEL enforces proxy-group annotation rules for Ingress resources.
	//
	// Logic:
	//
	//   - If the object is NOT an Ingress → allow (this validation is irrelevant)
	//   - If the annotation is absent → allow (annotation is optional)
	//   - If the annotation is present → its value must be in the allowlist
	//
	// Empty allowlist behavior:
	//   If the list is empty, any present annotation will fail membership,
	//   effectively acting as "deny-all".
	ingressCEL = `request.kind.kind != "Ingress" || !("tailscale.com/proxy-group" in object.metadata.annotations) || object.metadata.annotations["tailscale.com/proxy-group"] in [%s]`

	// ingressServiceCEL enforces proxy-group annotation rules for Services
	// that are using the tailscale load balancer.
	//
	// Logic:
	//
	//   - If the object is NOT a Service → allow
	//   - If Service does NOT use loadBalancerClass "tailscale" → allow
	//     (egress policy will handle those)
	//   - If annotation is absent → allow
	//   - If annotation is present → must be in allowlist
	//
	// This makes ingress policy apply ONLY to tailscale Services.
	ingressServiceCEL = `request.kind.kind != "Service" || !((has(object.spec.loadBalancerClass) && object.spec.loadBalancerClass == "tailscale") || ("tailscale.com/expose" in object.metadata.annotations && object.metadata.annotations["tailscale.com/expose"] == "true")) || (!("tailscale.com/proxy-group" in object.metadata.annotations) || object.metadata.annotations["tailscale.com/proxy-group"] in [%s])`
	// egressCEL enforces proxy-group annotation rules for Services that
	// are NOT using the tailscale load balancer.
	//
	// Logic:
	//
	//   - If Service uses loadBalancerClass "tailscale" → allow
	//     (ingress policy handles those)
	//	 - If Service uses "tailscale.com/expose" → allow
	//     (ingress policy handles those)
	//   - If annotation is absent → allow
	//   - If annotation is present → must be in allowlist
	//
	// Empty allowlist behavior:
	//   Any present annotation is rejected ("deny-all").
	//
	// This expression is mutually exclusive with ingressServiceCEL,
	// preventing policy conflicts.
	egressCEL = `((has(object.spec.loadBalancerClass) && object.spec.loadBalancerClass == "tailscale") || ("tailscale.com/expose" in object.metadata.annotations && object.metadata.annotations["tailscale.com/expose"] == "true")) || !("tailscale.com/proxy-group" in object.metadata.annotations) || object.metadata.annotations["tailscale.com/proxy-group"] in [%s]`
)

func (r *Reconciler) generateIngressPolicy(ctx context.Context, namespace string, names set.Set[string]) (*admr.ValidatingAdmissionPolicy, error) {
	name := "ts-ingress-" + namespace

	var policy admr.ValidatingAdmissionPolicy
	err := r.Get(ctx, client.ObjectKey{Name: name}, &policy)
	switch {
	case apierrors.IsNotFound(err):
		// If it's not found, we can create a new one. We only want the existing one for
		// its resource version.
	case err != nil:
		return nil, fmt.Errorf("failed to get ValidatingAdmissionPolicy %q: %w", name, err)
	}

	return &admr.ValidatingAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			ResourceVersion: policy.ResourceVersion,
		},
		Spec: admr.ValidatingAdmissionPolicySpec{
			FailurePolicy: ptr.To(admr.Fail),
			MatchConstraints: &admr.MatchResources{
				// The operator allows ingress via Ingress resources & Service resources (that use the "tailscale" load
				// balancer class), so we have two resource rules here with multiple validation expressions that attempt
				// to keep out of each other's way.
				ResourceRules: []admr.NamedRuleWithOperations{
					{
						RuleWithOperations: admr.RuleWithOperations{
							Operations: []admr.OperationType{
								admr.Create,
								admr.Update,
							},
							Rule: admr.Rule{
								APIGroups:   []string{"networking.k8s.io"},
								APIVersions: []string{"*"},
								Resources:   []string{"ingresses"},
							},
						},
					},
					{
						RuleWithOperations: admr.RuleWithOperations{
							Operations: []admr.OperationType{
								admr.Create,
								admr.Update,
							},
							Rule: admr.Rule{
								APIGroups:   []string{""},
								APIVersions: []string{"v1"},
								Resources:   []string{"services"},
							},
						},
					},
				},
			},
			Validations: []admr.Validation{
				generateValidation(names, ingressCEL),
				generateValidation(names, ingressServiceCEL),
			},
		},
	}, nil
}

func (r *Reconciler) generateEgressPolicy(ctx context.Context, namespace string, names set.Set[string]) (*admr.ValidatingAdmissionPolicy, error) {
	name := "ts-egress-" + namespace

	var policy admr.ValidatingAdmissionPolicy
	err := r.Get(ctx, client.ObjectKey{Name: name}, &policy)
	switch {
	case apierrors.IsNotFound(err):
		// If it's not found, we can create a new one. We only want the existing one for
		// its resource version.
	case err != nil:
		return nil, fmt.Errorf("failed to get ValidatingAdmissionPolicy %q: %w", name, err)
	}

	return &admr.ValidatingAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			ResourceVersion: policy.ResourceVersion,
		},
		Spec: admr.ValidatingAdmissionPolicySpec{
			FailurePolicy: ptr.To(admr.Fail),
			MatchConstraints: &admr.MatchResources{
				ResourceRules: []admr.NamedRuleWithOperations{
					{
						RuleWithOperations: admr.RuleWithOperations{
							Operations: []admr.OperationType{
								admr.Create,
								admr.Update,
							},
							Rule: admr.Rule{
								APIGroups:   []string{""},
								APIVersions: []string{"v1"},
								Resources:   []string{"services"},
							},
						},
					},
				},
			},
			Validations: []admr.Validation{
				generateValidation(names, egressCEL),
			},
		},
	}, nil
}

const (
	denyMessage   = `Annotation "tailscale.com/proxy-group" cannot be used on this resource in this namespace`
	messageFormat = `If set, annotation "tailscale.com/proxy-group" must be one of [%s]`
)

func generateValidation(names set.Set[string], format string) admr.Validation {
	values := names.Slice()

	// We use a sort here so that the order of the proxy-group names are consistent
	// across reconciliation loops.
	sort.Strings(values)

	quoted := make([]string, len(values))
	for i, v := range values {
		quoted[i] = strconv.Quote(v)
	}

	joined := strings.Join(quoted, ",")
	message := fmt.Sprintf(messageFormat, strings.Join(values, ", "))
	if len(values) == 0 {
		message = denyMessage
	}

	return admr.Validation{
		Expression: fmt.Sprintf(format, joined),
		Message:    message,
	}
}

func (r *Reconciler) generatePolicyBinding(ctx context.Context, namespace string, policy *admr.ValidatingAdmissionPolicy) (*admr.ValidatingAdmissionPolicyBinding, error) {
	var binding admr.ValidatingAdmissionPolicyBinding
	err := r.Get(ctx, client.ObjectKey{Name: policy.Name}, &binding)
	switch {
	case apierrors.IsNotFound(err):
		// If it's not found, we can create a new one. We only want the existing one for
		// its resource version.
	case err != nil:
		return nil, fmt.Errorf("failed to get ValidatingAdmissionPolicyBinding %q: %w", policy.Name, err)
	}

	return &admr.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:            policy.Name,
			ResourceVersion: binding.ResourceVersion,
		},
		Spec: admr.ValidatingAdmissionPolicyBindingSpec{
			PolicyName: policy.Name,
			ValidationActions: []admr.ValidationAction{
				admr.Deny,
			},
			MatchResources: &admr.MatchResources{
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"kubernetes.io/metadata.name": namespace,
					},
				},
			},
		},
	}, nil
}
