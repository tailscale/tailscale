// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package proxygrouppolicy_test

import (
	"slices"
	"strings"
	"testing"

	admr "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler/proxygrouppolicy"
)

func TestReconciler_Reconcile(t *testing.T) {
	t.Parallel()

	tt := []struct {
		Name                string
		Request             reconcile.Request
		ExpectedPolicyCount int
		ExistingResources   []client.Object
		ExpectsError        bool
	}{
		{
			Name:                "single policy, denies all",
			ExpectedPolicyCount: 2,
			Request: reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      "deny-all",
					Namespace: metav1.NamespaceDefault,
				},
			},
			ExistingResources: []client.Object{
				&tsapi.ProxyGroupPolicy{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "deny-all",
						Namespace: metav1.NamespaceDefault,
					},
					Spec: tsapi.ProxyGroupPolicySpec{
						Ingress: []string{},
						Egress:  []string{},
					},
				},
			},
		},
		{
			Name:                "multiple policies merged",
			ExpectedPolicyCount: 2,
			Request: reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      "deny-all",
					Namespace: metav1.NamespaceDefault,
				},
			},
			ExistingResources: []client.Object{
				&tsapi.ProxyGroupPolicy{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "deny-all",
						Namespace: metav1.NamespaceDefault,
					},
					Spec: tsapi.ProxyGroupPolicySpec{
						Ingress: []string{},
						Egress:  []string{},
					},
				},
				&tsapi.ProxyGroupPolicy{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "allow-one",
						Namespace: metav1.NamespaceDefault,
					},
					Spec: tsapi.ProxyGroupPolicySpec{
						Ingress: []string{
							"test-ingress",
						},
						Egress: []string{},
					},
				},
			},
		},
		{
			Name:                "no policies, no child resources",
			ExpectedPolicyCount: 0,
			Request: reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      "deny-all",
					Namespace: metav1.NamespaceDefault,
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			bldr := fake.NewClientBuilder().WithScheme(tsapi.GlobalScheme)
			bldr = bldr.WithObjects(tc.ExistingResources...)

			fc := bldr.Build()
			opts := proxygrouppolicy.ReconcilerOptions{
				Client: fc,
			}

			reconciler := proxygrouppolicy.NewReconciler(opts)
			_, err := reconciler.Reconcile(t.Context(), tc.Request)
			if tc.ExpectsError && err == nil {
				t.Fatalf("expected error, got none")
			}

			if !tc.ExpectsError && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			var policies admr.ValidatingAdmissionPolicyList
			if err = fc.List(t.Context(), &policies); err != nil {
				t.Fatal(err)
			}

			if len(policies.Items) != tc.ExpectedPolicyCount {
				t.Fatalf("expected %d ValidatingAdmissionPolicy resources, got %d", tc.ExpectedPolicyCount, len(policies.Items))
			}

			var bindings admr.ValidatingAdmissionPolicyBindingList
			if err = fc.List(t.Context(), &bindings); err != nil {
				t.Fatal(err)
			}

			if len(bindings.Items) != tc.ExpectedPolicyCount {
				t.Fatalf("expected %d ValidatingAdmissionPolicyBinding resources, got %d", tc.ExpectedPolicyCount, len(bindings.Items))
			}

			for _, binding := range bindings.Items {
				actual, ok := binding.Spec.MatchResources.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"]
				if !ok || actual != metav1.NamespaceDefault {
					t.Fatalf("expected binding to be for default namespace, got %v", actual)
				}

				if !slices.Contains(binding.Spec.ValidationActions, admr.Deny) {
					t.Fatalf("expected binding to be deny, got %v", binding.Spec.ValidationActions)
				}
			}

			for _, policy := range policies.Items {
				// Each ValidatingAdmissionPolicy must be set to fail (rejecting resources).
				if policy.Spec.FailurePolicy == nil || *policy.Spec.FailurePolicy != admr.Fail {
					t.Fatalf("expected fail policy, got %v", *policy.Spec.FailurePolicy)
				}

				// Each ValidatingAdmissionPolicy must have a matching ValidatingAdmissionPolicyBinding
				bound := slices.ContainsFunc(bindings.Items, func(obj admr.ValidatingAdmissionPolicyBinding) bool {
					return obj.Spec.PolicyName == policy.Name
				})
				if !bound {
					t.Fatalf("expected policy %s to be bound, but wasn't", policy.Name)
				}

				// Each ValidatingAdmissionPolicy must be set to evaluate on creation and update of resources.
				for _, rule := range policy.Spec.MatchConstraints.ResourceRules {
					if !slices.Contains(rule.Operations, admr.Update) {
						t.Fatal("expected ingress rule to act on update, but doesn't")
					}

					if !slices.Contains(rule.Operations, admr.Create) {
						t.Fatal("expected ingress rule to act on create, but doesn't")
					}
				}

				// Egress policies should only act on Service resources.
				if strings.Contains(policy.Name, "egress") {
					if len(policy.Spec.MatchConstraints.ResourceRules) != 1 {
						t.Fatalf("expected exactly one matching resource, got %d", len(policy.Spec.MatchConstraints.ResourceRules))
					}

					rule := policy.Spec.MatchConstraints.ResourceRules[0]

					if !slices.Contains(rule.Resources, "services") {
						t.Fatal("expected egress rule to act on services, but doesn't")
					}

					if len(policy.Spec.Validations) != 1 {
						t.Fatalf("expected exactly one validation, got %d", len(policy.Spec.Validations))
					}
				}

				// Ingress policies should act on both Ingress and Service resources.
				if strings.Contains(policy.Name, "ingress") {
					if len(policy.Spec.MatchConstraints.ResourceRules) != 2 {
						t.Fatalf("expected exactly two matching resources, got %d", len(policy.Spec.MatchConstraints.ResourceRules))
					}

					ingressRule := policy.Spec.MatchConstraints.ResourceRules[0]
					if !slices.Contains(ingressRule.Resources, "ingresses") {
						t.Fatal("expected ingress rule to act on ingresses, but doesn't")
					}

					serviceRule := policy.Spec.MatchConstraints.ResourceRules[1]
					if !slices.Contains(serviceRule.Resources, "services") {
						t.Fatal("expected ingress rule to act on services, but doesn't")
					}

					if len(policy.Spec.Validations) != 2 {
						t.Fatalf("expected exactly two validations, got %d", len(policy.Spec.Validations))
					}
				}
			}
		})
	}
}
