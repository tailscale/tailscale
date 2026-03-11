// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package acl provides reconciliation logic for the ACL custom resource.
// It syncs the policy file from the resource to the Tailscale API (GET/POST
// tailnet ACL) using the referenced Tailnet's OAuth credentials.
package acl

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	tsclient "tailscale.com/client/tailscale"
	operatorutils "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler"
	"tailscale.com/k8s-operator/reconciler/tailnet"
	"tailscale.com/tstime"
)

const reconcilerName = "acl-reconciler"

// Reconciler reconciles ACL resources by syncing their spec to the Tailscale API.
type Reconciler struct {
	client.Client

	tailscaleNamespace string
	clock              tstime.Clock
	logger             *zap.SugaredLogger
	clientFunc         func(*tsapi.Tailnet, *corev1.Secret) tailnet.TailscaleClient
}

// ReconcilerOptions configures the ACL reconciler.
type ReconcilerOptions struct {
	Client             client.Client
	TailscaleNamespace string
	Clock              tstime.Clock
	Logger             *zap.SugaredLogger
	ClientFunc         func(*tsapi.Tailnet, *corev1.Secret) tailnet.TailscaleClient
}

// NewReconciler returns a new ACL reconciler.
func NewReconciler(opts ReconcilerOptions) *Reconciler {
	return &Reconciler{
		Client:             opts.Client,
		tailscaleNamespace: opts.TailscaleNamespace,
		clock:              opts.Clock,
		logger:             opts.Logger.Named(reconcilerName),
		clientFunc:         opts.ClientFunc,
	}
}

// Register registers the reconciler with the manager.
func (r *Reconciler) Register(mgr manager.Manager) error {
	return builder.
		ControllerManagedBy(mgr).
		For(&tsapi.ACL{}).
		Named(reconcilerName).
		Complete(r)
}

// Reconcile syncs the ACL spec to the Tailnet's ACL via the Tailscale API.
func (r *Reconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	var acl tsapi.ACL
	if err := r.Get(ctx, req.NamespacedName, &acl); err != nil {
		if apierrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("get ACL: %w", err)
	}

	if !acl.DeletionTimestamp.IsZero() {
		reconciler.RemoveFinalizer(&acl)
		if err := r.Update(ctx, &acl); err != nil {
			return reconcile.Result{}, fmt.Errorf("remove finalizer: %w", err)
		}
		return reconcile.Result{}, nil
	}

	desiredPolicy, err := r.desiredPolicyContent(ctx, &acl)
	if err != nil {
		operatorutils.SetACLCondition(&acl, tsapi.ACLSynced, metav1.ConditionFalse, "InvalidPolicy", err.Error(), acl.Generation, r.clock, r.logger)
		_ = r.Status().Update(ctx, &acl)
		return reconcile.Result{}, nil
	}

	var tn tsapi.Tailnet
	if err := r.Get(ctx, client.ObjectKey{Name: acl.Spec.TailnetRef}, &tn); err != nil {
		if apierrors.IsNotFound(err) {
			operatorutils.SetACLCondition(&acl, tsapi.ACLSynced, metav1.ConditionFalse, "TailnetNotFound", fmt.Sprintf("Tailnet %q not found", acl.Spec.TailnetRef), acl.Generation, r.clock, r.logger)
			_ = r.Status().Update(ctx, &acl)
			return reconcile.Result{RequeueAfter: time.Minute / 2}, nil
		}
		return reconcile.Result{}, fmt.Errorf("get Tailnet: %w", err)
	}

	if !operatorutils.TailnetIsReady(&tn) {
		operatorutils.SetACLCondition(&acl, tsapi.ACLSynced, metav1.ConditionFalse, "TailnetNotReady", fmt.Sprintf("Tailnet %q is not ready", acl.Spec.TailnetRef), acl.Generation, r.clock, r.logger)
		_ = r.Status().Update(ctx, &acl)
		return reconcile.Result{RequeueAfter: time.Minute / 2}, nil
	}

	secretName := tn.Spec.Credentials.SecretName
	var secret corev1.Secret
	if err := r.Get(ctx, client.ObjectKey{Name: secretName, Namespace: r.tailscaleNamespace}, &secret); err != nil {
		if apierrors.IsNotFound(err) {
			operatorutils.SetACLCondition(&acl, tsapi.ACLSynced, metav1.ConditionFalse, "SecretNotFound", fmt.Sprintf("Secret %q not found in namespace %q", secretName, r.tailscaleNamespace), acl.Generation, r.clock, r.logger)
			_ = r.Status().Update(ctx, &acl)
			return reconcile.Result{RequeueAfter: time.Minute / 2}, nil
		}
		return reconcile.Result{}, fmt.Errorf("get Secret: %w", err)
	}

	tsClient := r.tailscaleClient(&tn, &secret)
	currentACL, err := tsClient.ACL(ctx)
	if err != nil {
		operatorutils.SetACLCondition(&acl, tsapi.ACLSynced, metav1.ConditionFalse, "ACLGetFailed", err.Error(), acl.Generation, r.clock, r.logger)
		_ = r.Status().Update(ctx, &acl)
		return reconcile.Result{RequeueAfter: time.Minute / 2}, nil
	}

	var desiredDetails tsclient.ACLDetails
	if err := json.Unmarshal([]byte(desiredPolicy), &desiredDetails); err != nil {
		operatorutils.SetACLCondition(&acl, tsapi.ACLSynced, metav1.ConditionFalse, "InvalidPolicy", fmt.Sprintf("policy is not valid JSON: %v", err), acl.Generation, r.clock, r.logger)
		_ = r.Status().Update(ctx, &acl)
		return reconcile.Result{}, nil
	}

	if reflect.DeepEqual(currentACL.ACL, desiredDetails) {
		operatorutils.SetACLCondition(&acl, tsapi.ACLSynced, metav1.ConditionTrue, "Synced", "Policy is in sync with Tailnet", acl.Generation, r.clock, r.logger)
		acl.Status.ETag = currentACL.ETag
		if acl.Status.LastSyncTime == nil {
			acl.Status.LastSyncTime = &metav1.Time{Time: r.clock.Now()}
		}
		reconciler.SetFinalizer(&acl)
		_ = r.Update(ctx, &acl)
		_ = r.Status().Update(ctx, &acl)
		return reconcile.Result{}, nil
	}

	testErr, err := tsClient.ValidateACL(ctx, desiredDetails)
	if err != nil {
		operatorutils.SetACLCondition(&acl, tsapi.ACLSynced, metav1.ConditionFalse, "ValidationError", fmt.Sprintf("failed to call ACL validate endpoint: %v", err), acl.Generation, r.clock, r.logger)
		_ = r.Status().Update(ctx, &acl)
		return reconcile.Result{RequeueAfter: time.Minute / 2}, nil
	}
	if testErr != nil {
		operatorutils.SetACLCondition(&acl, tsapi.ACLSynced, metav1.ConditionFalse, "ValidationFailed", fmt.Sprintf("policy validation failed: %v", testErr), acl.Generation, r.clock, r.logger)
		_ = r.Status().Update(ctx, &acl)
		return reconcile.Result{}, nil
	}

	toSet := tsclient.ACL{
		ACL:  desiredDetails,
		ETag: acl.Status.ETag,
	}
	if toSet.ETag == "" {
		toSet.ETag = currentACL.ETag
	}
	updated, err := tsClient.SetACL(ctx, toSet, true)
	if err != nil {
		operatorutils.SetACLCondition(&acl, tsapi.ACLSynced, metav1.ConditionFalse, "ACLSetFailed", err.Error(), acl.Generation, r.clock, r.logger)
		_ = r.Status().Update(ctx, &acl)
		return reconcile.Result{RequeueAfter: time.Minute / 2}, nil
	}

	operatorutils.SetACLCondition(&acl, tsapi.ACLSynced, metav1.ConditionTrue, "Synced", "Policy synced to Tailnet", acl.Generation, r.clock, r.logger)
	acl.Status.ETag = updated.ETag
	acl.Status.LastSyncTime = &metav1.Time{Time: r.clock.Now()}
	reconciler.SetFinalizer(&acl)
	_ = r.Update(ctx, &acl)
	_ = r.Status().Update(ctx, &acl)
	return reconcile.Result{}, nil
}

func (r *Reconciler) tailscaleClient(tn *tsapi.Tailnet, secret *corev1.Secret) tailnet.TailscaleClient {
	if r.clientFunc != nil {
		return r.clientFunc(tn, secret)
	}
	return tailnet.ClientFromCredentials(tn, secret)
}

func (r *Reconciler) desiredPolicyContent(ctx context.Context, acl *tsapi.ACL) (string, error) {
	if acl.Spec.Policy != "" {
		return acl.Spec.Policy, nil
	}
	if acl.Spec.PolicyFrom == nil {
		return "", fmt.Errorf("either spec.policy or spec.policyFrom must be set")
	}
	ns := r.tailscaleNamespace
	if acl.Spec.PolicyFrom.ConfigMapKeyRef != nil {
		ref := acl.Spec.PolicyFrom.ConfigMapKeyRef
		var cm corev1.ConfigMap
		if err := r.Get(ctx, client.ObjectKey{Name: ref.Name, Namespace: ns}, &cm); err != nil {
			return "", fmt.Errorf("get ConfigMap %q: %w", ref.Name, err)
		}
		data, ok := cm.Data[ref.Key]
		if !ok {
			return "", fmt.Errorf("ConfigMap %q has no key %q", ref.Name, ref.Key)
		}
		return data, nil
	}
	if acl.Spec.PolicyFrom.SecretKeyRef != nil {
		ref := acl.Spec.PolicyFrom.SecretKeyRef
		var sec corev1.Secret
		if err := r.Get(ctx, client.ObjectKey{Name: ref.Name, Namespace: ns}, &sec); err != nil {
			return "", fmt.Errorf("get Secret %q: %w", ref.Name, err)
		}
		data, ok := sec.Data[ref.Key]
		if !ok {
			return "", fmt.Errorf("Secret %q has no key %q", ref.Name, ref.Key)
		}
		return string(data), nil
	}
	return "", fmt.Errorf("spec.policyFrom must set configMapKeyRef or secretKeyRef")
}
