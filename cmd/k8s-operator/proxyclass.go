// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"fmt"
	"strings"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apivalidation "k8s.io/apimachinery/pkg/api/validation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	metavalidation "k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/tstime"
)

const (
	reasonProxyClassInvalid  = "ProxyClassInvalid"
	reasonProxyClassValid    = "ProxyClassValid"
	reasonCustomTSEnvVar     = "CustomTSEnvVar"
	messageProxyClassInvalid = "ProxyClass is not valid: %v"
	messageCustomTSEnvVar    = "ProxyClass overrides the default value for %s env var for %s container. Running with custom values for Tailscale env vars is not recommended and might break in the future."
)

type ProxyClassReconciler struct {
	client.Client

	recorder record.EventRecorder
	logger   *zap.SugaredLogger
	clock    tstime.Clock
}

func (pcr *ProxyClassReconciler) Reconcile(ctx context.Context, req reconcile.Request) (res reconcile.Result, err error) {
	logger := pcr.logger.With("ProxyClass", req.Name)
	logger.Debugf("starting reconcile")
	defer logger.Debugf("reconcile finished")

	pc := new(tsapi.ProxyClass)
	err = pcr.Get(ctx, req.NamespacedName, pc)
	if apierrors.IsNotFound(err) {
		logger.Debugf("ProxyClass not found, assuming it was deleted")
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get tailscale.com ProxyClass: %w", err)
	}
	if !pc.DeletionTimestamp.IsZero() {
		logger.Debugf("ProxyClass is being deleted, do nothing")
		return reconcile.Result{}, nil
	}
	oldPCStatus := pc.Status.DeepCopy()
	if errs := pcr.validate(pc); errs != nil {
		msg := fmt.Sprintf(messageProxyClassInvalid, errs.ToAggregate().Error())
		pcr.recorder.Event(pc, corev1.EventTypeWarning, reasonProxyClassInvalid, msg)
		tsoperator.SetProxyClassCondition(pc, tsapi.ProxyClassready, metav1.ConditionFalse, reasonProxyClassInvalid, msg, pc.Generation, pcr.clock, logger)
	} else {
		tsoperator.SetProxyClassCondition(pc, tsapi.ProxyClassready, metav1.ConditionTrue, reasonProxyClassValid, reasonProxyClassValid, pc.Generation, pcr.clock, logger)
	}
	if !apiequality.Semantic.DeepEqual(oldPCStatus, pc.Status) {
		if err := pcr.Client.Status().Update(ctx, pc); err != nil {
			logger.Errorf("error updating ProxyClass status: %v", err)
			return reconcile.Result{}, err
		}
	}
	return reconcile.Result{}, nil
}

func (a *ProxyClassReconciler) validate(pc *tsapi.ProxyClass) (violations field.ErrorList) {
	if sts := pc.Spec.StatefulSet; sts != nil {
		if len(sts.Labels) > 0 {
			if errs := metavalidation.ValidateLabels(sts.Labels, field.NewPath(".spec.statefulSet.labels")); errs != nil {
				violations = append(violations, errs...)
			}
		}
		if len(sts.Annotations) > 0 {
			if errs := apivalidation.ValidateAnnotations(sts.Annotations, field.NewPath(".spec.statefulSet.annotations")); errs != nil {
				violations = append(violations, errs...)
			}
		}
		if pod := sts.Pod; pod != nil {
			if len(pod.Labels) > 0 {
				if errs := metavalidation.ValidateLabels(pod.Labels, field.NewPath(".spec.statefulSet.pod.labels")); errs != nil {
					violations = append(violations, errs...)
				}
			}
			if len(pod.Annotations) > 0 {
				if errs := apivalidation.ValidateAnnotations(pod.Annotations, field.NewPath(".spec.statefulSet.pod.annotations")); errs != nil {
					violations = append(violations, errs...)
				}
			}
			if tc := pod.TailscaleContainer; tc != nil {
				for _, e := range tc.Env {
					if strings.HasPrefix(string(e.Name), "TS_") {
						a.recorder.Event(pc, corev1.EventTypeWarning, reasonCustomTSEnvVar, fmt.Sprintf(messageCustomTSEnvVar, string(e.Name), "tailscale"))
					}
					if strings.EqualFold(string(e.Name), "EXPERIMENTAL_TS_CONFIGFILE_PATH") {
						a.recorder.Event(pc, corev1.EventTypeWarning, reasonCustomTSEnvVar, fmt.Sprintf(messageCustomTSEnvVar, string(e.Name), "tailscale"))
					}
					if strings.EqualFold(string(e.Name), "EXPERIMENTAL_ALLOW_PROXYING_CLUSTER_TRAFFIC_VIA_INGRESS") {
						a.recorder.Event(pc, corev1.EventTypeWarning, reasonCustomTSEnvVar, fmt.Sprintf(messageCustomTSEnvVar, string(e.Name), "tailscale"))
					}
				}
			}
		}
	}
	// We do not validate embedded fields (security context, resource
	// requirements etc) as we inherit upstream validation for those fields.
	// Invalid values would get rejected by upstream validations at apply
	// time.
	return violations
}
