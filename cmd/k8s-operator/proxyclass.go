// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"

	dockerref "github.com/distribution/reference"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apivalidation "k8s.io/apimachinery/pkg/api/validation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	metavalidation "k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/tstime"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/set"
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

	mu sync.Mutex // protects following

	// managedProxyClasses is a set of all ProxyClass resources that we're currently
	// managing. This is only used for metrics.
	managedProxyClasses set.Slice[types.UID]
}

var (
	// gaugeProxyClassResources tracks the number of ProxyClass resources
	// that we're currently managing.
	gaugeProxyClassResources = clientmetric.NewGauge("k8s_proxyclass_resources")
)

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
		logger.Debugf("ProxyClass is being deleted")
		return reconcile.Result{}, pcr.maybeCleanup(ctx, logger, pc)
	}

	// Add a finalizer so that we can ensure that metrics get updated when
	// this ProxyClass is deleted.
	if !slices.Contains(pc.Finalizers, FinalizerName) {
		logger.Debugf("updating ProxyClass finalizers")
		pc.Finalizers = append(pc.Finalizers, FinalizerName)
		if err := pcr.Update(ctx, pc); err != nil {
			return res, fmt.Errorf("failed to add finalizer: %w", err)
		}
	}

	// Ensure this ProxyClass is tracked in metrics.
	pcr.mu.Lock()
	pcr.managedProxyClasses.Add(pc.UID)
	gaugeProxyClassResources.Set(int64(pcr.managedProxyClasses.Len()))
	pcr.mu.Unlock()

	oldPCStatus := pc.Status.DeepCopy()
	if errs := pcr.validate(ctx, pc); errs != nil {
		msg := fmt.Sprintf(messageProxyClassInvalid, errs.ToAggregate().Error())
		pcr.recorder.Event(pc, corev1.EventTypeWarning, reasonProxyClassInvalid, msg)
		tsoperator.SetProxyClassCondition(pc, tsapi.ProxyClassReady, metav1.ConditionFalse, reasonProxyClassInvalid, msg, pc.Generation, pcr.clock, logger)
	} else {
		tsoperator.SetProxyClassCondition(pc, tsapi.ProxyClassReady, metav1.ConditionTrue, reasonProxyClassValid, reasonProxyClassValid, pc.Generation, pcr.clock, logger)
	}
	if !apiequality.Semantic.DeepEqual(oldPCStatus, &pc.Status) {
		if err := pcr.Client.Status().Update(ctx, pc); err != nil {
			logger.Errorf("error updating ProxyClass status: %v", err)
			return reconcile.Result{}, err
		}
	}
	return reconcile.Result{}, nil
}

func (pcr *ProxyClassReconciler) validate(ctx context.Context, pc *tsapi.ProxyClass) (violations field.ErrorList) {
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
						pcr.recorder.Event(pc, corev1.EventTypeWarning, reasonCustomTSEnvVar, fmt.Sprintf(messageCustomTSEnvVar, string(e.Name), "tailscale"))
					}
					if strings.EqualFold(string(e.Name), "EXPERIMENTAL_TS_CONFIGFILE_PATH") {
						pcr.recorder.Event(pc, corev1.EventTypeWarning, reasonCustomTSEnvVar, fmt.Sprintf(messageCustomTSEnvVar, string(e.Name), "tailscale"))
					}
					if strings.EqualFold(string(e.Name), "EXPERIMENTAL_ALLOW_PROXYING_CLUSTER_TRAFFIC_VIA_INGRESS") {
						pcr.recorder.Event(pc, corev1.EventTypeWarning, reasonCustomTSEnvVar, fmt.Sprintf(messageCustomTSEnvVar, string(e.Name), "tailscale"))
					}
				}
				if tc.Image != "" {
					// Same validation as used by kubelet https://github.com/kubernetes/kubernetes/blob/release-1.30/pkg/kubelet/images/image_manager.go#L212
					if _, err := dockerref.ParseNormalizedNamed(tc.Image); err != nil {
						violations = append(violations, field.TypeInvalid(field.NewPath("spec", "statefulSet", "pod", "tailscaleContainer", "image"), tc.Image, err.Error()))
					}
				}
			}
			if tc := pod.TailscaleInitContainer; tc != nil {
				if tc.Image != "" {
					// Same validation as used by kubelet https://github.com/kubernetes/kubernetes/blob/release-1.30/pkg/kubelet/images/image_manager.go#L212
					if _, err := dockerref.ParseNormalizedNamed(tc.Image); err != nil {
						violations = append(violations, field.TypeInvalid(field.NewPath("spec", "statefulSet", "pod", "tailscaleInitContainer", "image"), tc.Image, err.Error()))
					}
				}

				if tc.Debug != nil {
					violations = append(violations, field.TypeInvalid(field.NewPath("spec", "statefulSet", "pod", "tailscaleInitContainer", "debug"), tc.Debug, "debug settings cannot be configured on the init container"))
				}
			}
		}
	}
	if pc.Spec.Metrics != nil && pc.Spec.Metrics.ServiceMonitor != nil && pc.Spec.Metrics.ServiceMonitor.Enable {
		found, err := hasServiceMonitorCRD(ctx, pcr.Client)
		if err != nil {
			pcr.logger.Infof("[unexpected]: error retrieving %q CRD: %v", serviceMonitorCRD, err)
			// best effort validation - don't error out here
		} else if !found {
			msg := fmt.Sprintf("ProxyClass defines that a ServiceMonitor custom resource should be created, but %q CRD was not found", serviceMonitorCRD)
			violations = append(violations, field.TypeInvalid(field.NewPath("spec", "metrics", "serviceMonitor"), "enable", msg))
		}
	}
	// We do not validate embedded fields (security context, resource
	// requirements etc) as we inherit upstream validation for those fields.
	// Invalid values would get rejected by upstream validations at apply
	// time.
	return violations
}

func hasServiceMonitorCRD(ctx context.Context, cl client.Client) (bool, error) {
	sm := &apiextensionsv1.CustomResourceDefinition{}
	if err := cl.Get(ctx, types.NamespacedName{Name: serviceMonitorCRD}, sm); apierrors.IsNotFound(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

// maybeCleanup removes tailscale.com finalizer and ensures that the ProxyClass
// is no longer counted towards k8s_proxyclass_resources.
func (pcr *ProxyClassReconciler) maybeCleanup(ctx context.Context, logger *zap.SugaredLogger, pc *tsapi.ProxyClass) error {
	ix := slices.Index(pc.Finalizers, FinalizerName)
	if ix < 0 {
		logger.Debugf("no finalizer, nothing to do")
		pcr.mu.Lock()
		defer pcr.mu.Unlock()
		pcr.managedProxyClasses.Remove(pc.UID)
		gaugeProxyClassResources.Set(int64(pcr.managedProxyClasses.Len()))
		return nil
	}
	pc.Finalizers = append(pc.Finalizers[:ix], pc.Finalizers[ix+1:]...)
	if err := pcr.Update(ctx, pc); err != nil {
		return fmt.Errorf("failed to remove finalizer: %w", err)
	}
	pcr.mu.Lock()
	defer pcr.mu.Unlock()
	pcr.managedProxyClasses.Remove(pc.UID)
	gaugeProxyClassResources.Set(int64(pcr.managedProxyClasses.Len()))
	logger.Infof("ProxyClass resources have been cleaned up")
	return nil
}
