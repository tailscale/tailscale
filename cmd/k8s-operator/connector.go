// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	xslices "golang.org/x/exp/slices"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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
	reasonSubnetRouterCreationFailed    = "SubnetRouterCreationFailed"
	reasonSubnetRouterCreated           = "SubnetRouterCreated"
	reasonSubnetRouterCleanupFailed     = "SubnetRouterCleanupFailed"
	reasonSubnetRouterCleanupInProgress = "SubnetRouterCleanupInProgress"
	reasonSubnetRouterInvalid           = "SubnetRouterInvalid"

	messageSubnetRouterCreationFailed = "Failed creating subnet router for routes %s: %v"
	messageSubnetRouterInvalid        = "Subnet router is invalid: %v"
	messageSubnetRouterCreated        = "Created subnet router for routes %s"
	messageSubnetRouterCleanupFailed  = "Failed cleaning up subnet router resources: %v"
	msgSubnetRouterCleanupInProgress  = "SubnetRouterCleanupInProgress"

	shortRequeue = time.Second * 5
)

type ConnectorReconciler struct {
	client.Client

	recorder record.EventRecorder
	ssr      *tailscaleSTSReconciler
	logger   *zap.SugaredLogger

	tsnamespace string

	clock tstime.Clock

	mu sync.Mutex // protects following

	// subnetRouters tracks the subnet routers managed by this Tailscale
	// Operator instance.
	subnetRouters set.Slice[types.UID]
}

var (
	// gaugeIngressResources tracks the number of subnet routers that we're
	// currently managing.
	gaugeSubnetRouterResources = clientmetric.NewGauge("k8s_subnet_router_resources")
)

func (a *ConnectorReconciler) Reconcile(ctx context.Context, req reconcile.Request) (_ reconcile.Result, err error) {
	logger := a.logger.With("connector", req.Name)
	logger.Debugf("starting reconcile")
	defer logger.Debugf("reconcile finished")

	cn := new(tsapi.Connector)
	err = a.Get(ctx, req.NamespacedName, cn)
	if apierrors.IsNotFound(err) {
		logger.Debugf("connector not found, assuming it was deleted")
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get tailscale.com Connector: %w", err)
	}
	if !cn.DeletionTimestamp.IsZero() {
		logger.Debugf("connector is being deleted or should not be exposed, cleaning up components")
		ix := xslices.Index(cn.Finalizers, FinalizerName)
		if ix < 0 {
			logger.Debugf("no finalizer, nothing to do")
			return reconcile.Result{}, nil
		}

		if done, err := a.maybeCleanupSubnetRouter(ctx, logger, cn); err != nil {
			return reconcile.Result{}, err
		} else if !done {
			logger.Debugf("cleanup not finished, will retry...")
			return reconcile.Result{RequeueAfter: shortRequeue}, nil
		}

		cn.Finalizers = append(cn.Finalizers[:ix], cn.Finalizers[ix+1:]...)
		if err := a.Update(ctx, cn); err != nil {
			return reconcile.Result{}, err
		}
		logger.Infof("connector resources cleaned up")
		return reconcile.Result{}, nil
	}

	oldCnStatus := cn.Status.DeepCopy()
	defer func() {
		if cn.Status.SubnetRouter == nil {
			tsoperator.SetConnectorCondition(cn, tsapi.ConnectorReady, metav1.ConditionUnknown, "", "", cn.Generation, a.clock, logger)
		} else if cn.Status.SubnetRouter.Ready == metav1.ConditionTrue {
			tsoperator.SetConnectorCondition(cn, tsapi.ConnectorReady, metav1.ConditionTrue, reasonSubnetRouterCreated, reasonSubnetRouterCreated, cn.Generation, a.clock, logger)
		} else {
			tsoperator.SetConnectorCondition(cn, tsapi.ConnectorReady, metav1.ConditionFalse, cn.Status.SubnetRouter.Reason, cn.Status.SubnetRouter.Reason, cn.Generation, a.clock, logger)
		}
		if !apiequality.Semantic.DeepEqual(oldCnStatus, cn.Status) {
			// an error encountered here should get returned by the Reconcile function
			if updateErr := a.Client.Status().Update(ctx, cn); updateErr != nil {
				err = updateErr
			}
		}
	}()

	if !slices.Contains(cn.Finalizers, FinalizerName) {
		// This log line is printed exactly once during initial provisioning,
		// because once the finalizer is in place this block gets skipped. So,
		// this is a nice place to tell the operator that the high level,
		// multi-reconcile operation is underway.
		logger.Infof("ensuring connector is set up")
		cn.Finalizers = append(cn.Finalizers, FinalizerName)
		if err := a.Update(ctx, cn); err != nil {
			err = fmt.Errorf("failed to add finalizer: %w", err)
			logger.Errorf("error adding finalizer: %v", err)
			return reconcile.Result{}, err
		}
	}

	// A Connector with unset .spec.subnetRouter and unset
	// cn.spec.subnetRouter.Routes will be rejected at apply time (because
	// these fields are set as required by our CRD validation). This check
	// is here for if our CRD validation breaks unnoticed we don't crash the
	// operator with nil pointer exception.
	if cn.Spec.SubnetRouter == nil || len(cn.Spec.SubnetRouter.Routes) < 1 {
		return reconcile.Result{}, nil
	}

	if err := validateSubnetRouter(*cn.Spec.SubnetRouter); err != nil {
		msg := fmt.Sprintf(messageSubnetRouterInvalid, err)
		cn.Status.SubnetRouter = &tsapi.SubnetRouterStatus{
			Ready:   metav1.ConditionFalse,
			Reason:  reasonSubnetRouterInvalid,
			Message: msg,
		}
		a.recorder.Eventf(cn, corev1.EventTypeWarning, reasonSubnetRouterInvalid, msg)
		return reconcile.Result{}, nil
	}

	var sb strings.Builder
	sb.WriteString(string(cn.Spec.SubnetRouter.Routes[0]))
	for _, r := range cn.Spec.SubnetRouter.Routes[1:] {
		sb.WriteString(fmt.Sprintf(",%s", r))
	}
	cidrsS := sb.String()
	logger.Debugf("ensuring a subnet router is deployed")
	err = a.maybeProvisionSubnetRouter(ctx, logger, cn, cidrsS)
	if err != nil {
		msg := fmt.Sprintf(messageSubnetRouterCreationFailed, cidrsS, err)
		cn.Status.SubnetRouter = &tsapi.SubnetRouterStatus{
			Ready:   metav1.ConditionFalse,
			Reason:  reasonSubnetRouterCreationFailed,
			Message: msg,
		}
		a.recorder.Eventf(cn, corev1.EventTypeWarning, reasonSubnetRouterCreationFailed, msg)
		return reconcile.Result{}, err
	}
	cn.Status.SubnetRouter = &tsapi.SubnetRouterStatus{
		Routes:  cidrsS,
		Ready:   metav1.ConditionTrue,
		Reason:  reasonSubnetRouterCreated,
		Message: fmt.Sprintf(messageSubnetRouterCreated, cidrsS),
	}
	return reconcile.Result{}, nil
}

func (a *ConnectorReconciler) maybeCleanupSubnetRouter(ctx context.Context, logger *zap.SugaredLogger, cn *tsapi.Connector) (bool, error) {
	if done, err := a.ssr.Cleanup(ctx, logger, childResourceLabels(cn.Name, a.tsnamespace, "subnetrouter")); err != nil {
		return false, fmt.Errorf("failed to cleanup: %w", err)
	} else if !done {
		logger.Debugf("cleanup not done yet, waiting for next reconcile")
		return false, nil
	}

	// Unlike most log entries in the reconcile loop, this will get printed
	// exactly once at the very end of cleanup, because the final step of
	// cleanup removes the tailscale finalizer, which will make all future
	// reconciles exit early.
	logger.Infof("cleaned up subnet router")
	a.mu.Lock()
	defer a.mu.Unlock()
	a.subnetRouters.Remove(cn.UID)
	gaugeSubnetRouterResources.Set(int64(a.subnetRouters.Len()))
	return true, nil
}

// maybeProvisionSubnetRouter maybe deploys subnet router that exposes a subset of cluster cidrs to the tailnet
func (a *ConnectorReconciler) maybeProvisionSubnetRouter(ctx context.Context, logger *zap.SugaredLogger, cn *tsapi.Connector, cidrs string) error {
	if cn.Spec.SubnetRouter == nil || len(cn.Spec.SubnetRouter.Routes) < 1 {
		return nil
	}
	a.mu.Lock()
	a.subnetRouters.Add(cn.UID)
	gaugeSubnetRouterResources.Set(int64(a.subnetRouters.Len()))
	a.mu.Unlock()

	crl := childResourceLabels(cn.Name, a.tsnamespace, "subnetrouter")
	hostname := hostnameForSubnetRouter(cn)
	sts := &tailscaleSTSConfig{
		ParentResourceName:  cn.Name,
		ParentResourceUID:   string(cn.UID),
		Hostname:            hostname,
		ChildResourceLabels: crl,
		Routes:              cidrs,
	}
	for _, tag := range cn.Spec.SubnetRouter.Tags {
		sts.Tags = append(sts.Tags, string(tag))
	}

	_, err := a.ssr.Provision(ctx, logger, sts)

	return err
}
func validateSubnetRouter(sb tsapi.SubnetRouter) error {
	var err error
	for _, route := range sb.Routes {
		pfx, e := netip.ParsePrefix(string(route))
		if e != nil {
			err = errors.Wrap(err, fmt.Sprintf("route %s is invalid: %v", route, err))
			continue
		}
		if pfx.Masked() != pfx {
			err = errors.Wrap(err, fmt.Sprintf("route %s has non-address bits set; expected %s", pfx, pfx.Masked()))
		}
	}
	return err
}

func hostnameForSubnetRouter(cn *tsapi.Connector) string {
	if cn.Spec.SubnetRouter == nil {
		return ""
	}
	if cn.Spec.SubnetRouter.Hostname != "" {
		return string(cn.Spec.SubnetRouter.Hostname)
	}
	return cn.Name + "-" + "subnetrouter"
}
