// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
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
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tstime"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/set"
)

const (
	reasonConnectorCreationFailed = "ConnectorCreationFailed"
	reasonConnectorCreated        = "ConnectorCreated"
	reasonConnectorInvalid        = "ConnectorInvalid"

	messageConnectorCreationFailed = "Failed creating Connector: %v"
	messageConnectorInvalid        = "Connector is invalid: %v"

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

	subnetRouters set.Slice[types.UID] // for subnet routers gauge
	exitNodes     set.Slice[types.UID] // for exit nodes gauge
}

var (
	// gaugeConnectorResources tracks the overall number of Connectors currently managed by this operator instance.
	gaugeConnectorResources = clientmetric.NewGauge(kubetypes.MetricConnectorResourceCount)
	// gaugeConnectorSubnetRouterResources tracks the number of Connectors managed by this operator instance that are subnet routers.
	gaugeConnectorSubnetRouterResources = clientmetric.NewGauge(kubetypes.MetricConnectorWithSubnetRouterCount)
	// gaugeConnectorExitNodeResources tracks the number of Connectors currently managed by this operator instance that are exit nodes.
	gaugeConnectorExitNodeResources = clientmetric.NewGauge(kubetypes.MetricConnectorWithExitNodeCount)
)

func (a *ConnectorReconciler) Reconcile(ctx context.Context, req reconcile.Request) (res reconcile.Result, err error) {
	logger := a.logger.With("Connector", req.Name)
	logger.Debugf("starting reconcile")
	defer logger.Debugf("reconcile finished")

	cn := new(tsapi.Connector)
	err = a.Get(ctx, req.NamespacedName, cn)
	if apierrors.IsNotFound(err) {
		logger.Debugf("Connector not found, assuming it was deleted")
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get tailscale.com Connector: %w", err)
	}
	if !cn.DeletionTimestamp.IsZero() {
		logger.Debugf("Connector is being deleted or should not be exposed, cleaning up resources")
		ix := xslices.Index(cn.Finalizers, FinalizerName)
		if ix < 0 {
			logger.Debugf("no finalizer, nothing to do")
			return reconcile.Result{}, nil
		}

		if done, err := a.maybeCleanupConnector(ctx, logger, cn); err != nil {
			return reconcile.Result{}, err
		} else if !done {
			logger.Debugf("Connector resource cleanup not yet finished, will retry...")
			return reconcile.Result{RequeueAfter: shortRequeue}, nil
		}

		cn.Finalizers = append(cn.Finalizers[:ix], cn.Finalizers[ix+1:]...)
		if err := a.Update(ctx, cn); err != nil {
			return reconcile.Result{}, err
		}
		logger.Infof("Connector resources cleaned up")
		return reconcile.Result{}, nil
	}

	oldCnStatus := cn.Status.DeepCopy()
	setStatus := func(cn *tsapi.Connector, _ tsapi.ConditionType, status metav1.ConditionStatus, reason, message string) (reconcile.Result, error) {
		tsoperator.SetConnectorCondition(cn, tsapi.ConnectorReady, status, reason, message, cn.Generation, a.clock, logger)
		if !apiequality.Semantic.DeepEqual(oldCnStatus, cn.Status) {
			// An error encountered here should get returned by the Reconcile function.
			if updateErr := a.Client.Status().Update(ctx, cn); updateErr != nil {
				err = errors.Wrap(err, updateErr.Error())
			}
		}
		return res, err
	}

	if !slices.Contains(cn.Finalizers, FinalizerName) {
		// This log line is printed exactly once during initial provisioning,
		// because once the finalizer is in place this block gets skipped. So,
		// this is a nice place to tell the operator that the high level,
		// multi-reconcile operation is underway.
		logger.Infof("ensuring Connector is set up")
		cn.Finalizers = append(cn.Finalizers, FinalizerName)
		if err := a.Update(ctx, cn); err != nil {
			logger.Errorf("error adding finalizer: %w", err)
			return setStatus(cn, tsapi.ConnectorReady, metav1.ConditionFalse, reasonConnectorCreationFailed, reasonConnectorCreationFailed)
		}
	}

	if err := a.validate(cn); err != nil {
		logger.Errorf("error validating Connector spec: %w", err)
		message := fmt.Sprintf(messageConnectorInvalid, err)
		a.recorder.Eventf(cn, corev1.EventTypeWarning, reasonConnectorInvalid, message)
		return setStatus(cn, tsapi.ConnectorReady, metav1.ConditionFalse, reasonConnectorInvalid, message)
	}

	if err = a.maybeProvisionConnector(ctx, logger, cn); err != nil {
		logger.Errorf("error creating Connector resources: %w", err)
		message := fmt.Sprintf(messageConnectorCreationFailed, err)
		a.recorder.Eventf(cn, corev1.EventTypeWarning, reasonConnectorCreationFailed, message)
		return setStatus(cn, tsapi.ConnectorReady, metav1.ConditionFalse, reasonConnectorCreationFailed, message)
	}

	logger.Info("Connector resources synced")
	cn.Status.IsExitNode = cn.Spec.ExitNode
	if cn.Spec.SubnetRouter != nil {
		cn.Status.SubnetRoutes = cn.Spec.SubnetRouter.AdvertiseRoutes.Stringify()
		return setStatus(cn, tsapi.ConnectorReady, metav1.ConditionTrue, reasonConnectorCreated, reasonConnectorCreated)
	}
	cn.Status.SubnetRoutes = ""
	return setStatus(cn, tsapi.ConnectorReady, metav1.ConditionTrue, reasonConnectorCreated, reasonConnectorCreated)
}

// maybeProvisionConnector ensures that any new resources required for this
// Connector instance are deployed to the cluster.
func (a *ConnectorReconciler) maybeProvisionConnector(ctx context.Context, logger *zap.SugaredLogger, cn *tsapi.Connector) error {
	hostname := cn.Name + "-connector"
	if cn.Spec.Hostname != "" {
		hostname = string(cn.Spec.Hostname)
	}
	crl := childResourceLabels(cn.Name, a.tsnamespace, "connector")

	proxyClass := cn.Spec.ProxyClass
	if proxyClass != "" {
		if ready, err := proxyClassIsReady(ctx, proxyClass, a.Client); err != nil {
			return fmt.Errorf("error verifying ProxyClass for Connector: %w", err)
		} else if !ready {
			logger.Infof("ProxyClass %s specified for the Connector, but is not (yet) Ready, waiting..", proxyClass)
			return nil
		}
	}

	sts := &tailscaleSTSConfig{
		ParentResourceName:  cn.Name,
		ParentResourceUID:   string(cn.UID),
		Hostname:            hostname,
		ChildResourceLabels: crl,
		Tags:                cn.Spec.Tags.Stringify(),
		Connector: &connector{
			isExitNode: cn.Spec.ExitNode,
		},
		ProxyClassName: proxyClass,
	}

	if cn.Spec.SubnetRouter != nil && len(cn.Spec.SubnetRouter.AdvertiseRoutes) > 0 {
		sts.Connector.routes = cn.Spec.SubnetRouter.AdvertiseRoutes.Stringify()
	}

	a.mu.Lock()
	if sts.Connector.isExitNode {
		a.exitNodes.Add(cn.UID)
	} else {
		a.exitNodes.Remove(cn.UID)
	}
	if sts.Connector.routes != "" {
		a.subnetRouters.Add(cn.GetUID())
	} else {
		a.subnetRouters.Remove(cn.GetUID())
	}
	a.mu.Unlock()
	gaugeConnectorSubnetRouterResources.Set(int64(a.subnetRouters.Len()))
	gaugeConnectorExitNodeResources.Set(int64(a.exitNodes.Len()))
	var connectors set.Slice[types.UID]
	connectors.AddSlice(a.exitNodes.Slice())
	connectors.AddSlice(a.subnetRouters.Slice())
	gaugeConnectorResources.Set(int64(connectors.Len()))

	_, err := a.ssr.Provision(ctx, logger, sts)
	if err != nil {
		return err
	}

	_, tsHost, ips, err := a.ssr.DeviceInfo(ctx, crl)
	if err != nil {
		return err
	}

	if tsHost == "" {
		logger.Debugf("no Tailscale hostname known yet, waiting for connector pod to finish auth")
		// No hostname yet. Wait for the connector pod to auth.
		cn.Status.TailnetIPs = nil
		cn.Status.Hostname = ""
		return nil
	}

	cn.Status.TailnetIPs = ips
	cn.Status.Hostname = tsHost

	return nil
}

func (a *ConnectorReconciler) maybeCleanupConnector(ctx context.Context, logger *zap.SugaredLogger, cn *tsapi.Connector) (bool, error) {
	if done, err := a.ssr.Cleanup(ctx, logger, childResourceLabels(cn.Name, a.tsnamespace, "connector")); err != nil {
		return false, fmt.Errorf("failed to cleanup Connector resources: %w", err)
	} else if !done {
		logger.Debugf("Connector cleanup not done yet, waiting for next reconcile")
		return false, nil
	}

	// Unlike most log entries in the reconcile loop, this will get printed
	// exactly once at the very end of cleanup, because the final step of
	// cleanup removes the tailscale finalizer, which will make all future
	// reconciles exit early.
	logger.Infof("cleaned up Connector resources")
	a.mu.Lock()
	a.subnetRouters.Remove(cn.UID)
	a.exitNodes.Remove(cn.UID)
	a.mu.Unlock()
	gaugeConnectorExitNodeResources.Set(int64(a.exitNodes.Len()))
	gaugeConnectorSubnetRouterResources.Set(int64(a.subnetRouters.Len()))
	var connectors set.Slice[types.UID]
	connectors.AddSlice(a.exitNodes.Slice())
	connectors.AddSlice(a.subnetRouters.Slice())
	gaugeConnectorResources.Set(int64(connectors.Len()))
	return true, nil
}

func (a *ConnectorReconciler) validate(cn *tsapi.Connector) error {
	// Connector fields are already validated at apply time with CEL validation
	// on custom resource fields. The checks here are a backup in case the
	// CEL validation breaks without us noticing.
	if !(cn.Spec.SubnetRouter != nil || cn.Spec.ExitNode) {
		return errors.New("invalid spec: a Connector must expose subnet routes or act as an exit node (or both)")
	}
	if cn.Spec.SubnetRouter == nil {
		return nil
	}
	return validateSubnetRouter(cn.Spec.SubnetRouter)
}

func validateSubnetRouter(sb *tsapi.SubnetRouter) error {
	if len(sb.AdvertiseRoutes) < 1 {
		return errors.New("invalid subnet router spec: no routes defined")
	}
	var err error
	for _, route := range sb.AdvertiseRoutes {
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
