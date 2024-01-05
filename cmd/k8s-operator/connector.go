// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"encoding/json"
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
	"tailscale.com/ipn"
	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/net/netutil"
	"tailscale.com/tstime"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/set"
)

const (
	reasonConnectorCreationFailed = "ConnectorCreationFailed"

	reasonConnectorCreated           = "ConnectorCreated"
	reasonConnectorCleanupFailed     = "ConnectorCleanupFailed"
	reasonConnectorCleanupInProgress = "ConnectorCleanupInProgress"
	reasonConnectorInvalid           = "ConnectorInvalid"

	messageConnectorCreationFailed   = "Failed creating Connector: %v"
	messageConnectorInvalid          = "Connector is invalid: %v"
	messageSubnetRouterCleanupFailed = "Failed cleaning up Connector resources: %v"

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

	connectors set.Slice[types.UID] // for connectors gauge
}

var (
	// gaugeConnectorResources tracks the number of Connectors currently managed by this operator instance
	gaugeConnectorResources = clientmetric.NewGauge("k8s_connector_resources")
)

func (a *ConnectorReconciler) Reconcile(ctx context.Context, req reconcile.Request) (_ reconcile.Result, err error) {
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

	var (
		reason, message string
		readyStatus     metav1.ConditionStatus
	)

	oldCnStatus := cn.Status.DeepCopy()
	defer func() {
		tsoperator.SetConnectorCondition(cn, tsapi.ConnectorReady, readyStatus, reason, message, cn.Generation, a.clock, logger)
		if !apiequality.Semantic.DeepEqual(oldCnStatus, cn.Status) {
			// An error encountered here should get returned by the Reconcile function.
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
		logger.Infof("ensuring Connector is set up")
		cn.Finalizers = append(cn.Finalizers, FinalizerName)
		if err := a.Update(ctx, cn); err != nil {
			err = fmt.Errorf("failed to add finalizer: %w", err)
			logger.Errorf("error adding finalizer: %v", err)
			reason = reasonConnectorCreationFailed
			message = fmt.Sprintf(messageConnectorCreationFailed, err)
			readyStatus = metav1.ConditionFalse
			return reconcile.Result{}, err
		}
	}

	if err := a.validate(cn); err != nil {
		logger.Errorf("error validating Connector spec: %w", err)
		reason = reasonConnectorInvalid
		message = fmt.Sprintf(messageConnectorInvalid, err)
		readyStatus = metav1.ConditionFalse
		a.recorder.Eventf(cn, corev1.EventTypeWarning, reasonConnectorInvalid, message)
		return reconcile.Result{}, nil
	}

	if err = a.maybeProvisionConnector(ctx, logger, cn); err != nil {
		logger.Errorf("error creating Connector resources: %w", err)
		reason = reasonConnectorCreationFailed
		message = fmt.Sprintf(messageConnectorCreationFailed, err)
		readyStatus = metav1.ConditionFalse
		a.recorder.Eventf(cn, corev1.EventTypeWarning, reason, message)
	} else {
		logger.Info("Connector resources synced")
		reason = reasonConnectorCreated
		message = reasonConnectorCreated
		readyStatus = metav1.ConditionTrue
		cn.Status.IsExitNode = cn.Spec.IsExitNode
		if cn.Spec.SubnetRouter != nil {
			cn.Status.SubnetRoutes = cn.Spec.SubnetRouter.Routes.Stringify()
		} else {
			cn.Status.SubnetRoutes = ""
		}
	}
	return reconcile.Result{}, err
}

// maybeProvisionConnector ensures that any new resources required for this
// Connector instance are deployed to the cluster.
func (a *ConnectorReconciler) maybeProvisionConnector(ctx context.Context, logger *zap.SugaredLogger, cn *tsapi.Connector) error {
	hostname := cn.Name + "-connector"
	if cn.Spec.Hostname != "" {
		hostname = string(cn.Spec.Hostname)
	}
	crl := childResourceLabels(cn.Name, a.tsnamespace, "connector")
	sts := &tailscaleSTSConfig{
		ParentResourceName:  cn.Name,
		ParentResourceUID:   string(cn.UID),
		Hostname:            hostname,
		ChildResourceLabels: crl,
		Tags:                cn.Spec.Tags.Stringify(),
		Connector: &connector{
			isExitNode: cn.Spec.IsExitNode,
		},
	}

	if cn.Spec.SubnetRouter != nil && len(cn.Spec.SubnetRouter.Routes) > 0 {
		sts.Connector.routes = cn.Spec.SubnetRouter.Routes.Stringify()
	}

	a.mu.Lock()
	a.connectors.Add(cn.UID)
	gaugeConnectorResources.Set(int64(a.connectors.Len()))
	a.mu.Unlock()

	_, err := a.ssr.Provision(ctx, logger, sts)
	return err
}

func (a *tailscaleSTSReconciler) tsConfigCM(ctx context.Context, name, namespace string, logger *zap.SugaredLogger, sts *tailscaleSTSConfig) error {
	confFile, err := confFile(sts)
	if err != nil {
		return fmt.Errorf("error provisioning config: %v", err)
	}

	jsonBytes, err := json.Marshal(confFile)
	if err != nil {
		return fmt.Errorf("error marshaling config file: %v", err)
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    sts.ChildResourceLabels,
		},
		Data: map[string]string{
			"tailscaled": string(jsonBytes),
		},
	}
	_, err = createOrUpdate(ctx, a.Client, namespace, cm, func(config *corev1.ConfigMap) { config.Labels = cm.Labels; config.Data = cm.Data })
	if err != nil {
		return fmt.Errorf("error creating a ConfigMap: %v", err)
	}
	return nil
}

func confFile(sts *tailscaleSTSConfig) (*ipn.ConfigVAlpha, error) {
	var (
		routes []netip.Prefix
		err    error
	)
	if sts.Connector != nil {
		routes, err = netutil.CalcAdvertiseRoutes(sts.Connector.routes, sts.Connector.isExitNode)
		if err != nil {
			return nil, fmt.Errorf("error calculating routes: %v", err)
		}
	}
	conf := &ipn.ConfigVAlpha{
		Version:         "alpha0",
		AdvertiseRoutes: routes,
		AcceptDNS:       "false",
		Hostname:        &sts.Hostname,
		// Not sure how to log in if it's locked?
		Locked: "false",
	}
	// fix - don't put the key there
	if sts.key != "" {
		conf.AuthKey = &sts.key
	}
	return conf, nil
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
	defer a.mu.Unlock()
	a.connectors.Remove(cn.UID)
	gaugeConnectorResources.Set(int64(a.connectors.Len()))
	return true, nil
}

func (a *ConnectorReconciler) validate(cn *tsapi.Connector) error {
	// Connector fields are already validated at apply time with CEL validation
	// on custom resource fields. The checks here are a backup in case the
	// CEL validation breaks without us noticing.
	if !(cn.Spec.SubnetRouter != nil || cn.Spec.IsExitNode) {
		return errors.New("invalid Connector spec- a Connector must be either expose subnet routes or act as exit node (or both)")
	}
	if cn.Spec.SubnetRouter == nil {
		return nil
	}
	return validateSubnetRouter(cn.Spec.SubnetRouter)
}

func validateSubnetRouter(sb *tsapi.SubnetRouter) error {
	if len(sb.Routes) < 1 {
		return errors.New("invalid subnet router spec: no routes defined")
	}
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
