// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package routeacceptor provides reconciliation logic for the RouteAcceptor custom resource definition. It runs a
// tailscaled device in the host network namespace of every selected node (as a DaemonSet), configured to accept
// routes, so that subnet routes advertised to the tailnet are routable from every Pod on those nodes.
package routeacceptor

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorutils "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler"
	"tailscale.com/k8s-operator/reconciler/tailscaled"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
	"tailscale.com/util/clientmetric"
)

type (
	// The Reconciler type is a reconcile.TypedReconciler implementation used to manage the reconciliation of
	// RouteAcceptor custom resources.
	Reconciler struct {
		client.Client

		apiReader              client.Reader
		tailscaleNamespace     string
		proxyImage             string
		proxyPriorityClassName string
		defaultTags            []string
		tsClients              tailscaled.ClientProvider
		recorder               record.EventRecorder
		logger                 *zap.SugaredLogger
		clock                  tstime.Clock
		reissuer               *tailscaled.Reissuer

		tracker *reconciler.ResourceTracker
	}

	// The ReconcilerOptions type contains configuration values for the Reconciler.
	ReconcilerOptions struct {
		// The client for interacting with the Kubernetes API.
		Client client.Client
		// APIReader reads directly from the API server, bypassing the cache. It is used for resource types that
		// may not be served by the cluster, such as ServiceCIDRs, which the cached client cannot handle gracefully.
		// Defaults to Client when unset.
		APIReader client.Reader
		// The namespace the operator is installed in. RouteAcceptor-managed resources (DaemonSets, Secrets) are
		// created within this namespace.
		TailscaleNamespace string
		// ProxyImage is the container image used for the tailscaled pods that run on each node.
		ProxyImage string
		// ProxyPriorityClassName is the PriorityClass applied to the DaemonSet's Pods unless the ProxyClass sets
		// one. Optional.
		ProxyPriorityClassName string
		// DefaultTags is the tag list applied to freshly minted auth keys when a RouteAcceptor hasn't set its own
		// spec.tags. Must be non-empty at construction time.
		DefaultTags []string
		// Clients resolves the Tailscale API client for a given tailnet name. Used to mint auth keys and delete
		// devices. Blank tailnet returns the operator's default client.
		Clients tailscaled.ClientProvider
		// Recorder records Kubernetes Events on RouteAcceptors. Optional.
		Recorder record.EventRecorder
		// The logger to use for this Reconciler.
		Logger *zap.SugaredLogger
		// Clock is used to stamp condition transitions and to decide when to rotate auth keys. Defaults to a real
		// clock when unset.
		Clock tstime.Clock
	}
)

const (
	reconcilerName                   = "routeacceptor-reconciler"
	fieldOwner     client.FieldOwner = "routeacceptor-reconciler"

	// parentTypeRouteAcceptor is the value used for reconciler.LabelParentType on RouteAcceptor-managed resources.
	parentTypeRouteAcceptor = "routeacceptor"

	// annotationNodeName records, on a state Secret, the name of the node whose device state it holds. It is an
	// annotation rather than a label because node names may exceed the length limit of label values and may
	// contain dots.
	annotationNodeName = "tailscale.com/node-name"

	// serviceAccountName is the ServiceAccount the operator's Helm chart creates for proxies. It may create, get,
	// patch and update Secrets in the operator's namespace, which is what containerboot needs for its state.
	serviceAccountName = "proxies"

	// routeAcceptorEnvVar is the containerboot env var that enables route acceptor mode.
	routeAcceptorEnvVar = "TS_EXPERIMENTAL_ROUTE_ACCEPTOR"

	// notReadyRequeue is how long to wait before checking again whether all nodes are ready.
	notReadyRequeue = 30 * time.Second

	// dataPlaneRequeue is how long to wait before re-checking the CNI's configuration while it keeps the route
	// acceptor from being deployed. It is not watched, as it lives outside the operator's namespace.
	dataPlaneRequeue = 10 * time.Minute

	// egressGatewayRequeue is how often the CiliumEgressGatewayPolicy is re-checked for drift, as it is not watched.
	egressGatewayRequeue = 5 * time.Minute
)

// Constants for condition reasons.
const (
	ReasonReady                    = "RouteAcceptorReady"
	ReasonNoNodesSelected          = "NoNodesSelected"
	ReasonPodsPending              = "PodsPending"
	ReasonProxyClassNotReady       = "ProxyClassNotReady"
	ReasonTailnetUnavailable       = "TailnetUnavailable"
	ReasonNodeNameTooLong          = "NodeNameTooLong"
	ReasonClusterCIDROverlapsCGNAT = "ClusterCIDROverlapsCGNAT"
	ReasonRoutesValid              = "RoutesValid"
	ReasonRouteOverlapsClusterCIDR = "RouteOverlapsClusterCIDR"

	// Reasons for the RouteAcceptorDataPlaneSupported condition.
	ReasonDataPlaneSupported              = "DataPlaneSupported"
	ReasonCiliumManagedDevice             = "CiliumManagedDevice"
	ReasonCiliumEBPFHostRouting           = "CiliumEBPFHostRouting"
	ReasonCiliumNoConntrackRules          = "CiliumNoConntrackRules"
	ReasonCiliumIPMasqAgent               = "CiliumIPMasqAgent"
	ReasonCiliumEgressGateway             = "CiliumEgressGateway"
	ReasonCiliumNotDetected               = "CiliumNotDetected"
	ReasonCiliumEgressGatewayCRDMissing   = "CiliumEgressGatewayCRDMissing"
	ReasonCiliumEgressGatewayDisabled     = "CiliumEgressGatewayDisabled"
	ReasonCiliumDevicesMissingTailscale0  = "CiliumDevicesMissingTailscale0"
	ReasonCiliumEgressGatewayPolicyFailed = "CiliumEgressGatewayPolicyFailed"
)

var (
	// gaugeRouteAcceptorResources tracks the overall number of RouteAcceptor resources currently managed by this
	// operator instance.
	gaugeRouteAcceptorResources = clientmetric.NewGauge(kubetypes.MetricRouteAcceptorCount)

	// managedLabelKeys are the labels a ProxyClass must not override on managed resources.
	managedLabelKeys = []string{
		kubetypes.LabelManaged,
		reconciler.LabelParentType,
		reconciler.LabelParentName,
	}
)

// NewReconciler returns a new instance of the Reconciler type. It watches specifically for changes to RouteAcceptor
// custom resources. The ReconcilerOptions can be used to modify the behaviour of the Reconciler.
func NewReconciler(options ReconcilerOptions) *Reconciler {
	clock := options.Clock
	if clock == nil {
		clock = tstime.DefaultClock{}
	}

	apiReader := options.APIReader
	if apiReader == nil {
		apiReader = options.Client
	}

	return &Reconciler{
		Client:                 options.Client,
		apiReader:              apiReader,
		tailscaleNamespace:     options.TailscaleNamespace,
		proxyImage:             options.ProxyImage,
		proxyPriorityClassName: options.ProxyPriorityClassName,
		defaultTags:            options.DefaultTags,
		tsClients:              options.Clients,
		recorder:               options.Recorder,
		logger:                 options.Logger.Named(reconcilerName),
		clock:                  clock,
		tracker:                reconciler.NewResourceTracker(gaugeRouteAcceptorResources),
		reissuer:               tailscaled.NewReissuer(),
	}
}

// Register the Reconciler onto the given manager.Manager implementation. It watches RouteAcceptor resources
// directly, the child resources it manages (DaemonSets, Secrets) so external drift or state written by containerboot
// enqueues a reconcile for the owning RouteAcceptor, ProxyClass so config changes propagate to referring
// RouteAcceptors, and Nodes so devices are set up and torn down as nodes come and go.
func (r *Reconciler) Register(mgr manager.Manager) error {
	enqueue := handler.EnqueueRequestsFromMapFunc(reconciler.EnqueueForChild(parentTypeRouteAcceptor))
	return builder.
		ControllerManagedBy(mgr).
		For(&tsapi.RouteAcceptor{}).
		Watches(&appsv1.DaemonSet{}, enqueue).
		Watches(&corev1.Secret{}, enqueue).
		Watches(&tsapi.ProxyClass{}, handler.EnqueueRequestsFromMapFunc(r.enqueueForProxyClass)).
		Watches(&corev1.Node{}, handler.EnqueueRequestsFromMapFunc(r.enqueueAll), builder.WithPredicates(nodePredicate)).
		Named(reconcilerName).
		Complete(r)
}

// nodePredicate limits Node events to those that can change which nodes are selected or which IP ranges the
// cluster uses: creation, deletion, and changes to labels or Pod CIDRs.
var nodePredicate = predicate.Funcs{
	CreateFunc:  func(event.CreateEvent) bool { return true },
	DeleteFunc:  func(event.DeleteEvent) bool { return true },
	GenericFunc: func(event.GenericEvent) bool { return false },
	UpdateFunc: func(e event.UpdateEvent) bool {
		if !maps.Equal(e.ObjectOld.GetLabels(), e.ObjectNew.GetLabels()) {
			return true
		}
		oldNode, ok := e.ObjectOld.(*corev1.Node)
		if !ok {
			return false
		}
		newNode, ok := e.ObjectNew.(*corev1.Node)
		if !ok {
			return false
		}
		return oldNode.Spec.PodCIDR != newNode.Spec.PodCIDR || !slices.Equal(oldNode.Spec.PodCIDRs, newNode.Spec.PodCIDRs)
	},
}

func (r *Reconciler) enqueueForProxyClass(ctx context.Context, o client.Object) []reconcile.Request {
	pc, ok := o.(*tsapi.ProxyClass)
	if !ok {
		return nil
	}

	var list tsapi.RouteAcceptorList
	if err := r.List(ctx, &list); err != nil {
		r.logger.Errorf("failed to list RouteAcceptors for ProxyClass %q change: %v", pc.Name, err)
		return nil
	}

	var reqs []reconcile.Request
	for _, ra := range list.Items {
		if ra.Spec.ProxyClass == pc.Name {
			reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{Name: ra.Name}})
		}
	}
	return reqs
}

// enqueueAll enqueues every RouteAcceptor. It is used for Node events, as every RouteAcceptor may select the node.
func (r *Reconciler) enqueueAll(ctx context.Context, _ client.Object) []reconcile.Request {
	var list tsapi.RouteAcceptorList
	if err := r.List(ctx, &list); err != nil {
		r.logger.Errorf("failed to list RouteAcceptors for Node change: %v", err)
		return nil
	}

	var reqs []reconcile.Request
	for _, ra := range list.Items {
		reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{Name: ra.Name}})
	}
	return reqs
}

// Reconcile is invoked when a change occurs to RouteAcceptor resources within the cluster, or to the resources they
// depend on. On create/update, it ensures a DaemonSet of tailscaled devices exists together with the Secrets it
// needs. On delete, all devices and managed resources are removed before the finalizer is released.
func (r *Reconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	logger := r.logger.With("RouteAcceptor", req.Name)
	logger.Debug("starting reconcile")
	defer logger.Debug("reconcile finished")

	var ra tsapi.RouteAcceptor
	err := r.Get(ctx, req.NamespacedName, &ra)
	switch {
	case apierrors.IsNotFound(err):
		logger.Debug("RouteAcceptor not found, assuming it was deleted")
		return reconcile.Result{}, nil
	case err != nil:
		return reconcile.Result{}, fmt.Errorf("failed to get RouteAcceptor %q: %w", req.NamespacedName, err)
	}

	if r.tsClients != nil {
		if _, err = r.tsClients.For(ra.Spec.Tailnet); err != nil {
			return r.reportTailnetUnavailable(ctx, logger, &ra, err)
		}
	}

	if !ra.DeletionTimestamp.IsZero() {
		return r.delete(ctx, logger, &ra)
	}

	return r.createOrUpdate(ctx, logger, &ra)
}

func (r *Reconciler) reportTailnetUnavailable(ctx context.Context, logger *zap.SugaredLogger, ra *tsapi.RouteAcceptor, tsErr error) (reconcile.Result, error) {
	operatorutils.SetRouteAcceptorCondition(ra, tsapi.RouteAcceptorReady, metav1.ConditionFalse, ReasonTailnetUnavailable, tsErr.Error(), r.clock, logger)
	if err := r.Status().Update(ctx, ra); err != nil {
		return reconcile.Result{}, errors.Join(tsErr, fmt.Errorf("failed to update RouteAcceptor status: %w", err))
	}

	return reconcile.Result{}, tsErr
}

// setNotReady records why the RouteAcceptor cannot (yet) be deployed and stops the reconcile without an error, as
// the situation is not resolved by retrying: a watched resource changing triggers the next reconcile.
func (r *Reconciler) setNotReady(ctx context.Context, logger *zap.SugaredLogger, ra *tsapi.RouteAcceptor, reason, message string) (reconcile.Result, error) {
	logger.Infof("RouteAcceptor %q is not ready: %s", ra.Name, message)
	operatorutils.SetRouteAcceptorCondition(ra, tsapi.RouteAcceptorReady, metav1.ConditionFalse, reason, message, r.clock, logger)
	if err := r.Status().Update(ctx, ra); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to update RouteAcceptor status for %q: %w", ra.Name, err)
	}
	return reconcile.Result{}, nil
}

func (r *Reconciler) createOrUpdate(ctx context.Context, logger *zap.SugaredLogger, ra *tsapi.RouteAcceptor) (reconcile.Result, error) {
	if err := reconciler.EnsureFinalizer(ctx, r.Client, ra, reconciler.Finalizer); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to add finalizer to RouteAcceptor %q: %w", ra.Name, err)
	}

	r.tracker.Add(ra.UID)

	pc, err := r.getProxyClass(ctx, ra)
	if err != nil {
		return reconcile.Result{}, err
	}
	if pc != nil && !operatorutils.ProxyClassIsReady(pc) {
		return r.setNotReady(ctx, logger, ra, ReasonProxyClassNotReady, fmt.Sprintf("ProxyClass %q is not (yet) ready", pc.Name))
	}

	allNodes, err := r.listNodes(ctx)
	if err != nil {
		return reconcile.Result{}, err
	}
	selected := selectNodes(allNodes, pc)
	r.reissuer.EnsureState(ra.Name, len(selected))

	// Each node's device state lives in a Secret named after the node. Node names are valid DNS subdomain names,
	// as are Secret names, but the prefix we add may push a name over the limit.
	for _, n := range selected {
		if name := stateSecretName(ra.Name, n.Name); len(name) > validation.DNS1123SubdomainMaxLength {
			message := fmt.Sprintf("state Secret name %q for node %q exceeds %d characters", name, n.Name, validation.DNS1123SubdomainMaxLength)
			return r.setNotReady(ctx, logger, ra, ReasonNodeNameTooLong, message)
		}
	}

	clusterCIDRs := r.clusterCIDRs(ctx, logger, ra, allNodes)
	if !ra.Spec.UnsafeAllowCGNATClusterCIDR {
		if cidr, ok := overlapsCGNAT(clusterCIDRs); ok {
			message := fmt.Sprintf("cluster IP range %s overlaps the Tailscale IP range %s: tailscaled would drop traffic from Pods to the nodes. "+
				"Grant the devices' tags the %q node attribute in the tailnet and set spec.unsafeAllowCGNATClusterCIDR to proceed",
				cidr, tsaddr.CGNATRange(), string(tailcfg.NodeAttrDisableLinuxCGNATDropRule))
			r.event(ra, corev1.EventTypeWarning, ReasonClusterCIDROverlapsCGNAT, message)
			return r.setNotReady(ctx, logger, ra, ReasonClusterCIDROverlapsCGNAT, message)
		}
	}

	dp, err := r.detectDataPlane(ctx)
	if err != nil {
		return reconcile.Result{}, err
	}
	// In the egress gateway mode Cilium steers and masquerades the traffic itself; the condition is set once
	// the policy has been ensured, below.
	dataPlane := conditionSpec{metav1.ConditionTrue, ReasonDataPlaneSupported, ReasonDataPlaneSupported}
	if !ciliumEgressGatewayEnabled(ra) {
		dataPlane = dp.classify(ra)
		if dataPlane.status == metav1.ConditionFalse {
			r.event(ra, corev1.EventTypeWarning, dataPlane.reason, dataPlane.message)
			operatorutils.SetRouteAcceptorCondition(ra, tsapi.RouteAcceptorDataPlaneSupported, metav1.ConditionFalse, dataPlane.reason, dataPlane.message, r.clock, logger)
			res, err := r.setNotReady(ctx, logger, ra, dataPlane.reason, dataPlane.message)
			res.RequeueAfter = dataPlaneRequeue
			return res, err
		}
	}

	for _, n := range selected {
		if err = r.ensureStateSecret(ctx, logger, ra, n.Name); err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to apply state Secret for RouteAcceptor %q node %q: %w", ra.Name, n.Name, err)
		}
	}

	rotateIn, err := r.ensureConfigSecret(ctx, logger, ra, selected)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to apply config Secret for RouteAcceptor %q: %w", ra.Name, err)
	}

	ds, err := r.ensureDaemonSet(ctx, logger, ra, pc)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to apply DaemonSet for RouteAcceptor %q: %w", ra.Name, err)
	}

	if err = r.reapStaleNodes(ctx, logger, ra, allNodes, selected); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to clean up devices of removed nodes for RouteAcceptor %q: %w", ra.Name, err)
	}

	prevStatus := ra.Status.DeepCopy()
	if err = r.collectStatus(ctx, ra, ds); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to collect status for RouteAcceptor %q: %w", ra.Name, err)
	}

	// Come back when the auth key needs rotating, and sooner while nodes are still joining.
	requeueAfter := rotateIn
	if ciliumEgressGatewayEnabled(ra) {
		dataPlane = r.ensureCiliumEgressGatewayPolicy(ctx, logger, ra, dp)
		requeueAfter = minRequeue(requeueAfter, egressGatewayRequeue)
	}

	if err = r.writeStatus(ctx, logger, ra, prevStatus, clusterCIDRs, dataPlane); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to update RouteAcceptor status for %q: %w", ra.Name, err)
	}

	if !routeAcceptorReady(ra) {
		requeueAfter = minRequeue(requeueAfter, notReadyRequeue)
	}
	return reconcile.Result{RequeueAfter: requeueAfter}, nil
}

// minRequeue returns the shorter of the two requeue intervals, treating a non-positive interval as "none".
func minRequeue(a, b time.Duration) time.Duration {
	if a <= 0 || (b > 0 && b < a) {
		return b
	}
	return a
}

func (r *Reconciler) delete(ctx context.Context, logger *zap.SugaredLogger, ra *tsapi.RouteAcceptor) (reconcile.Result, error) {
	logger.Infof("deleting RouteAcceptor %q", ra.Name)

	if err := r.deleteDaemonSet(ctx, logger, ra); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to delete DaemonSet for RouteAcceptor %q: %w", ra.Name, err)
	}

	if err := r.deleteAllNodeState(ctx, logger, ra); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to delete tailnet devices for RouteAcceptor %q: %w", ra.Name, err)
	}

	if err := r.deleteConfigSecret(ctx, logger, ra); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to delete config Secret for RouteAcceptor %q: %w", ra.Name, err)
	}

	if err := r.deleteCiliumEgressGatewayPolicy(ctx, logger, ra); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to delete CiliumEgressGatewayPolicy for RouteAcceptor %q: %w", ra.Name, err)
	}

	if err := reconciler.ClearFinalizer(ctx, r.Client, ra, reconciler.Finalizer); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to remove finalizer from RouteAcceptor %q: %w", ra.Name, err)
	}

	r.tracker.Remove(ra.UID)
	r.reissuer.RemoveState(ra.Name)

	return reconcile.Result{}, nil
}

// event records a Kubernetes Event on ra, if a recorder is configured.
func (r *Reconciler) event(ra *tsapi.RouteAcceptor, eventType, reason, message string) {
	if r.recorder == nil {
		return
	}
	r.recorder.Event(ra, eventType, reason, message)
}

func routeAcceptorReady(ra *tsapi.RouteAcceptor) bool {
	for _, c := range ra.Status.Conditions {
		if c.Type == string(tsapi.RouteAcceptorReady) {
			return c.Status == metav1.ConditionTrue
		}
	}
	return false
}
