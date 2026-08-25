// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package peerrelay provides reconciliation logic for the PeerRelay custom resource definition. It is responsible
// for managing the lifecycle of PeerRelay devices, including the StatefulSet and Service resources used to expose
// them.
package peerrelay

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"time"

	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorutils "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler"
	"tailscale.com/k8s-operator/reconciler/tailscaled"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tstime"
	"tailscale.com/util/clientmetric"
)

type (
	// The Reconciler type is a reconcile.TypedReconciler implementation used to manage the reconciliation of
	// PeerRelay custom resources.
	Reconciler struct {
		client.Client

		tailscaleNamespace string
		proxyImage         string
		defaultTags        []string
		tsClients          tailscaled.ClientProvider
		resolver           func(ctx context.Context, network, host string) ([]netip.Addr, error)
		logger             *zap.SugaredLogger
		clock              tstime.Clock
		reissuer           *tailscaled.Reissuer

		tracker *reconciler.ResourceTracker
	}

	// The ReconcilerOptions type contains configuration values for the Reconciler.
	ReconcilerOptions struct {
		// The client for interacting with the Kubernetes API.
		Client client.Client
		// The namespace the operator is installed in. PeerRelay-managed resources (Services, StatefulSets, etc.)
		// are created within this namespace.
		TailscaleNamespace string
		// ProxyImage is the container image used for the tailscaled pods that back each peer relay replica.
		ProxyImage string
		// DefaultTags is the tag list applied to freshly minted auth keys when a PeerRelay hasn't set its own
		// spec.tags. Must be non-empty at construction time.
		DefaultTags []string
		// Clients resolves the Tailscale API client for a given tailnet name. Used to mint auth keys for each
		// replica. Blank tailnet returns the operator's default client.
		Clients tailscaled.ClientProvider
		// Resolver is used to convert LoadBalancer Service hostnames to concrete IPs when the cloud
		// controller doesn't populate Ingress[].IP directly (e.g. AWS NLBs). Defaults to a resolver backed by
		// net.DefaultResolver when unset.
		Resolver func(ctx context.Context, network string, host string) ([]netip.Addr, error)
		// The logger to use for this Reconciler.
		Logger *zap.SugaredLogger
		// Clock is used to stamp condition transitions. Defaults to a real clock when unset.
		Clock tstime.Clock
	}
)

const (
	reconcilerName                   = "peerrelay-reconciler"
	fieldOwner     client.FieldOwner = "peerrelay-reconciler"
)

// Constants for condition reasons.
const (
	ReasonEndpointsPending       = "EndpointsPending"
	ReasonPodsPending            = "PodsPending"
	ReasonAWSConfigInvalid       = "AWSConfigInvalid"
	ReasonStaticEndpointsInvalid = "StaticEndpointsInvalid"
	ReasonTailnetUnavailable     = "TailnetUnavailable"
	ReasonReady                  = "PeerRelayReady"
)

var (
	// gaugePeerRelayResources tracks the overall number of PeerRelay resources currently managed by this operator
	// instance.
	gaugePeerRelayResources = clientmetric.NewGauge(kubetypes.MetricPeerRelayCount)
)

// NewReconciler returns a new instance of the Reconciler type. It watches specifically for changes to PeerRelay
// custom resources. The ReconcilerOptions can be used to modify the behaviour of the Reconciler.
func NewReconciler(options ReconcilerOptions) *Reconciler {
	clock := options.Clock
	if clock == nil {
		clock = tstime.DefaultClock{}
	}

	resolver := options.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver.LookupNetIP
	}

	return &Reconciler{
		Client:             options.Client,
		tailscaleNamespace: options.TailscaleNamespace,
		proxyImage:         options.ProxyImage,
		defaultTags:        options.DefaultTags,
		tsClients:          options.Clients,
		resolver:           resolver,
		logger:             options.Logger.Named(reconcilerName),
		clock:              clock,
		tracker:            reconciler.NewResourceTracker(gaugePeerRelayResources),
		reissuer:           tailscaled.NewReissuer(),
	}
}

// Register the Reconciler onto the given manager.Manager implementation. It watches PeerRelay resources directly,
// the child resources it manages (Services, StatefulSets, Secrets) so external drift or cloud controller updates
// enqueue a reconcile for the owning PeerRelay, and ProxyClass so config changes propagate to referring
// PeerRelays.
func (r *Reconciler) Register(mgr manager.Manager) error {
	enqueue := handler.EnqueueRequestsFromMapFunc(reconciler.EnqueueForChild(parentTypePeerRelay))
	return builder.
		ControllerManagedBy(mgr).
		For(&tsapi.PeerRelay{}).
		Watches(&corev1.Service{}, enqueue).
		Watches(&appsv1.StatefulSet{}, enqueue).
		Watches(&corev1.Secret{}, enqueue).
		Watches(&tsapi.ProxyClass{}, handler.EnqueueRequestsFromMapFunc(r.enqueuePeerRelaysForProxyClass)).
		Named(reconcilerName).
		Complete(r)
}

func (r *Reconciler) enqueuePeerRelaysForProxyClass(ctx context.Context, o client.Object) []reconcile.Request {
	pc, ok := o.(*tsapi.ProxyClass)
	if !ok {
		return nil
	}

	var list tsapi.PeerRelayList
	if err := r.List(ctx, &list); err != nil {
		r.logger.Errorf("failed to list PeerRelays for ProxyClass %q change: %v", pc.Name, err)
		return nil
	}

	var reqs []reconcile.Request
	for _, pr := range list.Items {
		if pr.Spec.ProxyClass == pc.Name {
			reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{Name: pr.Name}})
		}
	}
	return reqs
}

// Reconcile is invoked when a change occurs to PeerRelay resources within the cluster. On create/update, it ensures
// one LoadBalancer Service exists per replica. On delete, all managed Services are removed before the finalizer is
// released.
func (r *Reconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	logger := r.logger.With("PeerRelay", req.Name)
	logger.Debug("starting reconcile")
	defer logger.Debug("reconcile finished")

	var pr tsapi.PeerRelay
	err := r.Get(ctx, req.NamespacedName, &pr)
	switch {
	case apierrors.IsNotFound(err):
		logger.Debug("PeerRelay not found, assuming it was deleted")
		return reconcile.Result{}, nil
	case err != nil:
		return reconcile.Result{}, fmt.Errorf("failed to get PeerRelay %q: %w", req.NamespacedName, err)
	}

	if r.tsClients != nil {
		if _, err = r.tsClients.For(pr.Spec.Tailnet); err != nil {
			return r.reportTailnetUnavailable(ctx, logger, &pr, err)
		}
	}

	if !pr.DeletionTimestamp.IsZero() {
		return r.delete(ctx, logger, &pr)
	}

	return r.createOrUpdate(ctx, logger, &pr)
}

func (r *Reconciler) reportTailnetUnavailable(ctx context.Context, logger *zap.SugaredLogger, pr *tsapi.PeerRelay, tsErr error) (reconcile.Result, error) {
	operatorutils.SetPeerRelayCondition(pr, tsapi.PeerRelayReady, metav1.ConditionFalse, ReasonTailnetUnavailable, tsErr.Error(), r.clock, logger)
	if err := r.Status().Update(ctx, pr); err != nil {
		return reconcile.Result{}, errors.Join(tsErr, fmt.Errorf("failed to update PeerRelay status: %w", err))
	}

	return reconcile.Result{}, tsErr
}

func (r *Reconciler) createOrUpdate(ctx context.Context, logger *zap.SugaredLogger, pr *tsapi.PeerRelay) (reconcile.Result, error) {
	if err := reconciler.EnsureFinalizer(ctx, r.Client, pr, reconciler.Finalizer); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to add finalizer to PeerRelay %q: %w", pr.Name, err)
	}

	r.tracker.Add(pr.UID)

	replicas := int32(1)
	if pr.Spec.Replicas != nil {
		replicas = *pr.Spec.Replicas
	}

	r.reissuer.EnsureState(pr.Name, int(replicas))

	// Belt-and-braces: CEL on the CRD enforces this at admission, but we also validate here to guard against older
	// clusters without CEL, resources created before the CRD schema landed, or hand-edited status paths. If the user
	// hasn't supplied enough EIPs for the requested replica count we refuse to touch existing state and surface the
	// condition so they can fix the spec.
	if pr.Spec.AWS != nil && int32(len(pr.Spec.AWS.ElasticIPs)) < replicas {
		message := fmt.Sprintf("spec.aws.elasticIPs has %d entries but spec.replicas is %d", len(pr.Spec.AWS.ElasticIPs), replicas)
		operatorutils.SetPeerRelayCondition(pr, tsapi.PeerRelayReady, metav1.ConditionFalse, ReasonAWSConfigInvalid, message, r.clock, logger)
		if err := r.Status().Update(ctx, pr); err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to update PeerRelay status for %q: %w", pr.Name, err)
		}
		return reconcile.Result{}, nil
	}

	// Belt-and-braces for the same reasons as above: the Pattern on spec.staticEndpoints entries only rejects
	// obvious junk at admission, and Go's netip.ParseAddrPort is the authoritative parser.
	static, err := parseStaticEndpoints(pr)
	if err != nil {
		operatorutils.SetPeerRelayCondition(pr, tsapi.PeerRelayReady, metav1.ConditionFalse, ReasonStaticEndpointsInvalid, err.Error(), r.clock, logger)
		if err := r.Status().Update(ctx, pr); err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to update PeerRelay status for %q: %w", pr.Name, err)
		}
		return reconcile.Result{}, nil
	}

	for i := int32(0); i < replicas; i++ {
		desired := r.peerRelayService(pr, i)
		if err := r.ensureService(ctx, logger, desired); err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to apply Service %q: %w", desired.Name, err)
		}
	}

	// Read the LB addresses assigned by the cloud so each pod's config file can advertise its own public endpoint
	// via RelayServerStaticEndpoints. On first reconcile the LBs aren't provisioned yet, so each replica only has
	// the spec.staticEndpoints entries, if any; the Watches-triggered reconcile that fires when the LB IP lands
	// will fill in the rest.
	endpoints, err := r.readEndpoints(ctx, logger, pr, replicas, static)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to read endpoints for PeerRelay %q: %w", pr.Name, err)
	}

	endpointsByReplica := make(map[int32][]tsapi.PeerRelayEndpoint, len(endpoints))
	for _, ep := range endpoints {
		endpointsByReplica[ep.Replica] = append(endpointsByReplica[ep.Replica], ep)
	}

	for i := int32(0); i < replicas; i++ {
		if err = r.ensureStateSecret(ctx, logger, pr, i); err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to apply state Secret for PeerRelay %q replica %d: %w", pr.Name, i, err)
		}

		if err = r.ensureConfigSecret(ctx, logger, pr, i, endpointsByReplica[i]); err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to apply config Secret for PeerRelay %q replica %d: %w", pr.Name, i, err)
		}
	}

	ss, err := r.ensureStatefulSet(ctx, logger, pr, replicas)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to apply StatefulSet for PeerRelay %q: %w", pr.Name, err)
	}

	if err = r.deleteDevicesFrom(ctx, logger, pr, replicas); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to clean up scaled-down tailnet devices for PeerRelay %q: %w", pr.Name, err)
	}

	if err = r.deleteServicesFrom(ctx, logger, pr, replicas); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to clean up scaled-down Services for PeerRelay %q: %w", pr.Name, err)
	}

	if err = r.deleteConfigSecretsFrom(ctx, logger, pr, replicas); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to clean up scaled-down config Secrets for PeerRelay %q: %w", pr.Name, err)
	}

	if err = r.writeStatus(ctx, logger, pr, endpoints, replicas, ss); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to update PeerRelay status for %q: %w", pr.Name, err)
	}

	if !peerRelayReady(pr) {
		return reconcile.Result{RequeueAfter: 30 * time.Second}, nil
	}

	return reconcile.Result{}, nil
}

func peerRelayReady(pr *tsapi.PeerRelay) bool {
	for _, c := range pr.Status.Conditions {
		if c.Type == string(tsapi.PeerRelayReady) {
			return c.Status == metav1.ConditionTrue
		}
	}

	return false
}

func (r *Reconciler) readEndpoints(ctx context.Context, logger *zap.SugaredLogger, pr *tsapi.PeerRelay, replicas int32, static []netip.AddrPort) ([]tsapi.PeerRelayEndpoint, error) {
	var list corev1.ServiceList
	if err := r.List(ctx, &list, client.InNamespace(r.tailscaleNamespace), client.MatchingLabels(peerRelayLabels(pr.Name))); err != nil {
		return nil, fmt.Errorf("failed to list Services: %w", err)
	}

	prevByReplica := make(map[int32][]tsapi.PeerRelayEndpoint, len(pr.Status.Endpoints))
	for _, ep := range pr.Status.Endpoints {
		prevByReplica[ep.Replica] = append(prevByReplica[ep.Replica], ep)
	}

	port := int32(peerRelayPort(pr))

	var endpoints []tsapi.PeerRelayEndpoint
	for i := range list.Items {
		svc := &list.Items[i]
		var prev []tsapi.PeerRelayEndpoint
		if idx, ok := replicaIndexFromLabels(svc.Labels); ok {
			prev = prevByReplica[idx]
		}

		endpoints = append(endpoints, r.peerRelayEndpoints(ctx, logger, svc, prev, port)...)
	}

	endpoints = mergeStaticEndpoints(endpoints, replicas, static)

	// Sorted by replica then address so the list is stable across reconciles, which keeps status updates and the
	// resulting tailscaled config free of spurious churn. status.endpoints is keyed on both fields, so the pair
	// is unique.
	slices.SortFunc(endpoints, func(a, b tsapi.PeerRelayEndpoint) int {
		if c := cmp.Compare(a.Replica, b.Replica); c != 0 {
			return c
		}
		return cmp.Compare(a.Address, b.Address)
	})

	return endpoints, nil
}

// parseStaticEndpoints parses spec.staticEndpoints into netip.AddrPort values. The CRD's Pattern on the AddrPort
// type only rejects obvious junk at admission; this is the authoritative parse.
func parseStaticEndpoints(pr *tsapi.PeerRelay) ([]netip.AddrPort, error) {
	var static []netip.AddrPort
	seen := make(map[netip.Addr]int, len(pr.Spec.StaticEndpoints))
	for i, s := range pr.Spec.StaticEndpoints {
		ap, err := netip.ParseAddrPort(s)
		if err != nil {
			return nil, fmt.Errorf("spec.staticEndpoints[%d]: %q is not a valid address:port: %w", i, s, err)
		}
		if ap.Addr().Zone() != "" {
			return nil, fmt.Errorf("spec.staticEndpoints[%d]: %q must not carry an IPv6 zone", i, s)
		}
		if ap.Port() == 0 {
			return nil, fmt.Errorf("spec.staticEndpoints[%d]: %q must not use port 0", i, s)
		}
		// status.endpoints allows an address only once per replica, so a second entry for the same address
		// would silently overwrite the first's port. Reject it so the user picks one.
		if j, ok := seen[ap.Addr()]; ok {
			return nil, fmt.Errorf("spec.staticEndpoints[%d]: %q repeats the address of spec.staticEndpoints[%d]", i, s, j)
		}
		seen[ap.Addr()] = i
		static = append(static, ap)
	}
	return static, nil
}

// mergeStaticEndpoints adds the spec.staticEndpoints entries to every replica's endpoint list. status.endpoints is
// a map list keyed on (replica, address), so an address may appear only once per replica: when a static endpoint
// names an address the replica's load balancer already provides, the static entry's port wins, since it is a
// deliberate user statement (e.g. an external DNAT rewrites the port). The merge is idempotent, which matters
// because the endpoints derived from a Service fall back to the previously published, already merged status
// entries when a hostname lookup fails.
func mergeStaticEndpoints(endpoints []tsapi.PeerRelayEndpoint, replicas int32, static []netip.AddrPort) []tsapi.PeerRelayEndpoint {
	for i := range replicas {
		for _, ap := range static {
			endpoints = mergeEndpoint(endpoints, tsapi.PeerRelayEndpoint{
				Replica: i,
				Address: ap.Addr().String(),
				Port:    int32(ap.Port()),
			})
		}
	}
	return endpoints
}

// mergeEndpoint appends ep to endpoints, or overwrites the port of an existing entry with the same replica and
// address. Addresses are compared as IPs when both parse, so a non-canonical form from the cloud still matches,
// and as strings otherwise.
func mergeEndpoint(endpoints []tsapi.PeerRelayEndpoint, ep tsapi.PeerRelayEndpoint) []tsapi.PeerRelayEndpoint {
	addr, err := netip.ParseAddr(ep.Address)
	idx := slices.IndexFunc(endpoints, func(other tsapi.PeerRelayEndpoint) bool {
		if other.Replica != ep.Replica {
			return false
		}
		if other.Address == ep.Address {
			return true
		}
		if err != nil {
			return false
		}

		otherAddr, otherErr := netip.ParseAddr(other.Address)
		return otherErr == nil && otherAddr == addr
	})

	if idx < 0 {
		return append(endpoints, ep)
	}

	endpoints[idx].Port = ep.Port
	return endpoints
}

func (r *Reconciler) writeStatus(ctx context.Context, logger *zap.SugaredLogger, pr *tsapi.PeerRelay, endpoints []tsapi.PeerRelayEndpoint, replicas int32, ss *appsv1.StatefulSet) error {
	prevStatus := pr.Status.DeepCopy()

	pr.Status.Endpoints = endpoints

	var readyReplicas int32
	if ss != nil {
		readyReplicas = ss.Status.ReadyReplicas
	}

	addressed := make(map[int32]struct{}, len(endpoints))
	for _, ep := range endpoints {
		addressed[ep.Replica] = struct{}{}
	}

	switch {
	case int32(len(addressed)) < replicas:
		message := fmt.Sprintf("%d of %d replicas have an endpoint", len(addressed), replicas)
		operatorutils.SetPeerRelayCondition(pr, tsapi.PeerRelayReady, metav1.ConditionFalse, ReasonEndpointsPending, message, r.clock, logger)
	case readyReplicas < replicas:
		message := fmt.Sprintf("%d of %d pods are ready", readyReplicas, replicas)
		operatorutils.SetPeerRelayCondition(pr, tsapi.PeerRelayReady, metav1.ConditionFalse, ReasonPodsPending, message, r.clock, logger)
	default:
		operatorutils.SetPeerRelayCondition(pr, tsapi.PeerRelayReady, metav1.ConditionTrue, ReasonReady, ReasonReady, r.clock, logger)
	}

	if reflect.DeepEqual(prevStatus, &pr.Status) {
		return nil
	}

	if err := r.Status().Update(ctx, pr); err != nil {
		return fmt.Errorf("failed to update PeerRelay status: %w", err)
	}

	return nil
}

func (r *Reconciler) delete(ctx context.Context, logger *zap.SugaredLogger, pr *tsapi.PeerRelay) (reconcile.Result, error) {
	logger.Infof("deleting PeerRelay %q", pr.Name)

	if err := r.deleteDevicesFrom(ctx, logger, pr, 0); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to delete tailnet devices for PeerRelay %q: %w", pr.Name, err)
	}

	if err := r.deleteStatefulSet(ctx, logger, pr); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to delete StatefulSet for PeerRelay %q: %w", pr.Name, err)
	}

	if err := r.deleteConfigSecretsFrom(ctx, logger, pr, 0); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to delete config Secrets for PeerRelay %q: %w", pr.Name, err)
	}

	if err := r.deleteServicesFrom(ctx, logger, pr, 0); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to delete Services for PeerRelay %q: %w", pr.Name, err)
	}

	if err := reconciler.ClearFinalizer(ctx, r.Client, pr, reconciler.Finalizer); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to remove finalizer from PeerRelay %q: %w", pr.Name, err)
	}

	r.tracker.Remove(pr.UID)
	r.reissuer.RemoveState(pr.Name)

	return reconcile.Result{}, nil
}

func (r *Reconciler) ensureService(ctx context.Context, logger *zap.SugaredLogger, desired *corev1.Service) error {
	logger.Debugf("applying Service %q", desired.Name)
	if err := r.Patch(ctx, desired, client.Apply, fieldOwner, client.ForceOwnership); err != nil {
		return fmt.Errorf("failed to apply Service: %w", err)
	}
	return nil
}

func (r *Reconciler) deleteServicesFrom(ctx context.Context, logger *zap.SugaredLogger, pr *tsapi.PeerRelay, fromIdx int32) error {
	var list corev1.ServiceList
	if err := r.List(ctx, &list, client.InNamespace(r.tailscaleNamespace), client.MatchingLabels(peerRelayLabels(pr.Name))); err != nil {
		return fmt.Errorf("failed to list Services: %w", err)
	}

	for i := range list.Items {
		svc := &list.Items[i]
		idx, ok := replicaIndexFromLabels(svc.Labels)
		if !ok || idx < fromIdx {
			continue
		}

		logger.Debugf("deleting Service %q", svc.Name)
		if err := r.Delete(ctx, svc); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete Service %q: %w", svc.Name, err)
		}
	}

	return nil
}

func (r *Reconciler) ensureConfigSecret(ctx context.Context, logger *zap.SugaredLogger, pr *tsapi.PeerRelay, idx int32, endpoints []tsapi.PeerRelayEndpoint) error {
	tsClient, err := r.tsClients.For(pr.Spec.Tailnet)
	if err != nil {
		return fmt.Errorf("failed to resolve Tailscale API client for tailnet %q: %w", pr.Spec.Tailnet, err)
	}

	authKey, err := r.getAuthKey(ctx, tsClient, pr, idx)
	if err != nil {
		return err
	}

	desired, err := r.peerRelayConfigSecret(pr, idx, endpoints, authKey, tsClient.LoginURL())
	if err != nil {
		return fmt.Errorf("failed to build config Secret: %w", err)
	}

	logger.Debugf("applying config Secret %q", desired.Name)
	if err = r.Patch(ctx, desired, client.Apply, fieldOwner, client.ForceOwnership); err != nil {
		return fmt.Errorf("failed to apply config Secret: %w", err)
	}

	return nil
}

func (r *Reconciler) ensureStateSecret(ctx context.Context, logger *zap.SugaredLogger, pr *tsapi.PeerRelay, idx int32) error {
	desired := tailscaled.NewStateSecret(tailscaled.StateSecretOptions{
		Name:      replicaName(pr.Name, idx),
		Namespace: r.tailscaleNamespace,
		Labels:    peerRelayServiceLabels(pr.Name, idx),
	})

	logger.Debugf("applying state Secret %q", desired.Name)
	if err := r.Patch(ctx, desired, client.Apply, fieldOwner, client.ForceOwnership); err != nil {
		return fmt.Errorf("failed to apply state Secret: %w", err)
	}

	return nil
}

func (r *Reconciler) deleteConfigSecretsFrom(ctx context.Context, logger *zap.SugaredLogger, pr *tsapi.PeerRelay, fromIdx int32) error {
	labels := peerRelayLabels(pr.Name)
	labels[kubetypes.LabelSecretType] = kubetypes.LabelSecretTypeConfig

	var list corev1.SecretList
	if err := r.List(ctx, &list, client.InNamespace(r.tailscaleNamespace), client.MatchingLabels(labels)); err != nil {
		return fmt.Errorf("failed to list config Secrets: %w", err)
	}

	for i := range list.Items {
		secret := &list.Items[i]
		idx, ok := replicaIndexFromLabels(secret.Labels)
		if !ok || idx < fromIdx {
			continue
		}

		logger.Debugf("deleting config Secret %q", secret.Name)
		if err := r.Delete(ctx, secret); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete config Secret %q: %w", secret.Name, err)
		}
	}

	return nil
}

func (r *Reconciler) ensureStatefulSet(ctx context.Context, logger *zap.SugaredLogger, pr *tsapi.PeerRelay, replicas int32) (*appsv1.StatefulSet, error) {
	pc, err := r.getProxyClass(ctx, pr)
	if err != nil {
		return nil, err
	}

	desired := r.peerRelayStatefulSet(pr, replicas, pc)

	logger.Debugf("applying StatefulSet %q", desired.Name)
	if err = r.Patch(ctx, desired, client.Apply, fieldOwner, client.ForceOwnership); err != nil {
		return nil, fmt.Errorf("failed to apply StatefulSet: %w", err)
	}

	var current appsv1.StatefulSet
	if err = r.Get(ctx, types.NamespacedName{Namespace: desired.Namespace, Name: desired.Name}, &current); err != nil {
		return nil, fmt.Errorf("failed to get StatefulSet: %w", err)
	}

	return &current, nil
}

func (r *Reconciler) deleteStatefulSet(ctx context.Context, logger *zap.SugaredLogger, pr *tsapi.PeerRelay) error {
	ss := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: resourceName(pr.Name), Namespace: r.tailscaleNamespace},
	}
	logger.Debugf("deleting StatefulSet %q", ss.Name)
	if err := r.Delete(ctx, ss); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to delete StatefulSet: %w", err)
	}
	return nil
}
