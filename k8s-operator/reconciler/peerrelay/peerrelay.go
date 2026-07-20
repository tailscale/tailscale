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
	"sync"
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
	"tailscale.com/util/set"
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

		// Metrics related fields
		mu         sync.Mutex
		peerRelays set.Slice[types.UID]
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
	ReasonEndpointsPending   = "EndpointsPending"
	ReasonPodsPending        = "PodsPending"
	ReasonAWSConfigInvalid   = "AWSConfigInvalid"
	ReasonTailnetUnavailable = "TailnetUnavailable"
	ReasonReady              = "PeerRelayReady"
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
	if !slices.Contains(pr.Finalizers, reconciler.FinalizerName) {
		reconciler.SetFinalizer(pr)
		if err := r.Update(ctx, pr); err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to add finalizer to PeerRelay %q: %w", pr.Name, err)
		}
	}

	r.mu.Lock()
	if !r.peerRelays.Contains(pr.UID) {
		r.peerRelays.Add(pr.UID)
		logger.Infof("now managing PeerRelay %q", pr.Name)
	}
	r.mu.Unlock()
	gaugePeerRelayResources.Set(int64(r.peerRelays.Len()))

	replicas := int32(1)
	if pr.Spec.Replicas != nil {
		replicas = *pr.Spec.Replicas
	}

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

	for i := int32(0); i < replicas; i++ {
		desired := r.peerRelayService(pr, i)
		if err := r.ensureService(ctx, logger, desired); err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to apply Service %q: %w", desired.Name, err)
		}
	}

	// Read the LB addresses assigned by the cloud so each pod's config file can advertise its own public endpoint
	// via RelayServerStaticEndpoints. On first reconcile the LBs aren't provisioned yet , endpointsByReplica ends
	// up empty and the configs are written without static endpoints; the Watches-triggered reconcile that fires
	// when the LB IP lands will fill them in.
	endpoints, err := r.readEndpoints(ctx, logger, pr)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to read endpoints for PeerRelay %q: %w", pr.Name, err)
	}

	endpointsByReplica := make(map[int32]tsapi.PeerRelayEndpoint, len(endpoints))
	for _, ep := range endpoints {
		endpointsByReplica[ep.Replica] = ep
	}

	for i := int32(0); i < replicas; i++ {
		var endpoint *tsapi.PeerRelayEndpoint
		if ep, ok := endpointsByReplica[i]; ok {
			endpoint = &ep
		}

		if err = r.ensureStateSecret(ctx, logger, pr, i); err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to apply state Secret for PeerRelay %q replica %d: %w", pr.Name, i, err)
		}

		if err = r.ensureConfigSecret(ctx, logger, pr, i, endpoint); err != nil {
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

func (r *Reconciler) readEndpoints(ctx context.Context, logger *zap.SugaredLogger, pr *tsapi.PeerRelay) ([]tsapi.PeerRelayEndpoint, error) {
	var list corev1.ServiceList
	if err := r.List(ctx, &list, client.InNamespace(r.tailscaleNamespace), client.MatchingLabels(peerRelayLabels(pr.Name))); err != nil {
		return nil, fmt.Errorf("failed to list Services: %w", err)
	}

	prevByReplica := make(map[int32]tsapi.PeerRelayEndpoint, len(pr.Status.Endpoints))
	for _, ep := range pr.Status.Endpoints {
		prevByReplica[ep.Replica] = ep
	}

	var endpoints []tsapi.PeerRelayEndpoint
	for i := range list.Items {
		svc := &list.Items[i]
		var prev *tsapi.PeerRelayEndpoint
		if idx, ok := replicaIndexFromLabels(svc.Labels); ok {
			if ep, ok := prevByReplica[idx]; ok {
				prev = &ep
			}
		}

		if endpoint := r.peerRelayEndpoint(ctx, logger, svc, prev); endpoint != nil {
			endpoints = append(endpoints, *endpoint)
		}
	}

	slices.SortFunc(endpoints, func(a, b tsapi.PeerRelayEndpoint) int {
		return cmp.Compare(a.Replica, b.Replica)
	})

	return endpoints, nil
}

func (r *Reconciler) writeStatus(ctx context.Context, logger *zap.SugaredLogger, pr *tsapi.PeerRelay, endpoints []tsapi.PeerRelayEndpoint, replicas int32, ss *appsv1.StatefulSet) error {
	prevStatus := pr.Status.DeepCopy()

	pr.Status.Endpoints = endpoints

	var readyReplicas int32
	if ss != nil {
		readyReplicas = ss.Status.ReadyReplicas
	}

	switch {
	case int32(len(endpoints)) < replicas:
		message := fmt.Sprintf("%d of %d replicas have a public IP", len(endpoints), replicas)
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

	reconciler.RemoveFinalizer(pr)
	if err := r.Update(ctx, pr); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to remove finalizer from PeerRelay %q: %w", pr.Name, err)
	}

	r.mu.Lock()
	r.peerRelays.Remove(pr.UID)
	r.mu.Unlock()
	gaugePeerRelayResources.Set(int64(r.peerRelays.Len()))

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

func (r *Reconciler) ensureConfigSecret(ctx context.Context, logger *zap.SugaredLogger, pr *tsapi.PeerRelay, idx int32, endpoint *tsapi.PeerRelayEndpoint) error {
	authKey, err := r.reuseOrMintAuthKey(ctx, pr, idx)
	if err != nil {
		return err
	}

	desired, err := r.peerRelayConfigSecret(pr, idx, endpoint, authKey)
	if err != nil {
		return fmt.Errorf("failed to build config Secret: %w", err)
	}

	logger.Debugf("applying config Secret %q", desired.Name)
	if err = r.Patch(ctx, desired, client.Apply, fieldOwner, client.ForceOwnership); err != nil {
		return fmt.Errorf("failed to apply config Secret: %w", err)
	}

	return nil
}

func (r *Reconciler) reuseOrMintAuthKey(ctx context.Context, pr *tsapi.PeerRelay, idx int32) (*string, error) {
	var existing corev1.Secret
	err := r.Get(ctx, types.NamespacedName{Namespace: r.tailscaleNamespace, Name: configSecretName(pr.Name, idx)}, &existing)
	switch {
	case apierrors.IsNotFound(err):
		key, err := r.mintAuthKey(ctx, pr)
		if err != nil {
			return nil, err
		}
		return &key, nil
	case err != nil:
		return nil, fmt.Errorf("failed to get config Secret: %w", err)
	}

	if existingKey := tailscaled.AuthKeyFromConfigSecret(&existing); existingKey != nil {
		return existingKey, nil
	}

	key, err := r.mintAuthKey(ctx, pr)
	if err != nil {
		return nil, err
	}

	return &key, nil
}

func (r *Reconciler) mintAuthKey(ctx context.Context, pr *tsapi.PeerRelay) (string, error) {
	client, err := r.tsClients.For(pr.Spec.Tailnet)
	if err != nil {
		return "", fmt.Errorf("failed to resolve Tailscale API client for tailnet %q: %w", pr.Spec.Tailnet, err)
	}

	return tailscaled.NewAuthKey(ctx, client, r.peerRelayTags(pr))
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
