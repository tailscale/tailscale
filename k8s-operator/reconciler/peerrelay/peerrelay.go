// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package peerrelay provides reconciliation logic for the PeerRelay custom resource definition. It is responsible
// for managing the lifecycle of PeerRelay devices, including the StatefulSet and Service resources used to expose
// them.
package peerrelay

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"

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
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tstime"
)

type (
	// The Reconciler type is a reconcile.TypedReconciler implementation used to manage the reconciliation of
	// PeerRelay custom resources.
	Reconciler struct {
		client.Client

		tailscaleNamespace string
		proxyImage         string
		defaultTags        []string
		tsClients          ClientProvider
		logger             *zap.SugaredLogger
		clock              tstime.Clock
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
		Clients ClientProvider
		// The logger to use for this Reconciler.
		Logger *zap.SugaredLogger
		// Clock is used to stamp condition transitions. Defaults to a real clock when unset.
		Clock tstime.Clock
	}
)

const reconcilerName = "peerrelay-reconciler"

// Constants for condition reasons.
const (
	ReasonEndpointsInvalid = "EndpointsInvalid"
	ReasonEndpointsPending = "EndpointsPending"
	ReasonPodsPending      = "PodsPending"
	ReasonReady            = "PeerRelayReady"
)

// NewReconciler returns a new instance of the Reconciler type. It watches specifically for changes to PeerRelay
// custom resources. The ReconcilerOptions can be used to modify the behaviour of the Reconciler.
func NewReconciler(options ReconcilerOptions) *Reconciler {
	clock := options.Clock
	if clock == nil {
		clock = tstime.DefaultClock{}
	}

	return &Reconciler{
		Client:             options.Client,
		tailscaleNamespace: options.TailscaleNamespace,
		proxyImage:         options.ProxyImage,
		defaultTags:        options.DefaultTags,
		tsClients:          options.Clients,
		logger:             options.Logger.Named(reconcilerName),
		clock:              clock,
	}
}

// Register the Reconciler onto the given manager.Manager implementation. It watches PeerRelay resources directly
// and also watches the child resources it manages (Services, StatefulSets, Secrets) so external drift or cloud
// controller updates enqueue a reconcile for the owning PeerRelay.
func (r *Reconciler) Register(mgr manager.Manager) error {
	enqueue := handler.EnqueueRequestsFromMapFunc(enqueuePeerRelayForChild)
	return builder.
		ControllerManagedBy(mgr).
		For(&tsapi.PeerRelay{}).
		Watches(&corev1.Service{}, enqueue).
		Watches(&appsv1.StatefulSet{}, enqueue).
		Watches(&corev1.Secret{}, enqueue).
		Named(reconcilerName).
		Complete(r)
}

func enqueuePeerRelayForChild(_ context.Context, o client.Object) []reconcile.Request {
	labels := o.GetLabels()
	if labels[kubetypes.LabelManaged] != "true" || labels[labelParentType] != parentTypePeerRelay {
		return nil
	}

	name := labels[labelParentName]
	if name == "" {
		return nil
	}

	return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: name}}}
}

// Reconcile is invoked when a change occurs to PeerRelay resources within the cluster. On create/update, it ensures
// one LoadBalancer Service exists per replica. On delete, all managed Services are removed before the finalizer is
// released.
func (r *Reconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	var pr tsapi.PeerRelay
	err := r.Get(ctx, req.NamespacedName, &pr)
	switch {
	case apierrors.IsNotFound(err):
		return reconcile.Result{}, nil
	case err != nil:
		return reconcile.Result{}, fmt.Errorf("failed to get PeerRelay %q: %w", req.NamespacedName, err)
	}

	if !pr.DeletionTimestamp.IsZero() {
		return r.delete(ctx, &pr)
	}

	return r.createOrUpdate(ctx, &pr)
}

func (r *Reconciler) createOrUpdate(ctx context.Context, pr *tsapi.PeerRelay) (reconcile.Result, error) {
	if !slices.Contains(pr.Finalizers, reconciler.FinalizerName) {
		reconciler.SetFinalizer(pr)
		if err := r.Update(ctx, pr); err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to add finalizer to PeerRelay %q: %w", pr.Name, err)
		}
	}

	replicas := int32(1)
	if pr.Spec.Replicas != nil {
		replicas = *pr.Spec.Replicas
	}

	for i := int32(0); i < replicas; i++ {
		desired := r.peerRelayService(pr, i)
		if err := r.ensureService(ctx, desired); err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to apply Service %q: %w", desired.Name, err)
		}
	}

	// Read the LB addresses assigned by the cloud so each pod's config file can advertise its own public endpoint
	// via RelayServerStaticEndpoints. On first reconcile the LBs aren't provisioned yet — endpointsByReplica ends
	// up empty and the configs are written without static endpoints; the Watches-triggered reconcile that fires
	// when the LB IP lands will fill them in.
	endpoints, endpointErrs, err := r.readEndpoints(ctx, pr)
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

		if err := r.ensureConfigSecret(ctx, pr, i, endpoint); err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to apply config Secret for PeerRelay %q replica %d: %w", pr.Name, i, err)
		}
	}

	ss, err := r.ensureStatefulSet(ctx, pr, replicas)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to apply StatefulSet for PeerRelay %q: %w", pr.Name, err)
	}

	if err := r.deleteServicesFrom(ctx, pr, replicas); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to clean up scaled-down Services for PeerRelay %q: %w", pr.Name, err)
	}

	if err := r.deleteConfigSecretsFrom(ctx, pr, replicas); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to clean up scaled-down config Secrets for PeerRelay %q: %w", pr.Name, err)
	}

	if err := r.writeStatus(ctx, pr, endpoints, endpointErrs, replicas, ss); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to update PeerRelay status for %q: %w", pr.Name, err)
	}

	return reconcile.Result{}, nil
}

func (r *Reconciler) readEndpoints(ctx context.Context, pr *tsapi.PeerRelay) ([]tsapi.PeerRelayEndpoint, []error, error) {
	var list corev1.ServiceList
	if err := r.List(ctx, &list, client.InNamespace(r.tailscaleNamespace), client.MatchingLabels(peerRelayLabels(pr.Name))); err != nil {
		return nil, nil, fmt.Errorf("failed to list Services: %w", err)
	}

	var (
		endpoints []tsapi.PeerRelayEndpoint
		errs      []error
	)
	for i := range list.Items {
		endpoint, err := peerRelayEndpoint(&list.Items[i])
		if err != nil {
			errs = append(errs, err)
			continue
		}

		if endpoint != nil {
			endpoints = append(endpoints, *endpoint)
		}
	}

	slices.SortFunc(endpoints, func(a, b tsapi.PeerRelayEndpoint) int {
		return cmp.Compare(a.Replica, b.Replica)
	})

	return endpoints, errs, nil
}

func (r *Reconciler) writeStatus(ctx context.Context, pr *tsapi.PeerRelay, endpoints []tsapi.PeerRelayEndpoint, errs []error, replicas int32, ss *appsv1.StatefulSet) error {
	prevStatus := pr.Status.DeepCopy()

	pr.Status.Endpoints = endpoints
	joined := errors.Join(errs...)

	var readyReplicas int32
	if ss != nil {
		readyReplicas = ss.Status.ReadyReplicas
	}

	switch {
	case len(errs) > 0:
		operatorutils.SetPeerRelayCondition(pr, tsapi.PeerRelayReady, metav1.ConditionFalse, ReasonEndpointsInvalid, joined.Error(), r.clock, r.logger)
	case int32(len(endpoints)) < replicas:
		message := fmt.Sprintf("%d of %d replicas have a public IP", len(endpoints), replicas)
		operatorutils.SetPeerRelayCondition(pr, tsapi.PeerRelayReady, metav1.ConditionFalse, ReasonEndpointsPending, message, r.clock, r.logger)
	case readyReplicas < replicas:
		message := fmt.Sprintf("%d of %d pods are ready", readyReplicas, replicas)
		operatorutils.SetPeerRelayCondition(pr, tsapi.PeerRelayReady, metav1.ConditionFalse, ReasonPodsPending, message, r.clock, r.logger)
	default:
		operatorutils.SetPeerRelayCondition(pr, tsapi.PeerRelayReady, metav1.ConditionTrue, ReasonReady, ReasonReady, r.clock, r.logger)
	}

	if reflect.DeepEqual(prevStatus, &pr.Status) {
		return joined
	}

	if err := r.Status().Update(ctx, pr); err != nil {
		return fmt.Errorf("failed to update PeerRelay status: %w", err)
	}

	return joined
}

func (r *Reconciler) delete(ctx context.Context, pr *tsapi.PeerRelay) (reconcile.Result, error) {
	if err := r.deleteStatefulSet(ctx, pr); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to delete StatefulSet for PeerRelay %q: %w", pr.Name, err)
	}

	if err := r.deleteConfigSecretsFrom(ctx, pr, 0); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to delete config Secrets for PeerRelay %q: %w", pr.Name, err)
	}

	if err := r.deleteServicesFrom(ctx, pr, 0); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to delete Services for PeerRelay %q: %w", pr.Name, err)
	}

	reconciler.RemoveFinalizer(pr)
	if err := r.Update(ctx, pr); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to remove finalizer from PeerRelay %q: %w", pr.Name, err)
	}

	return reconcile.Result{}, nil
}

func (r *Reconciler) ensureService(ctx context.Context, desired *corev1.Service) error {
	var existing corev1.Service
	err := r.Get(ctx, types.NamespacedName{Namespace: desired.Namespace, Name: desired.Name}, &existing)
	switch {
	case apierrors.IsNotFound(err):
		if err = r.Create(ctx, desired); err != nil {
			return fmt.Errorf("failed to create Service: %w", err)
		}

		return nil
	case err != nil:
		return fmt.Errorf("failed to get Service: %w", err)
	}

	updated := existing.DeepCopy()
	if updated.Labels == nil && len(desired.Labels) > 0 {
		updated.Labels = make(map[string]string, len(desired.Labels))
	}
	for k, v := range desired.Labels {
		updated.Labels[k] = v
	}

	if updated.Annotations == nil && len(desired.Annotations) > 0 {
		updated.Annotations = make(map[string]string, len(desired.Annotations))
	}
	for k, v := range desired.Annotations {
		updated.Annotations[k] = v
	}

	updated.Spec.Type = desired.Spec.Type
	updated.Spec.Selector = desired.Spec.Selector
	updated.Spec.Ports = desired.Spec.Ports

	if maps.Equal(existing.Labels, updated.Labels) &&
		maps.Equal(existing.Annotations, updated.Annotations) &&
		existing.Spec.Type == updated.Spec.Type &&
		maps.Equal(existing.Spec.Selector, updated.Spec.Selector) &&
		portsMatch(existing.Spec.Ports, updated.Spec.Ports) {
		return nil
	}

	if err = r.Update(ctx, updated); err != nil {
		return fmt.Errorf("failed to update Service: %w", err)
	}

	return nil
}

func (r *Reconciler) deleteServicesFrom(ctx context.Context, pr *tsapi.PeerRelay, fromIdx int32) error {
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

		if err := r.Delete(ctx, svc); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete Service %q: %w", svc.Name, err)
		}
	}

	return nil
}

func (r *Reconciler) ensureConfigSecret(ctx context.Context, pr *tsapi.PeerRelay, idx int32, endpoint *tsapi.PeerRelayEndpoint) error {
	var existing corev1.Secret
	err := r.Get(ctx, types.NamespacedName{Namespace: r.tailscaleNamespace, Name: configSecretName(pr.Name, idx)}, &existing)
	switch {
	case apierrors.IsNotFound(err):
		key, err := r.mintAuthKey(ctx, pr)
		if err != nil {
			return err
		}

		desired, err := r.peerRelayConfigSecret(pr, idx, endpoint, &key)
		if err != nil {
			return fmt.Errorf("failed to build config Secret: %w", err)
		}

		if err := r.Create(ctx, desired); err != nil {
			return fmt.Errorf("failed to create config Secret: %w", err)
		}

		return nil
	case err != nil:
		return fmt.Errorf("failed to get config Secret: %w", err)
	}

	desired, err := r.peerRelayConfigSecret(pr, idx, endpoint, authKeyFromConfigSecret(&existing))
	if err != nil {
		return fmt.Errorf("failed to build config Secret: %w", err)
	}

	updated := existing.DeepCopy()
	if updated.Labels == nil && len(desired.Labels) > 0 {
		updated.Labels = make(map[string]string, len(desired.Labels))
	}

	for k, v := range desired.Labels {
		updated.Labels[k] = v
	}

	updated.Data = desired.Data

	if maps.Equal(existing.Labels, updated.Labels) &&
		maps.EqualFunc(existing.Data, updated.Data, bytes.Equal) {
		return nil
	}

	if err = r.Update(ctx, updated); err != nil {
		return fmt.Errorf("failed to update config Secret: %w", err)
	}

	return nil
}

func (r *Reconciler) mintAuthKey(ctx context.Context, pr *tsapi.PeerRelay) (string, error) {
	client, err := r.tsClients.For(pr.Spec.Tailnet)
	if err != nil {
		return "", fmt.Errorf("failed to resolve Tailscale API client for tailnet %q: %w", pr.Spec.Tailnet, err)
	}

	return newAuthKey(ctx, client, r.peerRelayTags(pr))
}

func (r *Reconciler) deleteConfigSecretsFrom(ctx context.Context, pr *tsapi.PeerRelay, fromIdx int32) error {
	var list corev1.SecretList
	if err := r.List(ctx, &list, client.InNamespace(r.tailscaleNamespace), client.MatchingLabels(peerRelayLabels(pr.Name))); err != nil {
		return fmt.Errorf("failed to list config Secrets: %w", err)
	}

	for i := range list.Items {
		secret := &list.Items[i]
		idx, ok := replicaIndexFromLabels(secret.Labels)
		if !ok || idx < fromIdx {
			continue
		}

		if err := r.Delete(ctx, secret); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete config Secret %q: %w", secret.Name, err)
		}
	}

	return nil
}

// ensureStatefulSet creates or reconciles the StatefulSet backing pr and returns its current in-cluster state.
// The returned StatefulSet's Status is what the API server most recently reported (ReadyReplicas etc.), which
// writeStatus uses to decide whether the PeerRelay is Ready.
func (r *Reconciler) ensureStatefulSet(ctx context.Context, pr *tsapi.PeerRelay, replicas int32) (*appsv1.StatefulSet, error) {
	desired := r.peerRelayStatefulSet(pr, replicas)

	var existing appsv1.StatefulSet
	err := r.Get(ctx, types.NamespacedName{Namespace: desired.Namespace, Name: desired.Name}, &existing)
	switch {
	case apierrors.IsNotFound(err):
		if err = r.Create(ctx, desired); err != nil {
			return nil, fmt.Errorf("failed to create StatefulSet: %w", err)
		}

		return desired, nil
	case err != nil:
		return nil, fmt.Errorf("failed to get StatefulSet: %w", err)
	}

	updated := existing.DeepCopy()
	if updated.Labels == nil && len(desired.Labels) > 0 {
		updated.Labels = make(map[string]string, len(desired.Labels))
	}
	for k, v := range desired.Labels {
		updated.Labels[k] = v
	}

	updated.Spec.Replicas = desired.Spec.Replicas
	updated.Spec.Selector = desired.Spec.Selector
	updated.Spec.Template = desired.Spec.Template

	if maps.Equal(existing.Labels, updated.Labels) &&
		reflect.DeepEqual(existing.Spec.Replicas, updated.Spec.Replicas) &&
		reflect.DeepEqual(existing.Spec.Selector, updated.Spec.Selector) &&
		reflect.DeepEqual(existing.Spec.Template, updated.Spec.Template) {
		return &existing, nil
	}

	if err = r.Update(ctx, updated); err != nil {
		return nil, fmt.Errorf("failed to update StatefulSet: %w", err)
	}

	return updated, nil
}

func (r *Reconciler) deleteStatefulSet(ctx context.Context, pr *tsapi.PeerRelay) error {
	ss := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: pr.Name, Namespace: r.tailscaleNamespace},
	}
	if err := r.Delete(ctx, ss); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to delete StatefulSet: %w", err)
	}
	return nil
}
