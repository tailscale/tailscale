// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package tailnet provides reconciliation logic for the Tailnet custom resource definition. It is responsible for
// ensuring the referenced OAuth credentials are valid and have the required scopes to be able to generate authentication
// keys, manage devices & manage VIP services.
package tailnet

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"tailscale.com/client/tailscale/v2"

	"tailscale.com/ipn"
	operatorutils "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler"
	"tailscale.com/k8s-operator/tsclient"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tstime"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/set"
)

type (
	// The Reconciler type is a reconcile.TypedReconciler implementation used to manage the reconciliation of
	// Tailnet custom resources.
	Reconciler struct {
		client.Client

		tailscaleNamespace string
		clock              tstime.Clock
		logger             *zap.SugaredLogger
		clientFunc         func(*tsapi.Tailnet, *corev1.Secret) tsclient.Client
		registry           ClientRegistry

		// Metrics related fields
		mu       sync.Mutex
		tailnets set.Slice[types.UID]
	}

	// The ReconcilerOptions type contains configuration values for the Reconciler.
	ReconcilerOptions struct {
		// The client for interacting with the Kubernetes API.
		Client client.Client
		// The namespace the operator is installed in. This reconciler expects Tailnet OAuth credentials to be stored
		// in Secret resources within this namespace.
		TailscaleNamespace string
		// Controls which clock to use for performing time-based functions. This is typically modified for use
		// in tests.
		Clock tstime.Clock
		// The logger to use for this Reconciler.
		Logger *zap.SugaredLogger
		// ClientFunc is a function that takes tailscale credentials and returns an implementation for the Tailscale
		// HTTP API. This should generally be nil unless needed for testing.
		ClientFunc func(*tsapi.Tailnet, *corev1.Secret) tsclient.Client
		// Registry is used to store and share initialized tailscale clients for use by other reconcilers.
		Registry ClientRegistry
	}

	// The ClientRegistry interface describes types that can store initialized tailscale clients for use by other
	// reconcilers.
	ClientRegistry interface {
		// Add should store the given tsclient.Client implementation for a specified tailnet.
		Add(tailnet string, client tsclient.Client)
		// Remove should remove any tsclient.Client implementation for a specified tailnet.
		Remove(tailnet string)
	}
)

const reconcilerName = "tailnet-reconciler"

// NewReconciler returns a new instance of the Reconciler type. It watches specifically for changes to Tailnet custom
// resources. The ReconcilerOptions can be used to modify the behaviour of the Reconciler.
func NewReconciler(options ReconcilerOptions) *Reconciler {
	return &Reconciler{
		Client:             options.Client,
		tailscaleNamespace: options.TailscaleNamespace,
		clock:              options.Clock,
		logger:             options.Logger.Named(reconcilerName),
		clientFunc:         options.ClientFunc,
		registry:           options.Registry,
	}
}

// Register the Reconciler onto the given manager.Manager implementation.
func (r *Reconciler) Register(mgr manager.Manager) error {
	return builder.
		ControllerManagedBy(mgr).
		For(&tsapi.Tailnet{}).
		Named(reconcilerName).
		Complete(r)
}

var (
	// gaugeTailnetResources tracks the overall number of Tailnet resources currently managed by this operator instance.
	gaugeTailnetResources = clientmetric.NewGauge(kubetypes.MetricTailnetCount)
)

// Reconcile is invoked when a change occurs to Tailnet resources within the cluster. On create/update, the Tailnet
// resource is validated ensuring that the specified Secret exists and contains valid OAuth credentials that have
// required permissions to perform all necessary functions by the operator.
func (r *Reconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	var tailnet tsapi.Tailnet
	err := r.Get(ctx, req.NamespacedName, &tailnet)
	switch {
	case apierrors.IsNotFound(err):
		return reconcile.Result{}, nil
	case err != nil:
		return reconcile.Result{}, fmt.Errorf("failed to get Tailnet %q: %w", req.NamespacedName, err)
	}

	if !tailnet.DeletionTimestamp.IsZero() {
		return r.delete(ctx, &tailnet)
	}

	return r.createOrUpdate(ctx, &tailnet)
}

func (r *Reconciler) delete(ctx context.Context, tailnet *tsapi.Tailnet) (reconcile.Result, error) {
	reconciler.RemoveFinalizer(tailnet)
	if err := r.Update(ctx, tailnet); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to remove finalizer from Tailnet %q: %w", tailnet.Name, err)
	}

	r.mu.Lock()
	r.tailnets.Remove(tailnet.UID)
	r.mu.Unlock()
	gaugeTailnetResources.Set(int64(r.tailnets.Len()))
	r.registry.Remove(tailnet.Name)

	return reconcile.Result{}, nil
}

// Constants for condition reasons.
const (
	ReasonInvalidOAuth  = "InvalidOAuth"
	ReasonInvalidSecret = "InvalidSecret"
	ReasonValid         = "TailnetValid"
)

func (r *Reconciler) createOrUpdate(ctx context.Context, tailnet *tsapi.Tailnet) (reconcile.Result, error) {
	r.mu.Lock()
	r.tailnets.Add(tailnet.UID)
	r.mu.Unlock()
	gaugeTailnetResources.Set(int64(r.tailnets.Len()))

	name := types.NamespacedName{Name: tailnet.Spec.Credentials.SecretName, Namespace: r.tailscaleNamespace}

	var secret corev1.Secret
	err := r.Get(ctx, name, &secret)

	// The referenced Secret does not exist within the tailscale namespace, so we'll mark the Tailnet as not ready
	// for use.
	if apierrors.IsNotFound(err) {
		operatorutils.SetTailnetCondition(
			tailnet,
			tsapi.TailnetReady,
			metav1.ConditionFalse,
			ReasonInvalidSecret,
			fmt.Sprintf("referenced secret %q does not exist in namespace %q", name.Name, r.tailscaleNamespace),
			r.clock,
			r.logger,
		)

		if err = r.Status().Update(ctx, tailnet); err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to update Tailnet status for %q: %w", tailnet.Name, err)
		}

		return reconcile.Result{}, nil
	}

	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get secret %q: %w", name, err)
	}

	// We first ensure that the referenced secret contains the required fields. Otherwise, we set the Tailnet as
	// invalid. The operator will not allow the use of this Tailnet while it is in an invalid state.
	if ok := r.ensureSecret(tailnet, &secret); !ok {
		if err = r.Status().Update(ctx, tailnet); err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to update Tailnet status for %q: %w", tailnet.Name, err)
		}

		return reconcile.Result{RequeueAfter: time.Minute / 2}, nil
	}

	tsClient, err := r.createClient(tailnet, &secret)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to create tailnet client: %w", err)
	}

	// Second, we ensure the OAuth credentials supplied in the secret are valid and have the required scopes to access
	// the various API endpoints required by the operator.
	if ok := r.ensurePermissions(ctx, tsClient, tailnet); !ok {
		if err = r.Status().Update(ctx, tailnet); err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to update Tailnet status for %q: %w", tailnet.Name, err)
		}

		// We provide a requeue duration here as a user will likely want to go and modify their scopes and come back.
		// This should save them having to delete and recreate the resource.
		return reconcile.Result{RequeueAfter: time.Minute / 2}, nil
	}

	operatorutils.SetTailnetCondition(
		tailnet,
		tsapi.TailnetReady,
		metav1.ConditionTrue,
		ReasonValid,
		ReasonValid,
		r.clock,
		r.logger,
	)

	if err = r.Status().Update(ctx, tailnet); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to update Tailnet status for %q: %w", tailnet.Name, err)
	}

	reconciler.SetFinalizer(tailnet)
	if err = r.Update(ctx, tailnet); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to add finalizer to Tailnet %q: %w", tailnet.Name, err)
	}

	r.registry.Add(tailnet.Name, tsClient)

	return reconcile.Result{}, nil
}

// Constants for OAuth credential fields within the Secret referenced by the Tailnet.
const (
	clientIDKey     = "client_id"
	clientSecretKey = "client_secret"
)

func (r *Reconciler) createClient(tailnet *tsapi.Tailnet, secret *corev1.Secret) (tsclient.Client, error) {
	if r.clientFunc != nil {
		return r.clientFunc(tailnet, secret), nil
	}

	baseURL := ipn.DefaultControlURL
	if tailnet.Spec.LoginURL != "" {
		baseURL = tailnet.Spec.LoginURL
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse base URL %q: %w", baseURL, err)
	}

	return tsclient.Wrap(&tailscale.Client{
		BaseURL:   base,
		UserAgent: "tailscale-k8s-operator",
		Auth: &tailscale.OAuth{
			ClientID:     string(secret.Data[clientIDKey]),
			ClientSecret: string(secret.Data[clientSecretKey]),
		},
	}), nil
}

func (r *Reconciler) ensurePermissions(ctx context.Context, tsClient tsclient.Client, tailnet *tsapi.Tailnet) bool {
	// Perform basic list requests here to confirm that the OAuth credentials referenced on the Tailnet resource
	// can perform the basic operations required for the operator to function. This has a caveat of only performing
	// read actions, as we don't want to create arbitrary keys and VIP services. However, it will catch when a user
	// has completely forgotten an entire scope that's required.
	var errs error
	if _, err := tsClient.Devices().List(ctx); err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to list devices: %w", err))
	}

	if _, err := tsClient.Keys().List(ctx, false); err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to list auth keys: %w", err))
	}

	if _, err := tsClient.VIPServices().List(ctx); err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to list tailscale services: %w", err))
	}

	if errs != nil {
		operatorutils.SetTailnetCondition(
			tailnet,
			tsapi.TailnetReady,
			metav1.ConditionFalse,
			ReasonInvalidOAuth,
			errs.Error(),
			r.clock,
			r.logger,
		)

		return false
	}

	return true
}

func (r *Reconciler) ensureSecret(tailnet *tsapi.Tailnet, secret *corev1.Secret) bool {
	var message string

	switch {
	case len(secret.Data) == 0:
		message = fmt.Sprintf("Secret %q is empty", secret.Name)
	case len(secret.Data[clientIDKey]) == 0:
		message = fmt.Sprintf("Secret %q is missing the client_id field", secret.Name)
	case len(secret.Data[clientSecretKey]) == 0:
		message = fmt.Sprintf("Secret %q is missing the client_secret field", secret.Name)
	}

	if message == "" {
		return true
	}

	operatorutils.SetTailnetCondition(
		tailnet,
		tsapi.TailnetReady,
		metav1.ConditionFalse,
		ReasonInvalidSecret,
		message,
		r.clock,
		r.logger,
	)

	return false
}
