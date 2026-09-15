// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package recorder provides reconciliation logic for the Recorder custom resource definition. It is responsible for
// managing the lifecycle of tsrecorder devices, including the StatefulSet, ServiceAccount and RBAC resources used to
// run them.
package recorder

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apivalidation "k8s.io/apimachinery/pkg/api/validation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler"
	"tailscale.com/k8s-operator/reconciler/tailscaled"
	"tailscale.com/k8s-operator/tsclient"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tstime"
	"tailscale.com/util/clientmetric"
)

const (
	reconcilerName = "recorder-reconciler"

	// shortRequeue is how long to wait before retrying a reconcile that made progress but hasn't finished, e.g.
	// cleanup that is waiting on control to catch up.
	shortRequeue = 5 * time.Second
)

// Condition reasons set on Recorder resources.
const (
	// ReasonRecorderCreated is the condition reason set once all of a Recorder's resources have been synced.
	ReasonRecorderCreated = "RecorderCreated"

	reasonRecorderCreationFailed     = "RecorderCreationFailed"
	reasonRecorderCreating           = "RecorderCreating"
	reasonRecorderInvalid            = "RecorderInvalid"
	reasonRecorderTailnetUnavailable = "RecorderTailnetUnavailable"
)

// gaugeRecorderResources tracks the overall number of Recorder resources currently managed by this operator instance.
var gaugeRecorderResources = clientmetric.NewGauge(kubetypes.MetricRecorderCount)

type (
	// Reconciler is a reconcile.Reconciler implementation that syncs Recorder StatefulSets with their definition in
	// Recorder custom resources.
	Reconciler struct {
		client.Client

		recorder    record.EventRecorder
		logger      *zap.SugaredLogger
		clock       tstime.Clock
		clients     tailscaled.ClientProvider
		tsNamespace string
		reissuer    *tailscaled.Reissuer

		tracker *reconciler.ResourceTracker
	}

	// ReconcilerOptions contains configuration values for the Reconciler.
	ReconcilerOptions struct {
		// Client is used to interact with the Kubernetes API.
		Client client.Client
		// Recorder is used to emit Kubernetes events.
		Recorder record.EventRecorder
		// TailscaleNamespace is the namespace the operator is installed in. Recorder-managed resources
		// (StatefulSets, Secrets, etc.) are created within this namespace.
		TailscaleNamespace string
		// Clients resolves the Tailscale API client for a given tailnet name. Used to mint auth keys for each
		// replica and to delete their devices on cleanup. Blank tailnet returns the operator's default client.
		Clients tailscaled.ClientProvider
		// Logger is the logger to use for this Reconciler.
		Logger *zap.SugaredLogger
		// Clock is used to stamp condition transitions. Defaults to a real clock when unset.
		Clock tstime.Clock
	}
)

// NewReconciler returns a new instance of the Reconciler type. It watches specifically for changes to Recorder
// custom resources. The ReconcilerOptions can be used to modify the behaviour of the Reconciler.
func NewReconciler(options ReconcilerOptions) *Reconciler {
	clock := options.Clock
	if clock == nil {
		clock = tstime.DefaultClock{}
	}

	return &Reconciler{
		Client:      options.Client,
		recorder:    options.Recorder,
		logger:      options.Logger.Named(reconcilerName),
		clock:       clock,
		clients:     options.Clients,
		tsNamespace: options.TailscaleNamespace,
		reissuer:    tailscaled.NewReissuer(),
		tracker:     reconciler.NewResourceTracker(gaugeRecorderResources),
	}
}

// Register the Reconciler onto the given manager.Manager implementation. It watches Recorder resources directly, as
// well as the child resources it manages, so that drift is corrected by a reconcile of the owning Recorder. All
// children carry a controller owner reference to their Recorder, so they are matched by owner rather than by label.
func (r *Reconciler) Register(mgr manager.Manager) error {
	enqueue := handler.EnqueueRequestForOwner(mgr.GetScheme(), mgr.GetRESTMapper(), &tsapi.Recorder{})
	return builder.
		ControllerManagedBy(mgr).
		For(&tsapi.Recorder{}).
		Named(reconcilerName).
		Watches(&appsv1.StatefulSet{}, enqueue).
		Watches(&corev1.ServiceAccount{}, enqueue).
		Watches(&corev1.Secret{}, enqueue).
		Watches(&rbacv1.Role{}, enqueue).
		Watches(&rbacv1.RoleBinding{}, enqueue).
		Complete(r)
}

// Reconcile is invoked when a change occurs to Recorder resources within the cluster. On create/update it ensures a
// StatefulSet and the Secrets and RBAC resources each replica needs exist. On delete it removes each replica's
// device from the tailnet before releasing the finalizer; the in-cluster resources are garbage collected via their
// owner references.
func (r *Reconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	logger := r.logger.With("Recorder", req.Name)
	logger.Debugf("starting reconcile")
	defer logger.Debugf("reconcile finished")

	tsr := new(tsapi.Recorder)
	err := r.Get(ctx, req.NamespacedName, tsr)
	switch {
	case apierrors.IsNotFound(err):
		logger.Debugf("Recorder not found, assuming it was deleted")
		return reconcile.Result{}, nil
	case err != nil:
		return reconcile.Result{}, fmt.Errorf("failed to get tailscale.com Recorder: %w", err)
	}

	oldTSRStatus := tsr.Status.DeepCopy()
	setStatusReady := func(tsr *tsapi.Recorder, status metav1.ConditionStatus, reason, message string) (reconcile.Result, error) {
		tsoperator.SetRecorderCondition(tsr, tsapi.RecorderReady, status, reason, message, tsr.Generation, r.clock, logger)
		if !apiequality.Semantic.DeepEqual(oldTSRStatus, &tsr.Status) {
			// An error encountered here should get returned by the Reconcile function.
			if updateErr := r.Client.Status().Update(ctx, tsr); updateErr != nil {
				return reconcile.Result{}, errors.Join(err, updateErr)
			}
		}

		return reconcile.Result{}, nil
	}

	tsClient, err := r.clients.For(tsr.Spec.Tailnet)
	if err != nil {
		return setStatusReady(tsr, metav1.ConditionFalse, reasonRecorderTailnetUnavailable, err.Error())
	}

	if !tsr.DeletionTimestamp.IsZero() {
		logger.Debugf("Recorder is being deleted, cleaning up resources")
		if !slices.Contains(tsr.Finalizers, reconciler.Finalizer) {
			logger.Debugf("no finalizer, nothing to do")
			return reconcile.Result{}, nil
		}

		if done, err := r.maybeCleanup(ctx, logger, tsr, tsClient); err != nil {
			return reconcile.Result{}, err
		} else if !done {
			logger.Debugf("Recorder resource cleanup not yet finished, will retry...")
			return reconcile.Result{RequeueAfter: shortRequeue}, nil
		}

		if err = reconciler.ClearFinalizer(ctx, r.Client, tsr, reconciler.Finalizer); err != nil {
			return reconcile.Result{}, err
		}
		return reconcile.Result{}, nil
	}

	if !slices.Contains(tsr.Finalizers, reconciler.Finalizer) {
		// This log line is printed exactly once during initial provisioning,
		// because once the finalizer is in place this block gets skipped. So,
		// this is a nice place to log that the high level, multi-reconcile
		// operation is underway.
		logger.Infof("ensuring Recorder is set up")
		if err = reconciler.EnsureFinalizer(ctx, r.Client, tsr, reconciler.Finalizer); err != nil {
			return setStatusReady(tsr, metav1.ConditionFalse, reasonRecorderCreationFailed, reasonRecorderCreationFailed)
		}
	}

	if err = r.validate(ctx, tsr); err != nil {
		message := fmt.Sprintf("Recorder is invalid: %s", err)
		r.recorder.Eventf(tsr, corev1.EventTypeWarning, reasonRecorderInvalid, message)
		return setStatusReady(tsr, metav1.ConditionFalse, reasonRecorderInvalid, message)
	}

	if err = r.maybeProvision(ctx, logger, tsClient, tsr); err != nil {
		reason := reasonRecorderCreationFailed
		message := fmt.Sprintf("failed creating Recorder: %s", err)
		if reconciler.IsOptimisticLockError(err) {
			reason = reasonRecorderCreating
			message = fmt.Sprintf("optimistic lock error, retrying: %s", err)
			err = nil
			logger.Info(message)
		} else {
			r.recorder.Eventf(tsr, corev1.EventTypeWarning, reasonRecorderCreationFailed, message)
		}
		return setStatusReady(tsr, metav1.ConditionFalse, reason, message)
	}

	logger.Info("Recorder resources synced")
	return setStatusReady(tsr, metav1.ConditionTrue, ReasonRecorderCreated, ReasonRecorderCreated)
}

func (r *Reconciler) maybeProvision(ctx context.Context, logger *zap.SugaredLogger, tsClient tsclient.Client, tsr *tsapi.Recorder) error {
	replicas := replicas(tsr)

	r.tracker.Add(tsr.UID)
	r.reissuer.EnsureState(tsr.Name, int(replicas))

	if err := r.ensureAuthSecretsCreated(ctx, logger, tsClient, tsr); err != nil {
		return fmt.Errorf("error creating secrets: %w", err)
	}

	// State Secrets are pre-created so we can use the Recorder CR as its owner ref.
	for replica := range replicas {
		sec := tsrStateSecret(tsr, r.tsNamespace, replica)
		_, err := reconciler.CreateOrUpdate(ctx, r.Client, r.tsNamespace, sec, func(s *corev1.Secret) {
			s.ObjectMeta.Labels = sec.ObjectMeta.Labels
			s.ObjectMeta.Annotations = sec.ObjectMeta.Annotations
		})
		if err != nil {
			return fmt.Errorf("error creating state Secret %q: %w", sec.Name, err)
		}
	}

	sa := tsrServiceAccount(tsr, r.tsNamespace)
	_, err := reconciler.CreateOrMaybeUpdate(ctx, r.Client, r.tsNamespace, sa, func(s *corev1.ServiceAccount) error {
		// Perform this check within the update function to make sure we don't
		// have a race condition between the previous check and the update.
		if err := saOwnedByRecorder(s, tsr); err != nil {
			return err
		}

		s.ObjectMeta.Labels = sa.ObjectMeta.Labels
		s.ObjectMeta.Annotations = sa.ObjectMeta.Annotations

		return nil
	})
	if err != nil {
		return fmt.Errorf("error creating ServiceAccount: %w", err)
	}

	role := tsrRole(tsr, r.tsNamespace)
	_, err = reconciler.CreateOrUpdate(ctx, r.Client, r.tsNamespace, role, func(r *rbacv1.Role) {
		r.ObjectMeta.Labels = role.ObjectMeta.Labels
		r.ObjectMeta.Annotations = role.ObjectMeta.Annotations
		r.Rules = role.Rules
	})
	if err != nil {
		return fmt.Errorf("error creating Role: %w", err)
	}

	roleBinding := tsrRoleBinding(tsr, r.tsNamespace)
	_, err = reconciler.CreateOrUpdate(ctx, r.Client, r.tsNamespace, roleBinding, func(r *rbacv1.RoleBinding) {
		r.ObjectMeta.Labels = roleBinding.ObjectMeta.Labels
		r.ObjectMeta.Annotations = roleBinding.ObjectMeta.Annotations
		r.RoleRef = roleBinding.RoleRef
		r.Subjects = roleBinding.Subjects
	})
	if err != nil {
		return fmt.Errorf("error creating RoleBinding: %w", err)
	}

	ss := tsrStatefulSet(tsr, r.tsNamespace, tsClient.LoginURL())
	_, err = reconciler.CreateOrUpdate(ctx, r.Client, r.tsNamespace, ss, func(s *appsv1.StatefulSet) {
		s.ObjectMeta.Labels = ss.ObjectMeta.Labels
		s.ObjectMeta.Annotations = ss.ObjectMeta.Annotations
		s.Spec = ss.Spec
	})
	if err != nil {
		return fmt.Errorf("error creating StatefulSet: %w", err)
	}

	// ServiceAccount name may have changed, in which case we need to clean up
	// the previous ServiceAccount. RoleBinding will already be updated to point
	// to the new ServiceAccount.
	if err = r.maybeCleanupServiceAccounts(ctx, logger, tsr, sa.Name); err != nil {
		return fmt.Errorf("error cleaning up ServiceAccounts: %w", err)
	}

	// If we have scaled the recorder down, we will have dangling state secrets
	// that we need to clean up.
	if err = r.maybeCleanupSecrets(ctx, logger, tsClient, tsr); err != nil {
		return fmt.Errorf("error cleaning up Secrets: %w", err)
	}

	var devices []tsapi.RecorderTailnetDevice
	for replica := range replicas {
		dev, ok, err := r.getDeviceInfo(ctx, tsClient, tsr.Name, replica)
		switch {
		case err != nil:
			return fmt.Errorf("failed to get device info: %w", err)
		case !ok:
			logger.Debugf("no Tailscale hostname known yet, waiting for Recorder pod to finish auth")
			continue
		}

		devices = append(devices, dev)
	}

	tsr.Status.Devices = devices

	return nil
}

func saOwnedByRecorder(sa *corev1.ServiceAccount, tsr *tsapi.Recorder) error {
	// If ServiceAccount name has been configured, check that we don't clobber
	// a pre-existing SA not owned by this Recorder.
	if sa.Name != tsr.Name && !apiequality.Semantic.DeepEqual(sa.OwnerReferences, tsrOwnerReference(tsr)) {
		return fmt.Errorf("custom ServiceAccount name %q specified but conflicts with a pre-existing ServiceAccount in the %s namespace", sa.Name, sa.Namespace)
	}

	return nil
}

// maybeCleanupServiceAccounts deletes any dangling ServiceAccounts
// owned by the Recorder if the ServiceAccount name has been changed.
// They would eventually be cleaned up by owner reference deletion, but
// this avoids a long-lived Recorder with many ServiceAccount name changes
// accumulating a large amount of garbage.
//
// This is a no-op if the ServiceAccount name has not changed.
func (r *Reconciler) maybeCleanupServiceAccounts(ctx context.Context, logger *zap.SugaredLogger, tsr *tsapi.Recorder, currentName string) error {
	options := []client.ListOption{
		client.InNamespace(r.tsNamespace),
		client.MatchingLabels(tsrLabels("recorder", tsr.Name, nil)),
	}

	sas := &corev1.ServiceAccountList{}
	if err := r.List(ctx, sas, options...); err != nil {
		return fmt.Errorf("error listing ServiceAccounts for cleanup: %w", err)
	}

	for _, serviceAccount := range sas.Items {
		if serviceAccount.Name == currentName {
			continue
		}

		err := r.Delete(ctx, &serviceAccount)
		switch {
		case apierrors.IsNotFound(err):
			logger.Debugf("ServiceAccount %s not found, likely already deleted", serviceAccount.Name)
			continue
		case err != nil:
			return fmt.Errorf("error deleting ServiceAccount %s: %w", serviceAccount.Name, err)
		}
	}

	return nil
}

// maybeCleanupSecrets deletes the state and auth Secrets of any replica beyond the Recorder's current replica count,
// along with each one's tailnet device. Their ordinals are read back from the Secret names.
func (r *Reconciler) maybeCleanupSecrets(ctx context.Context, logger *zap.SugaredLogger, tsClient tsclient.Client, tsr *tsapi.Recorder) error {
	options := []client.ListOption{
		client.InNamespace(r.tsNamespace),
		client.MatchingLabels(tsrLabels("recorder", tsr.Name, nil)),
	}

	secrets := &corev1.SecretList{}
	if err := r.List(ctx, secrets, options...); err != nil {
		return fmt.Errorf("error listing Secrets for cleanup: %w", err)
	}

	// Get the largest ordinal suffix that we expect. Then we'll go through the list of secrets owned by this
	// recorder and remove them.
	replicas := replicas(tsr)

	for _, secret := range secrets.Items {
		parts := strings.Split(secret.Name, "-")
		if len(parts) == 0 {
			continue
		}

		ordinal, err := strconv.ParseUint(parts[len(parts)-1], 10, 32)
		if err != nil {
			return fmt.Errorf("error parsing secret name %q: %w", secret.Name, err)
		}

		if int32(ordinal) < replicas {
			continue
		}

		devicePrefs, ok, err := tailscaled.PrefsFromStateSecret(&secret)
		if err != nil {
			return err
		}

		if ok {
			if err = tailscaled.EnsureDeviceDeleted(ctx, tsClient, logger, devicePrefs.Config.NodeID); err != nil {
				return err
			}
		}

		if err = r.Delete(ctx, &secret); err != nil {
			return err
		}
	}

	return nil
}

// maybeCleanup just deletes the device from the tailnet. All the kubernetes
// resources linked to a Recorder will get cleaned up via owner references
// (which we can use because they are all in the same namespace).
func (r *Reconciler) maybeCleanup(ctx context.Context, logger *zap.SugaredLogger, tsr *tsapi.Recorder, tsClient tsclient.Client) (bool, error) {
	for replica := range replicas(tsr) {
		devicePrefs, ok, err := r.getDevicePrefs(ctx, tsr.Name, replica)
		if err != nil {
			return false, err
		}
		if !ok {
			logger.Debugf("state Secret %s not found or does not contain node ID, continuing cleanup", stateSecretName(tsr.Name, replica))
			r.tracker.Remove(tsr.UID)
			return true, nil
		}

		if err = tailscaled.EnsureDeviceDeleted(ctx, tsClient, logger, devicePrefs.Config.NodeID); err != nil {
			return false, err
		}
	}

	// Unlike most log entries in the reconcile loop, this will get printed
	// exactly once at the very end of cleanup, because the final step of
	// cleanup removes the tailscale finalizer, which will make all future
	// reconciles exit early.
	logger.Infof("cleaned up Recorder resources")
	r.tracker.Remove(tsr.UID)
	r.reissuer.RemoveState(tsr.Name)

	return true, nil
}

func (r *Reconciler) validate(ctx context.Context, tsr *tsapi.Recorder) error {
	if !tsr.Spec.EnableUI && tsr.Spec.Storage.S3 == nil {
		return errors.New("must either enable UI or use S3 storage to ensure recordings are accessible")
	}

	if tsr.Spec.Replicas != nil && *tsr.Spec.Replicas > 1 && tsr.Spec.Storage.S3 == nil {
		return errors.New("must use S3 storage when using multiple replicas to ensure recordings are accessible")
	}

	// Check any custom ServiceAccount config doesn't conflict with pre-existing
	// ServiceAccounts. This check is performed once during validation to ensure
	// errors are raised early, but also again during any Updates to prevent a race.
	specSA := tsr.Spec.StatefulSet.Pod.ServiceAccount
	if specSA.Name != "" && specSA.Name != tsr.Name {
		sa := &corev1.ServiceAccount{}
		key := client.ObjectKey{
			Name:      specSA.Name,
			Namespace: r.tsNamespace,
		}

		err := r.Get(ctx, key, sa)
		switch {
		case apierrors.IsNotFound(err):
			// ServiceAccount doesn't exist, so no conflict.
		case err != nil:
			return fmt.Errorf("error getting ServiceAccount %q for validation: %w", specSA.Name, err)
		default:
			// ServiceAccount exists, check if it's owned by the Recorder.
			if err := saOwnedByRecorder(sa, tsr); err != nil {
				return err
			}
		}
	}
	if len(specSA.Annotations) > 0 {
		if violations := apivalidation.ValidateAnnotations(specSA.Annotations, field.NewPath(".spec.statefulSet.pod.serviceAccount.annotations")); len(violations) > 0 {
			return violations.ToAggregate()
		}
	}

	return nil
}

// getStateSecret returns the tailscaled state Secret for the given Recorder replica, or nil if it does not exist
// yet.
func (r *Reconciler) getStateSecret(ctx context.Context, tsrName string, replica int32) (*corev1.Secret, error) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: r.tsNamespace,
			Name:      stateSecretName(tsrName, replica),
		},
	}
	if err := r.Get(ctx, client.ObjectKeyFromObject(secret), secret); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}

		return nil, fmt.Errorf("error getting state Secret: %w", err)
	}

	return secret, nil
}

func (r *Reconciler) getDevicePrefs(ctx context.Context, tsrName string, replica int32) (prefs tailscaled.Prefs, ok bool, err error) {
	secret, err := r.getStateSecret(ctx, tsrName, replica)
	if err != nil || secret == nil {
		return prefs, false, err
	}

	return tailscaled.PrefsFromStateSecret(secret)
}

func (r *Reconciler) getDeviceInfo(ctx context.Context, tsClient tsclient.Client, tsrName string, replica int32) (d tsapi.RecorderTailnetDevice, ok bool, err error) {
	prefs, ok, err := r.getDevicePrefs(ctx, tsrName, replica)
	if !ok || err != nil {
		return tsapi.RecorderTailnetDevice{}, false, err
	}

	// TODO(tomhjp): The profile info doesn't include addresses, which is why we
	// need the API. Should maybe update tsrecorder to write IPs to the state
	// Secret like containerboot does.
	device, err := tsClient.Devices().Get(ctx, string(prefs.Config.NodeID))
	if err != nil {
		return tsapi.RecorderTailnetDevice{}, false, fmt.Errorf("failed to get device info from API: %w", err)
	}

	d = tsapi.RecorderTailnetDevice{
		Hostname:   device.Hostname,
		TailnetIPs: device.Addresses,
	}
	if dnsName := prefs.Config.UserProfile.LoginName; dnsName != "" {
		d.URL = fmt.Sprintf("https://%s", dnsName)
	}

	return d, true, nil
}

// replicas returns the number of replicas the Recorder asks for, defaulting to one.
func replicas(tsr *tsapi.Recorder) int32 {
	if tsr.Spec.Replicas != nil {
		return *tsr.Spec.Replicas
	}

	return 1
}
