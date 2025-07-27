// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"

	"go.uber.org/zap"
	xslices "golang.org/x/exp/slices"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"tailscale.com/client/tailscale"
	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/set"
)

const (
	reasonIDPCreationFailed = "IDPCreationFailed"
	reasonIDPCreating       = "IDPCreating"
	reasonIDPCreated        = "IDPCreated"
	reasonIDPInvalid        = "IDPInvalid"

	// emptyJSONObject is the initial value for funnel clients secret data
	emptyJSONObject = "{}"

	// Network constants
	minPort = 1
	maxPort = 65535
)

var (
	// dnsLabelRegex validates DNS labels according to RFC 1123
	dnsLabelRegex = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
)

var gaugeIDPResources = clientmetric.NewGauge(kubetypes.MetricIDPCount)

// IDPReconciler syncs IDP statefulsets with their definition in
// IDP CRs.
type IDPReconciler struct {
	client.Client
	l           *zap.SugaredLogger
	recorder    record.EventRecorder
	clock       tstime.Clock
	tsNamespace string
	tsClient    tsClient
	loginServer string // optional URL of the control server

	mu   sync.Mutex           // protects following
	idps set.Slice[types.UID] // for idps gauge
}

func (r *IDPReconciler) logger(name string) *zap.SugaredLogger {
	return r.l.With("IDP", name)
}

func (r *IDPReconciler) Reconcile(ctx context.Context, req reconcile.Request) (res reconcile.Result, err error) {
	logger := r.logger(req.Name)
	logger.Debugf("starting reconcile")
	defer func() {
		if err != nil {
			logger.Errorf("reconcile finished with error: %v", err)
		} else {
			logger.Debugf("reconcile finished")
		}
	}()

	idp := new(tsapi.IDP)
	err = r.Get(ctx, req.NamespacedName, idp)
	if apierrors.IsNotFound(err) {
		logger.Debugf("IDP not found, assuming it was deleted")
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get tailscale.com IDP: %w", err)
	}
	if markedForDeletion(idp) {
		logger.Debugf("IDP is being deleted, cleaning up resources")
		ix := xslices.Index(idp.Finalizers, FinalizerName)
		if ix < 0 {
			logger.Debugf("no finalizer, nothing to do")
			return reconcile.Result{}, nil
		}

		if done, err := r.maybeCleanup(ctx, idp); err != nil {
			if strings.Contains(err.Error(), optimisticLockErrorMsg) {
				logger.Debugf("optimistic lock error during cleanup, retrying: %v", err)
				return reconcile.Result{RequeueAfter: shortRequeue}, nil
			}
			return reconcile.Result{}, err
		} else if !done {
			logger.Debugf("IDP resource cleanup not yet finished, will retry...")
			return reconcile.Result{RequeueAfter: shortRequeue}, nil
		}

		idp.Finalizers = slices.Delete(idp.Finalizers, ix, ix+1)
		if err := r.Update(ctx, idp); err != nil {
			return reconcile.Result{}, err
		}
		return reconcile.Result{}, nil
	}

	oldIDPStatus := idp.Status.DeepCopy()
	setStatusReady := func(idp *tsapi.IDP, status metav1.ConditionStatus, reason, message string) (reconcile.Result, error) {
		tsoperator.SetIDPCondition(idp, tsapi.IDPReady, status, reason, message, idp.Generation, r.clock, logger)
		if !apiequality.Semantic.DeepEqual(oldIDPStatus, &idp.Status) {
			// An error encountered here should get returned by the Reconcile function.
			if updateErr := r.Client.Status().Update(ctx, idp); updateErr != nil {
				err = errors.Join(err, updateErr)
			}
		}
		return reconcile.Result{}, err
	}

	if !slices.Contains(idp.Finalizers, FinalizerName) {
		// Log once during initial provisioning when finalizer is added.
		logger.Infof("ensuring IDP is set up")
		idp.Finalizers = append(idp.Finalizers, FinalizerName)
		if err := r.Update(ctx, idp); err != nil {
			return setStatusReady(idp, metav1.ConditionFalse, reasonIDPCreationFailed, fmt.Sprintf("failed to add finalizer: %v", err))
		}
	}

	if err := r.validate(ctx, idp); err != nil {
		message := fmt.Sprintf("IDP is invalid: %s", err)
		r.recorder.Eventf(idp, corev1.EventTypeWarning, reasonIDPInvalid, message)
		return setStatusReady(idp, metav1.ConditionFalse, reasonIDPInvalid, message)
	}

	if err = r.maybeProvision(ctx, idp); err != nil {
		reason := reasonIDPCreationFailed
		message := fmt.Sprintf("failed creating IDP: %s", err)
		if strings.Contains(err.Error(), optimisticLockErrorMsg) {
			reason = reasonIDPCreating
			message = fmt.Sprintf("optimistic lock error, retrying: %s", err)
			err = nil
			logger.Info(message)
		} else {
			r.recorder.Eventf(idp, corev1.EventTypeWarning, reasonIDPCreationFailed, message)
		}
		return setStatusReady(idp, metav1.ConditionFalse, reason, message)
	}

	logger.Info("IDP resources synced")

	// Update status with device information, similar to how Recorder does it
	if err = r.updateStatus(ctx, idp); err != nil {
		return setStatusReady(idp, metav1.ConditionFalse, reasonIDPCreationFailed, fmt.Sprintf("failed updating status: %s", err))
	}

	// Update the status after successful provisioning.
	// Note: oldIDPStatus was captured before maybeProvision, so any status
	// updates made during provisioning will be included in the update.
	return setStatusReady(idp, metav1.ConditionTrue, reasonIDPCreated, reasonIDPCreated)
}

// validate validates the IDP spec.
func (r *IDPReconciler) validate(_ context.Context, idp *tsapi.IDP) error {
	// Validate tags using the standard CheckTag function
	for _, tag := range idp.Spec.Tags {
		if err := tailcfg.CheckTag(string(tag)); err != nil {
			return fmt.Errorf("invalid tag %q: %w", tag, err)
		}
	}

	// Validate hostname
	if idp.Spec.Hostname != "" {
		if len(idp.Spec.Hostname) > 63 {
			return fmt.Errorf("hostname %q must be 63 characters or less", idp.Spec.Hostname)
		}
		// Validate hostname format (DNS label)
		if !isValidDNSLabel(idp.Spec.Hostname) {
			return fmt.Errorf("hostname %q must be a valid DNS label (lowercase letters, numbers, and hyphens only; cannot start or end with hyphen)", idp.Spec.Hostname)
		}
	}

	// Validate port
	if idp.Spec.Port != 0 {
		if idp.Spec.Port < minPort || idp.Spec.Port > maxPort {
			return fmt.Errorf("port %d is out of valid range (%d-%d)", idp.Spec.Port, minPort, maxPort)
		}
	}

	// Validate local port
	if idp.Spec.LocalPort != nil {
		if *idp.Spec.LocalPort < minPort || *idp.Spec.LocalPort > maxPort {
			return fmt.Errorf("localPort %d is out of valid range (%d-%d)", *idp.Spec.LocalPort, minPort, maxPort)
		}
	}

	// Validate funnel with port
	if idp.Spec.EnableFunnel && idp.Spec.Port != 0 && idp.Spec.Port != 443 {
		return fmt.Errorf("when enableFunnel is true, port must be 443 or unset")
	}

	return nil
}

// maybeProvision ensures that all IDP resources are created as needed.
func (r *IDPReconciler) maybeProvision(ctx context.Context, idp *tsapi.IDP) error {
	logger := r.logger(idp.Name)

	// Ensure ServiceAccount exists
	logger.Debugf("ensuring ServiceAccount %s exists", idp.Name)
	sa := idpServiceAccount(idp, r.tsNamespace)
	if _, err := createOrMaybeUpdate(ctx, r.Client, r.tsNamespace, sa, func(existing *corev1.ServiceAccount) error {
		// Check that we don't clobber a pre-existing ServiceAccount not owned by this IDP
		if sa.Name != idp.Name && !apiequality.Semantic.DeepEqual(existing.OwnerReferences, idpOwnerReference(idp)) {
			return fmt.Errorf("custom ServiceAccount name %q specified but conflicts with a pre-existing ServiceAccount in the %s namespace", sa.Name, sa.Namespace)
		}

		existing.Annotations = sa.Annotations
		existing.Labels = sa.Labels
		return nil
	}); err != nil {
		return fmt.Errorf("failed to create or update ServiceAccount: %w", err)
	}

	// Clean up any old ServiceAccounts if the name changed
	if err := r.maybeCleanupServiceAccounts(ctx, idp, sa.Name); err != nil {
		return fmt.Errorf("failed to cleanup old ServiceAccounts: %w", err)
	}
	logger.Debugf("ServiceAccount synced")

	// Ensure Role exists
	role := idpRole(idp, r.tsNamespace)
	if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, role, func(existing *rbacv1.Role) {
		existing.Rules = role.Rules
		existing.Labels = role.Labels
		existing.Annotations = role.Annotations
	}); err != nil {
		return fmt.Errorf("failed to create or update Role: %w", err)
	}
	logger.Debugf("Role synced")

	// Ensure RoleBinding exists
	roleBinding := idpRoleBinding(idp, r.tsNamespace)
	if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, roleBinding, func(existing *rbacv1.RoleBinding) {
		existing.RoleRef = roleBinding.RoleRef
		existing.Subjects = roleBinding.Subjects
		existing.Labels = roleBinding.Labels
		existing.Annotations = roleBinding.Annotations
	}); err != nil {
		return fmt.Errorf("failed to create or update RoleBinding: %w", err)
	}
	logger.Debugf("RoleBinding synced")

	// Create auth secret
	logger.Debugf("ensuring auth secret exists")
	authSecret, err := r.authSecret(ctx, idp)
	if err != nil {
		return fmt.Errorf("failed to create auth secret: %w", err)
	}
	if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, authSecret, func(existing *corev1.Secret) {
		existing.StringData = authSecret.StringData
	}); err != nil {
		return fmt.Errorf("failed to create or update auth Secret: %w", err)
	}
	logger.Debugf("Auth Secret synced")

	// State Secret is precreated so we can use the IDP CR as its owner ref.
	// This follows the same pattern as the Recorder reconciler.
	stateSecret := idpStateSecret(idp, r.tsNamespace)
	if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, stateSecret, func(s *corev1.Secret) {
		s.ObjectMeta.Labels = stateSecret.ObjectMeta.Labels
		s.ObjectMeta.Annotations = stateSecret.ObjectMeta.Annotations
	}); err != nil {
		return fmt.Errorf("error creating state Secret: %w", err)
	}
	logger.Debugf("State Secret synced")

	// Ensure funnel clients secret exists with proper owner reference.
	// This secret stores state for the IDP when running with funnel enabled.
	funnelClientsSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            fmt.Sprintf("%s-funnel-clients", idp.Name),
			Namespace:       r.tsNamespace,
			Labels:          map[string]string{"app": "idp", "idp": idp.Name},
			OwnerReferences: idpOwnerReference(idp),
		},
		Data: map[string][]byte{
			"funnel-clients": []byte(emptyJSONObject),
		},
	}
	if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, funnelClientsSecret, func(existing *corev1.Secret) {
		existing.Labels = funnelClientsSecret.Labels
		// Initialize data if it doesn't exist, but don't overwrite existing data
		if existing.Data == nil {
			existing.Data = map[string][]byte{}
		}
		if _, exists := existing.Data["funnel-clients"]; !exists {
			existing.Data["funnel-clients"] = []byte(emptyJSONObject)
		}
	}); err != nil {
		return fmt.Errorf("failed to create or update funnel clients Secret: %w", err)
	}
	logger.Debugf("Funnel clients Secret synced")

	// Ensure StatefulSet exists
	sts := idpStatefulSet(idp, r.tsNamespace, r.loginServer)
	if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, sts, func(existing *appsv1.StatefulSet) {
		existing.Spec.Replicas = sts.Spec.Replicas
		existing.Spec.Template = sts.Spec.Template
		existing.Labels = sts.Labels
		existing.Annotations = sts.Annotations
	}); err != nil {
		return fmt.Errorf("failed to create or update StatefulSet: %w", err)
	}
	logger.Debugf("StatefulSet synced")

	// Create Service for OIDC endpoints
	svc := idpService(idp, r.tsNamespace)
	if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, svc, func(existing *corev1.Service) {
		existing.Spec.Selector = svc.Spec.Selector
		existing.Spec.Ports = svc.Spec.Ports
		existing.Spec.Type = svc.Spec.Type
	}); err != nil {
		return fmt.Errorf("failed to create or update Service: %w", err)
	}
	logger.Debugf("Service synced")

	// Update gauge metrics
	r.mu.Lock()
	r.idps.Add(idp.UID)
	gaugeIDPResources.Set(int64(r.idps.Len()))
	r.mu.Unlock()
	logger.Debugf("updated metrics, total IDPs: %d", r.idps.Len())

	// Don't update status here - it will be updated in the main reconcile loop
	// after provisioning is complete, similar to how Recorder works
	return nil
}

// updateStatus updates the IDP status with current device information.
func (r *IDPReconciler) updateStatus(ctx context.Context, idp *tsapi.IDP) error {
	logger := r.logger(idp.Name)

	// Update basic status fields
	idp.Status.ObservedGeneration = idp.Generation

	// Set hostname
	if idp.Spec.Hostname != "" {
		idp.Status.Hostname = idp.Spec.Hostname
	} else {
		idp.Status.Hostname = "idp"
	}

	// Check kubestore state secret for device info.
	stateSecretName := fmt.Sprintf("%s-state", idp.Name)
	stateSecret := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{
		Name:      stateSecretName,
		Namespace: r.tsNamespace,
	}, stateSecret); err != nil {
		// Device not ready yet, don't set URL
		logger.Debugf("state secret not found yet, device may still be initializing")
		return nil
	}

	// Extract device info from kubestore state
	prefs, ok, err := getDevicePrefs(stateSecret)
	if err != nil {
		return fmt.Errorf("error parsing state secret: %w", err)
	}
	if !ok || prefs.Config == nil || prefs.Config.NodeID == "" {
		// Device not fully registered yet
		logger.Debugf("device not fully registered yet")
		return nil
	}

	// Get device details from API
	device, err := r.tsClient.Device(ctx, string(prefs.Config.NodeID), nil)
	if err != nil {
		logger.Debugf("failed to get device info: %v", err)
		// Don't fail on API errors, device exists but we can't get details
		return nil
	}

	// Update status with actual device information
	if device.Hostname != "" {
		idp.Status.Hostname = device.Hostname
	}

	if len(device.Addresses) > 0 {
		idp.Status.TailnetIPs = device.Addresses
	}

	// Set URL based on LoginName from prefs (MagicDNS name)
	if dnsName := prefs.Config.UserProfile.LoginName; dnsName != "" {
		idp.Status.URL = fmt.Sprintf("https://%s", dnsName)
	}

	logger.Debugf("updated status with device info from API")
	return nil
}

// maybeCleanupServiceAccounts deletes any dangling ServiceAccounts owned by the IDP
// if the ServiceAccount name has been changed. This is a no-op if the name hasn't changed.
func (r *IDPReconciler) maybeCleanupServiceAccounts(ctx context.Context, idp *tsapi.IDP, currentName string) error {
	logger := r.logger(idp.Name)

	// List all ServiceAccounts owned by this IDP
	sas := &corev1.ServiceAccountList{}
	if err := r.List(ctx, sas, client.InNamespace(r.tsNamespace), client.MatchingLabels(map[string]string{
		"app": "idp",
		"idp": idp.Name,
	})); err != nil {
		return fmt.Errorf("error listing ServiceAccounts for cleanup: %w", err)
	}

	for _, sa := range sas.Items {
		if sa.Name == currentName {
			continue
		}
		if err := r.Delete(ctx, &sa); err != nil {
			if apierrors.IsNotFound(err) {
				logger.Debugf("ServiceAccount %s not found, likely already deleted", sa.Name)
			} else {
				return fmt.Errorf("error deleting ServiceAccount %s: %w", sa.Name, err)
			}
		} else {
			logger.Debugf("deleted old ServiceAccount %s", sa.Name)
		}
	}

	return nil
}

// maybeCleanup just deletes the device from the tailnet. All the kubernetes
// resources linked to an IDP will get cleaned up via owner references
// (which we can use because they are all in the same namespace).
func (r *IDPReconciler) maybeCleanup(ctx context.Context, idp *tsapi.IDP) (bool, error) {
	logger := r.logger(idp.Name)

	// Get the state secret
	stateSecretName := fmt.Sprintf("%s-state", idp.Name)
	stateSecret := &corev1.Secret{}
	err := r.Get(ctx, client.ObjectKey{
		Name:      stateSecretName,
		Namespace: r.tsNamespace,
	}, stateSecret)

	if apierrors.IsNotFound(err) {
		logger.Debugf("state Secret %s not found, device may not have been registered, continuing cleanup", stateSecretName)
		r.mu.Lock()
		r.idps.Remove(idp.UID)
		gaugeIDPResources.Set(int64(r.idps.Len()))
		r.mu.Unlock()
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("error getting state Secret: %w", err)
	}

	// Extract device info from kubestore state secret
	prefs, ok, err := getDevicePrefs(stateSecret)
	if err != nil {
		return false, fmt.Errorf("error parsing state Secret: %w", err)
	}
	if !ok || prefs.Config == nil {
		logger.Debugf("state Secret %s does not contain node ID, continuing cleanup", stateSecretName)
		r.mu.Lock()
		r.idps.Remove(idp.UID)
		gaugeIDPResources.Set(int64(r.idps.Len()))
		r.mu.Unlock()
		return true, nil
	}

	// Delete device from tailnet
	nodeID := string(prefs.Config.NodeID)
	logger.Debugf("deleting device %s from control", nodeID)
	if err := r.tsClient.DeleteDevice(ctx, nodeID); err != nil {
		errResp := &tailscale.ErrResponse{}
		if ok := errors.As(err, errResp); ok && errResp.Status == http.StatusNotFound {
			logger.Debugf("device %s not found, likely because it has already been deleted from control", nodeID)
		} else {
			return false, fmt.Errorf("error deleting device: %w", err)
		}
	} else {
		logger.Debugf("device %s deleted from control", nodeID)
	}

	// Log final cleanup completion before removing finalizer.
	logger.Infof("cleaned up IDP resources")
	r.mu.Lock()
	r.idps.Remove(idp.UID)
	gaugeIDPResources.Set(int64(r.idps.Len()))
	r.mu.Unlock()
	return true, nil
}

// authSecret creates a secret containing the auth key for the IDP.
func (r *IDPReconciler) authSecret(ctx context.Context, idp *tsapi.IDP) (*corev1.Secret, error) {
	logger := r.logger(idp.Name)

	tags := idp.Spec.Tags
	if len(tags) == 0 {
		tags = tsapi.Tags{"tag:k8s"}
	}

	tagsSlice := make([]string, len(tags))
	for i, tag := range tags {
		tagsSlice[i] = string(tag)
	}
	authKey, err := newAuthKey(ctx, r.tsClient, tagsSlice)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth key: %w", err)
	}
	logger.Debugf("created auth key for tags %v", tags)

	return idpAuthSecret(idp, r.tsNamespace, authKey), nil
}

// isValidDNSLabel checks if a string is a valid DNS label according to RFC 1123
func isValidDNSLabel(label string) bool {
	return dnsLabelRegex.MatchString(label)
}
