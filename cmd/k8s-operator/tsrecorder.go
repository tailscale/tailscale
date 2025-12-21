// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"

	"go.uber.org/zap"
	xslices "golang.org/x/exp/slices"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apivalidation "k8s.io/apimachinery/pkg/api/validation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
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
	reasonRecorderCreationFailed = "RecorderCreationFailed"
	reasonRecorderCreating       = "RecorderCreating"
	reasonRecorderCreated        = "RecorderCreated"
	reasonRecorderInvalid        = "RecorderInvalid"

	currentProfileKey = "_current-profile"
)

var gaugeRecorderResources = clientmetric.NewGauge(kubetypes.MetricRecorderCount)

// RecorderReconciler syncs Recorder statefulsets with their definition in
// Recorder CRs.
type RecorderReconciler struct {
	client.Client
	log         *zap.SugaredLogger
	recorder    record.EventRecorder
	clock       tstime.Clock
	tsNamespace string
	tsClient    tsClient
	loginServer string

	mu        sync.Mutex           // protects following
	recorders set.Slice[types.UID] // for recorders gauge
}

func (r *RecorderReconciler) logger(name string) *zap.SugaredLogger {
	return r.log.With("Recorder", name)
}

func (r *RecorderReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	logger := r.logger(req.Name)
	logger.Debugf("starting reconcile")
	defer logger.Debugf("reconcile finished")

	tsr := new(tsapi.Recorder)
	err := r.Get(ctx, req.NamespacedName, tsr)
	if apierrors.IsNotFound(err) {
		logger.Debugf("Recorder not found, assuming it was deleted")
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get tailscale.com Recorder: %w", err)
	}
	if markedForDeletion(tsr) {
		logger.Debugf("Recorder is being deleted, cleaning up resources")
		ix := xslices.Index(tsr.Finalizers, FinalizerName)
		if ix < 0 {
			logger.Debugf("no finalizer, nothing to do")
			return reconcile.Result{}, nil
		}

		if done, err := r.maybeCleanup(ctx, tsr); err != nil {
			return reconcile.Result{}, err
		} else if !done {
			logger.Debugf("Recorder resource cleanup not yet finished, will retry...")
			return reconcile.Result{RequeueAfter: shortRequeue}, nil
		}

		tsr.Finalizers = slices.Delete(tsr.Finalizers, ix, ix+1)
		if err = r.Update(ctx, tsr); err != nil {
			return reconcile.Result{}, err
		}
		return reconcile.Result{}, nil
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

	if !slices.Contains(tsr.Finalizers, FinalizerName) {
		// This log line is printed exactly once during initial provisioning,
		// because once the finalizer is in place this block gets skipped. So,
		// this is a nice place to log that the high level, multi-reconcile
		// operation is underway.
		logger.Infof("ensuring Recorder is set up")
		tsr.Finalizers = append(tsr.Finalizers, FinalizerName)
		if err = r.Update(ctx, tsr); err != nil {
			return setStatusReady(tsr, metav1.ConditionFalse, reasonRecorderCreationFailed, reasonRecorderCreationFailed)
		}
	}

	if err = r.validate(ctx, tsr); err != nil {
		message := fmt.Sprintf("Recorder is invalid: %s", err)
		r.recorder.Eventf(tsr, corev1.EventTypeWarning, reasonRecorderInvalid, message)
		return setStatusReady(tsr, metav1.ConditionFalse, reasonRecorderInvalid, message)
	}

	if err = r.maybeProvision(ctx, tsr); err != nil {
		reason := reasonRecorderCreationFailed
		message := fmt.Sprintf("failed creating Recorder: %s", err)
		if strings.Contains(err.Error(), optimisticLockErrorMsg) {
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
	return setStatusReady(tsr, metav1.ConditionTrue, reasonRecorderCreated, reasonRecorderCreated)
}

func (r *RecorderReconciler) maybeProvision(ctx context.Context, tsr *tsapi.Recorder) error {
	logger := r.logger(tsr.Name)

	r.mu.Lock()
	r.recorders.Add(tsr.UID)
	gaugeRecorderResources.Set(int64(r.recorders.Len()))
	r.mu.Unlock()

	if err := r.ensureAuthSecretsCreated(ctx, tsr); err != nil {
		return fmt.Errorf("error creating secrets: %w", err)
	}

	// State Secrets are pre-created so we can use the Recorder CR as its owner ref.
	var replicas int32 = 1
	if tsr.Spec.Replicas != nil {
		replicas = *tsr.Spec.Replicas
	}

	for replica := range replicas {
		sec := tsrStateSecret(tsr, r.tsNamespace, replica)
		_, err := createOrUpdate(ctx, r.Client, r.tsNamespace, sec, func(s *corev1.Secret) {
			s.ObjectMeta.Labels = sec.ObjectMeta.Labels
			s.ObjectMeta.Annotations = sec.ObjectMeta.Annotations
		})
		if err != nil {
			return fmt.Errorf("error creating state Secret %q: %w", sec.Name, err)
		}
	}

	sa := tsrServiceAccount(tsr, r.tsNamespace)
	_, err := createOrMaybeUpdate(ctx, r.Client, r.tsNamespace, sa, func(s *corev1.ServiceAccount) error {
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
	_, err = createOrUpdate(ctx, r.Client, r.tsNamespace, role, func(r *rbacv1.Role) {
		r.ObjectMeta.Labels = role.ObjectMeta.Labels
		r.ObjectMeta.Annotations = role.ObjectMeta.Annotations
		r.Rules = role.Rules
	})
	if err != nil {
		return fmt.Errorf("error creating Role: %w", err)
	}

	roleBinding := tsrRoleBinding(tsr, r.tsNamespace)
	_, err = createOrUpdate(ctx, r.Client, r.tsNamespace, roleBinding, func(r *rbacv1.RoleBinding) {
		r.ObjectMeta.Labels = roleBinding.ObjectMeta.Labels
		r.ObjectMeta.Annotations = roleBinding.ObjectMeta.Annotations
		r.RoleRef = roleBinding.RoleRef
		r.Subjects = roleBinding.Subjects
	})
	if err != nil {
		return fmt.Errorf("error creating RoleBinding: %w", err)
	}

	ss := tsrStatefulSet(tsr, r.tsNamespace, r.loginServer)
	_, err = createOrUpdate(ctx, r.Client, r.tsNamespace, ss, func(s *appsv1.StatefulSet) {
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
	if err = r.maybeCleanupServiceAccounts(ctx, tsr, sa.Name); err != nil {
		return fmt.Errorf("error cleaning up ServiceAccounts: %w", err)
	}

	// If we have scaled the recorder down, we will have dangling state secrets
	// that we need to clean up.
	if err = r.maybeCleanupSecrets(ctx, tsr); err != nil {
		return fmt.Errorf("error cleaning up Secrets: %w", err)
	}

	var devices []tsapi.RecorderTailnetDevice
	for replica := range replicas {
		dev, ok, err := r.getDeviceInfo(ctx, tsr.Name, replica)
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
func (r *RecorderReconciler) maybeCleanupServiceAccounts(ctx context.Context, tsr *tsapi.Recorder, currentName string) error {
	logger := r.logger(tsr.Name)

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

func (r *RecorderReconciler) maybeCleanupSecrets(ctx context.Context, tsr *tsapi.Recorder) error {
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
	var replicas int32 = 1
	if tsr.Spec.Replicas != nil {
		replicas = *tsr.Spec.Replicas
	}

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

		devicePrefs, ok, err := getDevicePrefs(&secret)
		if err != nil {
			return err
		}

		if ok {
			var errResp *tailscale.ErrResponse

			r.log.Debugf("deleting device %s", devicePrefs.Config.NodeID)
			err = r.tsClient.DeleteDevice(ctx, string(devicePrefs.Config.NodeID))
			switch {
			case errors.As(err, &errResp) && errResp.Status == http.StatusNotFound:
				// This device has possibly already been deleted in the admin console. So we can ignore this
				// and move on to removing the secret.
			case err != nil:
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
func (r *RecorderReconciler) maybeCleanup(ctx context.Context, tsr *tsapi.Recorder) (bool, error) {
	logger := r.logger(tsr.Name)

	var replicas int32 = 1
	if tsr.Spec.Replicas != nil {
		replicas = *tsr.Spec.Replicas
	}

	for replica := range replicas {
		devicePrefs, ok, err := r.getDevicePrefs(ctx, tsr.Name, replica)
		if err != nil {
			return false, err
		}
		if !ok {
			logger.Debugf("state Secret %s-%d not found or does not contain node ID, continuing cleanup", tsr.Name, replica)
			r.mu.Lock()
			r.recorders.Remove(tsr.UID)
			gaugeRecorderResources.Set(int64(r.recorders.Len()))
			r.mu.Unlock()
			return true, nil
		}

		nodeID := string(devicePrefs.Config.NodeID)
		logger.Debugf("deleting device %s from control", nodeID)
		if err = r.tsClient.DeleteDevice(ctx, nodeID); err != nil {
			errResp := &tailscale.ErrResponse{}
			if errors.As(err, errResp) && errResp.Status == http.StatusNotFound {
				logger.Debugf("device %s not found, likely because it has already been deleted from control", nodeID)
				continue
			}

			return false, fmt.Errorf("error deleting device: %w", err)
		}

		logger.Debugf("device %s deleted from control", nodeID)
	}

	// Unlike most log entries in the reconcile loop, this will get printed
	// exactly once at the very end of cleanup, because the final step of
	// cleanup removes the tailscale finalizer, which will make all future
	// reconciles exit early.
	logger.Infof("cleaned up Recorder resources")
	r.mu.Lock()
	r.recorders.Remove(tsr.UID)
	gaugeRecorderResources.Set(int64(r.recorders.Len()))
	r.mu.Unlock()

	return true, nil
}

func (r *RecorderReconciler) ensureAuthSecretsCreated(ctx context.Context, tsr *tsapi.Recorder) error {
	var replicas int32 = 1
	if tsr.Spec.Replicas != nil {
		replicas = *tsr.Spec.Replicas
	}

	tags := tsr.Spec.Tags
	if len(tags) == 0 {
		tags = tsapi.Tags{"tag:k8s"}
	}

	logger := r.logger(tsr.Name)

	for replica := range replicas {
		key := types.NamespacedName{
			Namespace: r.tsNamespace,
			Name:      fmt.Sprintf("%s-auth-%d", tsr.Name, replica),
		}

		err := r.Get(ctx, key, &corev1.Secret{})
		switch {
		case err == nil:
			logger.Debugf("auth Secret %q already exists", key.Name)
			continue
		case !apierrors.IsNotFound(err):
			return fmt.Errorf("failed to get Secret %q: %w", key.Name, err)
		}

		authKey, err := newAuthKey(ctx, r.tsClient, tags.Stringify())
		if err != nil {
			return err
		}

		if err = r.Create(ctx, tsrAuthSecret(tsr, r.tsNamespace, authKey, replica)); err != nil {
			return err
		}
	}

	return nil
}

func (r *RecorderReconciler) validate(ctx context.Context, tsr *tsapi.Recorder) error {
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
			return fmt.Errorf("error getting ServiceAccount %q for validation: %w", tsr.Spec.StatefulSet.Pod.ServiceAccount.Name, err)
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

func (r *RecorderReconciler) getStateSecret(ctx context.Context, tsrName string, replica int32) (*corev1.Secret, error) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: r.tsNamespace,
			Name:      fmt.Sprintf("%s-%d", tsrName, replica),
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

func (r *RecorderReconciler) getDevicePrefs(ctx context.Context, tsrName string, replica int32) (prefs prefs, ok bool, err error) {
	secret, err := r.getStateSecret(ctx, tsrName, replica)
	if err != nil || secret == nil {
		return prefs, false, err
	}

	return getDevicePrefs(secret)
}

// getDevicePrefs returns 'ok == true' iff the node ID is found. The dnsName
// is expected to always be non-empty if the node ID is, but not required.
func getDevicePrefs(secret *corev1.Secret) (prefs prefs, ok bool, err error) {
	// TODO(tomhjp): Should maybe use ipn to parse the following info instead.
	currentProfile, ok := secret.Data[currentProfileKey]
	if !ok {
		return prefs, false, nil
	}
	profileBytes, ok := secret.Data[string(currentProfile)]
	if !ok {
		return prefs, false, nil
	}
	if err := json.Unmarshal(profileBytes, &prefs); err != nil {
		return prefs, false, fmt.Errorf("failed to extract node profile info from state Secret %s: %w", secret.Name, err)
	}

	ok = prefs.Config.NodeID != ""
	return prefs, ok, nil
}

func (r *RecorderReconciler) getDeviceInfo(ctx context.Context, tsrName string, replica int32) (d tsapi.RecorderTailnetDevice, ok bool, err error) {
	secret, err := r.getStateSecret(ctx, tsrName, replica)
	if err != nil || secret == nil {
		return tsapi.RecorderTailnetDevice{}, false, err
	}

	prefs, ok, err := getDevicePrefs(secret)
	if !ok || err != nil {
		return tsapi.RecorderTailnetDevice{}, false, err
	}

	// TODO(tomhjp): The profile info doesn't include addresses, which is why we
	// need the API. Should maybe update tsrecorder to write IPs to the state
	// Secret like containerboot does.
	device, err := r.tsClient.Device(ctx, string(prefs.Config.NodeID), nil)
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

// [prefs] is a subset of the ipn.Prefs struct used for extracting information
// from the state Secret of Tailscale devices.
type prefs struct {
	Config struct {
		NodeID      tailcfg.StableNodeID `json:"NodeID"`
		UserProfile struct {
			// LoginName is the MagicDNS name of the device, e.g. foo.tail-scale.ts.net.
			LoginName string `json:"LoginName"`
		} `json:"UserProfile"`
	} `json:"Config"`

	AdvertiseServices []string `json:"AdvertiseServices"`
}

func markedForDeletion(obj metav1.Object) bool {
	return !obj.GetDeletionTimestamp().IsZero()
}
