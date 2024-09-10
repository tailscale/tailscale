// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sync"

	"github.com/pkg/errors"
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
	reasonTSRecorderCreationFailed = "TSRecorderCreationFailed"
	reasonTSRecorderCreated        = "TSRecorderCreated"
	reasonTSRecorderInvalid        = "TSRecorderInvalid"

	currentProfileKey = "_current-profile"
)

var gaugeTSRecorderResources = clientmetric.NewGauge(kubetypes.MetricTSRecorderCount)

// TSRecorderReconciler syncs TSRecorder statefulsets with their definition in
// TSRecorder CRs.
type TSRecorderReconciler struct {
	client.Client
	l           *zap.SugaredLogger
	recorder    record.EventRecorder
	clock       tstime.Clock
	tsNamespace string
	tsClient    tsClient

	mu          sync.Mutex           // protects following
	tsRecorders set.Slice[types.UID] // for tsrecorders gauge
}

func (r *TSRecorderReconciler) logger(name string) *zap.SugaredLogger {
	return r.l.With("TSRecorder", name)
}

func (r *TSRecorderReconciler) Reconcile(ctx context.Context, req reconcile.Request) (_ reconcile.Result, err error) {
	logger := r.logger(req.Name)
	logger.Debugf("starting reconcile")
	defer logger.Debugf("reconcile finished")

	tsr := new(tsapi.TSRecorder)
	err = r.Get(ctx, req.NamespacedName, tsr)
	if apierrors.IsNotFound(err) {
		logger.Debugf("TSRecorder not found, assuming it was deleted")
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get tailscale.com TSRecorder: %w", err)
	}
	if markedForDeletion(tsr) {
		logger.Debugf("TSRecorder is being deleted, cleaning up resources")
		ix := xslices.Index(tsr.Finalizers, FinalizerName)
		if ix < 0 {
			logger.Debugf("no finalizer, nothing to do")
			return reconcile.Result{}, nil
		}

		if done, err := r.maybeCleanup(ctx, tsr); err != nil {
			return reconcile.Result{}, err
		} else if !done {
			logger.Debugf("TSRecorder resource cleanup not yet finished, will retry...")
			return reconcile.Result{RequeueAfter: shortRequeue}, nil
		}

		tsr.Finalizers = slices.Delete(tsr.Finalizers, ix, ix+1)
		if err := r.Update(ctx, tsr); err != nil {
			return reconcile.Result{}, err
		}
		return reconcile.Result{}, nil
	}

	oldTSRStatus := tsr.Status.DeepCopy()
	setStatusReady := func(tsr *tsapi.TSRecorder, status metav1.ConditionStatus, reason, message string) (reconcile.Result, error) {
		tsoperator.SetTSRecorderCondition(tsr, tsapi.TSRecorderReady, status, reason, message, tsr.Generation, r.clock, logger)
		if !apiequality.Semantic.DeepEqual(oldTSRStatus, tsr.Status) {
			// An error encountered here should get returned by the Reconcile function.
			if updateErr := r.Client.Status().Update(ctx, tsr); updateErr != nil {
				err = errors.Wrap(err, updateErr.Error())
			}
		}
		return reconcile.Result{}, err
	}

	if !slices.Contains(tsr.Finalizers, FinalizerName) {
		// This log line is printed exactly once during initial provisioning,
		// because once the finalizer is in place this block gets skipped. So,
		// this is a nice place to log that the high level, multi-reconcile
		// operation is underway.
		logger.Infof("ensuring TSRecorder is set up")
		tsr.Finalizers = append(tsr.Finalizers, FinalizerName)
		if err := r.Update(ctx, tsr); err != nil {
			logger.Errorf("error adding finalizer: %w", err)
			return setStatusReady(tsr, metav1.ConditionFalse, reasonTSRecorderCreationFailed, reasonTSRecorderCreationFailed)
		}
	}

	if err := r.validate(tsr); err != nil {
		logger.Errorf("error validating TSRecorder spec: %w", err)
		message := fmt.Sprintf("TSRecorder is invalid: %s", err)
		r.recorder.Eventf(tsr, corev1.EventTypeWarning, reasonTSRecorderInvalid, message)
		return setStatusReady(tsr, metav1.ConditionFalse, reasonTSRecorderInvalid, message)
	}

	if err = r.maybeProvision(ctx, tsr); err != nil {
		logger.Errorf("error creating TSRecorder resources: %w", err)
		message := fmt.Sprintf("failed creating TSRecorder: %s", err)
		r.recorder.Eventf(tsr, corev1.EventTypeWarning, reasonTSRecorderCreationFailed, message)
		return setStatusReady(tsr, metav1.ConditionFalse, reasonTSRecorderCreationFailed, message)
	}

	logger.Info("TSRecorder resources synced")
	return setStatusReady(tsr, metav1.ConditionTrue, reasonTSRecorderCreated, reasonTSRecorderCreated)
}

func (r *TSRecorderReconciler) maybeProvision(ctx context.Context, tsr *tsapi.TSRecorder) error {
	logger := r.logger(tsr.Name)

	r.mu.Lock()
	r.tsRecorders.Add(tsr.UID)
	gaugeTSRecorderResources.Set(int64(r.tsRecorders.Len()))
	r.mu.Unlock()

	if err := r.ensureAuthSecretCreated(ctx, tsr); err != nil {
		return fmt.Errorf("error creating secrets: %w", err)
	}
	// State secret is precreated so we can use the TSRecorder CR as its owner ref.
	sec := tsrStateSecret(tsr, r.tsNamespace)
	if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, sec, func(s *corev1.Secret) {
		s.ObjectMeta.Labels = sec.ObjectMeta.Labels
		s.ObjectMeta.Annotations = sec.ObjectMeta.Annotations
		s.ObjectMeta.OwnerReferences = sec.ObjectMeta.OwnerReferences
	}); err != nil {
		return fmt.Errorf("error creating state Secret: %w", err)
	}
	sa := tsrServiceAccount(tsr, r.tsNamespace)
	if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, sa, func(s *corev1.ServiceAccount) {
		s.ObjectMeta.Labels = sa.ObjectMeta.Labels
		s.ObjectMeta.Annotations = sa.ObjectMeta.Annotations
		s.ObjectMeta.OwnerReferences = sa.ObjectMeta.OwnerReferences
	}); err != nil {
		return fmt.Errorf("error creating ServiceAccount: %w", err)
	}
	role := tsrRole(tsr, r.tsNamespace)
	if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, role, func(r *rbacv1.Role) {
		r.ObjectMeta.Labels = role.ObjectMeta.Labels
		r.ObjectMeta.Annotations = role.ObjectMeta.Annotations
		r.ObjectMeta.OwnerReferences = role.ObjectMeta.OwnerReferences
		r.Rules = role.Rules
	}); err != nil {
		return fmt.Errorf("error creating Role: %w", err)
	}
	roleBinding := tsrRoleBinding(tsr, r.tsNamespace)
	if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, roleBinding, func(r *rbacv1.RoleBinding) {
		r.ObjectMeta.Labels = roleBinding.ObjectMeta.Labels
		r.ObjectMeta.Annotations = roleBinding.ObjectMeta.Annotations
		r.ObjectMeta.OwnerReferences = roleBinding.ObjectMeta.OwnerReferences
		r.RoleRef = roleBinding.RoleRef
		r.Subjects = roleBinding.Subjects
	}); err != nil {
		return fmt.Errorf("error creating RoleBinding: %w", err)
	}
	ss := tsrStatefulSet(tsr, r.tsNamespace)
	if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, ss, func(s *appsv1.StatefulSet) {
		s.ObjectMeta.Labels = ss.ObjectMeta.Labels
		s.ObjectMeta.Annotations = ss.ObjectMeta.Annotations
		s.ObjectMeta.OwnerReferences = ss.ObjectMeta.OwnerReferences
		s.Spec = ss.Spec
	}); err != nil {
		return fmt.Errorf("error creating StatefulSet: %w", err)
	}

	var devices []tsapi.TailnetDevice

	device, ok, err := r.getDeviceInfo(ctx, tsr.Name)
	if err != nil {
		return fmt.Errorf("failed to get device info: %w", err)
	}
	if !ok {
		logger.Debugf("no Tailscale hostname known yet, waiting for tsrecorder pod to finish auth")
		return nil
	}

	devices = append(devices, device)

	tsr.Status.Devices = devices

	return nil
}

// maybeCleanup just deletes the device from the tailnet. All the kubernetes
// resources linked to a TSRecorder will get cleaned up via owner references
// (which we can use because they are all in the same namespace).
func (r *TSRecorderReconciler) maybeCleanup(ctx context.Context, tsr *tsapi.TSRecorder) (bool, error) {
	logger := r.logger(tsr.Name)

	id, _, ok, err := r.getNodeMetadata(ctx, tsr.Name)
	if err != nil {
		return false, err
	}
	if !ok {
		logger.Debugf("state Secret %s-0 not found or does not contain node ID, continuing cleanup", tsr.Name)
		r.mu.Lock()
		r.tsRecorders.Remove(tsr.UID)
		gaugeTSRecorderResources.Set(int64(r.tsRecorders.Len()))
		r.mu.Unlock()
		return true, nil
	}

	logger.Debugf("deleting device %s from control", string(id))
	if err := r.tsClient.DeleteDevice(ctx, string(id)); err != nil {
		errResp := &tailscale.ErrResponse{}
		if ok := errors.As(err, errResp); ok && errResp.Status == http.StatusNotFound {
			logger.Debugf("device %s not found, likely because it has already been deleted from control", string(id))
		} else {
			return false, fmt.Errorf("error deleting device: %w", err)
		}
	} else {
		logger.Debugf("device %s deleted from control", string(id))
	}

	// Unlike most log entries in the reconcile loop, this will get printed
	// exactly once at the very end of cleanup, because the final step of
	// cleanup removes the tailscale finalizer, which will make all future
	// reconciles exit early.
	logger.Infof("cleaned up TSRecorder resources")
	r.mu.Lock()
	r.tsRecorders.Remove(tsr.UID)
	gaugeTSRecorderResources.Set(int64(r.tsRecorders.Len()))
	r.mu.Unlock()
	return true, nil
}

func (r *TSRecorderReconciler) ensureAuthSecretCreated(ctx context.Context, tsr *tsapi.TSRecorder) error {
	logger := r.logger(tsr.Name)
	key := types.NamespacedName{
		Namespace: r.tsNamespace,
		Name:      tsr.Name,
	}
	if err := r.Get(ctx, key, &corev1.Secret{}); err == nil {
		// No updates, already created the auth key.
		logger.Debugf("auth Secret %s already exists", key.Name)
		return nil
	} else if !apierrors.IsNotFound(err) {
		return err
	}

	// Create the auth key Secret which is going to be used by the StatefulSet
	// to authenticate with Tailscale.
	logger.Debugf("creating authkey for new TSRecorder")
	tags := tsr.Spec.Tags
	if len(tags) == 0 {
		tags = tsapi.Tags{"tag:k8s"}
	}
	authKey, err := newAuthKey(ctx, r.tsClient, tags.Stringify())
	if err != nil {
		return err
	}

	logger.Debug("creating a new Secret for the TSRecorder")
	if err := r.Create(ctx, tsrAuthSecret(tsr, r.tsNamespace, authKey)); err != nil {
		return err
	}

	return nil
}

func (r *TSRecorderReconciler) validate(tsr *tsapi.TSRecorder) error {
	if !tsr.Spec.EnableUI && tsr.Spec.Storage.S3 == nil {
		return errors.New("must either enable UI or use S3 storage to ensure recordings are accessible")
	}

	return nil
}

// getNodeMetadata returns 'ok == true' iff the node ID is found. The dnsName
// is expected to always be non-empty if the node ID is, but not required.
func (r *TSRecorderReconciler) getNodeMetadata(ctx context.Context, tsrName string) (id tailcfg.StableNodeID, dnsName string, ok bool, err error) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: r.tsNamespace,
			Name:      fmt.Sprintf("%s-0", tsrName),
		},
	}
	if err := r.Get(ctx, client.ObjectKeyFromObject(secret), secret); err != nil {
		if apierrors.IsNotFound(err) {
			return "", "", false, nil
		}

		return "", "", false, err
	}

	// TODO(tomhjp): Should maybe use ipn to parse the following info instead.
	currentProfile, ok := secret.Data[currentProfileKey]
	if !ok {
		return "", "", false, nil
	}
	profileBytes, ok := secret.Data[string(currentProfile)]
	if !ok {
		return "", "", false, nil
	}
	var profile profile
	if err := json.Unmarshal(profileBytes, &profile); err != nil {
		return "", "", false, fmt.Errorf("failed to extract node profile info from state Secret %s: %w", secret.Name, err)
	}

	ok = profile.Config.NodeID != ""
	return tailcfg.StableNodeID(profile.Config.NodeID), profile.Config.UserProfile.LoginName, ok, nil
}

func (r *TSRecorderReconciler) getDeviceInfo(ctx context.Context, tsrName string) (d tsapi.TailnetDevice, ok bool, err error) {
	nodeID, dnsName, ok, err := r.getNodeMetadata(ctx, tsrName)
	if !ok || err != nil {
		return tsapi.TailnetDevice{}, false, err
	}

	// TODO(tomhjp): The profile info doesn't include addresses, which is why we
	// need the API. Should we instead update the profile to include addresses?
	device, err := r.tsClient.Device(ctx, string(nodeID), nil)
	if err != nil {
		return tsapi.TailnetDevice{}, false, fmt.Errorf("failed to get device info from API: %w", err)
	}

	d = tsapi.TailnetDevice{
		Hostname:   device.Hostname,
		TailnetIPs: device.Addresses,
	}
	if dnsName != "" {
		d.URL = fmt.Sprintf("https://%s", dnsName)
	}

	return d, true, nil
}

type profile struct {
	Config struct {
		NodeID      string `json:"NodeID"`
		UserProfile struct {
			LoginName string `json:"LoginName"`
		} `json:"UserProfile"`
	} `json:"Config"`
}

func markedForDeletion(tsr *tsapi.TSRecorder) bool {
	return !tsr.DeletionTimestamp.IsZero()
}
