// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
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
	"tailscale.com/ipn"
	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
	"tailscale.com/types/ptr"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
)

const (
	reasonProxyGroupCreationFailed = "ProxyGroupCreationFailed"
	reasonProxyGroupReady          = "ProxyGroupReady"
	reasonProxyGroupCreating       = "ProxyGroupCreating"
	reasonProxyGroupInvalid        = "ProxyGroupInvalid"

	// Copied from k8s.io/apiserver/pkg/registry/generic/registry/store.go@cccad306d649184bf2a0e319ba830c53f65c445c
	optimisticLockErrorMsg = "the object has been modified; please apply your changes to the latest version and try again"
)

var gaugeProxyGroupResources = clientmetric.NewGauge(kubetypes.MetricProxyGroupEgressCount)

// ProxyGroupReconciler ensures cluster resources for a ProxyGroup definition.
type ProxyGroupReconciler struct {
	client.Client
	l        *zap.SugaredLogger
	recorder record.EventRecorder
	clock    tstime.Clock
	tsClient tsClient

	// User-specified defaults from the helm installation.
	tsNamespace       string
	proxyImage        string
	defaultTags       []string
	tsFirewallMode    string
	defaultProxyClass string

	mu          sync.Mutex           // protects following
	proxyGroups set.Slice[types.UID] // for proxygroups gauge
}

func (r *ProxyGroupReconciler) logger(name string) *zap.SugaredLogger {
	return r.l.With("ProxyGroup", name)
}

func (r *ProxyGroupReconciler) Reconcile(ctx context.Context, req reconcile.Request) (_ reconcile.Result, err error) {
	logger := r.logger(req.Name)
	logger.Debugf("starting reconcile")
	defer logger.Debugf("reconcile finished")

	pg := new(tsapi.ProxyGroup)
	err = r.Get(ctx, req.NamespacedName, pg)
	if apierrors.IsNotFound(err) {
		logger.Debugf("ProxyGroup not found, assuming it was deleted")
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get tailscale.com ProxyGroup: %w", err)
	}
	if markedForDeletion(pg) {
		logger.Debugf("ProxyGroup is being deleted, cleaning up resources")
		ix := xslices.Index(pg.Finalizers, FinalizerName)
		if ix < 0 {
			logger.Debugf("no finalizer, nothing to do")
			return reconcile.Result{}, nil
		}

		if done, err := r.maybeCleanup(ctx, pg); err != nil {
			return reconcile.Result{}, err
		} else if !done {
			logger.Debugf("ProxyGroup resource cleanup not yet finished, will retry...")
			return reconcile.Result{RequeueAfter: shortRequeue}, nil
		}

		pg.Finalizers = slices.Delete(pg.Finalizers, ix, ix+1)
		if err := r.Update(ctx, pg); err != nil {
			return reconcile.Result{}, err
		}
		return reconcile.Result{}, nil
	}

	oldPGStatus := pg.Status.DeepCopy()
	setStatusReady := func(pg *tsapi.ProxyGroup, status metav1.ConditionStatus, reason, message string) (reconcile.Result, error) {
		tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupReady, status, reason, message, pg.Generation, r.clock, logger)
		if !apiequality.Semantic.DeepEqual(oldPGStatus, &pg.Status) {
			// An error encountered here should get returned by the Reconcile function.
			if updateErr := r.Client.Status().Update(ctx, pg); updateErr != nil {
				err = errors.Wrap(err, updateErr.Error())
			}
		}
		return reconcile.Result{}, err
	}

	if !slices.Contains(pg.Finalizers, FinalizerName) {
		// This log line is printed exactly once during initial provisioning,
		// because once the finalizer is in place this block gets skipped. So,
		// this is a nice place to log that the high level, multi-reconcile
		// operation is underway.
		logger.Infof("ensuring ProxyGroup is set up")
		pg.Finalizers = append(pg.Finalizers, FinalizerName)
		if err = r.Update(ctx, pg); err != nil {
			err = fmt.Errorf("error adding finalizer: %w", err)
			return setStatusReady(pg, metav1.ConditionFalse, reasonProxyGroupCreationFailed, reasonProxyGroupCreationFailed)
		}
	}

	if err = r.validate(pg); err != nil {
		message := fmt.Sprintf("ProxyGroup is invalid: %s", err)
		r.recorder.Eventf(pg, corev1.EventTypeWarning, reasonProxyGroupInvalid, message)
		return setStatusReady(pg, metav1.ConditionFalse, reasonProxyGroupInvalid, message)
	}

	proxyClassName := r.defaultProxyClass
	if pg.Spec.ProxyClass != "" {
		proxyClassName = pg.Spec.ProxyClass
	}

	var proxyClass *tsapi.ProxyClass
	if proxyClassName != "" {
		proxyClass = new(tsapi.ProxyClass)
		err := r.Get(ctx, types.NamespacedName{Name: proxyClassName}, proxyClass)
		if apierrors.IsNotFound(err) {
			err = nil
			message := fmt.Sprintf("the ProxyGroup's ProxyClass %s does not (yet) exist", proxyClassName)
			logger.Info(message)
			return setStatusReady(pg, metav1.ConditionFalse, reasonProxyGroupCreating, message)
		}
		if err != nil {
			err = fmt.Errorf("error getting ProxyGroup's ProxyClass %s: %s", proxyClassName, err)
			r.recorder.Eventf(pg, corev1.EventTypeWarning, reasonProxyGroupCreationFailed, err.Error())
			return setStatusReady(pg, metav1.ConditionFalse, reasonProxyGroupCreationFailed, err.Error())
		}
		if !tsoperator.ProxyClassIsReady(proxyClass) {
			message := fmt.Sprintf("the ProxyGroup's ProxyClass %s is not yet in a ready state, waiting...", proxyClassName)
			logger.Info(message)
			return setStatusReady(pg, metav1.ConditionFalse, reasonProxyGroupCreating, message)
		}
	}

	if err = r.maybeProvision(ctx, pg, proxyClass); err != nil {
		reason := reasonProxyGroupCreationFailed
		msg := fmt.Sprintf("error provisioning ProxyGroup resources: %s", err)
		if strings.Contains(err.Error(), optimisticLockErrorMsg) {
			reason = reasonProxyGroupCreating
			msg = fmt.Sprintf("optimistic lock error, retrying: %s", err)
			err = nil
			logger.Info(msg)
		} else {
			r.recorder.Eventf(pg, corev1.EventTypeWarning, reason, msg)
		}
		return setStatusReady(pg, metav1.ConditionFalse, reason, msg)
	}

	desiredReplicas := int(pgReplicas(pg))
	if len(pg.Status.Devices) < desiredReplicas {
		message := fmt.Sprintf("%d/%d ProxyGroup pods running", len(pg.Status.Devices), desiredReplicas)
		logger.Debug(message)
		return setStatusReady(pg, metav1.ConditionFalse, reasonProxyGroupCreating, message)
	}

	if len(pg.Status.Devices) > desiredReplicas {
		message := fmt.Sprintf("waiting for %d ProxyGroup pods to shut down", len(pg.Status.Devices)-desiredReplicas)
		logger.Debug(message)
		return setStatusReady(pg, metav1.ConditionFalse, reasonProxyGroupCreating, message)
	}

	logger.Info("ProxyGroup resources synced")
	return setStatusReady(pg, metav1.ConditionTrue, reasonProxyGroupReady, reasonProxyGroupReady)
}

func (r *ProxyGroupReconciler) maybeProvision(ctx context.Context, pg *tsapi.ProxyGroup, proxyClass *tsapi.ProxyClass) error {
	logger := r.logger(pg.Name)
	r.mu.Lock()
	r.proxyGroups.Add(pg.UID)
	gaugeProxyGroupResources.Set(int64(r.proxyGroups.Len()))
	r.mu.Unlock()

	cfgHash, err := r.ensureConfigSecretsCreated(ctx, pg, proxyClass)
	if err != nil {
		return fmt.Errorf("error provisioning config Secrets: %w", err)
	}
	// State secrets are precreated so we can use the ProxyGroup CR as their owner ref.
	stateSecrets := pgStateSecrets(pg, r.tsNamespace)
	for _, sec := range stateSecrets {
		if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, sec, func(s *corev1.Secret) {
			s.ObjectMeta.Labels = sec.ObjectMeta.Labels
			s.ObjectMeta.Annotations = sec.ObjectMeta.Annotations
			s.ObjectMeta.OwnerReferences = sec.ObjectMeta.OwnerReferences
		}); err != nil {
			return fmt.Errorf("error provisioning state Secrets: %w", err)
		}
	}
	sa := pgServiceAccount(pg, r.tsNamespace)
	if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, sa, func(s *corev1.ServiceAccount) {
		s.ObjectMeta.Labels = sa.ObjectMeta.Labels
		s.ObjectMeta.Annotations = sa.ObjectMeta.Annotations
		s.ObjectMeta.OwnerReferences = sa.ObjectMeta.OwnerReferences
	}); err != nil {
		return fmt.Errorf("error provisioning ServiceAccount: %w", err)
	}
	role := pgRole(pg, r.tsNamespace)
	if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, role, func(r *rbacv1.Role) {
		r.ObjectMeta.Labels = role.ObjectMeta.Labels
		r.ObjectMeta.Annotations = role.ObjectMeta.Annotations
		r.ObjectMeta.OwnerReferences = role.ObjectMeta.OwnerReferences
		r.Rules = role.Rules
	}); err != nil {
		return fmt.Errorf("error provisioning Role: %w", err)
	}
	roleBinding := pgRoleBinding(pg, r.tsNamespace)
	if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, roleBinding, func(r *rbacv1.RoleBinding) {
		r.ObjectMeta.Labels = roleBinding.ObjectMeta.Labels
		r.ObjectMeta.Annotations = roleBinding.ObjectMeta.Annotations
		r.ObjectMeta.OwnerReferences = roleBinding.ObjectMeta.OwnerReferences
		r.RoleRef = roleBinding.RoleRef
		r.Subjects = roleBinding.Subjects
	}); err != nil {
		return fmt.Errorf("error provisioning RoleBinding: %w", err)
	}
	if pg.Spec.Type == tsapi.ProxyGroupTypeEgress {
		cm := pgEgressCM(pg, r.tsNamespace)
		if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, cm, func(existing *corev1.ConfigMap) {
			existing.ObjectMeta.Labels = cm.ObjectMeta.Labels
			existing.ObjectMeta.OwnerReferences = cm.ObjectMeta.OwnerReferences
		}); err != nil {
			return fmt.Errorf("error provisioning ConfigMap: %w", err)
		}
	}
	ss, err := pgStatefulSet(pg, r.tsNamespace, r.proxyImage, r.tsFirewallMode, cfgHash)
	if err != nil {
		return fmt.Errorf("error generating StatefulSet spec: %w", err)
	}
	ss = applyProxyClassToStatefulSet(proxyClass, ss, nil, logger)
	if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, ss, func(s *appsv1.StatefulSet) {
		s.ObjectMeta.Labels = ss.ObjectMeta.Labels
		s.ObjectMeta.Annotations = ss.ObjectMeta.Annotations
		s.ObjectMeta.OwnerReferences = ss.ObjectMeta.OwnerReferences
		s.Spec = ss.Spec
	}); err != nil {
		return fmt.Errorf("error provisioning StatefulSet: %w", err)
	}
	mo := &metricsOpts{
		tsNamespace:  r.tsNamespace,
		proxyStsName: pg.Name,
		proxyLabels:  pgLabels(pg.Name, nil),
		proxyType:    "proxygroup",
	}
	if err := reconcileMetricsResources(ctx, logger, mo, proxyClass, r.Client); err != nil {
		return fmt.Errorf("error reconciling metrics resources: %w", err)
	}

	if err := r.cleanupDanglingResources(ctx, pg); err != nil {
		return fmt.Errorf("error cleaning up dangling resources: %w", err)
	}

	devices, err := r.getDeviceInfo(ctx, pg)
	if err != nil {
		return fmt.Errorf("failed to get device info: %w", err)
	}

	pg.Status.Devices = devices

	return nil
}

// cleanupDanglingResources ensures we don't leak config secrets, state secrets, and
// tailnet devices when the number of replicas specified is reduced.
func (r *ProxyGroupReconciler) cleanupDanglingResources(ctx context.Context, pg *tsapi.ProxyGroup) error {
	logger := r.logger(pg.Name)
	metadata, err := r.getNodeMetadata(ctx, pg)
	if err != nil {
		return err
	}

	for _, m := range metadata {
		if m.ordinal+1 <= int(pgReplicas(pg)) {
			continue
		}

		// Dangling resource, delete the config + state Secrets, as well as
		// deleting the device from the tailnet.
		if err := r.deleteTailnetDevice(ctx, m.tsID, logger); err != nil {
			return err
		}
		if err := r.Delete(ctx, m.stateSecret); err != nil {
			if !apierrors.IsNotFound(err) {
				return fmt.Errorf("error deleting state Secret %s: %w", m.stateSecret.Name, err)
			}
		}
		configSecret := m.stateSecret.DeepCopy()
		configSecret.Name += "-config"
		if err := r.Delete(ctx, configSecret); err != nil {
			if !apierrors.IsNotFound(err) {
				return fmt.Errorf("error deleting config Secret %s: %w", configSecret.Name, err)
			}
		}
	}

	return nil
}

// maybeCleanup just deletes the device from the tailnet. All the kubernetes
// resources linked to a ProxyGroup will get cleaned up via owner references
// (which we can use because they are all in the same namespace).
func (r *ProxyGroupReconciler) maybeCleanup(ctx context.Context, pg *tsapi.ProxyGroup) (bool, error) {
	logger := r.logger(pg.Name)

	metadata, err := r.getNodeMetadata(ctx, pg)
	if err != nil {
		return false, err
	}

	for _, m := range metadata {
		if err := r.deleteTailnetDevice(ctx, m.tsID, logger); err != nil {
			return false, err
		}
	}

	mo := &metricsOpts{
		proxyLabels: pgLabels(pg.Name, nil),
		tsNamespace: r.tsNamespace,
		proxyType:   "proxygroup"}
	if err := maybeCleanupMetricsResources(ctx, mo, r.Client); err != nil {
		return false, fmt.Errorf("error cleaning up metrics resources: %w", err)
	}

	logger.Infof("cleaned up ProxyGroup resources")
	r.mu.Lock()
	r.proxyGroups.Remove(pg.UID)
	gaugeProxyGroupResources.Set(int64(r.proxyGroups.Len()))
	r.mu.Unlock()
	return true, nil
}

func (r *ProxyGroupReconciler) deleteTailnetDevice(ctx context.Context, id tailcfg.StableNodeID, logger *zap.SugaredLogger) error {
	logger.Debugf("deleting device %s from control", string(id))
	if err := r.tsClient.DeleteDevice(ctx, string(id)); err != nil {
		errResp := &tailscale.ErrResponse{}
		if ok := errors.As(err, errResp); ok && errResp.Status == http.StatusNotFound {
			logger.Debugf("device %s not found, likely because it has already been deleted from control", string(id))
		} else {
			return fmt.Errorf("error deleting device: %w", err)
		}
	} else {
		logger.Debugf("device %s deleted from control", string(id))
	}

	return nil
}

func (r *ProxyGroupReconciler) ensureConfigSecretsCreated(ctx context.Context, pg *tsapi.ProxyGroup, proxyClass *tsapi.ProxyClass) (hash string, err error) {
	logger := r.logger(pg.Name)
	var configSHA256Sum string
	for i := range pgReplicas(pg) {
		cfgSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:            fmt.Sprintf("%s-%d-config", pg.Name, i),
				Namespace:       r.tsNamespace,
				Labels:          pgSecretLabels(pg.Name, "config"),
				OwnerReferences: pgOwnerReference(pg),
			},
		}

		var existingCfgSecret *corev1.Secret // unmodified copy of secret
		if err := r.Get(ctx, client.ObjectKeyFromObject(cfgSecret), cfgSecret); err == nil {
			logger.Debugf("secret %s/%s already exists", cfgSecret.GetNamespace(), cfgSecret.GetName())
			existingCfgSecret = cfgSecret.DeepCopy()
		} else if !apierrors.IsNotFound(err) {
			return "", err
		}

		var authKey string
		if existingCfgSecret == nil {
			logger.Debugf("creating authkey for new ProxyGroup proxy")
			tags := pg.Spec.Tags.Stringify()
			if len(tags) == 0 {
				tags = r.defaultTags
			}
			authKey, err = newAuthKey(ctx, r.tsClient, tags)
			if err != nil {
				return "", err
			}
		}

		configs, err := pgTailscaledConfig(pg, proxyClass, i, authKey, existingCfgSecret)
		if err != nil {
			return "", fmt.Errorf("error creating tailscaled config: %w", err)
		}

		for cap, cfg := range configs {
			cfgJSON, err := json.Marshal(cfg)
			if err != nil {
				return "", fmt.Errorf("error marshalling tailscaled config: %w", err)
			}
			mak.Set(&cfgSecret.StringData, tsoperator.TailscaledConfigFileName(cap), string(cfgJSON))
		}

		// The config sha256 sum is a value for a hash annotation used to trigger
		// pod restarts when tailscaled config changes. Any config changes apply
		// to all replicas, so it is sufficient to only hash the config for the
		// first replica.
		//
		// In future, we're aiming to eliminate restarts altogether and have
		// pods dynamically reload their config when it changes.
		if i == 0 {
			sum := sha256.New()
			for _, cfg := range configs {
				// Zero out the auth key so it doesn't affect the sha256 hash when we
				// remove it from the config after the pods have all authed. Otherwise
				// all the pods will need to restart immediately after authing.
				cfg.AuthKey = nil
				b, err := json.Marshal(cfg)
				if err != nil {
					return "", err
				}
				if _, err := sum.Write(b); err != nil {
					return "", err
				}
			}

			configSHA256Sum = fmt.Sprintf("%x", sum.Sum(nil))
		}

		if existingCfgSecret != nil {
			logger.Debugf("patching the existing ProxyGroup config Secret %s", cfgSecret.Name)
			if err := r.Patch(ctx, cfgSecret, client.MergeFrom(existingCfgSecret)); err != nil {
				return "", err
			}
		} else {
			logger.Debugf("creating a new config Secret %s for the ProxyGroup", cfgSecret.Name)
			if err := r.Create(ctx, cfgSecret); err != nil {
				return "", err
			}
		}
	}

	return configSHA256Sum, nil
}

func pgTailscaledConfig(pg *tsapi.ProxyGroup, class *tsapi.ProxyClass, idx int32, authKey string, oldSecret *corev1.Secret) (tailscaledConfigs, error) {
	conf := &ipn.ConfigVAlpha{
		Version:      "alpha0",
		AcceptDNS:    "false",
		AcceptRoutes: "false", // AcceptRoutes defaults to true
		Locked:       "false",
		Hostname:     ptr.To(fmt.Sprintf("%s-%d", pg.Name, idx)),
	}

	if pg.Spec.HostnamePrefix != "" {
		conf.Hostname = ptr.To(fmt.Sprintf("%s%d", pg.Spec.HostnamePrefix, idx))
	}

	if shouldAcceptRoutes(class) {
		conf.AcceptRoutes = "true"
	}

	deviceAuthed := false
	for _, d := range pg.Status.Devices {
		if d.Hostname == *conf.Hostname {
			deviceAuthed = true
			break
		}
	}

	if authKey != "" {
		conf.AuthKey = &authKey
	} else if !deviceAuthed {
		key, err := authKeyFromSecret(oldSecret)
		if err != nil {
			return nil, fmt.Errorf("error retrieving auth key from Secret: %w", err)
		}
		conf.AuthKey = key
	}
	capVerConfigs := make(map[tailcfg.CapabilityVersion]ipn.ConfigVAlpha)
	capVerConfigs[106] = *conf
	return capVerConfigs, nil
}

func (r *ProxyGroupReconciler) validate(_ *tsapi.ProxyGroup) error {
	return nil
}

// getNodeMetadata gets metadata for all the pods owned by this ProxyGroup by
// querying their state Secrets. It may not return the same number of items as
// specified in the ProxyGroup spec if e.g. it is getting scaled up or down, or
// some pods have failed to write state.
func (r *ProxyGroupReconciler) getNodeMetadata(ctx context.Context, pg *tsapi.ProxyGroup) (metadata []nodeMetadata, _ error) {
	// List all state secrets owned by this ProxyGroup.
	secrets := &corev1.SecretList{}
	if err := r.List(ctx, secrets, client.InNamespace(r.tsNamespace), client.MatchingLabels(pgSecretLabels(pg.Name, "state"))); err != nil {
		return nil, fmt.Errorf("failed to list state Secrets: %w", err)
	}
	for _, secret := range secrets.Items {
		var ordinal int
		if _, err := fmt.Sscanf(secret.Name, pg.Name+"-%d", &ordinal); err != nil {
			return nil, fmt.Errorf("unexpected secret %s was labelled as owned by the ProxyGroup %s: %w", secret.Name, pg.Name, err)
		}

		id, dnsName, ok, err := getNodeMetadata(ctx, &secret)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}

		metadata = append(metadata, nodeMetadata{
			ordinal:     ordinal,
			stateSecret: &secret,
			tsID:        id,
			dnsName:     dnsName,
		})
	}

	return metadata, nil
}

func (r *ProxyGroupReconciler) getDeviceInfo(ctx context.Context, pg *tsapi.ProxyGroup) (devices []tsapi.TailnetDevice, _ error) {
	metadata, err := r.getNodeMetadata(ctx, pg)
	if err != nil {
		return nil, err
	}

	for _, m := range metadata {
		device, ok, err := getDeviceInfo(ctx, r.tsClient, m.stateSecret)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		devices = append(devices, tsapi.TailnetDevice{
			Hostname:   device.Hostname,
			TailnetIPs: device.TailnetIPs,
		})
	}

	return devices, nil
}

type nodeMetadata struct {
	ordinal     int
	stateSecret *corev1.Secret
	tsID        tailcfg.StableNodeID
	dnsName     string
}
