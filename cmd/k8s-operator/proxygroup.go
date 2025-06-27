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
	"net/netip"
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
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn"
	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/egressservices"
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
	optimisticLockErrorMsg  = "the object has been modified; please apply your changes to the latest version and try again"
	staticEndpointsMaxAddrs = 2

	// The minimum tailcfg.CapabilityVersion that deployed clients are expected
	// to support to be compatible with the current ProxyGroup controller.
	// If the controller needs to depend on newer client behaviour, it should
	// maintain backwards compatible logic for older capability versions for 3
	// stable releases, as per documentation on supported version drift:
	// https://tailscale.com/kb/1236/kubernetes-operator#supported-versions
	//
	// tailcfg.CurrentCapabilityVersion was 106 when the ProxyGroup controller was
	// first introduced.
	pgMinCapabilityVersion = 106
)

var (
	gaugeEgressProxyGroupResources  = clientmetric.NewGauge(kubetypes.MetricProxyGroupEgressCount)
	gaugeIngressProxyGroupResources = clientmetric.NewGauge(kubetypes.MetricProxyGroupIngressCount)
)

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

	mu                 sync.Mutex           // protects following
	egressProxyGroups  set.Slice[types.UID] // for egress proxygroups gauge
	ingressProxyGroups set.Slice[types.UID] // for ingress proxygroups gauge
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
				err = errors.Join(err, updateErr)
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
		validateProxyClassForPG(logger, pg, proxyClass)
		if !tsoperator.ProxyClassIsReady(proxyClass) {
			message := fmt.Sprintf("the ProxyGroup's ProxyClass %s is not yet in a ready state, waiting...", proxyClassName)
			logger.Info(message)
			return setStatusReady(pg, metav1.ConditionFalse, reasonProxyGroupCreating, message)
		}
	}

	isProvisioned, err := r.maybeProvision(ctx, pg, proxyClass)
	if err != nil {
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

	if !isProvisioned {
		if !apiequality.Semantic.DeepEqual(oldPGStatus, &pg.Status) {
			// An error encountered here should get returned by the Reconcile function.
			if updateErr := r.Client.Status().Update(ctx, pg); updateErr != nil {
				return reconcile.Result{}, errors.Join(err, updateErr)
			}
		}
		return
	}

	desiredReplicas := int(pgReplicas(pg))

	// Set ProxyGroupAvailable condition.
	status := metav1.ConditionFalse
	reason := reasonProxyGroupCreating
	message := fmt.Sprintf("%d/%d ProxyGroup pods running", len(pg.Status.Devices), desiredReplicas)
	if len(pg.Status.Devices) > 0 {
		status = metav1.ConditionTrue
		if len(pg.Status.Devices) == desiredReplicas {
			reason = reasonProxyGroupReady
		}
	}
	tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupAvailable, status, reason, message, pg.Generation, r.clock, logger)

	// Set ProxyGroupReady condition.
	if len(pg.Status.Devices) < desiredReplicas {
		logger.Debug(message)
		return setStatusReady(pg, metav1.ConditionFalse, reasonProxyGroupCreating, message)
	}

	if len(pg.Status.Devices) > desiredReplicas {
		message = fmt.Sprintf("waiting for %d ProxyGroup pods to shut down", len(pg.Status.Devices)-desiredReplicas)
		logger.Debug(message)
		return setStatusReady(pg, metav1.ConditionFalse, reasonProxyGroupCreating, message)
	}

	logger.Info("ProxyGroup resources synced")
	return setStatusReady(pg, metav1.ConditionTrue, reasonProxyGroupReady, reasonProxyGroupReady)
}

// validateProxyClassForPG applies custom validation logic for ProxyClass applied to ProxyGroup.
func validateProxyClassForPG(logger *zap.SugaredLogger, pg *tsapi.ProxyGroup, pc *tsapi.ProxyClass) {
	if pg.Spec.Type == tsapi.ProxyGroupTypeIngress {
		return
	}
	// Our custom logic for ensuring minimum downtime ProxyGroup update rollouts relies on the local health check
	// beig accessible on the replica Pod IP:9002. This address can also be modified by users, via
	// TS_LOCAL_ADDR_PORT env var.
	//
	// Currently TS_LOCAL_ADDR_PORT controls Pod's health check and metrics address. _Probably_ there is no need for
	// users to set this to a custom value. Users who want to consume metrics, should integrate with the metrics
	// Service and/or ServiceMonitor, rather than Pods directly. The health check is likely not useful to integrate
	// directly with for operator proxies (and we should aim for unified lifecycle logic in the operator, users
	// shouldn't need to set their own).
	//
	// TODO(irbekrm): maybe disallow configuring this env var in future (in Tailscale 1.84 or later).
	if hasLocalAddrPortSet(pc) {
		msg := fmt.Sprintf("ProxyClass %s applied to an egress ProxyGroup has TS_LOCAL_ADDR_PORT env var set to a custom value."+
			"This will disable the ProxyGroup graceful failover mechanism, so you might experience downtime when ProxyGroup pods are restarted."+
			"In future we will remove the ability to set custom TS_LOCAL_ADDR_PORT for egress ProxyGroups."+
			"Please raise an issue if you expect that this will cause issues for your workflow.", pc.Name)
		logger.Warn(msg)
	}
}

func (r *ProxyGroupReconciler) maybeProvision(ctx context.Context, pg *tsapi.ProxyGroup, proxyClass *tsapi.ProxyClass) (isProvisioned bool, err error) {
	logger := r.logger(pg.Name)
	r.mu.Lock()
	r.ensureAddedToGaugeForProxyGroup(pg)
	r.mu.Unlock()

	svcToNodePorts := make(map[string]uint16)
	var tailscaledPort *uint16
	if proxyClass != nil && proxyClass.Spec.StaticEndpoints != nil {
		svcToNodePorts, tailscaledPort, err = r.ensureNodePortServiceCreated(ctx, pg, proxyClass)
		if err != nil {
			wrappedErr := fmt.Errorf("error provisioning NodePort Services for static endpoints: %w", err)
			var allocatePortErr *allocatePortsErr
			if errors.As(err, &allocatePortErr) {
				reason := reasonProxyGroupCreationFailed
				msg := fmt.Sprintf("error provisioning ProxyGroup resources: %s", wrappedErr)
				r.setStatusReady(pg, metav1.ConditionFalse, reason, msg, logger)
				return false, nil
			}
			return false, wrappedErr
		}
	}

	staticEndpoints, err := r.ensureConfigSecretsCreated(ctx, pg, proxyClass, svcToNodePorts)
	if err != nil {
		wrappedErr := fmt.Errorf("error provisioning config Secrets: %w", err)
		var selectorErr *FindStaticEndpointErr
		if errors.As(err, &selectorErr) {
			reason := reasonProxyGroupCreationFailed
			msg := fmt.Sprintf("error provisioning ProxyGroup resources: %s", wrappedErr)
			r.setStatusReady(pg, metav1.ConditionFalse, reason, msg, logger)
			return false, nil
		}
		return false, wrappedErr
	}

	// State secrets are precreated so we can use the ProxyGroup CR as their owner ref.
	stateSecrets := pgStateSecrets(pg, r.tsNamespace)
	for _, sec := range stateSecrets {
		if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, sec, func(s *corev1.Secret) {
			s.ObjectMeta.Labels = sec.ObjectMeta.Labels
			s.ObjectMeta.Annotations = sec.ObjectMeta.Annotations
			s.ObjectMeta.OwnerReferences = sec.ObjectMeta.OwnerReferences
		}); err != nil {
			return false, fmt.Errorf("error provisioning state Secrets: %w", err)
		}
	}
	sa := pgServiceAccount(pg, r.tsNamespace)
	if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, sa, func(s *corev1.ServiceAccount) {
		s.ObjectMeta.Labels = sa.ObjectMeta.Labels
		s.ObjectMeta.Annotations = sa.ObjectMeta.Annotations
		s.ObjectMeta.OwnerReferences = sa.ObjectMeta.OwnerReferences
	}); err != nil {
		return false, fmt.Errorf("error provisioning ServiceAccount: %w", err)
	}
	role := pgRole(pg, r.tsNamespace)
	if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, role, func(r *rbacv1.Role) {
		r.ObjectMeta.Labels = role.ObjectMeta.Labels
		r.ObjectMeta.Annotations = role.ObjectMeta.Annotations
		r.ObjectMeta.OwnerReferences = role.ObjectMeta.OwnerReferences
		r.Rules = role.Rules
	}); err != nil {
		return false, fmt.Errorf("error provisioning Role: %w", err)
	}
	roleBinding := pgRoleBinding(pg, r.tsNamespace)
	if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, roleBinding, func(r *rbacv1.RoleBinding) {
		r.ObjectMeta.Labels = roleBinding.ObjectMeta.Labels
		r.ObjectMeta.Annotations = roleBinding.ObjectMeta.Annotations
		r.ObjectMeta.OwnerReferences = roleBinding.ObjectMeta.OwnerReferences
		r.RoleRef = roleBinding.RoleRef
		r.Subjects = roleBinding.Subjects
	}); err != nil {
		return false, fmt.Errorf("error provisioning RoleBinding: %w", err)
	}
	if pg.Spec.Type == tsapi.ProxyGroupTypeEgress {
		cm, hp := pgEgressCM(pg, r.tsNamespace)
		if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, cm, func(existing *corev1.ConfigMap) {
			existing.ObjectMeta.Labels = cm.ObjectMeta.Labels
			existing.ObjectMeta.OwnerReferences = cm.ObjectMeta.OwnerReferences
			mak.Set(&existing.BinaryData, egressservices.KeyHEPPings, hp)
		}); err != nil {
			return false, fmt.Errorf("error provisioning egress ConfigMap %q: %w", cm.Name, err)
		}
	}
	if pg.Spec.Type == tsapi.ProxyGroupTypeIngress {
		cm := pgIngressCM(pg, r.tsNamespace)
		if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, cm, func(existing *corev1.ConfigMap) {
			existing.ObjectMeta.Labels = cm.ObjectMeta.Labels
			existing.ObjectMeta.OwnerReferences = cm.ObjectMeta.OwnerReferences
		}); err != nil {
			return false, fmt.Errorf("error provisioning ingress ConfigMap %q: %w", cm.Name, err)
		}
	}
	ss, err := pgStatefulSet(pg, r.tsNamespace, r.proxyImage, r.tsFirewallMode, tailscaledPort, proxyClass)
	if err != nil {
		return false, fmt.Errorf("error generating StatefulSet spec: %w", err)
	}
	cfg := &tailscaleSTSConfig{
		proxyType: string(pg.Spec.Type),
	}
	ss = applyProxyClassToStatefulSet(proxyClass, ss, cfg, logger)

	updateSS := func(s *appsv1.StatefulSet) {
		s.Spec = ss.Spec

		s.ObjectMeta.Labels = ss.ObjectMeta.Labels
		s.ObjectMeta.Annotations = ss.ObjectMeta.Annotations
		s.ObjectMeta.OwnerReferences = ss.ObjectMeta.OwnerReferences
	}
	if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, ss, updateSS); err != nil {
		return false, fmt.Errorf("error provisioning StatefulSet: %w", err)
	}
	mo := &metricsOpts{
		tsNamespace:  r.tsNamespace,
		proxyStsName: pg.Name,
		proxyLabels:  pgLabels(pg.Name, nil),
		proxyType:    "proxygroup",
	}
	if err := reconcileMetricsResources(ctx, logger, mo, proxyClass, r.Client); err != nil {
		return false, fmt.Errorf("error reconciling metrics resources: %w", err)
	}

	if err := r.cleanupDanglingResources(ctx, pg, proxyClass); err != nil {
		return false, fmt.Errorf("error cleaning up dangling resources: %w", err)
	}

	devices, err := r.getDeviceInfo(ctx, staticEndpoints, pg)
	if err != nil {
		return false, fmt.Errorf("failed to get device info: %w", err)
	}

	pg.Status.Devices = devices

	return true, nil
}

// getServicePortsForProxyGroups returns a map of ProxyGroup Service names to their NodePorts,
// and a set of all allocated NodePorts for quick occupancy checking.
func getServicePortsForProxyGroups(ctx context.Context, c client.Client, namespace string, portRanges tsapi.PortRanges) (map[string]uint16, set.Set[uint16], error) {
	svcs := new(corev1.ServiceList)
	matchingLabels := client.MatchingLabels(map[string]string{
		LabelParentType: "proxygroup",
	})

	err := c.List(ctx, svcs, matchingLabels, client.InNamespace(namespace))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list ProxyGroup Services: %w", err)
	}

	svcToNodePorts := map[string]uint16{}
	usedPorts := set.Set[uint16]{}
	for _, svc := range svcs.Items {
		if len(svc.Spec.Ports) == 1 && svc.Spec.Ports[0].NodePort != 0 {
			p := uint16(svc.Spec.Ports[0].NodePort)
			if portRanges.Contains(p) {
				svcToNodePorts[svc.Name] = p
				usedPorts.Add(p)
			}
		}
	}

	return svcToNodePorts, usedPorts, nil
}

type allocatePortsErr struct {
	msg string
}

func (e *allocatePortsErr) Error() string {
	return e.msg
}

func (r *ProxyGroupReconciler) allocatePorts(ctx context.Context, pg *tsapi.ProxyGroup, proxyClassName string, portRanges tsapi.PortRanges) (map[string]uint16, error) {
	replicaCount := int(pgReplicas(pg))
	svcToNodePorts, usedPorts, err := getServicePortsForProxyGroups(ctx, r.Client, r.tsNamespace, portRanges)
	if err != nil {
		return nil, &allocatePortsErr{msg: fmt.Sprintf("failed to find ports for existing ProxyGroup NodePort Services: %s", err.Error())}
	}

	replicasAllocated := 0
	for i := range pgReplicas(pg) {
		if _, ok := svcToNodePorts[pgNodePortServiceName(pg.Name, i)]; !ok {
			svcToNodePorts[pgNodePortServiceName(pg.Name, i)] = 0
		} else {
			replicasAllocated++
		}
	}

	for replica, port := range svcToNodePorts {
		if port == 0 {
			for p := range portRanges.All() {
				if !usedPorts.Contains(p) {
					svcToNodePorts[replica] = p
					usedPorts.Add(p)
					replicasAllocated++
					break
				}
			}
		}
	}

	if replicasAllocated < replicaCount {
		return nil, &allocatePortsErr{msg: fmt.Sprintf("not enough available ports to allocate all replicas (needed %d, got %d). Field 'spec.staticEndpoints.nodePort.ports' on ProxyClass %q must have bigger range allocated", replicaCount, usedPorts.Len(), proxyClassName)}
	}

	return svcToNodePorts, nil
}

func (r *ProxyGroupReconciler) ensureNodePortServiceCreated(ctx context.Context, pg *tsapi.ProxyGroup, pc *tsapi.ProxyClass) (map[string]uint16, *uint16, error) {
	// NOTE: (ChaosInTheCRD) we want the same TargetPort for every static endpoint NodePort Service for the ProxyGroup
	tailscaledPort := getRandomPort()
	svcs := []*corev1.Service{}
	for i := range pgReplicas(pg) {
		replicaName := pgNodePortServiceName(pg.Name, i)

		svc := &corev1.Service{}
		err := r.Get(ctx, types.NamespacedName{Name: replicaName, Namespace: r.tsNamespace}, svc)
		if err != nil && !apierrors.IsNotFound(err) {
			return nil, nil, fmt.Errorf("error getting Kubernetes Service %q: %w", replicaName, err)
		}
		if apierrors.IsNotFound(err) {
			svcs = append(svcs, pgNodePortService(pg, replicaName, r.tsNamespace))
		} else {
			// NOTE: if we can we want to recover the random port used for tailscaled,
			// as well as the NodePort previously used for that Service
			if len(svc.Spec.Ports) == 1 {
				if svc.Spec.Ports[0].Port != 0 {
					tailscaledPort = uint16(svc.Spec.Ports[0].Port)
				}
			}
			svcs = append(svcs, svc)
		}
	}

	svcToNodePorts, err := r.allocatePorts(ctx, pg, pc.Name, pc.Spec.StaticEndpoints.NodePort.Ports)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to allocate NodePorts to ProxyGroup Services: %w", err)
	}

	for _, svc := range svcs {
		// NOTE: we know that every service is going to have 1 port here
		svc.Spec.Ports[0].Port = int32(tailscaledPort)
		svc.Spec.Ports[0].TargetPort = intstr.FromInt(int(tailscaledPort))
		svc.Spec.Ports[0].NodePort = int32(svcToNodePorts[svc.Name])

		_, err = createOrUpdate(ctx, r.Client, r.tsNamespace, svc, func(s *corev1.Service) {
			s.ObjectMeta.Labels = svc.ObjectMeta.Labels
			s.ObjectMeta.Annotations = svc.ObjectMeta.Annotations
			s.ObjectMeta.OwnerReferences = svc.ObjectMeta.OwnerReferences
			s.Spec.Selector = svc.Spec.Selector
			s.Spec.Ports = svc.Spec.Ports
		})
		if err != nil {
			return nil, nil, fmt.Errorf("error creating/updating Kubernetes NodePort Service %q: %w", svc.Name, err)
		}
	}

	return svcToNodePorts, ptr.To(tailscaledPort), nil
}

// cleanupDanglingResources ensures we don't leak config secrets, state secrets, and
// tailnet devices when the number of replicas specified is reduced.
func (r *ProxyGroupReconciler) cleanupDanglingResources(ctx context.Context, pg *tsapi.ProxyGroup, pc *tsapi.ProxyClass) error {
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
		if err := r.Delete(ctx, m.stateSecret); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("error deleting state Secret %q: %w", m.stateSecret.Name, err)
		}
		configSecret := m.stateSecret.DeepCopy()
		configSecret.Name += "-config"
		if err := r.Delete(ctx, configSecret); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("error deleting config Secret %q: %w", configSecret.Name, err)
		}
		// NOTE(ChaosInTheCRD): we shouldn't need to get the service first, checking for a not found error should be enough
		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("%s-nodeport", m.stateSecret.Name),
				Namespace: m.stateSecret.Namespace,
			},
		}
		if err := r.Delete(ctx, svc); err != nil {
			if !apierrors.IsNotFound(err) {
				return fmt.Errorf("error deleting static endpoints Kubernetes Service %q: %w", svc.Name, err)
			}
		}
	}

	// If the ProxyClass has its StaticEndpoints config removed, we want to remove all of the NodePort Services
	if pc != nil && pc.Spec.StaticEndpoints == nil {
		labels := map[string]string{
			kubetypes.LabelManaged: "true",
			LabelParentType:        proxyTypeProxyGroup,
			LabelParentName:        pg.Name,
		}
		if err := r.DeleteAllOf(ctx, &corev1.Service{}, client.InNamespace(r.tsNamespace), client.MatchingLabels(labels)); err != nil {
			return fmt.Errorf("error deleting Kubernetes Services for static endpoints: %w", err)
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
		proxyType:   "proxygroup",
	}
	if err := maybeCleanupMetricsResources(ctx, mo, r.Client); err != nil {
		return false, fmt.Errorf("error cleaning up metrics resources: %w", err)
	}

	logger.Infof("cleaned up ProxyGroup resources")
	r.mu.Lock()
	r.ensureRemovedFromGaugeForProxyGroup(pg)
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

func (r *ProxyGroupReconciler) ensureConfigSecretsCreated(ctx context.Context, pg *tsapi.ProxyGroup, proxyClass *tsapi.ProxyClass, svcToNodePorts map[string]uint16) (endpoints map[string][]netip.AddrPort, err error) {
	logger := r.logger(pg.Name)
	endpoints = make(map[string][]netip.AddrPort, pgReplicas(pg))
	for i := range pgReplicas(pg) {
		cfgSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:            pgConfigSecretName(pg.Name, i),
				Namespace:       r.tsNamespace,
				Labels:          pgSecretLabels(pg.Name, "config"),
				OwnerReferences: pgOwnerReference(pg),
			},
		}

		var existingCfgSecret *corev1.Secret // unmodified copy of secret
		if err := r.Get(ctx, client.ObjectKeyFromObject(cfgSecret), cfgSecret); err == nil {
			logger.Debugf("Secret %s/%s already exists", cfgSecret.GetNamespace(), cfgSecret.GetName())
			existingCfgSecret = cfgSecret.DeepCopy()
		} else if !apierrors.IsNotFound(err) {
			return nil, err
		}

		var authKey *string
		if existingCfgSecret == nil {
			logger.Debugf("Creating authkey for new ProxyGroup proxy")
			tags := pg.Spec.Tags.Stringify()
			if len(tags) == 0 {
				tags = r.defaultTags
			}
			key, err := newAuthKey(ctx, r.tsClient, tags)
			if err != nil {
				return nil, err
			}
			authKey = &key
		}

		if authKey == nil {
			// Get state Secret to check if it's already authed.
			stateSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      pgStateSecretName(pg.Name, i),
					Namespace: r.tsNamespace,
				},
			}
			if err := r.Get(ctx, client.ObjectKeyFromObject(stateSecret), stateSecret); err != nil && !apierrors.IsNotFound(err) {
				return nil, err
			}

			if shouldRetainAuthKey(stateSecret) && existingCfgSecret != nil {
				authKey, err = authKeyFromSecret(existingCfgSecret)
				if err != nil {
					return nil, fmt.Errorf("error retrieving auth key from existing config Secret: %w", err)
				}
			}
		}

		replicaName := pgNodePortServiceName(pg.Name, i)
		if len(svcToNodePorts) > 0 {
			port, ok := svcToNodePorts[replicaName]
			if !ok {
				return nil, fmt.Errorf("could not find configured NodePort for ProxyGroup replica %q", replicaName)
			}

			endpoints[replicaName], err = r.findStaticEndpoints(ctx, existingCfgSecret, proxyClass, port, logger)
			if err != nil {
				return nil, fmt.Errorf("could not find static endpoints for replica %q: %w", replicaName, err)
			}
		}

		// AdvertiseServices config is set by ingress-pg-reconciler, so make sure we
		// don't overwrite it if already set.
		existingAdvertiseServices, err := extractAdvertiseServicesConfig(existingCfgSecret)
		if err != nil {
			return nil, err
		}

		configs, err := pgTailscaledConfig(pg, proxyClass, i, authKey, endpoints[replicaName], existingAdvertiseServices)
		if err != nil {
			return nil, fmt.Errorf("error creating tailscaled config: %w", err)
		}

		for cap, cfg := range configs {
			cfgJSON, err := json.Marshal(cfg)
			if err != nil {
				return nil, fmt.Errorf("error marshalling tailscaled config: %w", err)
			}
			mak.Set(&cfgSecret.Data, tsoperator.TailscaledConfigFileName(cap), cfgJSON)
		}

		if existingCfgSecret != nil {
			if !apiequality.Semantic.DeepEqual(existingCfgSecret, cfgSecret) {
				logger.Debugf("Updating the existing ProxyGroup config Secret %s", cfgSecret.Name)
				if err := r.Update(ctx, cfgSecret); err != nil {
					return nil, err
				}
			}
		} else {
			logger.Debugf("Creating a new config Secret %s for the ProxyGroup", cfgSecret.Name)
			if err := r.Create(ctx, cfgSecret); err != nil {
				return nil, err
			}
		}
	}

	return endpoints, nil
}

type FindStaticEndpointErr struct {
	msg string
}

func (e *FindStaticEndpointErr) Error() string {
	return e.msg
}

// findStaticEndpoints returns up to two `netip.AddrPort` entries, derived from the ExternalIPs of Nodes that
// match the `proxyClass`'s selector within the StaticEndpoints configuration. The port is set to the replica's NodePort Service Port.
func (r *ProxyGroupReconciler) findStaticEndpoints(ctx context.Context, existingCfgSecret *corev1.Secret, proxyClass *tsapi.ProxyClass, port uint16, logger *zap.SugaredLogger) ([]netip.AddrPort, error) {
	var currAddrs []netip.AddrPort
	if existingCfgSecret != nil {
		oldConfB := existingCfgSecret.Data[tsoperator.TailscaledConfigFileName(106)]
		if len(oldConfB) > 0 {
			var oldConf ipn.ConfigVAlpha
			if err := json.Unmarshal(oldConfB, &oldConf); err == nil {
				currAddrs = oldConf.StaticEndpoints
			} else {
				logger.Debugf("failed to unmarshal tailscaled config from secret %q: %v", existingCfgSecret.Name, err)
			}
		} else {
			logger.Debugf("failed to get tailscaled config from secret %q: empty data", existingCfgSecret.Name)
		}
	}

	nodes := new(corev1.NodeList)
	selectors := client.MatchingLabels(proxyClass.Spec.StaticEndpoints.NodePort.Selector)

	err := r.List(ctx, nodes, selectors)
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}

	if len(nodes.Items) == 0 {
		return nil, &FindStaticEndpointErr{msg: fmt.Sprintf("failed to match nodes to configured Selectors on `spec.staticEndpoints.nodePort.selectors` field for ProxyClass %q", proxyClass.Name)}
	}

	endpoints := []netip.AddrPort{}

	// NOTE(ChaosInTheCRD): Setting a hard limit of two static endpoints.
	newAddrs := []netip.AddrPort{}
	for _, n := range nodes.Items {
		for _, a := range n.Status.Addresses {
			if a.Type == corev1.NodeExternalIP {
				addr := getStaticEndpointAddress(&a, port)
				if addr == nil {
					logger.Debugf("failed to parse %q address on node %q: %q", corev1.NodeExternalIP, n.Name, a.Address)
					continue
				}

				// we want to add the currently used IPs first before
				// adding new ones.
				if currAddrs != nil && slices.Contains(currAddrs, *addr) {
					endpoints = append(endpoints, *addr)
				} else {
					newAddrs = append(newAddrs, *addr)
				}
			}

			if len(endpoints) == 2 {
				break
			}
		}
	}

	// if the 2 endpoints limit hasn't been reached, we
	// can start adding newIPs.
	if len(endpoints) < 2 {
		for _, a := range newAddrs {
			endpoints = append(endpoints, a)
			if len(endpoints) == 2 {
				break
			}
		}
	}

	if len(endpoints) == 0 {
		return nil, &FindStaticEndpointErr{msg: fmt.Sprintf("failed to find any `status.addresses` of type %q on nodes using configured Selectors on `spec.staticEndpoints.nodePort.selectors` for ProxyClass %q", corev1.NodeExternalIP, proxyClass.Name)}
	}

	return endpoints, nil
}

func getStaticEndpointAddress(a *corev1.NodeAddress, port uint16) *netip.AddrPort {
	addr, err := netip.ParseAddr(a.Address)
	if err != nil {
		return nil
	}

	return ptr.To(netip.AddrPortFrom(addr, port))
}

// ensureAddedToGaugeForProxyGroup ensures the gauge metric for the ProxyGroup resource is updated when the ProxyGroup
// is created. r.mu must be held.
func (r *ProxyGroupReconciler) ensureAddedToGaugeForProxyGroup(pg *tsapi.ProxyGroup) {
	switch pg.Spec.Type {
	case tsapi.ProxyGroupTypeEgress:
		r.egressProxyGroups.Add(pg.UID)
	case tsapi.ProxyGroupTypeIngress:
		r.ingressProxyGroups.Add(pg.UID)
	}
	gaugeEgressProxyGroupResources.Set(int64(r.egressProxyGroups.Len()))
	gaugeIngressProxyGroupResources.Set(int64(r.ingressProxyGroups.Len()))
}

// ensureRemovedFromGaugeForProxyGroup ensures the gauge metric for the ProxyGroup resource type is updated when the
// ProxyGroup is deleted. r.mu must be held.
func (r *ProxyGroupReconciler) ensureRemovedFromGaugeForProxyGroup(pg *tsapi.ProxyGroup) {
	switch pg.Spec.Type {
	case tsapi.ProxyGroupTypeEgress:
		r.egressProxyGroups.Remove(pg.UID)
	case tsapi.ProxyGroupTypeIngress:
		r.ingressProxyGroups.Remove(pg.UID)
	}
	gaugeEgressProxyGroupResources.Set(int64(r.egressProxyGroups.Len()))
	gaugeIngressProxyGroupResources.Set(int64(r.ingressProxyGroups.Len()))
}

func pgTailscaledConfig(pg *tsapi.ProxyGroup, pc *tsapi.ProxyClass, idx int32, authKey *string, staticEndpoints []netip.AddrPort, oldAdvertiseServices []string) (tailscaledConfigs, error) {
	conf := &ipn.ConfigVAlpha{
		Version:           "alpha0",
		AcceptDNS:         "false",
		AcceptRoutes:      "false", // AcceptRoutes defaults to true
		Locked:            "false",
		Hostname:          ptr.To(fmt.Sprintf("%s-%d", pg.Name, idx)),
		AdvertiseServices: oldAdvertiseServices,
		AuthKey:           authKey,
	}

	if pg.Spec.HostnamePrefix != "" {
		conf.Hostname = ptr.To(fmt.Sprintf("%s-%d", pg.Spec.HostnamePrefix, idx))
	}

	if shouldAcceptRoutes(pc) {
		conf.AcceptRoutes = "true"
	}

	if len(staticEndpoints) > 0 {
		conf.StaticEndpoints = staticEndpoints
	}

	return map[tailcfg.CapabilityVersion]ipn.ConfigVAlpha{
		pgMinCapabilityVersion: *conf,
	}, nil
}

func extractAdvertiseServicesConfig(cfgSecret *corev1.Secret) ([]string, error) {
	if cfgSecret == nil {
		return nil, nil
	}

	conf, err := latestConfigFromSecret(cfgSecret)
	if err != nil {
		return nil, err
	}

	if conf == nil {
		return nil, nil
	}

	return conf.AdvertiseServices, nil
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

		prefs, ok, err := getDevicePrefs(&secret)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}

		nm := nodeMetadata{
			ordinal:     ordinal,
			stateSecret: &secret,
			tsID:        prefs.Config.NodeID,
			dnsName:     prefs.Config.UserProfile.LoginName,
		}
		pod := &corev1.Pod{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: r.tsNamespace, Name: fmt.Sprintf("%s-%d", pg.Name, ordinal)}, pod); err != nil && !apierrors.IsNotFound(err) {
			return nil, err
		} else if err == nil {
			nm.podUID = string(pod.UID)
		}
		metadata = append(metadata, nm)
	}

	return metadata, nil
}

func (r *ProxyGroupReconciler) getDeviceInfo(ctx context.Context, staticEndpoints map[string][]netip.AddrPort, pg *tsapi.ProxyGroup) (devices []tsapi.TailnetDevice, _ error) {
	metadata, err := r.getNodeMetadata(ctx, pg)
	if err != nil {
		return nil, err
	}

	for _, m := range metadata {
		if !strings.EqualFold(string(m.stateSecret.Data[kubetypes.KeyPodUID]), m.podUID) {
			// Current Pod has not yet written its UID to the state Secret, data may
			// be stale.
			continue
		}

		device := tsapi.TailnetDevice{}
		if ipsB := m.stateSecret.Data[kubetypes.KeyDeviceIPs]; len(ipsB) > 0 {
			ips := []string{}
			if err := json.Unmarshal(ipsB, &ips); err != nil {
				return nil, fmt.Errorf("failed to extract device IPs from state Secret %q: %w", m.stateSecret.Name, err)
			}
			device.TailnetIPs = ips
		}

		if hostname, _, ok := strings.Cut(string(m.stateSecret.Data[kubetypes.KeyDeviceFQDN]), "."); ok {
			device.Hostname = hostname
		}

		if ep, ok := staticEndpoints[device.Hostname]; ok && len(ep) > 0 {
			eps := make([]string, 0, len(ep))
			for _, e := range ep {
				eps = append(eps, e.String())
			}
			device.StaticEndpoints = eps
		}

		devices = append(devices, device)
	}

	return devices, nil
}

type nodeMetadata struct {
	ordinal     int
	stateSecret *corev1.Secret
	// podUID is the UID of the current Pod or empty if the Pod does not exist.
	podUID  string
	tsID    tailcfg.StableNodeID
	dnsName string
}

func (pr *ProxyGroupReconciler) setStatusReady(pg *tsapi.ProxyGroup, status metav1.ConditionStatus, reason string, msg string, logger *zap.SugaredLogger) {
	pr.recorder.Eventf(pg, corev1.EventTypeWarning, reason, msg)
	tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupReady, status, reason, msg, pg.Generation, pr.clock, logger)
}
