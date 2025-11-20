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
	"sort"
	"strings"
	"sync"

	dockerref "github.com/distribution/reference"
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
	"tailscale.com/kube/k8s-proxy/conf"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
	"tailscale.com/types/opt"
	"tailscale.com/types/ptr"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
)

const (
	reasonProxyGroupCreationFailed = "ProxyGroupCreationFailed"
	reasonProxyGroupReady          = "ProxyGroupReady"
	reasonProxyGroupAvailable      = "ProxyGroupAvailable"
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
	gaugeEgressProxyGroupResources    = clientmetric.NewGauge(kubetypes.MetricProxyGroupEgressCount)
	gaugeIngressProxyGroupResources   = clientmetric.NewGauge(kubetypes.MetricProxyGroupIngressCount)
	gaugeAPIServerProxyGroupResources = clientmetric.NewGauge(kubetypes.MetricProxyGroupAPIServerCount)
)

// ProxyGroupReconciler ensures cluster resources for a ProxyGroup definition.
type ProxyGroupReconciler struct {
	client.Client
	log      *zap.SugaredLogger
	recorder record.EventRecorder
	clock    tstime.Clock
	tsClient tsClient

	// User-specified defaults from the helm installation.
	tsNamespace       string
	tsProxyImage      string
	k8sProxyImage     string
	defaultTags       []string
	tsFirewallMode    string
	defaultProxyClass string
	loginServer       string

	mu                   sync.Mutex           // protects following
	egressProxyGroups    set.Slice[types.UID] // for egress proxygroups gauge
	ingressProxyGroups   set.Slice[types.UID] // for ingress proxygroups gauge
	apiServerProxyGroups set.Slice[types.UID] // for kube-apiserver proxygroups gauge
}

func (r *ProxyGroupReconciler) logger(name string) *zap.SugaredLogger {
	return r.log.With("ProxyGroup", name)
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
			if strings.Contains(err.Error(), optimisticLockErrorMsg) {
				logger.Infof("optimistic lock error, retrying: %s", err)
				return reconcile.Result{}, nil
			}
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
	staticEndpoints, nrr, err := r.reconcilePG(ctx, pg, logger)
	return reconcile.Result{}, errors.Join(err, r.maybeUpdateStatus(ctx, logger, pg, oldPGStatus, nrr, staticEndpoints))
}

// reconcilePG handles all reconciliation of a ProxyGroup that is not marked
// for deletion. It is separated out from Reconcile to make a clear separation
// between reconciling the ProxyGroup, and posting the status of its created
// resources onto the ProxyGroup status field.
func (r *ProxyGroupReconciler) reconcilePG(ctx context.Context, pg *tsapi.ProxyGroup, logger *zap.SugaredLogger) (map[string][]netip.AddrPort, *notReadyReason, error) {
	if !slices.Contains(pg.Finalizers, FinalizerName) {
		// This log line is printed exactly once during initial provisioning,
		// because once the finalizer is in place this block gets skipped. So,
		// this is a nice place to log that the high level, multi-reconcile
		// operation is underway.
		logger.Infof("ensuring ProxyGroup is set up")
		pg.Finalizers = append(pg.Finalizers, FinalizerName)
		if err := r.Update(ctx, pg); err != nil {
			return r.notReadyErrf(pg, logger, "error adding finalizer: %w", err)
		}
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
			msg := fmt.Sprintf("the ProxyGroup's ProxyClass %q does not (yet) exist", proxyClassName)
			logger.Info(msg)
			return notReady(reasonProxyGroupCreating, msg)
		}
		if err != nil {
			return r.notReadyErrf(pg, logger, "error getting ProxyGroup's ProxyClass %q: %w", proxyClassName, err)
		}
		if !tsoperator.ProxyClassIsReady(proxyClass) {
			msg := fmt.Sprintf("the ProxyGroup's ProxyClass %q is not yet in a ready state, waiting...", proxyClassName)
			logger.Info(msg)
			return notReady(reasonProxyGroupCreating, msg)
		}
	}

	if err := r.validate(ctx, pg, proxyClass, logger); err != nil {
		return notReady(reasonProxyGroupInvalid, fmt.Sprintf("invalid ProxyGroup spec: %v", err))
	}

	staticEndpoints, nrr, err := r.maybeProvision(ctx, pg, proxyClass)
	if err != nil {
		return nil, nrr, err
	}

	return staticEndpoints, nrr, nil
}

func (r *ProxyGroupReconciler) validate(ctx context.Context, pg *tsapi.ProxyGroup, pc *tsapi.ProxyClass, logger *zap.SugaredLogger) error {
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
	if pg.Spec.Type == tsapi.ProxyGroupTypeEgress && hasLocalAddrPortSet(pc) {
		msg := fmt.Sprintf("ProxyClass %s applied to an egress ProxyGroup has TS_LOCAL_ADDR_PORT env var set to a custom value."+
			"This will disable the ProxyGroup graceful failover mechanism, so you might experience downtime when ProxyGroup pods are restarted."+
			"In future we will remove the ability to set custom TS_LOCAL_ADDR_PORT for egress ProxyGroups."+
			"Please raise an issue if you expect that this will cause issues for your workflow.", pc.Name)
		logger.Warn(msg)
	}

	// image is the value of pc.Spec.StatefulSet.Pod.TailscaleContainer.Image or ""
	// imagePath is a slash-delimited path ending with the image name, e.g.
	// "tailscale/tailscale" or maybe "k8s-proxy" if hosted at example.com/k8s-proxy.
	var image, imagePath string
	if pc != nil &&
		pc.Spec.StatefulSet != nil &&
		pc.Spec.StatefulSet.Pod != nil &&
		pc.Spec.StatefulSet.Pod.TailscaleContainer != nil &&
		pc.Spec.StatefulSet.Pod.TailscaleContainer.Image != "" {
		image, err := dockerref.ParseNormalizedNamed(pc.Spec.StatefulSet.Pod.TailscaleContainer.Image)
		if err != nil {
			// Shouldn't be possible as the ProxyClass won't be marked ready
			// without successfully parsing the image.
			return fmt.Errorf("error parsing %q as a container image reference: %w", pc.Spec.StatefulSet.Pod.TailscaleContainer.Image, err)
		}
		imagePath = dockerref.Path(image)
	}

	var errs []error
	if isAuthAPIServerProxy(pg) {
		// Validate that the static ServiceAccount already exists.
		sa := &corev1.ServiceAccount{}
		if err := r.Get(ctx, types.NamespacedName{Namespace: r.tsNamespace, Name: authAPIServerProxySAName}, sa); err != nil {
			if !apierrors.IsNotFound(err) {
				return fmt.Errorf("error validating that ServiceAccount %q exists: %w", authAPIServerProxySAName, err)
			}

			errs = append(errs, fmt.Errorf("the ServiceAccount %q used for the API server proxy in auth mode does not exist but "+
				"should have been created during operator installation; use apiServerProxyConfig.allowImpersonation=true "+
				"in the helm chart, or authproxy-rbac.yaml from the static manifests", authAPIServerProxySAName))
		}
	} else {
		// Validate that the ServiceAccount we create won't overwrite the static one.
		// TODO(tomhjp): This doesn't cover other controllers that could create a
		// ServiceAccount. Perhaps should have some guards to ensure that an update
		// would never change the ownership of a resource we expect to already be owned.
		if pgServiceAccountName(pg) == authAPIServerProxySAName {
			errs = append(errs, fmt.Errorf("the name of the ProxyGroup %q conflicts with the static ServiceAccount used for the API server proxy in auth mode", pg.Name))
		}
	}

	if pg.Spec.Type == tsapi.ProxyGroupTypeKubernetesAPIServer {
		if strings.HasSuffix(imagePath, "tailscale") {
			errs = append(errs, fmt.Errorf("the configured ProxyClass %q specifies to use image %q but expected a %q image for ProxyGroup of type %q", pc.Name, image, "k8s-proxy", pg.Spec.Type))
		}

		if pc != nil && pc.Spec.StatefulSet != nil && pc.Spec.StatefulSet.Pod != nil && pc.Spec.StatefulSet.Pod.TailscaleInitContainer != nil {
			errs = append(errs, fmt.Errorf("the configured ProxyClass %q specifies Tailscale init container config, but ProxyGroups of type %q do not use init containers", pc.Name, pg.Spec.Type))
		}
	} else {
		if strings.HasSuffix(imagePath, "k8s-proxy") {
			errs = append(errs, fmt.Errorf("the configured ProxyClass %q specifies to use image %q but expected a %q image for ProxyGroup of type %q", pc.Name, image, "tailscale", pg.Spec.Type))
		}
	}

	return errors.Join(errs...)
}

func (r *ProxyGroupReconciler) maybeProvision(ctx context.Context, pg *tsapi.ProxyGroup, proxyClass *tsapi.ProxyClass) (map[string][]netip.AddrPort, *notReadyReason, error) {
	logger := r.logger(pg.Name)
	r.mu.Lock()
	r.ensureAddedToGaugeForProxyGroup(pg)
	r.mu.Unlock()

	svcToNodePorts := make(map[string]uint16)
	var tailscaledPort *uint16
	if proxyClass != nil && proxyClass.Spec.StaticEndpoints != nil {
		var err error
		svcToNodePorts, tailscaledPort, err = r.ensureNodePortServiceCreated(ctx, pg, proxyClass)
		if err != nil {
			var allocatePortErr *allocatePortsErr
			if errors.As(err, &allocatePortErr) {
				reason := reasonProxyGroupCreationFailed
				msg := fmt.Sprintf("error provisioning NodePort Services for static endpoints: %v", err)
				r.recorder.Event(pg, corev1.EventTypeWarning, reason, msg)
				return notReady(reason, msg)
			}
			return r.notReadyErrf(pg, logger, "error provisioning NodePort Services for static endpoints: %w", err)
		}
	}

	staticEndpoints, err := r.ensureConfigSecretsCreated(ctx, pg, proxyClass, svcToNodePorts)
	if err != nil {
		var selectorErr *FindStaticEndpointErr
		if errors.As(err, &selectorErr) {
			reason := reasonProxyGroupCreationFailed
			msg := fmt.Sprintf("error provisioning config Secrets: %v", err)
			r.recorder.Event(pg, corev1.EventTypeWarning, reason, msg)
			return notReady(reason, msg)
		}
		return r.notReadyErrf(pg, logger, "error provisioning config Secrets: %w", err)
	}

	// State secrets are precreated so we can use the ProxyGroup CR as their owner ref.
	stateSecrets := pgStateSecrets(pg, r.tsNamespace)
	for _, sec := range stateSecrets {
		if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, sec, func(s *corev1.Secret) {
			s.ObjectMeta.Labels = sec.ObjectMeta.Labels
			s.ObjectMeta.Annotations = sec.ObjectMeta.Annotations
			s.ObjectMeta.OwnerReferences = sec.ObjectMeta.OwnerReferences
		}); err != nil {
			return r.notReadyErrf(pg, logger, "error provisioning state Secrets: %w", err)
		}
	}

	// auth mode kube-apiserver ProxyGroups use a statically created
	// ServiceAccount to keep ClusterRole creation permissions limited to the
	// helm chart installer.
	if !isAuthAPIServerProxy(pg) {
		sa := pgServiceAccount(pg, r.tsNamespace)
		if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, sa, func(s *corev1.ServiceAccount) {
			s.ObjectMeta.Labels = sa.ObjectMeta.Labels
			s.ObjectMeta.Annotations = sa.ObjectMeta.Annotations
			s.ObjectMeta.OwnerReferences = sa.ObjectMeta.OwnerReferences
		}); err != nil {
			return r.notReadyErrf(pg, logger, "error provisioning ServiceAccount: %w", err)
		}
	}

	role := pgRole(pg, r.tsNamespace)
	if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, role, func(r *rbacv1.Role) {
		r.ObjectMeta.Labels = role.ObjectMeta.Labels
		r.ObjectMeta.Annotations = role.ObjectMeta.Annotations
		r.ObjectMeta.OwnerReferences = role.ObjectMeta.OwnerReferences
		r.Rules = role.Rules
	}); err != nil {
		return r.notReadyErrf(pg, logger, "error provisioning Role: %w", err)
	}

	roleBinding := pgRoleBinding(pg, r.tsNamespace)
	if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, roleBinding, func(r *rbacv1.RoleBinding) {
		r.ObjectMeta.Labels = roleBinding.ObjectMeta.Labels
		r.ObjectMeta.Annotations = roleBinding.ObjectMeta.Annotations
		r.ObjectMeta.OwnerReferences = roleBinding.ObjectMeta.OwnerReferences
		r.RoleRef = roleBinding.RoleRef
		r.Subjects = roleBinding.Subjects
	}); err != nil {
		return r.notReadyErrf(pg, logger, "error provisioning RoleBinding: %w", err)
	}

	if pg.Spec.Type == tsapi.ProxyGroupTypeEgress {
		cm, hp := pgEgressCM(pg, r.tsNamespace)
		if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, cm, func(existing *corev1.ConfigMap) {
			existing.ObjectMeta.Labels = cm.ObjectMeta.Labels
			existing.ObjectMeta.OwnerReferences = cm.ObjectMeta.OwnerReferences
			mak.Set(&existing.BinaryData, egressservices.KeyHEPPings, hp)
		}); err != nil {
			return r.notReadyErrf(pg, logger, "error provisioning egress ConfigMap %q: %w", cm.Name, err)
		}
	}

	if pg.Spec.Type == tsapi.ProxyGroupTypeIngress {
		cm := pgIngressCM(pg, r.tsNamespace)
		if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, cm, func(existing *corev1.ConfigMap) {
			existing.ObjectMeta.Labels = cm.ObjectMeta.Labels
			existing.ObjectMeta.OwnerReferences = cm.ObjectMeta.OwnerReferences
		}); err != nil {
			return r.notReadyErrf(pg, logger, "error provisioning ingress ConfigMap %q: %w", cm.Name, err)
		}
	}

	defaultImage := r.tsProxyImage
	if pg.Spec.Type == tsapi.ProxyGroupTypeKubernetesAPIServer {
		defaultImage = r.k8sProxyImage
	}
	ss, err := pgStatefulSet(pg, r.tsNamespace, defaultImage, r.tsFirewallMode, tailscaledPort, proxyClass)
	if err != nil {
		return r.notReadyErrf(pg, logger, "error generating StatefulSet spec: %w", err)
	}
	cfg := &tailscaleSTSConfig{
		proxyType: string(pg.Spec.Type),
	}
	ss = applyProxyClassToStatefulSet(proxyClass, ss, cfg, logger)

	if _, err := createOrUpdate(ctx, r.Client, r.tsNamespace, ss, func(s *appsv1.StatefulSet) {
		s.Spec = ss.Spec
		s.ObjectMeta.Labels = ss.ObjectMeta.Labels
		s.ObjectMeta.Annotations = ss.ObjectMeta.Annotations
		s.ObjectMeta.OwnerReferences = ss.ObjectMeta.OwnerReferences
	}); err != nil {
		return r.notReadyErrf(pg, logger, "error provisioning StatefulSet: %w", err)
	}

	mo := &metricsOpts{
		tsNamespace:  r.tsNamespace,
		proxyStsName: pg.Name,
		proxyLabels:  pgLabels(pg.Name, nil),
		proxyType:    "proxygroup",
	}
	if err := reconcileMetricsResources(ctx, logger, mo, proxyClass, r.Client); err != nil {
		return r.notReadyErrf(pg, logger, "error reconciling metrics resources: %w", err)
	}

	if err := r.cleanupDanglingResources(ctx, pg, proxyClass); err != nil {
		return r.notReadyErrf(pg, logger, "error cleaning up dangling resources: %w", err)
	}

	logger.Info("ProxyGroup resources synced")

	return staticEndpoints, nil, nil
}

func (r *ProxyGroupReconciler) maybeUpdateStatus(ctx context.Context, logger *zap.SugaredLogger, pg *tsapi.ProxyGroup, oldPGStatus *tsapi.ProxyGroupStatus, nrr *notReadyReason, endpoints map[string][]netip.AddrPort) (err error) {
	defer func() {
		if !apiequality.Semantic.DeepEqual(*oldPGStatus, pg.Status) {
			if updateErr := r.Client.Status().Update(ctx, pg); updateErr != nil {
				if strings.Contains(updateErr.Error(), optimisticLockErrorMsg) {
					logger.Infof("optimistic lock error updating status, retrying: %s", updateErr)
					updateErr = nil
				}
				err = errors.Join(err, updateErr)
			}
		}
	}()

	devices, err := r.getRunningProxies(ctx, pg, endpoints)
	if err != nil {
		return fmt.Errorf("failed to list running proxies: %w", err)
	}

	pg.Status.Devices = devices

	desiredReplicas := int(pgReplicas(pg))

	// Set ProxyGroupAvailable condition.
	status := metav1.ConditionFalse
	reason := reasonProxyGroupCreating
	message := fmt.Sprintf("%d/%d ProxyGroup pods running", len(devices), desiredReplicas)
	if len(devices) > 0 {
		status = metav1.ConditionTrue
		if len(devices) == desiredReplicas {
			reason = reasonProxyGroupAvailable
		}
	}
	tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupAvailable, status, reason, message, 0, r.clock, logger)

	// Set ProxyGroupReady condition.
	tsSvcValid, tsSvcSet := tsoperator.KubeAPIServerProxyValid(pg)
	status = metav1.ConditionFalse
	reason = reasonProxyGroupCreating
	switch {
	case nrr != nil:
		// If we failed earlier, that reason takes precedence.
		reason = nrr.reason
		message = nrr.message
	case pg.Spec.Type == tsapi.ProxyGroupTypeKubernetesAPIServer && tsSvcSet && !tsSvcValid:
		reason = reasonProxyGroupInvalid
		message = "waiting for config in spec.kubeAPIServer to be marked valid"
	case len(devices) < desiredReplicas:
	case len(devices) > desiredReplicas:
		message = fmt.Sprintf("waiting for %d ProxyGroup pods to shut down", len(devices)-desiredReplicas)
	case pg.Spec.Type == tsapi.ProxyGroupTypeKubernetesAPIServer && !tsoperator.KubeAPIServerProxyConfigured(pg):
		reason = reasonProxyGroupCreating
		message = "waiting for proxies to start advertising the kube-apiserver proxy's hostname"
	default:
		status = metav1.ConditionTrue
		reason = reasonProxyGroupReady
		message = reasonProxyGroupReady
	}
	tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupReady, status, reason, message, pg.Generation, r.clock, logger)

	return nil
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
		nodePortSvcName := pgNodePortServiceName(pg.Name, i)

		svc := &corev1.Service{}
		err := r.Get(ctx, types.NamespacedName{Name: nodePortSvcName, Namespace: r.tsNamespace}, svc)
		if err != nil && !apierrors.IsNotFound(err) {
			return nil, nil, fmt.Errorf("error getting Kubernetes Service %q: %w", nodePortSvcName, err)
		}
		if apierrors.IsNotFound(err) {
			svcs = append(svcs, pgNodePortService(pg, nodePortSvcName, r.tsNamespace))
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
	endpoints = make(map[string][]netip.AddrPort, pgReplicas(pg)) // keyed by Service name.
	for i := range pgReplicas(pg) {
		cfgSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:            pgConfigSecretName(pg.Name, i),
				Namespace:       r.tsNamespace,
				Labels:          pgSecretLabels(pg.Name, kubetypes.LabelSecretTypeConfig),
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

		nodePortSvcName := pgNodePortServiceName(pg.Name, i)
		if len(svcToNodePorts) > 0 {
			replicaName := fmt.Sprintf("%s-%d", pg.Name, i)
			port, ok := svcToNodePorts[nodePortSvcName]
			if !ok {
				return nil, fmt.Errorf("could not find configured NodePort for ProxyGroup replica %q", replicaName)
			}

			endpoints[nodePortSvcName], err = r.findStaticEndpoints(ctx, existingCfgSecret, proxyClass, port, logger)
			if err != nil {
				return nil, fmt.Errorf("could not find static endpoints for replica %q: %w", replicaName, err)
			}
		}

		if pg.Spec.Type == tsapi.ProxyGroupTypeKubernetesAPIServer {
			hostname := pgHostname(pg, i)

			if authKey == nil && existingCfgSecret != nil {
				deviceAuthed := false
				for _, d := range pg.Status.Devices {
					if d.Hostname == hostname {
						deviceAuthed = true
						break
					}
				}
				if !deviceAuthed {
					existingCfg := conf.ConfigV1Alpha1{}
					if err := json.Unmarshal(existingCfgSecret.Data[kubetypes.KubeAPIServerConfigFile], &existingCfg); err != nil {
						return nil, fmt.Errorf("error unmarshalling existing config: %w", err)
					}
					if existingCfg.AuthKey != nil {
						authKey = existingCfg.AuthKey
					}
				}
			}

			mode := kubetypes.APIServerProxyModeAuth
			if !isAuthAPIServerProxy(pg) {
				mode = kubetypes.APIServerProxyModeNoAuth
			}
			cfg := conf.VersionedConfig{
				Version: "v1alpha1",
				ConfigV1Alpha1: &conf.ConfigV1Alpha1{
					AuthKey:  authKey,
					State:    ptr.To(fmt.Sprintf("kube:%s", pgPodName(pg.Name, i))),
					App:      ptr.To(kubetypes.AppProxyGroupKubeAPIServer),
					LogLevel: ptr.To(logger.Level().String()),

					// Reloadable fields.
					Hostname: &hostname,
					APIServerProxy: &conf.APIServerProxyConfig{
						Enabled: opt.NewBool(true),
						Mode:    &mode,
						// The first replica is elected as the cert issuer, same
						// as containerboot does for ingress-pg-reconciler.
						IssueCerts: opt.NewBool(i == 0),
					},
					LocalPort:          ptr.To(uint16(9002)),
					HealthCheckEnabled: opt.NewBool(true),
				},
			}

			// Copy over config that the apiserver-proxy-service-reconciler sets.
			if existingCfgSecret != nil {
				if k8sProxyCfg, ok := cfgSecret.Data[kubetypes.KubeAPIServerConfigFile]; ok {
					k8sCfg := &conf.ConfigV1Alpha1{}
					if err := json.Unmarshal(k8sProxyCfg, k8sCfg); err != nil {
						return nil, fmt.Errorf("failed to unmarshal kube-apiserver config: %w", err)
					}

					cfg.AdvertiseServices = k8sCfg.AdvertiseServices
					if k8sCfg.APIServerProxy != nil {
						cfg.APIServerProxy.ServiceName = k8sCfg.APIServerProxy.ServiceName
					}
				}
			}

			if r.loginServer != "" {
				cfg.ServerURL = &r.loginServer
			}

			if proxyClass != nil && proxyClass.Spec.TailscaleConfig != nil {
				cfg.AcceptRoutes = opt.NewBool(proxyClass.Spec.TailscaleConfig.AcceptRoutes)
			}

			if proxyClass != nil && proxyClass.Spec.Metrics != nil {
				cfg.MetricsEnabled = opt.NewBool(proxyClass.Spec.Metrics.Enable)
			}

			if len(endpoints[nodePortSvcName]) > 0 {
				cfg.StaticEndpoints = endpoints[nodePortSvcName]
			}

			cfgB, err := json.Marshal(cfg)
			if err != nil {
				return nil, fmt.Errorf("error marshalling k8s-proxy config: %w", err)
			}
			mak.Set(&cfgSecret.Data, kubetypes.KubeAPIServerConfigFile, cfgB)
		} else {
			// AdvertiseServices config is set by ingress-pg-reconciler, so make sure we
			// don't overwrite it if already set.
			existingAdvertiseServices, err := extractAdvertiseServicesConfig(existingCfgSecret)
			if err != nil {
				return nil, err
			}

			configs, err := pgTailscaledConfig(pg, proxyClass, i, authKey, endpoints[nodePortSvcName], existingAdvertiseServices, r.loginServer)
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
	case tsapi.ProxyGroupTypeKubernetesAPIServer:
		r.apiServerProxyGroups.Add(pg.UID)
	}
	gaugeEgressProxyGroupResources.Set(int64(r.egressProxyGroups.Len()))
	gaugeIngressProxyGroupResources.Set(int64(r.ingressProxyGroups.Len()))
	gaugeAPIServerProxyGroupResources.Set(int64(r.apiServerProxyGroups.Len()))
}

// ensureRemovedFromGaugeForProxyGroup ensures the gauge metric for the ProxyGroup resource type is updated when the
// ProxyGroup is deleted. r.mu must be held.
func (r *ProxyGroupReconciler) ensureRemovedFromGaugeForProxyGroup(pg *tsapi.ProxyGroup) {
	switch pg.Spec.Type {
	case tsapi.ProxyGroupTypeEgress:
		r.egressProxyGroups.Remove(pg.UID)
	case tsapi.ProxyGroupTypeIngress:
		r.ingressProxyGroups.Remove(pg.UID)
	case tsapi.ProxyGroupTypeKubernetesAPIServer:
		r.apiServerProxyGroups.Remove(pg.UID)
	}
	gaugeEgressProxyGroupResources.Set(int64(r.egressProxyGroups.Len()))
	gaugeIngressProxyGroupResources.Set(int64(r.ingressProxyGroups.Len()))
	gaugeAPIServerProxyGroupResources.Set(int64(r.apiServerProxyGroups.Len()))
}

func pgTailscaledConfig(pg *tsapi.ProxyGroup, pc *tsapi.ProxyClass, idx int32, authKey *string, staticEndpoints []netip.AddrPort, oldAdvertiseServices []string, loginServer string) (tailscaledConfigs, error) {
	conf := &ipn.ConfigVAlpha{
		Version:           "alpha0",
		AcceptDNS:         "false",
		AcceptRoutes:      "false", // AcceptRoutes defaults to true
		Locked:            "false",
		Hostname:          ptr.To(pgHostname(pg, idx)),
		AdvertiseServices: oldAdvertiseServices,
		AuthKey:           authKey,
	}

	if loginServer != "" {
		conf.ServerURL = &loginServer
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

	cfg, err := latestConfigFromSecret(cfgSecret)
	if err != nil {
		return nil, err
	}

	if cfg == nil {
		return nil, nil
	}

	return cfg.AdvertiseServices, nil
}

// getNodeMetadata gets metadata for all the pods owned by this ProxyGroup by
// querying their state Secrets. It may not return the same number of items as
// specified in the ProxyGroup spec if e.g. it is getting scaled up or down, or
// some pods have failed to write state.
//
// The returned metadata will contain an entry for each state Secret that exists.
func (r *ProxyGroupReconciler) getNodeMetadata(ctx context.Context, pg *tsapi.ProxyGroup) (metadata []nodeMetadata, _ error) {
	// List all state Secrets owned by this ProxyGroup.
	secrets := &corev1.SecretList{}
	if err := r.List(ctx, secrets, client.InNamespace(r.tsNamespace), client.MatchingLabels(pgSecretLabels(pg.Name, kubetypes.LabelSecretTypeState))); err != nil {
		return nil, fmt.Errorf("failed to list state Secrets: %w", err)
	}
	for _, secret := range secrets.Items {
		var ordinal int
		if _, err := fmt.Sscanf(secret.Name, pg.Name+"-%d", &ordinal); err != nil {
			return nil, fmt.Errorf("unexpected secret %s was labelled as owned by the ProxyGroup %s: %w", secret.Name, pg.Name, err)
		}

		nm := nodeMetadata{
			ordinal:     ordinal,
			stateSecret: &secret,
		}

		prefs, ok, err := getDevicePrefs(&secret)
		if err != nil {
			return nil, err
		}
		if ok {
			nm.tsID = prefs.Config.NodeID
			nm.dnsName = prefs.Config.UserProfile.LoginName
		}

		pod := &corev1.Pod{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: r.tsNamespace, Name: fmt.Sprintf("%s-%d", pg.Name, ordinal)}, pod); err != nil && !apierrors.IsNotFound(err) {
			return nil, err
		} else if err == nil {
			nm.podUID = string(pod.UID)
		}
		metadata = append(metadata, nm)
	}

	// Sort for predictable ordering and status.
	sort.Slice(metadata, func(i, j int) bool {
		return metadata[i].ordinal < metadata[j].ordinal
	})

	return metadata, nil
}

// getRunningProxies will return status for all proxy Pods whose state Secret
// has an up to date Pod UID and at least a hostname.
func (r *ProxyGroupReconciler) getRunningProxies(ctx context.Context, pg *tsapi.ProxyGroup, staticEndpoints map[string][]netip.AddrPort) (devices []tsapi.TailnetDevice, _ error) {
	metadata, err := r.getNodeMetadata(ctx, pg)
	if err != nil {
		return nil, err
	}

	for i, m := range metadata {
		if m.podUID == "" || !strings.EqualFold(string(m.stateSecret.Data[kubetypes.KeyPodUID]), m.podUID) {
			// Current Pod has not yet written its UID to the state Secret, data may
			// be stale.
			continue
		}

		device := tsapi.TailnetDevice{}
		if hostname, _, ok := strings.Cut(string(m.stateSecret.Data[kubetypes.KeyDeviceFQDN]), "."); ok {
			device.Hostname = hostname
		} else {
			continue
		}

		if ipsB := m.stateSecret.Data[kubetypes.KeyDeviceIPs]; len(ipsB) > 0 {
			ips := []string{}
			if err := json.Unmarshal(ipsB, &ips); err != nil {
				return nil, fmt.Errorf("failed to extract device IPs from state Secret %q: %w", m.stateSecret.Name, err)
			}
			device.TailnetIPs = ips
		}

		// TODO(tomhjp): This is our input to the proxy, but we should instead
		// read this back from the proxy's state in some way to more accurately
		// reflect its status.
		if ep, ok := staticEndpoints[pgNodePortServiceName(pg.Name, int32(i))]; ok && len(ep) > 0 {
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
	podUID      string // or empty if the Pod no longer exists.
	tsID        tailcfg.StableNodeID
	dnsName     string
}

func notReady(reason, msg string) (map[string][]netip.AddrPort, *notReadyReason, error) {
	return nil, &notReadyReason{
		reason:  reason,
		message: msg,
	}, nil
}

func (r *ProxyGroupReconciler) notReadyErrf(pg *tsapi.ProxyGroup, logger *zap.SugaredLogger, format string, a ...any) (map[string][]netip.AddrPort, *notReadyReason, error) {
	err := fmt.Errorf(format, a...)
	if strings.Contains(err.Error(), optimisticLockErrorMsg) {
		msg := fmt.Sprintf("optimistic lock error, retrying: %s", err.Error())
		logger.Info(msg)
		return notReady(reasonProxyGroupCreating, msg)
	}

	r.recorder.Event(pg, corev1.EventTypeWarning, reasonProxyGroupCreationFailed, err.Error())
	return nil, &notReadyReason{
		reason:  reasonProxyGroupCreationFailed,
		message: err.Error(),
	}, err
}

type notReadyReason struct {
	reason  string
	message string
}
