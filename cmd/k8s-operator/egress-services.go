// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"sync"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/storage/names"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/egressservices"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tstime"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
)

const (
	reasonEgressSvcInvalid        = "EgressSvcInvalid"
	reasonEgressSvcValid          = "EgressSvcValid"
	reasonEgressSvcCreationFailed = "EgressSvcCreationFailed"
	reasonProxyGroupNotReady      = "ProxyGroupNotReady"

	labelProxyGroup = "tailscale.com/proxy-group"

	labelSvcType = "tailscale.com/svc-type" // ingress or egress
	typeEgress   = "egress"
	// maxPorts is the maximum number of ports that can be exposed on a
	// container. In practice this will be ports in range [10000 - 11000). The
	// high range should make it easier to distinguish container ports from
	// the tailnet target ports for debugging purposes (i.e when reading
	// netfilter rules). The limit of 1000 is somewhat arbitrary, the
	// assumption is that this would not be hit in practice.
	maxPorts = 1000

	indexEgressProxyGroup = ".metadata.annotations.egress-proxy-group"
)

var gaugeEgressServices = clientmetric.NewGauge(kubetypes.MetricEgressServiceCount)

// egressSvcsReconciler reconciles user created ExternalName Services that specify a tailnet
// endpoint that should be exposed to cluster workloads and an egress ProxyGroup
// on whose proxies it should be exposed.
type egressSvcsReconciler struct {
	client.Client
	logger      *zap.SugaredLogger
	recorder    record.EventRecorder
	clock       tstime.Clock
	tsNamespace string

	mu   sync.Mutex           // protects following
	svcs set.Slice[types.UID] // UIDs of all currently managed egress Services for ProxyGroup
}

// Reconcile reconciles an ExternalName Service that specifies a tailnet target and a ProxyGroup on whose proxies should
// forward cluster traffic to the target.
// For an ExternalName Service the reconciler:
//
// - for each port N defined on the ExternalName Service, allocates a port X in range [3000- 4000), unique for the
// ProxyGroup proxies. Proxies will forward cluster traffic received on port N to port M on the tailnet target
//
// - creates a ClusterIP Service in the operator's namespace with portmappings for all M->N port pairs. This will allow
// cluster workloads to send traffic on the user-defined tailnet target port and get it transparently mapped to the
// randomly selected port on proxy Pods.
//
// - creates an EndpointSlice in the operator's namespace with kubernetes.io/service-name label pointing to the
// ClusterIP Service. The endpoints will get dynamically updates to proxy Pod IPs as the Pods become ready to route
// traffic to the tailnet target. kubernetes.io/service-name label ensures that kube-proxy sets up routing rules to
// forward cluster traffic received on ClusterIP Service's IP address to the endpoints (Pod IPs).
//
// - updates the egress service config in a ConfigMap mounted to the ProxyGroup proxies with the tailnet target and the
// portmappings.
func (esr *egressSvcsReconciler) Reconcile(ctx context.Context, req reconcile.Request) (res reconcile.Result, err error) {
	l := esr.logger.With("Service", req.NamespacedName)
	defer l.Info("reconcile finished")

	svc := new(corev1.Service)
	if err = esr.Get(ctx, req.NamespacedName, svc); apierrors.IsNotFound(err) {
		l.Info("Service not found")
		return res, nil
	} else if err != nil {
		return res, fmt.Errorf("failed to get Service: %w", err)
	}

	// Name of the 'egress service', meaning the tailnet target.
	tailnetSvc := tailnetSvcName(svc)
	l = l.With("tailnet-service", tailnetSvc)

	// Note that resources for egress Services are only cleaned up when the
	// Service is actually deleted (and not if, for example, user decides to
	// remove the Tailscale annotation from it). This should be fine- we
	// assume that the egress ExternalName Services are always created for
	// Tailscale operator specifically.
	if !svc.DeletionTimestamp.IsZero() {
		l.Info("Service is being deleted, ensuring resource cleanup")
		return res, esr.maybeCleanup(ctx, svc, l)
	}

	oldStatus := svc.Status.DeepCopy()
	defer func() {
		if !apiequality.Semantic.DeepEqual(oldStatus, &svc.Status) {
			err = errors.Join(err, esr.Status().Update(ctx, svc))
		}
	}()

	// Validate the user-created ExternalName Service and the associated ProxyGroup.
	if ok, err := esr.validateClusterResources(ctx, svc, l); err != nil {
		return res, fmt.Errorf("error validating cluster resources: %w", err)
	} else if !ok {
		return res, nil
	}

	if !slices.Contains(svc.Finalizers, FinalizerName) {
		svc.Finalizers = append(svc.Finalizers, FinalizerName)
		if err := esr.updateSvcSpec(ctx, svc); err != nil {
			err := fmt.Errorf("failed to add finalizer: %w", err)
			r := svcConfiguredReason(svc, false, l)
			tsoperator.SetServiceCondition(svc, tsapi.EgressSvcConfigured, metav1.ConditionFalse, r, err.Error(), esr.clock, l)
			return res, err
		}
		esr.mu.Lock()
		esr.svcs.Add(svc.UID)
		gaugeEgressServices.Set(int64(esr.svcs.Len()))
		esr.mu.Unlock()
	}

	if err := esr.maybeCleanupProxyGroupConfig(ctx, svc, l); err != nil {
		err = fmt.Errorf("cleaning up resources for previous ProxyGroup failed: %w", err)
		r := svcConfiguredReason(svc, false, l)
		tsoperator.SetServiceCondition(svc, tsapi.EgressSvcConfigured, metav1.ConditionFalse, r, err.Error(), esr.clock, l)
		return res, err
	}

	if err := esr.maybeProvision(ctx, svc, l); err != nil {
		if strings.Contains(err.Error(), optimisticLockErrorMsg) {
			l.Infof("optimistic lock error, retrying: %s", err)
		} else {
			return reconcile.Result{}, err
		}
	}

	return res, nil
}

func (esr *egressSvcsReconciler) maybeProvision(ctx context.Context, svc *corev1.Service, l *zap.SugaredLogger) (err error) {
	r := svcConfiguredReason(svc, false, l)
	st := metav1.ConditionFalse
	defer func() {
		msg := r
		if st != metav1.ConditionTrue && err != nil {
			msg = err.Error()
		}
		tsoperator.SetServiceCondition(svc, tsapi.EgressSvcConfigured, st, r, msg, esr.clock, l)
	}()

	crl := egressSvcChildResourceLabels(svc)
	clusterIPSvc, err := getSingleObject[corev1.Service](ctx, esr.Client, esr.tsNamespace, crl)
	if err != nil {
		err = fmt.Errorf("error retrieving ClusterIP Service: %w", err)
		return err
	}
	if clusterIPSvc == nil {
		clusterIPSvc = esr.clusterIPSvcForEgress(crl)
	}
	upToDate := svcConfigurationUpToDate(svc, l)
	provisioned := true
	if !upToDate {
		if clusterIPSvc, provisioned, err = esr.provision(ctx, svc.Annotations[AnnotationProxyGroup], svc, clusterIPSvc, l); err != nil {
			return err
		}
	}
	if !provisioned {
		l.Infof("unable to provision cluster resources")
		return nil
	}

	// Update ExternalName Service to point at the ClusterIP Service.
	clusterDomain := retrieveClusterDomain(esr.tsNamespace, l)
	clusterIPSvcFQDN := fmt.Sprintf("%s.%s.svc.%s", clusterIPSvc.Name, clusterIPSvc.Namespace, clusterDomain)
	if svc.Spec.ExternalName != clusterIPSvcFQDN {
		l.Infof("Configuring ExternalName Service to point to ClusterIP Service %s", clusterIPSvcFQDN)
		svc.Spec.ExternalName = clusterIPSvcFQDN
		if err = esr.updateSvcSpec(ctx, svc); err != nil {
			err = fmt.Errorf("error updating ExternalName Service: %w", err)
			return err
		}
	}
	r = svcConfiguredReason(svc, true, l)
	st = metav1.ConditionTrue
	return nil
}

func (esr *egressSvcsReconciler) provision(ctx context.Context, proxyGroupName string, svc, clusterIPSvc *corev1.Service, l *zap.SugaredLogger) (*corev1.Service, bool, error) {
	l.Infof("updating configuration...")
	usedPorts, err := esr.usedPortsForPG(ctx, proxyGroupName)
	if err != nil {
		return nil, false, fmt.Errorf("error calculating used ports for ProxyGroup %s: %w", proxyGroupName, err)
	}

	oldClusterIPSvc := clusterIPSvc.DeepCopy()
	// loop over ClusterIP Service ports, remove any that are not needed.
	for i := len(clusterIPSvc.Spec.Ports) - 1; i >= 0; i-- {
		pm := clusterIPSvc.Spec.Ports[i]
		found := false
		for _, wantsPM := range svc.Spec.Ports {
			if wantsPM.Port == pm.Port && strings.EqualFold(string(wantsPM.Protocol), string(pm.Protocol)) {
				// We don't use the port name to distinguish this port internally, but Kubernetes
				// require that, for Service ports with more than one name each port is uniquely named.
				// So we can always pick the port name from the ExternalName Service as at this point we
				// know that those are valid names because Kuberentes already validated it once. Note
				// that users could have changed an unnamed port to a named port and might have changed
				// port names- this should still work.
				// https://kubernetes.io/docs/concepts/services-networking/service/#multi-port-services
				// See also https://github.com/tailscale/tailscale/issues/13406#issuecomment-2507230388
				clusterIPSvc.Spec.Ports[i].Name = wantsPM.Name
				found = true
				break
			}
		}
		if !found {
			l.Debugf("portmapping %s:%d -> %s:%d is no longer required, removing", pm.Protocol, pm.TargetPort.IntVal, pm.Protocol, pm.Port)
			clusterIPSvc.Spec.Ports = slices.Delete(clusterIPSvc.Spec.Ports, i, i+1)
		}
	}

	// loop over ExternalName Service ports, for each one not found on
	// ClusterIP Service produce new target port and add a portmapping to
	// the ClusterIP Service.
	for _, wantsPM := range svc.Spec.Ports {
		found := false
		for _, gotPM := range clusterIPSvc.Spec.Ports {
			if wantsPM.Port == gotPM.Port && strings.EqualFold(string(wantsPM.Protocol), string(gotPM.Protocol)) {
				found = true
				break
			}
		}
		if !found {
			// Calculate a free port to expose on container and add
			// a new PortMap to the ClusterIP Service.
			if usedPorts.Len() >= maxPorts {
				// TODO(irbekrm): refactor to avoid extra reconciles here. Low priority as in practice,
				// the limit should not be hit.
				return nil, false, fmt.Errorf("unable to allocate additional ports on ProxyGroup %s, %d ports already used. Create another ProxyGroup or open an issue if you believe this is unexpected.", proxyGroupName, maxPorts)
			}
			p := unusedPort(usedPorts)
			l.Debugf("mapping tailnet target port %d to container port %d", wantsPM.Port, p)
			usedPorts.Insert(p)
			clusterIPSvc.Spec.Ports = append(clusterIPSvc.Spec.Ports, corev1.ServicePort{
				Name:       wantsPM.Name,
				Protocol:   wantsPM.Protocol,
				Port:       wantsPM.Port,
				TargetPort: intstr.FromInt32(p),
			})
		}
	}
	if !reflect.DeepEqual(clusterIPSvc, oldClusterIPSvc) {
		if clusterIPSvc, err = createOrUpdate(ctx, esr.Client, esr.tsNamespace, clusterIPSvc, func(svc *corev1.Service) {
			svc.Labels = clusterIPSvc.Labels
			svc.Spec = clusterIPSvc.Spec
		}); err != nil {
			return nil, false, fmt.Errorf("error ensuring ClusterIP Service: %v", err)
		}
	}

	crl := egressSvcEpsLabels(svc, clusterIPSvc)
	// TODO(irbekrm): support IPv6, but need to investigate how kube proxy
	// sets up Service -> Pod routing when IPv6 is involved.
	eps := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-ipv4", clusterIPSvc.Name),
			Namespace: esr.tsNamespace,
			Labels:    crl,
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Ports:       epsPortsFromSvc(clusterIPSvc),
	}
	if eps, err = createOrUpdate(ctx, esr.Client, esr.tsNamespace, eps, func(e *discoveryv1.EndpointSlice) {
		e.Labels = eps.Labels
		e.AddressType = eps.AddressType
		e.Ports = eps.Ports
		for _, p := range e.Endpoints {
			p.Conditions.Ready = nil
		}
	}); err != nil {
		return nil, false, fmt.Errorf("error ensuring EndpointSlice: %w", err)
	}

	cm, cfgs, err := egressSvcsConfigs(ctx, esr.Client, proxyGroupName, esr.tsNamespace)
	if err != nil {
		return nil, false, fmt.Errorf("error retrieving egress services configuration: %w", err)
	}
	if cm == nil {
		l.Info("ConfigMap not yet created, waiting..")
		return nil, false, nil
	}
	tailnetSvc := tailnetSvcName(svc)
	gotCfg := (*cfgs)[tailnetSvc]
	wantsCfg := egressSvcCfg(svc, clusterIPSvc)
	if !reflect.DeepEqual(gotCfg, wantsCfg) {
		l.Debugf("updating egress services ConfigMap %s", cm.Name)
		mak.Set(cfgs, tailnetSvc, wantsCfg)
		bs, err := json.Marshal(cfgs)
		if err != nil {
			return nil, false, fmt.Errorf("error marshalling egress services configs: %w", err)
		}
		mak.Set(&cm.BinaryData, egressservices.KeyEgressServices, bs)
		if err := esr.Update(ctx, cm); err != nil {
			return nil, false, fmt.Errorf("error updating egress services ConfigMap: %w", err)
		}
	}
	l.Infof("egress service configuration has been updated")
	return clusterIPSvc, true, nil
}

func (esr *egressSvcsReconciler) maybeCleanup(ctx context.Context, svc *corev1.Service, logger *zap.SugaredLogger) error {
	logger.Info("ensuring that resources created for egress service are deleted")

	// Delete egress service config from the ConfigMap mounted by the proxies.
	if err := esr.ensureEgressSvcCfgDeleted(ctx, svc, logger); err != nil {
		return fmt.Errorf("error deleting egress service config: %w", err)
	}

	// Delete the ClusterIP Service and EndpointSlice for the egress
	// service.
	types := []client.Object{
		&corev1.Service{},
		&discoveryv1.EndpointSlice{},
	}
	crl := egressSvcChildResourceLabels(svc)
	for _, typ := range types {
		if err := esr.DeleteAllOf(ctx, typ, client.InNamespace(esr.tsNamespace), client.MatchingLabels(crl)); err != nil {
			return fmt.Errorf("error deleting %s: %w", typ, err)
		}
	}

	ix := slices.Index(svc.Finalizers, FinalizerName)
	if ix != -1 {
		logger.Debug("Removing Tailscale finalizer from Service")
		svc.Finalizers = append(svc.Finalizers[:ix], svc.Finalizers[ix+1:]...)
		if err := esr.Update(ctx, svc); err != nil {
			return fmt.Errorf("failed to remove finalizer: %w", err)
		}
	}
	esr.mu.Lock()
	esr.svcs.Remove(svc.UID)
	gaugeEgressServices.Set(int64(esr.svcs.Len()))
	esr.mu.Unlock()
	logger.Info("successfully cleaned up resources for egress Service")
	return nil
}

func (esr *egressSvcsReconciler) maybeCleanupProxyGroupConfig(ctx context.Context, svc *corev1.Service, l *zap.SugaredLogger) error {
	wantsProxyGroup := svc.Annotations[AnnotationProxyGroup]
	cond := tsoperator.GetServiceCondition(svc, tsapi.EgressSvcConfigured)
	if cond == nil {
		return nil
	}
	ss := strings.Split(cond.Reason, ":")
	if len(ss) < 3 {
		return nil
	}
	if strings.EqualFold(wantsProxyGroup, ss[2]) {
		return nil
	}
	esr.logger.Infof("egress Service configured on ProxyGroup %s, wants ProxyGroup %s, cleaning up...", ss[2], wantsProxyGroup)
	if err := esr.ensureEgressSvcCfgDeleted(ctx, svc, l); err != nil {
		return fmt.Errorf("error deleting egress service config: %w", err)
	}
	return nil
}

// usedPortsForPG calculates the currently used match ports for ProxyGroup
// containers. It does that by looking by retrieving all target ports of all
// ClusterIP Services created for egress services exposed on this ProxyGroup's
// proxies.
// TODO(irbekrm): this is currently good enough because we only have a single worker and
// because these Services are created by us, so we can always expect to get the
// latest ClusterIP Services via the controller cache. It will not work as well
// once we split into multiple workers- at that point we probably want to set
// used ports on ProxyGroup's status.
func (esr *egressSvcsReconciler) usedPortsForPG(ctx context.Context, pg string) (sets.Set[int32], error) {
	svcList := &corev1.ServiceList{}
	if err := esr.List(ctx, svcList, client.InNamespace(esr.tsNamespace), client.MatchingLabels(map[string]string{labelProxyGroup: pg})); err != nil {
		return nil, fmt.Errorf("error listing Services: %w", err)
	}
	usedPorts := sets.New[int32]()
	for _, s := range svcList.Items {
		for _, p := range s.Spec.Ports {
			usedPorts.Insert(p.TargetPort.IntVal)
		}
	}
	return usedPorts, nil
}

// clusterIPSvcForEgress returns a template for the ClusterIP Service created
// for an egress service exposed on ProxyGroup proxies. The ClusterIP Service
// has no selector. Traffic sent to it will be routed to the endpoints defined
// by an EndpointSlice created for this egress service.
func (esr *egressSvcsReconciler) clusterIPSvcForEgress(crl map[string]string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: svcNameBase(crl[LabelParentName]),
			Namespace:    esr.tsNamespace,
			Labels:       crl,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
		},
	}
}

func (esr *egressSvcsReconciler) ensureEgressSvcCfgDeleted(ctx context.Context, svc *corev1.Service, logger *zap.SugaredLogger) error {
	crl := egressSvcChildResourceLabels(svc)
	cmName := pgEgressCMName(crl[labelProxyGroup])
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cmName,
			Namespace: esr.tsNamespace,
		},
	}
	l := logger.With("ConfigMap", client.ObjectKeyFromObject(cm))
	l.Debug("ensuring that egress service configuration is removed from proxy config")
	if err := esr.Get(ctx, client.ObjectKeyFromObject(cm), cm); apierrors.IsNotFound(err) {
		l.Debugf("ConfigMap not found")
		return nil
	} else if err != nil {
		return fmt.Errorf("error retrieving ConfigMap: %w", err)
	}
	bs := cm.BinaryData[egressservices.KeyEgressServices]
	if len(bs) == 0 {
		l.Debugf("ConfigMap does not contain egress service configs")
		return nil
	}
	cfgs := &egressservices.Configs{}
	if err := json.Unmarshal(bs, cfgs); err != nil {
		return fmt.Errorf("error unmarshalling egress services configs")
	}
	tailnetSvc := tailnetSvcName(svc)
	_, ok := (*cfgs)[tailnetSvc]
	if !ok {
		l.Debugf("ConfigMap does not contain egress service config, likely because it was already deleted")
		return nil
	}
	l.Infof("before deleting config %+#v", *cfgs)
	delete(*cfgs, tailnetSvc)
	l.Infof("after deleting config %+#v", *cfgs)
	bs, err := json.Marshal(cfgs)
	if err != nil {
		return fmt.Errorf("error marshalling egress services configs: %w", err)
	}
	mak.Set(&cm.BinaryData, egressservices.KeyEgressServices, bs)
	return esr.Update(ctx, cm)
}

func (esr *egressSvcsReconciler) validateClusterResources(ctx context.Context, svc *corev1.Service, l *zap.SugaredLogger) (bool, error) {
	proxyGroupName := svc.Annotations[AnnotationProxyGroup]
	pg := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: proxyGroupName,
		},
	}
	if err := esr.Get(ctx, client.ObjectKeyFromObject(pg), pg); apierrors.IsNotFound(err) {
		l.Infof("ProxyGroup %q not found, waiting...", proxyGroupName)
		tsoperator.SetServiceCondition(svc, tsapi.EgressSvcValid, metav1.ConditionUnknown, reasonProxyGroupNotReady, reasonProxyGroupNotReady, esr.clock, l)
		tsoperator.RemoveServiceCondition(svc, tsapi.EgressSvcConfigured)
		return false, nil
	} else if err != nil {
		err := fmt.Errorf("unable to retrieve ProxyGroup %s: %w", proxyGroupName, err)
		tsoperator.SetServiceCondition(svc, tsapi.EgressSvcValid, metav1.ConditionUnknown, reasonProxyGroupNotReady, err.Error(), esr.clock, l)
		tsoperator.RemoveServiceCondition(svc, tsapi.EgressSvcConfigured)
		return false, err
	}
	if !tsoperator.ProxyGroupIsReady(pg) {
		l.Infof("ProxyGroup %s is not ready, waiting...", proxyGroupName)
		tsoperator.SetServiceCondition(svc, tsapi.EgressSvcValid, metav1.ConditionUnknown, reasonProxyGroupNotReady, reasonProxyGroupNotReady, esr.clock, l)
		tsoperator.RemoveServiceCondition(svc, tsapi.EgressSvcConfigured)
		return false, nil
	}

	if violations := validateEgressService(svc, pg); len(violations) > 0 {
		msg := fmt.Sprintf("invalid egress Service: %s", strings.Join(violations, ", "))
		esr.recorder.Event(svc, corev1.EventTypeWarning, "INVALIDSERVICE", msg)
		l.Info(msg)
		tsoperator.SetServiceCondition(svc, tsapi.EgressSvcValid, metav1.ConditionFalse, reasonEgressSvcInvalid, msg, esr.clock, l)
		tsoperator.RemoveServiceCondition(svc, tsapi.EgressSvcConfigured)
		return false, nil
	}
	l.Debugf("egress service is valid")
	tsoperator.SetServiceCondition(svc, tsapi.EgressSvcValid, metav1.ConditionTrue, reasonEgressSvcValid, reasonEgressSvcValid, esr.clock, l)
	return true, nil
}

func validateEgressService(svc *corev1.Service, pg *tsapi.ProxyGroup) []string {
	violations := validateService(svc)

	// We check that only one of these two is set in the earlier validateService function.
	if svc.Annotations[AnnotationTailnetTargetFQDN] == "" && svc.Annotations[AnnotationTailnetTargetIP] == "" {
		violations = append(violations, fmt.Sprintf("egress Service for ProxyGroup must have one of %s, %s annotations set", AnnotationTailnetTargetFQDN, AnnotationTailnetTargetIP))
	}
	if len(svc.Spec.Ports) == 0 {
		violations = append(violations, "egress Service for ProxyGroup must have at least one target Port specified")
	}
	if svc.Spec.Type != corev1.ServiceTypeExternalName {
		violations = append(violations, fmt.Sprintf("unexpected egress Service type %s. The only supported type is ExternalName.", svc.Spec.Type))
	}
	if pg.Spec.Type != tsapi.ProxyGroupTypeEgress {
		violations = append(violations, fmt.Sprintf("egress Service references ProxyGroup of type %s, must be type %s", pg.Spec.Type, tsapi.ProxyGroupTypeEgress))
	}
	return violations
}

// egressSvcNameBase returns a name base that can be passed to
// ObjectMeta.GenerateName to generate a name for the ClusterIP Service.
// The generated name needs to be short enough so that it can later be used to
// generate a valid Kubernetes resource name for the EndpointSlice in form
// 'ipv4-|ipv6-<ClusterIP Service name>.
// A valid Kubernetes resource name must not be longer than 253 chars.
func svcNameBase(s string) string {
	// -ipv4 - ipv6
	const maxClusterIPSvcNameLength = 253 - 5
	base := fmt.Sprintf("ts-%s-", s)
	generator := names.SimpleNameGenerator
	for {
		generatedName := generator.GenerateName(base)
		excess := len(generatedName) - maxClusterIPSvcNameLength
		if excess <= 0 {
			return base
		}
		base = base[:len(base)-1-excess] // cut off the excess chars
		base = base + "-"                // re-instate the dash
	}
}

// unusedPort returns a port in range [10000 - 11000). The caller must ensure that
// usedPorts does not contain all ports in range [10000 - 11000).
func unusedPort(usedPorts sets.Set[int32]) int32 {
	foundFreePort := false
	var suggestPort int32
	for !foundFreePort {
		suggestPort = rand.Int32N(maxPorts) + 10000
		if !usedPorts.Has(suggestPort) {
			foundFreePort = true
		}
	}
	return suggestPort
}

// tailnetTargetFromSvc returns a tailnet target for the given egress Service.
// Service must contain exactly one of tailscale.com/tailnet-ip,
// tailscale.com/tailnet-fqdn annotations.
func tailnetTargetFromSvc(svc *corev1.Service) egressservices.TailnetTarget {
	if fqdn := svc.Annotations[AnnotationTailnetTargetFQDN]; fqdn != "" {
		return egressservices.TailnetTarget{
			FQDN: fqdn,
		}
	}
	return egressservices.TailnetTarget{
		IP: svc.Annotations[AnnotationTailnetTargetIP],
	}
}

func egressSvcCfg(externalNameSvc, clusterIPSvc *corev1.Service) egressservices.Config {
	tt := tailnetTargetFromSvc(externalNameSvc)
	cfg := egressservices.Config{TailnetTarget: tt}
	for _, svcPort := range clusterIPSvc.Spec.Ports {
		pm := portMap(svcPort)
		mak.Set(&cfg.Ports, pm, struct{}{})
	}
	return cfg
}

func portMap(p corev1.ServicePort) egressservices.PortMap {
	// TODO (irbekrm): out of bounds check?
	return egressservices.PortMap{Protocol: string(p.Protocol), MatchPort: uint16(p.TargetPort.IntVal), TargetPort: uint16(p.Port)}
}

func isEgressSvcForProxyGroup(obj client.Object) bool {
	s, ok := obj.(*corev1.Service)
	if !ok {
		return false
	}
	annots := s.ObjectMeta.Annotations
	return annots[AnnotationProxyGroup] != "" && (annots[AnnotationTailnetTargetFQDN] != "" || annots[AnnotationTailnetTargetIP] != "")
}

// egressSvcConfig returns a ConfigMap that contains egress services configuration for the provided ProxyGroup as well
// as unmarshalled configuration from the ConfigMap.
func egressSvcsConfigs(ctx context.Context, cl client.Client, proxyGroupName, tsNamespace string) (cm *corev1.ConfigMap, cfgs *egressservices.Configs, err error) {
	name := pgEgressCMName(proxyGroupName)
	cm = &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: tsNamespace,
		},
	}
	if err := cl.Get(ctx, client.ObjectKeyFromObject(cm), cm); err != nil {
		return nil, nil, fmt.Errorf("error retrieving egress services ConfigMap %s: %v", name, err)
	}
	cfgs = &egressservices.Configs{}
	if len(cm.BinaryData[egressservices.KeyEgressServices]) != 0 {
		if err := json.Unmarshal(cm.BinaryData[egressservices.KeyEgressServices], cfgs); err != nil {
			return nil, nil, fmt.Errorf("error unmarshaling egress services config %v: %w", cm.BinaryData[egressservices.KeyEgressServices], err)
		}
	}
	return cm, cfgs, nil
}

// egressSvcChildResourceLabels returns labels that should be applied to the
// ClusterIP Service and the EndpointSlice created for the egress service.
// TODO(irbekrm): we currently set a bunch of labels based on Kubernetes
// resource names (ProxyGroup, Service). Maximum allowed label length is 63
// chars whilst the maximum allowed resource name length is 253 chars, so we
// should probably validate and truncate (?) the names is they are too long.
func egressSvcChildResourceLabels(svc *corev1.Service) map[string]string {
	return map[string]string{
		LabelManaged:         "true",
		LabelParentType:      "svc",
		LabelParentName:      svc.Name,
		LabelParentNamespace: svc.Namespace,
		labelProxyGroup:      svc.Annotations[AnnotationProxyGroup],
		labelSvcType:         typeEgress,
	}
}

// egressEpsLabels returns labels to be added to an EndpointSlice created for an egress service.
func egressSvcEpsLabels(extNSvc, clusterIPSvc *corev1.Service) map[string]string {
	l := egressSvcChildResourceLabels(extNSvc)
	// Adding this label is what makes kube proxy set up rules to route traffic sent to the clusterIP Service to the
	// endpoints defined on this EndpointSlice.
	// https://kubernetes.io/docs/concepts/services-networking/endpoint-slices/#ownership
	l[discoveryv1.LabelServiceName] = clusterIPSvc.Name
	// Kubernetes recommends setting this label.
	// https://kubernetes.io/docs/concepts/services-networking/endpoint-slices/#management
	l[discoveryv1.LabelManagedBy] = "tailscale.com"
	return l
}

func svcConfigurationUpToDate(svc *corev1.Service, l *zap.SugaredLogger) bool {
	cond := tsoperator.GetServiceCondition(svc, tsapi.EgressSvcConfigured)
	if cond == nil {
		return false
	}
	if cond.Status != metav1.ConditionTrue {
		return false
	}
	wantsReadyReason := svcConfiguredReason(svc, true, l)
	return strings.EqualFold(wantsReadyReason, cond.Reason)
}

func cfgHash(c cfg, l *zap.SugaredLogger) string {
	bs, err := json.Marshal(c)
	if err != nil {
		// Don't use l.Error as that messes up component logs with, in this case, unnecessary stack trace.
		l.Infof("error marhsalling Config: %v", err)
		return ""
	}
	h := sha256.New()
	if _, err := h.Write(bs); err != nil {
		// Don't use l.Error as that messes up component logs with, in this case, unnecessary stack trace.
		l.Infof("error producing Config hash: %v", err)
		return ""
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

type cfg struct {
	Ports         []corev1.ServicePort         `json:"ports"`
	TailnetTarget egressservices.TailnetTarget `json:"tailnetTarget"`
	ProxyGroup    string                       `json:"proxyGroup"`
}

func svcConfiguredReason(svc *corev1.Service, configured bool, l *zap.SugaredLogger) string {
	var r string
	if configured {
		r = "ConfiguredFor:"
	} else {
		r = fmt.Sprintf("ConfigurationFailed:%s", r)
	}
	r += fmt.Sprintf("ProxyGroup:%s", svc.Annotations[AnnotationProxyGroup])
	tt := tailnetTargetFromSvc(svc)
	s := cfg{
		Ports:         svc.Spec.Ports,
		TailnetTarget: tt,
		ProxyGroup:    svc.Annotations[AnnotationProxyGroup],
	}
	r += fmt.Sprintf(":Config:%s", cfgHash(s, l))
	return r
}

// tailnetSvc accepts and ExternalName Service name and returns a name that will be used to distinguish this tailnet
// service from other tailnet services exposed to cluster workloads.
func tailnetSvcName(extNSvc *corev1.Service) string {
	return fmt.Sprintf("%s-%s", extNSvc.Namespace, extNSvc.Name)
}

// epsPortsFromSvc takes the ClusterIP Service created for an egress service and
// returns its Port array in a form that can be used for an EndpointSlice.
func epsPortsFromSvc(svc *corev1.Service) (ep []discoveryv1.EndpointPort) {
	for _, p := range svc.Spec.Ports {
		ep = append(ep, discoveryv1.EndpointPort{
			Protocol: &p.Protocol,
			Port:     &p.TargetPort.IntVal,
			Name:     &p.Name,
		})
	}
	return ep
}

// updateSvcSpec ensures that the given Service's spec is updated in cluster, but the local Service object still retains
// the not-yet-applied status.
// TODO(irbekrm): once we do SSA for these patch updates, this will no longer be needed.
func (esr *egressSvcsReconciler) updateSvcSpec(ctx context.Context, svc *corev1.Service) error {
	st := svc.Status.DeepCopy()
	err := esr.Update(ctx, svc)
	svc.Status = *st
	return err
}
