// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/net/dns/resolvconffile"
	"tailscale.com/tstime"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/set"
)

const (
	resolvConfPath       = "/etc/resolv.conf"
	defaultClusterDomain = "cluster.local"

	reasonProxyCreated = "ProxyCreated"
	reasonProxyInvalid = "ProxyInvalid"
	reasonProxyFailed  = "ProxyFailed"
	reasonProxyPending = "ProxyPending"

	indexServiceProxyClass = ".metadata.annotations.service-proxy-class"
)

type ServiceReconciler struct {
	client.Client
	ssr                   *tailscaleSTSReconciler
	logger                *zap.SugaredLogger
	isDefaultLoadBalancer bool

	mu sync.Mutex // protects following

	// managedIngressProxies is a set of all ingress proxies that we're
	// currently managing. This is only used for metrics.
	managedIngressProxies set.Slice[types.UID]
	// managedEgressProxies is a set of all egress proxies that we're currently
	// managing. This is only used for metrics.
	managedEgressProxies set.Slice[types.UID]

	recorder record.EventRecorder

	tsNamespace string

	clock tstime.Clock

	defaultProxyClass string
}

var (
	// gaugeEgressProxies tracks the number of egress proxies that we're
	// currently managing.
	gaugeEgressProxies = clientmetric.NewGauge(kubetypes.MetricEgressProxyCount)
	// gaugeIngressProxies tracks the number of ingress proxies that we're
	// currently managing.
	gaugeIngressProxies = clientmetric.NewGauge(kubetypes.MetricIngressProxyCount)
)

func childResourceLabels(name, ns, typ string) map[string]string {
	// You might wonder why we're using owner references, since they seem to be
	// built for exactly this. Unfortunately, Kubernetes does not support
	// cross-namespace ownership, by design. This means we cannot make the
	// service being exposed the owner of the implementation details of the
	// proxying. Instead, we have to do our own filtering and tracking with
	// labels.
	return map[string]string{
		kubetypes.LabelManaged: "true",
		LabelParentName:        name,
		LabelParentNamespace:   ns,
		LabelParentType:        typ,
	}
}

func (a *ServiceReconciler) isTailscaleService(svc *corev1.Service) bool {
	targetIP := tailnetTargetAnnotation(svc)
	targetFQDN := svc.Annotations[AnnotationTailnetTargetFQDN]
	return a.shouldExpose(svc) || targetIP != "" || targetFQDN != ""
}

func (a *ServiceReconciler) Reconcile(ctx context.Context, req reconcile.Request) (_ reconcile.Result, err error) {
	logger := a.logger.With("service-ns", req.Namespace, "service-name", req.Name)
	logger.Debugf("starting reconcile")
	defer logger.Debugf("reconcile finished")

	svc := new(corev1.Service)
	err = a.Get(ctx, req.NamespacedName, svc)
	if apierrors.IsNotFound(err) {
		// Request object not found, could have been deleted after reconcile request.
		logger.Debugf("service not found, assuming it was deleted")
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get svc: %w", err)
	}

	if _, ok := svc.Annotations[AnnotationProxyGroup]; ok {
		return reconcile.Result{}, nil // this reconciler should not look at Services for ProxyGroup
	}

	if !svc.DeletionTimestamp.IsZero() || !a.isTailscaleService(svc) {
		logger.Debugf("service is being deleted or is (no longer) referring to Tailscale ingress/egress, ensuring any created resources are cleaned up")
		return reconcile.Result{}, a.maybeCleanup(ctx, logger, svc)
	}

	if err := a.maybeProvision(ctx, logger, svc); err != nil {
		if strings.Contains(err.Error(), optimisticLockErrorMsg) {
			logger.Infof("optimistic lock error, retrying: %s", err)
		} else {
			return reconcile.Result{}, err
		}
	}

	return reconcile.Result{}, nil
}

// maybeCleanup removes any existing resources related to serving svc over tailscale.
//
// This function is responsible for removing the finalizer from the service,
// once all associated resources are gone.
func (a *ServiceReconciler) maybeCleanup(ctx context.Context, logger *zap.SugaredLogger, svc *corev1.Service) (err error) {
	oldSvcStatus := svc.Status.DeepCopy()
	defer func() {
		if !apiequality.Semantic.DeepEqual(oldSvcStatus, &svc.Status) {
			// An error encountered here should get returned by the Reconcile function.
			err = errors.Join(err, a.Client.Status().Update(ctx, svc))
		}
	}()
	ix := slices.Index(svc.Finalizers, FinalizerName)
	if ix < 0 {
		logger.Debugf("no finalizer, nothing to do")
		a.mu.Lock()
		defer a.mu.Unlock()
		a.managedIngressProxies.Remove(svc.UID)
		a.managedEgressProxies.Remove(svc.UID)
		gaugeIngressProxies.Set(int64(a.managedIngressProxies.Len()))
		gaugeEgressProxies.Set(int64(a.managedEgressProxies.Len()))

		if !a.isTailscaleService(svc) {
			tsoperator.RemoveServiceCondition(svc, tsapi.ProxyReady)
		}
		return nil
	}

	proxyTyp := proxyTypeEgress
	if a.shouldExpose(svc) {
		proxyTyp = proxyTypeIngressService
	}

	if done, err := a.ssr.Cleanup(ctx, logger, childResourceLabels(svc.Name, svc.Namespace, "svc"), proxyTyp); err != nil {
		return fmt.Errorf("failed to cleanup: %w", err)
	} else if !done {
		logger.Debugf("cleanup not done yet, waiting for next reconcile")
		return nil
	}

	svc.Finalizers = append(svc.Finalizers[:ix], svc.Finalizers[ix+1:]...)
	if err := a.Update(ctx, svc); err != nil {
		return fmt.Errorf("failed to remove finalizer: %w", err)
	}

	// Unlike most log entries in the reconcile loop, this will get printed
	// exactly once at the very end of cleanup, because the final step of
	// cleanup removes the tailscale finalizer, which will make all future
	// reconciles exit early.
	logger.Infof("unexposed Service from tailnet")

	a.mu.Lock()
	defer a.mu.Unlock()
	a.managedIngressProxies.Remove(svc.UID)
	a.managedEgressProxies.Remove(svc.UID)
	gaugeIngressProxies.Set(int64(a.managedIngressProxies.Len()))
	gaugeEgressProxies.Set(int64(a.managedEgressProxies.Len()))

	if !a.isTailscaleService(svc) {
		tsoperator.RemoveServiceCondition(svc, tsapi.ProxyReady)
	}
	return nil
}

// maybeProvision ensures that svc is exposed over tailscale, taking any actions
// necessary to reach that state.
//
// This function adds a finalizer to svc, ensuring that we can handle orderly
// deprovisioning later.
func (a *ServiceReconciler) maybeProvision(ctx context.Context, logger *zap.SugaredLogger, svc *corev1.Service) (err error) {
	oldSvcStatus := svc.Status.DeepCopy()
	defer func() {
		if !apiequality.Semantic.DeepEqual(oldSvcStatus, &svc.Status) {
			// An error encountered here should get returned by the Reconcile function.
			err = errors.Join(err, a.Client.Status().Update(ctx, svc))
		}
	}()

	// Run for proxy config related validations here as opposed to running
	// them earlier. This is to prevent cleanup being blocked on a
	// misconfigured proxy param.
	if err := a.ssr.validate(); err != nil {
		msg := fmt.Sprintf("unable to provision proxy resources: invalid config: %v", err)
		a.recorder.Event(svc, corev1.EventTypeWarning, "INVALIDCONFIG", msg)
		a.logger.Error(msg)
		tsoperator.SetServiceCondition(svc, tsapi.ProxyReady, metav1.ConditionFalse, reasonProxyInvalid, msg, a.clock, logger)
		return nil
	}
	if violations := validateService(svc); len(violations) > 0 {
		msg := fmt.Sprintf("unable to provision proxy resources: invalid Service: %s", strings.Join(violations, ", "))
		a.recorder.Event(svc, corev1.EventTypeWarning, "INVALIDSERVICE", msg)
		a.logger.Error(msg)
		tsoperator.SetServiceCondition(svc, tsapi.ProxyReady, metav1.ConditionFalse, reasonProxyInvalid, msg, a.clock, logger)
		return nil
	}

	proxyClass := proxyClassForObject(svc, a.defaultProxyClass)
	if proxyClass != "" {
		if ready, err := proxyClassIsReady(ctx, proxyClass, a.Client); err != nil {
			errMsg := fmt.Errorf("error verifying ProxyClass for Service: %w", err)
			tsoperator.SetServiceCondition(svc, tsapi.ProxyReady, metav1.ConditionFalse, reasonProxyFailed, errMsg.Error(), a.clock, logger)
			return errMsg
		} else if !ready {
			msg := fmt.Sprintf("ProxyClass %s specified for the Service, but is not (yet) Ready, waiting..", proxyClass)
			tsoperator.SetServiceCondition(svc, tsapi.ProxyReady, metav1.ConditionFalse, reasonProxyPending, msg, a.clock, logger)
			logger.Info(msg)
			return nil
		}
	}

	if !slices.Contains(svc.Finalizers, FinalizerName) {
		// This log line is printed exactly once during initial provisioning,
		// because once the finalizer is in place this block gets skipped. So,
		// this is a nice place to tell the operator that the high level,
		// multi-reconcile operation is underway.
		logger.Infof("exposing service over tailscale")
		svc.Finalizers = append(svc.Finalizers, FinalizerName)
		if err := a.Update(ctx, svc); err != nil {
			errMsg := fmt.Errorf("failed to add finalizer: %w", err)
			tsoperator.SetServiceCondition(svc, tsapi.ProxyReady, metav1.ConditionFalse, reasonProxyFailed, errMsg.Error(), a.clock, logger)
			return errMsg
		}
	}
	crl := childResourceLabels(svc.Name, svc.Namespace, "svc")
	var tags []string
	if tstr, ok := svc.Annotations[AnnotationTags]; ok {
		tags = strings.Split(tstr, ",")
	}

	sts := &tailscaleSTSConfig{
		Replicas:            1,
		ParentResourceName:  svc.Name,
		ParentResourceUID:   string(svc.UID),
		Hostname:            nameForService(svc),
		Tags:                tags,
		ChildResourceLabels: crl,
		ProxyClassName:      proxyClass,
		LoginServer:         a.ssr.loginServer,
	}
	sts.proxyType = proxyTypeEgress
	if a.shouldExpose(svc) {
		sts.proxyType = proxyTypeIngressService
	}

	a.mu.Lock()
	if a.shouldExposeClusterIP(svc) {
		sts.ClusterTargetIP = svc.Spec.ClusterIP
		a.managedIngressProxies.Add(svc.UID)
		gaugeIngressProxies.Set(int64(a.managedIngressProxies.Len()))
	} else if a.shouldExposeDNSName(svc) {
		sts.ClusterTargetDNSName = svc.Spec.ExternalName
		a.managedIngressProxies.Add(svc.UID)
		gaugeIngressProxies.Set(int64(a.managedIngressProxies.Len()))
	} else if ip := tailnetTargetAnnotation(svc); ip != "" {
		sts.TailnetTargetIP = ip
		a.managedEgressProxies.Add(svc.UID)
		gaugeEgressProxies.Set(int64(a.managedEgressProxies.Len()))
	} else if fqdn := svc.Annotations[AnnotationTailnetTargetFQDN]; fqdn != "" {
		fqdn := svc.Annotations[AnnotationTailnetTargetFQDN]
		if !strings.HasSuffix(fqdn, ".") {
			fqdn = fqdn + "."
		}
		sts.TailnetTargetFQDN = fqdn
		a.managedEgressProxies.Add(svc.UID)
		gaugeEgressProxies.Set(int64(a.managedEgressProxies.Len()))
	}
	a.mu.Unlock()

	var hsvc *corev1.Service
	if hsvc, err = a.ssr.Provision(ctx, logger, sts); err != nil {
		errMsg := fmt.Errorf("failed to provision: %w", err)
		tsoperator.SetServiceCondition(svc, tsapi.ProxyReady, metav1.ConditionFalse, reasonProxyFailed, errMsg.Error(), a.clock, logger)
		return errMsg
	}

	if sts.TailnetTargetIP != "" || sts.TailnetTargetFQDN != "" { // if an egress proxy
		clusterDomain := retrieveClusterDomain(a.tsNamespace, logger)
		headlessSvcName := hsvc.Name + "." + hsvc.Namespace + ".svc." + clusterDomain
		if svc.Spec.ExternalName != headlessSvcName || svc.Spec.Type != corev1.ServiceTypeExternalName {
			svc.Spec.ExternalName = headlessSvcName
			svc.Spec.Selector = nil
			svc.Spec.Type = corev1.ServiceTypeExternalName
			if err := a.Update(ctx, svc); err != nil {
				errMsg := fmt.Errorf("failed to update service: %w", err)
				tsoperator.SetServiceCondition(svc, tsapi.ProxyReady, metav1.ConditionFalse, reasonProxyFailed, errMsg.Error(), a.clock, logger)
				return errMsg
			}
		}
		tsoperator.SetServiceCondition(svc, tsapi.ProxyReady, metav1.ConditionTrue, reasonProxyCreated, reasonProxyCreated, a.clock, logger)
		return nil
	}

	if !isTailscaleLoadBalancerService(svc, a.isDefaultLoadBalancer) {
		logger.Debugf("service is not a LoadBalancer, so not updating ingress")
		tsoperator.SetServiceCondition(svc, tsapi.ProxyReady, metav1.ConditionTrue, reasonProxyCreated, reasonProxyCreated, a.clock, logger)
		return nil
	}

	devices, err := a.ssr.DeviceInfo(ctx, crl, logger)
	if err != nil {
		return fmt.Errorf("failed to get device ID: %w", err)
	}

	if len(devices) == 0 || devices[0].hostname == "" {
		msg := "no Tailscale hostname known yet, waiting for proxy pod to finish auth"
		logger.Debug(msg)
		// No hostname yet. Wait for the proxy pod to auth.
		svc.Status.LoadBalancer.Ingress = nil
		tsoperator.SetServiceCondition(svc, tsapi.ProxyReady, metav1.ConditionFalse, reasonProxyPending, msg, a.clock, logger)
		return nil
	}

	dev := devices[0]
	logger.Debugf("setting Service LoadBalancer status to %q, %s", dev.hostname, strings.Join(dev.ips, ", "))

	ingress := []corev1.LoadBalancerIngress{
		{Hostname: dev.hostname},
	}

	clusterIPAddr, err := netip.ParseAddr(svc.Spec.ClusterIP)
	if err != nil {
		msg := fmt.Sprintf("failed to parse cluster IP: %v", err)
		tsoperator.SetServiceCondition(svc, tsapi.ProxyReady, metav1.ConditionFalse, reasonProxyFailed, msg, a.clock, logger)
		return errors.New(msg)
	}

	for _, ip := range dev.ips {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		if addr.Is4() == clusterIPAddr.Is4() { // only add addresses of the same family
			ingress = append(ingress, corev1.LoadBalancerIngress{IP: ip})
		}
	}

	svc.Status.LoadBalancer.Ingress = ingress
	tsoperator.SetServiceCondition(svc, tsapi.ProxyReady, metav1.ConditionTrue, reasonProxyCreated, reasonProxyCreated, a.clock, logger)
	return nil
}

func validateService(svc *corev1.Service) []string {
	violations := make([]string, 0)
	if svc.Annotations[AnnotationTailnetTargetFQDN] != "" && svc.Annotations[AnnotationTailnetTargetIP] != "" {
		violations = append(violations, fmt.Sprintf("only one of annotations %s and %s can be set", AnnotationTailnetTargetIP, AnnotationTailnetTargetFQDN))
	}
	if fqdn := svc.Annotations[AnnotationTailnetTargetFQDN]; fqdn != "" {
		if !isMagicDNSName(fqdn) {
			violations = append(violations, fmt.Sprintf("invalid value of annotation %s: %q does not appear to be a valid MagicDNS name", AnnotationTailnetTargetFQDN, fqdn))
		}
	}
	if ipStr := svc.Annotations[AnnotationTailnetTargetIP]; ipStr != "" {
		ip, err := netip.ParseAddr(ipStr)
		if err != nil {
			violations = append(violations, fmt.Sprintf("invalid value of annotation %s: %q could not be parsed as a valid IP Address, error: %s", AnnotationTailnetTargetIP, ipStr, err))
		} else if !ip.IsValid() {
			violations = append(violations, fmt.Sprintf("parsed IP address in annotation %s: %q is not valid", AnnotationTailnetTargetIP, ipStr))
		}
	}

	svcName := nameForService(svc)
	if err := dnsname.ValidLabel(svcName); err != nil {
		if _, ok := svc.Annotations[AnnotationHostname]; ok {
			violations = append(violations, fmt.Sprintf("invalid Tailscale hostname specified %q: %s", svcName, err))
		} else {
			violations = append(violations, fmt.Sprintf("invalid Tailscale hostname %q, use %q annotation to override: %s", svcName, AnnotationHostname, err))
		}
	}
	violations = append(violations, tagViolations(svc)...)
	return violations
}

func (a *ServiceReconciler) shouldExpose(svc *corev1.Service) bool {
	return a.shouldExposeClusterIP(svc) || a.shouldExposeDNSName(svc)
}

func (a *ServiceReconciler) shouldExposeDNSName(svc *corev1.Service) bool {
	return hasExposeAnnotation(svc) && svc.Spec.Type == corev1.ServiceTypeExternalName && svc.Spec.ExternalName != ""
}

func (a *ServiceReconciler) shouldExposeClusterIP(svc *corev1.Service) bool {
	if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == "None" {
		return false
	}
	return isTailscaleLoadBalancerService(svc, a.isDefaultLoadBalancer) || hasExposeAnnotation(svc)
}

func isTailscaleLoadBalancerService(svc *corev1.Service, isDefaultLoadBalancer bool) bool {
	return svc != nil &&
		svc.Spec.Type == corev1.ServiceTypeLoadBalancer &&
		(svc.Spec.LoadBalancerClass != nil && *svc.Spec.LoadBalancerClass == "tailscale" ||
			svc.Spec.LoadBalancerClass == nil && isDefaultLoadBalancer)
}

// hasExposeAnnotation reports whether Service has the tailscale.com/expose
// annotation set
func hasExposeAnnotation(svc *corev1.Service) bool {
	return svc != nil && svc.Annotations[AnnotationExpose] == "true"
}

// tailnetTargetAnnotation returns the value of tailscale.com/tailnet-ip
// annotation or of the deprecated tailscale.com/ts-tailnet-target-ip
// annotation. If neither is set, it returns an empty string. If both are set,
// it returns the value of the new annotation.
func tailnetTargetAnnotation(svc *corev1.Service) string {
	if svc == nil {
		return ""
	}
	if ip := svc.Annotations[AnnotationTailnetTargetIP]; ip != "" {
		return ip
	}
	return svc.Annotations[annotationTailnetTargetIPOld]
}

func proxyClassIsReady(ctx context.Context, name string, cl client.Client) (bool, error) {
	proxyClass := new(tsapi.ProxyClass)
	if err := cl.Get(ctx, types.NamespacedName{Name: name}, proxyClass); err != nil {
		return false, fmt.Errorf("error getting ProxyClass %s: %w", name, err)
	}
	return tsoperator.ProxyClassIsReady(proxyClass), nil
}

// retrieveClusterDomain determines and retrieves cluster domain i.e
// (cluster.local) in which this Pod is running by parsing search domains in
// /etc/resolv.conf. If an error is encountered at any point during the process,
// defaults cluster domain to 'cluster.local'.
func retrieveClusterDomain(namespace string, logger *zap.SugaredLogger) string {
	logger.Infof("attempting to retrieve cluster domain..")
	conf, err := resolvconffile.ParseFile(resolvConfPath)
	if err != nil {
		// Vast majority of clusters use the cluster.local domain, so it
		// is probably better to fall back to that than error out.
		logger.Infof("[unexpected] error parsing /etc/resolv.conf to determine cluster domain, defaulting to 'cluster.local'.")
		return defaultClusterDomain
	}
	return clusterDomainFromResolverConf(conf, namespace, logger)
}

// clusterDomainFromResolverConf attempts to retrieve cluster domain from the provided resolver config.
// It expects the first three search domains in the resolver config to be be ['<namespace>.svc.<cluster-domain>, svc.<cluster-domain>, <cluster-domain>, ...]
// If the first three domains match the expected structure, it returns the third.
// If the domains don't match the expected structure or an error is encountered, it defaults to 'cluster.local' domain.
func clusterDomainFromResolverConf(conf *resolvconffile.Config, namespace string, logger *zap.SugaredLogger) string {
	if len(conf.SearchDomains) < 3 {
		logger.Infof("[unexpected] resolver config contains only %d search domains, at least three expected.\nDefaulting cluster domain to 'cluster.local'.")
		return defaultClusterDomain
	}
	first := conf.SearchDomains[0]
	if !strings.HasPrefix(string(first), namespace+".svc") {
		logger.Infof("[unexpected] first search domain in resolver config is %s; expected %s.\nDefaulting cluster domain to 'cluster.local'.", first, namespace+".svc.<cluster-domain>")
		return defaultClusterDomain
	}
	second := conf.SearchDomains[1]
	if !strings.HasPrefix(string(second), "svc") {
		logger.Infof("[unexpected] second search domain in resolver config is %s; expected 'svc.<cluster-domain>'.\nDefaulting cluster domain to 'cluster.local'.", second)
		return defaultClusterDomain
	}
	// Trim the trailing dot for backwards compatibility purposes as the
	// cluster domain was previously hardcoded to 'cluster.local' without a
	// trailing dot.
	probablyClusterDomain := strings.TrimPrefix(second.WithoutTrailingDot(), "svc.")
	third := conf.SearchDomains[2]
	if !strings.EqualFold(third.WithoutTrailingDot(), probablyClusterDomain) {
		logger.Infof("[unexpected] expected resolver config to contain serch domains <namespace>.svc.<cluster-domain>, svc.<cluster-domain>, <cluster-domain>; got %s %s %s\n. Defaulting cluster domain to 'cluster.local'.", first, second, third)
		return defaultClusterDomain
	}
	logger.Infof("Cluster domain %q extracted from resolver config", probablyClusterDomain)
	return probablyClusterDomain
}
