// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"github.com/gaissmai/bart"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	kubeutils "tailscale.com/k8s-operator"
	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/net/dns/resolvconffile"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
)

const (
	resolvConfPath           = "/etc/resolv.conf"
	defaultClusterDomain     = "cluster.local"
	serviceDNSNameAnnotation = "tailscale.com/service-dns-name"
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
}

var (
	// gaugeEgressProxies tracks the number of egress proxies that we're
	// currently managing.
	gaugeEgressProxies = clientmetric.NewGauge("k8s_egress_proxies")
	// gaugeIngressProxies tracks the number of ingress proxies that we're
	// currently managing.
	gaugeIngressProxies = clientmetric.NewGauge("k8s_ingress_proxies")
)

func childResourceLabels(name, ns, typ string) map[string]string {
	// You might wonder why we're using owner references, since they seem to be
	// built for exactly this. Unfortunately, Kubernetes does not support
	// cross-namespace ownership, by design. This means we cannot make the
	// service being exposed the owner of the implementation details of the
	// proxying. Instead, we have to do our own filtering and tracking with
	// labels.
	return map[string]string{
		LabelManaged:         "true",
		LabelParentName:      name,
		LabelParentNamespace: ns,
		LabelParentType:      typ,
	}
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
	return reconcile.Result{}, a.maybeProvision(ctx, logger, svc)
}

// maybeCleanup removes any existing resources related to serving svc over tailscale.
//
// This function is responsible for removing the finalizer from the service,
// once all associated resources are gone.
func (a *ServiceReconciler) maybeCleanup(ctx context.Context, logger *zap.SugaredLogger, svc *corev1.Service) error {
	ix := slices.Index(svc.Finalizers, FinalizerName)
	if ix < 0 {
		logger.Debugf("no finalizer, nothing to do")
		a.mu.Lock()
		defer a.mu.Unlock()
		a.managedIngressProxies.Remove(svc.UID)
		a.managedEgressProxies.Remove(svc.UID)
		gaugeIngressProxies.Set(int64(a.managedIngressProxies.Len()))
		gaugeEgressProxies.Set(int64(a.managedEgressProxies.Len()))
		return nil
	}

	if done, err := a.ssr.Cleanup(ctx, logger, childResourceLabels(svc.Name, svc.Namespace, "svc")); err != nil {
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
	logger.Infof("unexposed service from tailnet")

	a.mu.Lock()
	defer a.mu.Unlock()
	a.managedIngressProxies.Remove(svc.UID)
	a.managedEgressProxies.Remove(svc.UID)
	gaugeIngressProxies.Set(int64(a.managedIngressProxies.Len()))
	gaugeEgressProxies.Set(int64(a.managedEgressProxies.Len()))
	return nil
}

// maybeProvision ensures that svc is exposed over tailscale, taking any actions
// necessary to reach that state.
//
// This function adds a finalizer to svc, ensuring that we can handle orderly
// deprovisioning later.
func (a *ServiceReconciler) maybeProvision(ctx context.Context, logger *zap.SugaredLogger, svc *corev1.Service) error {
	// Take a look at the Service
	// If it is an ingress Service (expose annotation or load balancer)
	// Add a record to the config map

	// This prototype only looks at ingress Services
	if !a.shouldExpose(svc) {
		return nil
	}

	// get clusterconfig
	// Exactly one ClusterConfig needs to exist, else we don't proceed.
	ccl := &tsapi.ClusterConfigList{}
	if err := a.List(ctx, ccl); err != nil {
		return fmt.Errorf("error listing ClusterConfigs: %w", err)
	}
	if len(ccl.Items) < 1 {
		logger.Info("got %d ClusterConfigs", len(ccl.Items))
		return nil
	}
	if svc.Spec.ClusterIP == "" {
		logger.Info("[unexpected] Service has no ClusterIP")
		return nil
	}

	cc := ccl.Items[0]
	svcDNSName := a.fqdnsForSvc(svc, cc.Spec.Domain)
	logger.Debugf("determined DNS name %s", svcDNSName)

	// Get all ConfigMaps for all proxies
	cmList := &corev1.ConfigMapList{}
	if err := a.List(ctx, cmList); err != nil {
		return fmt.Errorf("error listing proxy ConfigMaps: %w", err)
	}
	for _, cm := range cmList.Items {
		pcB := cm.BinaryData["proxyConfig"]
		if len(pcB) == 0 {
			a.logger.Info("[unexpected] ConfigMap %s does not contain proxyConfig", cm.Name)
			continue
		}
		pc := &kubeutils.ProxyConfig{}
		if err := json.Unmarshal(pcB, pc); err != nil {
			return fmt.Errorf("error unmarshalling proxyconfig for proxy %s: %w", cm.Name, err)
		}
		// does it have the service name already?
		if _, ok := pc.Services[svcDNSName]; ok {
			logger.Debugf("service %s already configured for proxy %s; do nothing", svcDNSName, cm.Name)
			// TODO: check if the record is correct
			continue
		}

		// pick an IP
		ip := unusedIPv4(pc.ServicesCIDRRange, pc.AddrsToDomain)
		if pc.AddrsToDomain == nil {
			pc.AddrsToDomain = &bart.Table[string]{}
		}
		pc.AddrsToDomain.Insert(netip.PrefixFrom(ip, ip.BitLen()), svcDNSName)
		clusterIP, err := netip.ParseAddr(svc.Spec.ClusterIP)
		if err != nil {
			return fmt.Errorf("error marshalling Service Cluster IP %v: %w", svc.Spec.ClusterIP, err)
		}
		svcConfig := kubeutils.Service{
			V4ServiceIPs: []netip.Addr{ip},
			FQDN:         svcDNSName,
			Ingress: &kubeutils.Ingress{
				Type:       "tcp", // currently unused
				V4Backends: []netip.Addr{clusterIP},
			},
		}
		logger.Info("assigning Service IP %v to %s", ip, svcDNSName)
		mak.Set(&pc.Services, svcDNSName, svcConfig)
		pcB, err = json.Marshal(pc)
		if err != nil {
			return fmt.Errorf("error marshalling ConfigMap for proxy %s: %w", cm.Name, err)
		}
		mak.Set(&cm.BinaryData, "proxyConfig", pcB)
		if err := a.Update(ctx, &cm); err != nil {
			return fmt.Errorf("error updating ConfigMap %s: %w", cm.Name, err)
		}
		logger.Info("ConfigMap %s updated with a record for %s", cm.Name, svcDNSName)
	}
	return nil
}

func validateService(svc *corev1.Service) []string {
	violations := make([]string, 0)
	if svc.Annotations[AnnotationTailnetTargetFQDN] != "" && svc.Annotations[AnnotationTailnetTargetIP] != "" {
		violations = append(violations, "only one of annotations %s and %s can be set", AnnotationTailnetTargetIP, AnnotationTailnetTargetFQDN)
	}
	if fqdn := svc.Annotations[AnnotationTailnetTargetFQDN]; fqdn != "" {
		if !isMagicDNSName(fqdn) {
			violations = append(violations, fmt.Sprintf("invalid value of annotation %s: %q does not appear to be a valid MagicDNS name", AnnotationTailnetTargetFQDN, fqdn))
		}
	}
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
func (a *ServiceReconciler) fqdnsForSvc(svc *corev1.Service, clusterDomain string) string {
	if annot := svc.Annotations["tailscale.com/svc-name"]; annot != "" {
		return annot + "." + clusterDomain
	}
	return svc.Name + "-" + svc.Namespace + "." + clusterDomain
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

// hasTailnetTargetAnnotation returns the value of tailscale.com/tailnet-ip
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

func proxyClassForObject(o client.Object) string {
	return o.GetLabels()[LabelProxyClass]
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

func unusedIPv4(serviceCIDR netip.Prefix, usedIPs *bart.Table[string]) netip.Addr {
	ip := randV4(serviceCIDR)
	if usedIPs == nil {
		return ip // first IP being assigned
	}
	for serviceCIDR.Contains(ip) {
		if !isIPUsed(ip, usedIPs) {
			return ip
		}
		ip = ip.Next()
	}
	return netip.Addr{}
}

func isIPUsed(ip netip.Addr, usedIPs *bart.Table[string]) bool {
	_, ok := usedIPs.Get(ip)
	return ok
}

// randV4 returns a random IPv4 address within the given prefix.
func randV4(maskedPfx netip.Prefix) netip.Addr {
	bits := 32 - maskedPfx.Bits()
	randBits := rand.Uint32N(1 << uint(bits))

	ip4 := maskedPfx.Addr().As4()
	pn := binary.BigEndian.Uint32(ip4[:])
	binary.BigEndian.PutUint32(ip4[:], randBits|pn)
	return netip.AddrFrom4(ip4)
}

// domainForIP returns the domain name assigned to the given IP address and
// whether it was found.
// func domainForIP(ip netip.Addr, serviceRecords ) (string, bool) {
// 	return ps.addrToDomain.Get(ip)
// }
