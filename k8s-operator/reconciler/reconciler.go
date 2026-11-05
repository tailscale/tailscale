// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package reconciler provides utilities for working with Kubernetes resources within controller reconciliation
// loops.
package reconciler

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/net/dns/resolvconffile"
	"tailscale.com/tailcfg"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/set"
)

const (
	// Finalizer is the common finalizer used across all Tailscale Kubernetes resources.
	Finalizer = "tailscale.com/finalizer"

	// LabelParentType identifies which Tailscale CRD kind owns a managed resource. Every resource that a Tailscale
	// CRD reconciler creates should carry this label alongside LabelParentName.
	LabelParentType = "tailscale.com/parent-resource-type"

	// LabelParentName identifies the name of the Tailscale CRD that owns a managed resource. Combined with
	// LabelParentType, this uniquely identifies the parent within its scope.
	LabelParentName = "tailscale.com/parent-resource"

	// LabelParentNamespace identifies the namespace of the owning Tailscale CRD. It is only stamped when the parent
	// CRD is namespaced; cluster-scoped parents omit it.
	LabelParentNamespace = "tailscale.com/parent-resource-ns"

	// optimisticLockErrorMsg is the message the API server returns when an Update is rejected because the object
	// has been modified since it was read. The API server does not give us a typed error for the conflict in all
	// cases, so callers match on the message via IsOptimisticLockError.
	optimisticLockErrorMsg = "the object has been modified; please apply your changes to the latest version and try again"
)

// Annotations that users can set on Services (and, for some of them, Ingresses) to configure how the operator exposes
// them.
const (
	// AnnotationTailnetTargetIP is the tailnet IP address that cluster traffic sent to the Service is forwarded to.
	AnnotationTailnetTargetIP = "tailscale.com/tailnet-ip"

	// AnnotationTailnetTargetFQDN is the MagicDNS name of the tailnet node that cluster traffic sent to the Service is
	// forwarded to.
	AnnotationTailnetTargetFQDN = "tailscale.com/tailnet-fqdn"

	// AnnotationProxyGroup is the name of the ProxyGroup whose proxies expose the annotated resource.
	AnnotationProxyGroup = "tailscale.com/proxy-group"

	// AnnotationHostname is the tailnet hostname for the proxy of the annotated resource.
	AnnotationHostname = "tailscale.com/hostname"

	// AnnotationTags is a comma-separated list of tags for the proxy of the annotated resource.
	AnnotationTags = "tailscale.com/tags"
)

// LabelProxyGroup is set on resources that the operator creates for a Service or Ingress exposed on a ProxyGroup. Its
// value is the name of the ProxyGroup.
const LabelProxyGroup = "tailscale.com/proxy-group"

const (
	// ParentTypeProxyGroup is the LabelParentType value on resources that the operator creates for a ProxyGroup.
	ParentTypeProxyGroup = "proxygroup"

	// EgressReadinessGate is the Pod readiness gate on egress ProxyGroup Pods. The egress Pod reconciler sets the
	// condition once the Pod can route traffic to all egress services of its ProxyGroup.
	EgressReadinessGate = "tailscale.com/egress-services"
)

const (
	resolvConfPath       = "/etc/resolv.conf"
	defaultClusterDomain = "cluster.local"
)

// IsOptimisticLockError reports whether err was caused by an optimistic locking conflict, i.e. the object being
// updated was modified after the reconciler read it. Such an error is transient: the reconciler should requeue and
// retry against a freshly read object rather than surface the error.
func IsOptimisticLockError(err error) bool {
	return err != nil && strings.Contains(err.Error(), optimisticLockErrorMsg)
}

// SetFinalizer adds name to obj's finalizers if not already present. Most CRD reconcilers pass Finalizer; per-
// reconciler names are used when a single resource may carry finalizers from multiple reconcilers that each need to run
// their own cleanup.
func SetFinalizer(obj client.Object, name string) {
	if idx := slices.Index(obj.GetFinalizers(), name); idx >= 0 {
		return
	}

	obj.SetFinalizers(append(obj.GetFinalizers(), name))
}

// RemoveFinalizer removes name from obj's finalizers if present.
func RemoveFinalizer(obj client.Object, name string) {
	idx := slices.Index(obj.GetFinalizers(), name)
	if idx < 0 {
		return
	}

	finalizers := obj.GetFinalizers()
	obj.SetFinalizers(append(finalizers[:idx], finalizers[idx+1:]...))
}

// EnsureFinalizer adds name to obj (if not already present) and persists the change via cl.Update. It is a no-op when
// the finalizer is already set. Callers should invoke it early in a create/update reconcile so cleanup logic gets a
// chance to run before the resource is garbage collected. Most callers pass Finalizer; per-reconciler names are
// used when a single resource may carry finalizers from multiple reconcilers.
func EnsureFinalizer(ctx context.Context, cl client.Client, obj client.Object, name string) error {
	if slices.Contains(obj.GetFinalizers(), name) {
		return nil
	}
	SetFinalizer(obj, name)
	return cl.Update(ctx, obj)
}

// ClearFinalizer removes name from obj (if present) and persists the change via cl.Update. It is a no-op when the
// finalizer is already absent. Callers should invoke it at the end of delete handling, once all owned resources are
// gone, so the API server can garbage collect obj.
func ClearFinalizer(ctx context.Context, cl client.Client, obj client.Object, name string) error {
	if !slices.Contains(obj.GetFinalizers(), name) {
		return nil
	}
	RemoveFinalizer(obj, name)
	return cl.Update(ctx, obj)
}

// Labels returns the standard ownership labels stamped on every resource a Tailscale CRD reconciler creates:
// tailscale.com/managed=true, plus LabelParentType and LabelParentName. If parentNamespace is non-empty (i.e. the
// parent CRD is namespaced) it is stamped as LabelParentNamespace; cluster-scoped parents pass "".
func Labels(parentType, parentName, parentNamespace string) map[string]string {
	labels := map[string]string{
		kubetypes.LabelManaged: "true",
		LabelParentType:        parentType,
		LabelParentName:        parentName,
	}
	if parentNamespace != "" {
		labels[LabelParentNamespace] = parentNamespace
	}
	return labels
}

// EnqueueForChild returns a handler.MapFunc that enqueues a reconcile.Request for the parent CRD of a managed child
// resource. It filters by tailscale.com/managed=true and LabelParentType, and derives the request's NamespacedName
// from LabelParentName plus LabelParentNamespace (blank namespace for cluster-scoped parents). Use it on Watches of
// child resources so drift or cloud-controller updates propagate to the owning CRD's reconciler.
func EnqueueForChild(parentType string) handler.MapFunc {
	return func(_ context.Context, o client.Object) []reconcile.Request {
		if !IsManagedByType(o, parentType) {
			return nil
		}

		parent := ParentFromObjectLabels(o)
		if parent.Name == "" {
			return nil
		}

		return []reconcile.Request{{NamespacedName: parent}}
	}
}

// IsManagedResource reports whether obj carries the tailscale.com/managed=true label — i.e. it is a child resource
// stamped by a Tailscale CRD reconciler.
func IsManagedResource(obj client.Object) bool {
	return obj.GetLabels()[kubetypes.LabelManaged] == "true"
}

// IsManagedByType reports whether obj is a managed child resource whose LabelParentType matches parentType.
func IsManagedByType(obj client.Object, parentType string) bool {
	return IsManagedResource(obj) && obj.GetLabels()[LabelParentType] == parentType
}

// SelectorForType returns the label selector that matches every managed child resource with the given parent type.
// Pass it to client.MatchingLabels when Listing children by type; it is the label-map counterpart of the IsManagedByType
// predicate.
func SelectorForType(parentType string) map[string]string {
	return map[string]string{
		kubetypes.LabelManaged: "true",
		LabelParentType:        parentType,
	}
}

// ParentFromObjectLabels returns the NamespacedName of the parent CRD encoded in obj's LabelParentName /
// LabelParentNamespace labels. The Namespace is empty for children of cluster-scoped parents.
func ParentFromObjectLabels(obj client.Object) types.NamespacedName {
	labels := obj.GetLabels()
	return types.NamespacedName{
		Name:      labels[LabelParentName],
		Namespace: labels[LabelParentNamespace],
	}
}

// ResourceTracker tracks the set of CRD UIDs a reconciler currently manages and mirrors the set's size to a
// clientmetric gauge. Callers Add on each successful reconcile and Remove on cleanup; the gauge stays in sync with
// the finalizer lifecycle so it reflects the live count of managed resources across restarts. ResourceTracker is
// safe for concurrent use.
type ResourceTracker struct {
	gauge *clientmetric.Metric

	mu   sync.Mutex // protects uids
	uids set.Slice[types.UID]
}

// NewResourceTracker returns a ResourceTracker that mirrors its size to the given gauge.
func NewResourceTracker(gauge *clientmetric.Metric) *ResourceTracker {
	return &ResourceTracker{gauge: gauge}
}

// Add records uid as managed. Duplicate adds are a no-op.
func (t *ResourceTracker) Add(uid types.UID) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.uids.Contains(uid) {
		return
	}
	t.uids.Add(uid)
	t.gauge.Set(int64(t.uids.Len()))
}

// Remove drops uid from the tracked set. It is a no-op if uid is not currently tracked.
func (t *ResourceTracker) Remove(uid types.UID) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.uids.Remove(uid)
	t.gauge.Set(int64(t.uids.Len()))
}

// Len returns the number of UIDs currently tracked.
func (t *ResourceTracker) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.uids.Len()
}

// PtrObject is a type constraint for pointer types that implement client.Object.
type PtrObject[T any] interface {
	client.Object
	*T
}

// CreateOrMaybeUpdate adds obj to the k8s cluster, unless the object already exists,
// in which case update is called to make changes to it. If update is nil or returns
// an error, the object is returned unmodified.
//
// obj is looked up by its Name and Namespace if Name is set, otherwise it's
// looked up by labels.
func CreateOrMaybeUpdate[T any, O PtrObject[T]](ctx context.Context, c client.Client, ns string, obj O, update func(O) error) (O, error) {
	var (
		existing O
		err      error
	)
	if obj.GetName() != "" {
		existing = new(T)
		existing.SetName(obj.GetName())
		existing.SetNamespace(obj.GetNamespace())
		err = c.Get(ctx, client.ObjectKeyFromObject(obj), existing)
	} else {
		existing, err = GetSingleObject[T, O](ctx, c, ns, obj.GetLabels())
	}
	if err == nil && existing != nil {
		if update != nil {
			if err := update(existing); err != nil {
				return nil, err
			}
			if err := c.Update(ctx, existing); err != nil {
				return nil, err
			}
		}
		return existing, nil
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("failed to get object: %w", err)
	}
	if err := c.Create(ctx, obj); err != nil {
		return nil, err
	}
	return obj, nil
}

// CreateOrUpdate adds obj to the k8s cluster, unless the object already exists,
// in which case update is called to make changes to it. If update is nil, the
// existing object is returned unmodified.
//
// obj is looked up by its Name and Namespace if Name is set, otherwise it's
// looked up by labels.
func CreateOrUpdate[T any, O PtrObject[T]](ctx context.Context, c client.Client, ns string, obj O, update func(O)) (O, error) {
	return CreateOrMaybeUpdate(ctx, c, ns, obj, func(o O) error {
		if update != nil {
			update(o)
		}
		return nil
	})
}

// GetSingleObject searches for k8s objects of type T (e.g. corev1.Service) with
// the given labels, and returns it. Returns nil if no objects match the labels,
// and an error if more than one object matches.
func GetSingleObject[T any, O PtrObject[T]](ctx context.Context, c client.Client, ns string, labels map[string]string) (O, error) {
	ret := O(new(T))
	kinds, _, err := c.Scheme().ObjectKinds(ret)
	if err != nil {
		return nil, err
	}
	if len(kinds) != 1 {
		// TODO: the runtime package apparently has a "pick the best
		// GVK" function somewhere that might be good enough?
		return nil, fmt.Errorf("more than 1 GroupVersionKind for %T", ret)
	}

	gvk := kinds[0]
	gvk.Kind += "List"
	lst := unstructured.UnstructuredList{}
	lst.SetGroupVersionKind(gvk)
	if err := c.List(ctx, &lst, client.InNamespace(ns), client.MatchingLabels(labels)); err != nil {
		return nil, err
	}

	if len(lst.Items) == 0 {
		return nil, nil
	}
	if len(lst.Items) > 1 {
		return nil, fmt.Errorf("found multiple matching %T objects", ret)
	}
	if err := c.Scheme().Convert(&lst.Items[0], ret, nil); err != nil {
		return nil, err
	}
	return ret, nil
}

// ValidateService returns the problems with the Tailscale configuration of svc. It checks the tailnet target
// annotations, the tailnet hostname, and the tags. It returns an empty slice if svc is valid.
func ValidateService(svc *corev1.Service) []string {
	violations := make([]string, 0)
	if svc.Spec.ClusterIP == "None" {
		violations = append(violations, "headless Services are not supported.")
	}
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

	svcName := NameForService(svc)
	if err := dnsname.ValidLabel(svcName); err != nil {
		if _, ok := svc.Annotations[AnnotationHostname]; ok {
			violations = append(violations, fmt.Sprintf("invalid Tailscale hostname specified %q: %s", svcName, err))
		} else {
			violations = append(violations, fmt.Sprintf("invalid Tailscale hostname %q, use %q annotation to override: %s", svcName, AnnotationHostname, err))
		}
	}
	violations = append(violations, TagViolations(svc)...)
	return violations
}

// NameForService returns the tailnet hostname for the proxy of svc. It is the value of AnnotationHostname if set, or
// <namespace>-<name> otherwise.
func NameForService(svc *corev1.Service) string {
	if h, ok := svc.Annotations[AnnotationHostname]; ok {
		return h
	}
	return svc.Namespace + "-" + svc.Name
}

// TagViolations returns a problem for each tag in the AnnotationTags annotation of obj that is not a valid tag. It
// returns nil if obj is nil or does not have the annotation.
func TagViolations(obj client.Object) []string {
	var violations []string
	if obj == nil {
		return nil
	}
	tags, ok := obj.GetAnnotations()[AnnotationTags]
	if !ok {
		return nil
	}

	for tag := range strings.SplitSeq(tags, ",") {
		tag = strings.TrimSpace(tag)
		if err := tailcfg.CheckTag(tag); err != nil {
			violations = append(violations, fmt.Sprintf("invalid tag %q: %v", tag, err))
		}
	}
	return violations
}

// isMagicDNSName reports whether name is a full tailnet node FQDN (with or
// without final dot).
func isMagicDNSName(name string) bool {
	validMagicDNSName := regexp.MustCompile(`^[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+\.ts\.net\.?$`)
	return validMagicDNSName.MatchString(name)
}

// ClusterDomainOption configures ClusterDomain.
type ClusterDomainOption func(*clusterDomainOptions)

type clusterDomainOptions struct {
	resolvConfPath string
}

// WithResolvConfPath sets the resolver config file that ClusterDomain parses. Only tests need it. The operator uses
// the resolver config of its own Pod.
func WithResolvConfPath(path string) ClusterDomainOption {
	return func(o *clusterDomainOptions) { o.resolvConfPath = path }
}

// ClusterDomain determines and retrieves cluster domain i.e
// (cluster.local) in which this Pod is running by parsing search domains in
// /etc/resolv.conf. If an error is encountered at any point during the process,
// defaults cluster domain to 'cluster.local'.
func ClusterDomain(namespace string, logger *zap.SugaredLogger, opts ...ClusterDomainOption) string {
	o := clusterDomainOptions{resolvConfPath: resolvConfPath}
	for _, opt := range opts {
		opt(&o)
	}

	logger.Infof("attempting to retrieve cluster domain..")
	conf, err := resolvconffile.ParseFile(o.resolvConfPath)
	if err != nil {
		// Vast majority of clusters use the cluster.local domain, so it
		// is probably better to fall back to that than error out.
		logger.Warn("error parsing /etc/resolv.conf to determine cluster domain, defaulting to 'cluster.local'.")
		return defaultClusterDomain
	}
	return clusterDomainFromResolverConf(conf, namespace, logger)
}

// clusterDomainFromResolverConf attempts to retrieve cluster domain from the provided resolver config.
// It expects the first three search domains in the resolver config to be ['<namespace>.svc.<cluster-domain>, svc.<cluster-domain>, <cluster-domain>, ...]
// If the first three domains match the expected structure, it returns the third.
// If the domains don't match the expected structure or an error is encountered, it defaults to 'cluster.local' domain.
func clusterDomainFromResolverConf(conf *resolvconffile.Config, namespace string, logger *zap.SugaredLogger) string {
	if len(conf.SearchDomains) < 3 {
		logger.Warnf(" resolver config contains only %d search domains, at least three expected.\nDefaulting cluster domain to 'cluster.local'.", len(conf.SearchDomains))
		return defaultClusterDomain
	}
	first := conf.SearchDomains[0]
	if !strings.HasPrefix(string(first), namespace+".svc") {
		logger.Warnf("first search domain in resolver config is %s; expected %s.\nDefaulting cluster domain to 'cluster.local'.", first, namespace+".svc.<cluster-domain>")
		return defaultClusterDomain
	}
	second := conf.SearchDomains[1]
	if !strings.HasPrefix(string(second), "svc") {
		logger.Warnf("second search domain in resolver config is %s; expected 'svc.<cluster-domain>'.\nDefaulting cluster domain to 'cluster.local'.", second)
		return defaultClusterDomain
	}
	// Trim the trailing dot for backwards compatibility purposes as the
	// cluster domain was previously hardcoded to 'cluster.local' without a
	// trailing dot.
	probablyClusterDomain := strings.TrimPrefix(second.WithoutTrailingDot(), "svc.")
	third := conf.SearchDomains[2]
	if !strings.EqualFold(third.WithoutTrailingDot(), probablyClusterDomain) {
		logger.Warnf("expected resolver config to contain serch domains <namespace>.svc.<cluster-domain>, svc.<cluster-domain>, <cluster-domain>; got %s %s %s\n. Defaulting cluster domain to 'cluster.local'.", first, second, third)
		return defaultClusterDomain
	}
	logger.Infof("Cluster domain %q extracted from resolver config", probablyClusterDomain)
	return probablyClusterDomain
}

// ProxyGroupLabels returns the labels for a resource that the operator creates for the named ProxyGroup. The result
// holds customLabels plus the standard labels for a managed child of the ProxyGroup. The standard labels take
// precedence.
func ProxyGroupLabels(pgName string, customLabels map[string]string) map[string]string {
	labels := make(map[string]string, len(customLabels)+3)
	maps.Copy(labels, customLabels)
	maps.Copy(labels, Labels(ParentTypeProxyGroup, pgName, ""))
	return labels
}

// ProxyGroupReplicas returns the number of replicas for pg. It is 2 if pg does not set the replicas.
func ProxyGroupReplicas(pg *tsapi.ProxyGroup) int32 {
	if pg.Spec.Replicas != nil {
		return *pg.Spec.Replicas
	}

	return 2
}

// ProxyGroupEgressConfigMapName returns the name of the ConfigMap that holds the egress service configuration for the
// named egress ProxyGroup.
func ProxyGroupEgressConfigMapName(pgName string) string {
	return fmt.Sprintf("%s-egress-config", pgName)
}
