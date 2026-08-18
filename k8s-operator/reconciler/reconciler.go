// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package reconciler provides utilities for working with Kubernetes resources within controller reconciliation
// loops.
package reconciler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/net/dns/resolvconffile"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
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

// Annotations that users set on Services and Ingresses to configure how the operator exposes them. They are read by
// several reconcilers — a Service annotated for egress is acted on by the egress reconcilers, and also by dnsrecords
// when it needs the tailnet target — so they live here rather than in any one reconciler's package.
const (
	// AnnotationTailnetTargetIP is the IP of the tailnet node that an egress Service forwards traffic to. Mutually
	// exclusive with AnnotationTailnetTargetFQDN.
	AnnotationTailnetTargetIP = "tailscale.com/tailnet-ip"

	// AnnotationTailnetTargetFQDN is the MagicDNS name of the tailnet node that an egress Service forwards traffic
	// to. Mutually exclusive with AnnotationTailnetTargetIP.
	AnnotationTailnetTargetFQDN = "tailscale.com/tailnet-fqdn"

	// AnnotationProxyGroup names the ProxyGroup whose proxies should expose an egress Service.
	AnnotationProxyGroup = "tailscale.com/proxy-group"

	// AnnotationHostname overrides the tailnet hostname the operator would otherwise derive from a resource's
	// namespace and name.
	AnnotationHostname = "tailscale.com/hostname"

	// AnnotationTags is a comma-separated list of ACL tags to apply to the tailnet device created for a resource.
	AnnotationTags = "tailscale.com/tags"
)

// Constants used when determining the cluster's DNS domain; see ClusterDomain.
const (
	resolvConfPath = "/etc/resolv.conf"

	// DefaultClusterDomain is the cluster domain assumed when it can't be determined from the resolver config. The
	// vast majority of clusters use it.
	DefaultClusterDomain = "cluster.local"
)

// validMagicDNSName matches a tailnet MagicDNS name, e.g. foo.tail-scale.ts.net.
var validMagicDNSName = regexp.MustCompile(`^[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+\.ts\.net\.?$`)

// Reconciler is a CRD reconciler that knows how to register itself with a controller manager, including the watches
// and field indexes it depends on. Every reconciler under this package implements it, so the operator can construct
// them into a slice and register them in a loop rather than wiring each one up by hand.
type Reconciler interface {
	reconcile.Reconciler

	// Register sets the reconciler up on mgr. Implementations own their own watches and field indexes, so that a
	// caller cannot forget to install something the reconciler needs in order to be triggered.
	Register(mgr manager.Manager) error
}

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

// IsMagicDNSName reports whether name looks like a tailnet MagicDNS name.
func IsMagicDNSName(name string) bool {
	return validMagicDNSName.MatchString(name)
}

// NameForService returns the tailnet hostname to use for svc: the AnnotationHostname override if set, otherwise
// <namespace>-<name>.
func NameForService(svc *corev1.Service) string {
	if h, ok := svc.Annotations[AnnotationHostname]; ok {
		return h
	}
	return svc.Namespace + "-" + svc.Name
}

// TagViolations returns a human-readable description of every invalid ACL tag in obj's AnnotationTags, or nil if the
// annotation is absent or every tag is valid.
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

// ValidateService returns a human-readable description of every way in which svc is not a valid Service for the
// operator to act on, or an empty slice if it is valid. Callers append their own resource-specific violations; the
// checks here are the ones common to every Service the operator exposes.
func ValidateService(svc *corev1.Service) []string {
	violations := make([]string, 0)
	if svc.Spec.ClusterIP == "None" {
		violations = append(violations, "headless Services are not supported.")
	}
	if svc.Annotations[AnnotationTailnetTargetFQDN] != "" && svc.Annotations[AnnotationTailnetTargetIP] != "" {
		violations = append(violations, fmt.Sprintf("only one of annotations %s and %s can be set", AnnotationTailnetTargetIP, AnnotationTailnetTargetFQDN))
	}
	if fqdn := svc.Annotations[AnnotationTailnetTargetFQDN]; fqdn != "" {
		if !IsMagicDNSName(fqdn) {
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

// ClusterDomainOption configures ClusterDomain.
type ClusterDomainOption func(*clusterDomainOpts)

type clusterDomainOpts struct {
	resolvConfPath string
}

// WithResolvConfPath overrides the resolver config that ClusterDomain parses. Only tests should need it: in the
// operator it is the resolver config of the Pod the operator itself runs in.
func WithResolvConfPath(path string) ClusterDomainOption {
	return func(o *clusterDomainOpts) { o.resolvConfPath = path }
}

// ClusterDomain returns the cluster's DNS domain, determined by parsing the resolver config of the Pod the operator
// runs in. It falls back to DefaultClusterDomain when the config is missing or doesn't have the expected shape, since
// erroring out would be worse than assuming the overwhelmingly common value.
func ClusterDomain(namespace string, logger *zap.SugaredLogger, opts ...ClusterDomainOption) string {
	o := clusterDomainOpts{resolvConfPath: resolvConfPath}
	for _, opt := range opts {
		opt(&o)
	}

	logger.Infof("attempting to retrieve cluster domain..")
	conf, err := resolvconffile.ParseFile(o.resolvConfPath)
	if err != nil {
		logger.Warnf("error parsing %s to determine cluster domain, defaulting to %q.", o.resolvConfPath, DefaultClusterDomain)
		return DefaultClusterDomain
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
		return DefaultClusterDomain
	}
	first := conf.SearchDomains[0]
	if !strings.HasPrefix(string(first), namespace+".svc") {
		logger.Warnf("first search domain in resolver config is %s; expected %s.\nDefaulting cluster domain to 'cluster.local'.", first, namespace+".svc.<cluster-domain>")
		return DefaultClusterDomain
	}
	second := conf.SearchDomains[1]
	if !strings.HasPrefix(string(second), "svc") {
		logger.Warnf("second search domain in resolver config is %s; expected 'svc.<cluster-domain>'.\nDefaulting cluster domain to 'cluster.local'.", second)
		return DefaultClusterDomain
	}
	// Trim the trailing dot for backwards compatibility purposes as the
	// cluster domain was previously hardcoded to 'cluster.local' without a
	// trailing dot.
	probablyClusterDomain := strings.TrimPrefix(second.WithoutTrailingDot(), "svc.")
	third := conf.SearchDomains[2]
	if !strings.EqualFold(third.WithoutTrailingDot(), probablyClusterDomain) {
		logger.Warnf("expected resolver config to contain serch domains <namespace>.svc.<cluster-domain>, svc.<cluster-domain>, <cluster-domain>; got %s %s %s\n. Defaulting cluster domain to 'cluster.local'.", first, second, third)
		return DefaultClusterDomain
	}
	logger.Infof("Cluster domain %q extracted from resolver config", probablyClusterDomain)
	return probablyClusterDomain
}

// TruncateLabelValue truncates a Kubernetes label value to fit within the
// 63-character limit. If the value exceeds the limit, it is truncated and a
// short hash suffix is appended to preserve uniqueness.
func TruncateLabelValue(val string) string {
	const maxLen = 63
	if len(val) <= maxLen {
		return val
	}
	hash := sha256.Sum256([]byte(val))
	suffix := hex.EncodeToString(hash[:4]) // 8 hex chars
	truncated := val[:maxLen-len(suffix)-1]
	return truncated + "-" + suffix
}

// SetCondition ensures conds has a condition of the given type with the supplied status, reason, message and observed
// generation, and returns the updated slice. LastTransitionTime is only advanced when the status actually changes, so
// callers can call it on every reconcile without churning the resource; a transition is logged when it happens.
//
// It operates on the condition slice rather than the owning object because the Tailscale CRD types expose
// Status.Conditions as a plain field with no accessor to constrain a type parameter on. Each reconciler wraps this in
// a small helper for its own CRD, e.g.
//
//	func setStatus(pr *tsapi.PeerRelay, ct tsapi.ConditionType, st metav1.ConditionStatus, reason, msg string, clock tstime.Clock, lg *zap.SugaredLogger) {
//		pr.Status.Conditions = reconciler.SetCondition(pr.Status.Conditions, ct, st, reason, msg, pr.Generation, clock, lg)
//	}
func SetCondition(conds []metav1.Condition, conditionType tsapi.ConditionType, status metav1.ConditionStatus, reason, message string, gen int64, clock tstime.Clock, logger *zap.SugaredLogger) []metav1.Condition {
	newCondition := metav1.Condition{
		Type:               string(conditionType),
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: gen,
	}

	newCondition.LastTransitionTime = metav1.NewTime(clock.Now().Truncate(time.Second))

	idx := slices.IndexFunc(conds, func(cond metav1.Condition) bool {
		return cond.Type == string(conditionType)
	})
	if idx == -1 {
		return append(conds, newCondition)
	}

	cond := conds[idx] // update the existing condition

	// If this update doesn't contain a state transition, don't update last
	// transition time.
	if cond.Status == status {
		newCondition.LastTransitionTime = cond.LastTransitionTime
	} else {
		logger.Infof("Status change for condition %s from %s to %s", conditionType, cond.Status, status)
	}
	conds[idx] = newCondition
	return conds
}

// Condition returns the condition of the given type from conds, or nil if it isn't present.
func Condition(conds []metav1.Condition, conditionType tsapi.ConditionType) *metav1.Condition {
	idx := slices.IndexFunc(conds, func(cond metav1.Condition) bool {
		return cond.Type == string(conditionType)
	})
	if idx == -1 {
		return nil
	}
	return &conds[idx]
}

// RemoveCondition removes the condition of the given type from conds if present, returning the updated slice.
func RemoveCondition(conds []metav1.Condition, conditionType tsapi.ConditionType) []metav1.Condition {
	return slices.DeleteFunc(conds, func(cond metav1.Condition) bool {
		return cond.Type == string(conditionType)
	})
}

// The helpers below wrap SetCondition and friends for the CRDs whose reconcilers still live in cmd/k8s-operator. As
// each of those moves into its own package under this one it should grow a package-local wrapper instead, at which
// point the corresponding helper here can go.

// SetConnectorCondition ensures that Connector status has a condition with the
// given attributes. LastTransitionTime gets set every time condition's status
// changes.
func SetConnectorCondition(cn *tsapi.Connector, conditionType tsapi.ConditionType, status metav1.ConditionStatus, reason, message string, gen int64, clock tstime.Clock, logger *zap.SugaredLogger) {
	cn.Status.Conditions = SetCondition(cn.Status.Conditions, conditionType, status, reason, message, gen, clock, logger)
}

// SetProxyClassCondition ensures that ProxyClass status has a condition with the
// given attributes. LastTransitionTime gets set every time condition's status
// changes.
func SetProxyClassCondition(pc *tsapi.ProxyClass, conditionType tsapi.ConditionType, status metav1.ConditionStatus, reason, message string, gen int64, clock tstime.Clock, logger *zap.SugaredLogger) {
	pc.Status.Conditions = SetCondition(pc.Status.Conditions, conditionType, status, reason, message, gen, clock, logger)
}

// SetDNSConfigCondition ensures that DNSConfig status has a condition with the
// given attributes. LastTransitionTime gets set every time condition's status
// changes
func SetDNSConfigCondition(dnsCfg *tsapi.DNSConfig, conditionType tsapi.ConditionType, status metav1.ConditionStatus, reason, message string, gen int64, clock tstime.Clock, logger *zap.SugaredLogger) {
	dnsCfg.Status.Conditions = SetCondition(dnsCfg.Status.Conditions, conditionType, status, reason, message, gen, clock, logger)
}

// SetServiceCondition ensures that Service status has a condition with the
// given attributes. LastTransitionTime gets set every time condition's status
// changes. Services carry no meaningful generation for the operator's purposes, so ObservedGeneration is always 0.
func SetServiceCondition(svc *corev1.Service, conditionType tsapi.ConditionType, status metav1.ConditionStatus, reason, message string, clock tstime.Clock, logger *zap.SugaredLogger) {
	svc.Status.Conditions = SetCondition(svc.Status.Conditions, conditionType, status, reason, message, 0, clock, logger)
}

// GetServiceCondition returns Service condition with the specified type, if it exists on the Service.
func GetServiceCondition(svc *corev1.Service, conditionType tsapi.ConditionType) *metav1.Condition {
	return Condition(svc.Status.Conditions, conditionType)
}

// RemoveServiceCondition will remove condition of the given type if it exists.
func RemoveServiceCondition(svc *corev1.Service, conditionType tsapi.ConditionType) {
	svc.Status.Conditions = RemoveCondition(svc.Status.Conditions, conditionType)
}

// SetProxyGroupCondition ensures that ProxyGroup status has a condition with the
// given attributes. LastTransitionTime gets set every time condition's status
// changes.
func SetProxyGroupCondition(pg *tsapi.ProxyGroup, conditionType tsapi.ConditionType, status metav1.ConditionStatus, reason, message string, gen int64, clock tstime.Clock, logger *zap.SugaredLogger) {
	pg.Status.Conditions = SetCondition(pg.Status.Conditions, conditionType, status, reason, message, gen, clock, logger)
}

// ProxyClassIsReady reports whether pc has been validated for its current generation.
func ProxyClassIsReady(pc *tsapi.ProxyClass) bool {
	cond := Condition(pc.Status.Conditions, tsapi.ProxyClassReady)
	return cond != nil && cond.Status == metav1.ConditionTrue && cond.ObservedGeneration == pc.Generation
}

// ProxyGroupAvailable reports whether at least one of pg's proxies is running and ready to serve traffic.
func ProxyGroupAvailable(pg *tsapi.ProxyGroup) bool {
	cond := Condition(pg.Status.Conditions, tsapi.ProxyGroupAvailable)
	return cond != nil && cond.Status == metav1.ConditionTrue
}

// ProxyGroupReplicas returns the number of replicas the ProxyGroup asks for, defaulting to two when unset.
func ProxyGroupReplicas(pg *tsapi.ProxyGroup) int32 {
	if pg.Spec.Replicas != nil {
		return *pg.Spec.Replicas
	}

	return 2
}

// KubeAPIServerProxyValid reports whether pg's kube-apiserver proxy config has been validated for its current
// generation, and whether the condition is present at all.
func KubeAPIServerProxyValid(pg *tsapi.ProxyGroup) (valid bool, set bool) {
	cond := Condition(pg.Status.Conditions, tsapi.KubeAPIServerProxyValid)
	return cond != nil && cond.Status == metav1.ConditionTrue && cond.ObservedGeneration == pg.Generation, cond != nil
}

// KubeAPIServerProxyConfigured reports whether pg's kube-apiserver proxy has been configured for its current
// generation.
func KubeAPIServerProxyConfigured(pg *tsapi.ProxyGroup) bool {
	cond := Condition(pg.Status.Conditions, tsapi.KubeAPIServerProxyConfigured)
	return cond != nil && cond.Status == metav1.ConditionTrue && cond.ObservedGeneration == pg.Generation
}

// SvcIsReady reports whether the proxy exposing svc is ready.
func SvcIsReady(svc *corev1.Service) bool {
	cond := Condition(svc.Status.Conditions, tsapi.ProxyReady)
	return cond != nil && cond.Status == metav1.ConditionTrue
}
