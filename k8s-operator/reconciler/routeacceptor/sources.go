// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package routeacceptor

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/kube/routesources"
)

const (
	sourcesReconcilerName = "routeacceptor-sources-reconciler"

	// sourcesFieldOwner identifies the patches that write route sources documents into state Secrets, so that
	// they are distinct from the RouteAcceptor reconciler's apply of the Secrets' metadata and from containerboot's
	// patches of the other data keys.
	sourcesFieldOwner client.FieldOwner = "routeacceptor-sources"

	// routeAcceptorSourcesEnvVar is the containerboot env var that makes the devices enforce spec.sources.
	routeAcceptorSourcesEnvVar = "TS_EXPERIMENTAL_ROUTE_ACCEPTOR_SOURCES"
)

type (
	// SourcesReconciler computes, for every node that runs a RouteAcceptor's device, which Pods may be routed via
	// the tailnet and to which routes (spec.sources), and writes the result into the node's state Secret as a
	// routesources.Document for containerboot to enforce. It is separate from the RouteAcceptor Reconciler
	// because Pod events drive it and those are frequent: a reconcile is one cached list of stripped-down Pods
	// and a patch of the Secrets whose document changed.
	SourcesReconciler struct {
		client.Client

		pods               client.Reader
		podCache           cache.Cache
		tailscaleNamespace string
		logger             *zap.SugaredLogger
	}

	// SourcesReconcilerOptions configures a SourcesReconciler.
	SourcesReconcilerOptions struct {
		// Client is the manager's cached client.
		Client client.Client
		// PodCache caches every Pod and Namespace of the cluster, transformed by StripPod and StripNamespace.
		PodCache cache.Cache
		// PodReader reads Pods and Namespaces. Defaults to PodCache; tests set a client.
		PodReader client.Reader
		// TailscaleNamespace is the namespace the state Secrets live in.
		TailscaleNamespace string
		// Logger is the logger to use.
		Logger *zap.SugaredLogger
	}
)

// NewSourcesReconciler returns a SourcesReconciler.
func NewSourcesReconciler(opts SourcesReconcilerOptions) *SourcesReconciler {
	pods := opts.PodReader
	if pods == nil {
		pods = opts.PodCache
	}
	return &SourcesReconciler{
		Client:             opts.Client,
		pods:               pods,
		podCache:           opts.PodCache,
		tailscaleNamespace: opts.TailscaleNamespace,
		logger:             opts.Logger,
	}
}

// Register the SourcesReconciler onto the manager. It reconciles a RouteAcceptor when its spec or cluster CIDRs
// change, when a device's state Secret is created, and when a Pod or a Namespace's labels change.
func (r *SourcesReconciler) Register(mgr manager.Manager) error {
	return builder.
		ControllerManagedBy(mgr).
		Named(sourcesReconcilerName).
		For(&tsapi.RouteAcceptor{}, builder.WithPredicates(routeAcceptorSourcesPredicate)).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(reconciler.EnqueueForChild(parentTypeRouteAcceptor)), builder.WithPredicates(stateSecretCreatedPredicate)).
		WatchesRawSource(source.Kind(r.podCache, &corev1.Pod{}, handler.TypedEnqueueRequestsFromMapFunc(enqueueAllWithSources[*corev1.Pod](r)), podSourcePredicate)).
		WatchesRawSource(source.Kind(r.podCache, &corev1.Namespace{}, handler.TypedEnqueueRequestsFromMapFunc(enqueueAllWithSources[*corev1.Namespace](r)), namespaceSourcePredicate)).
		Complete(r)
}

// routeAcceptorSourcesPredicate limits RouteAcceptor events to changes of the spec (generation) and of the cluster
// CIDRs the RouteAcceptor reconciler reports in the status.
var routeAcceptorSourcesPredicate = predicate.Funcs{
	UpdateFunc: func(e event.UpdateEvent) bool {
		if e.ObjectOld.GetGeneration() != e.ObjectNew.GetGeneration() {
			return true
		}
		oldRA, ok := e.ObjectOld.(*tsapi.RouteAcceptor)
		if !ok {
			return true
		}
		newRA, ok := e.ObjectNew.(*tsapi.RouteAcceptor)
		if !ok {
			return true
		}
		return !slices.Equal(oldRA.Status.ClusterCIDRs, newRA.Status.ClusterCIDRs)
	},
}

// stateSecretCreatedPredicate passes only the creation of state Secrets: a new device needs its document, and
// every other Secret change is either containerboot's or this reconciler's own.
var stateSecretCreatedPredicate = predicate.Funcs{
	CreateFunc: func(e event.CreateEvent) bool {
		return e.Object.GetLabels()[kubetypes.LabelSecretType] == kubetypes.LabelSecretTypeState
	},
	UpdateFunc:  func(event.UpdateEvent) bool { return false },
	DeleteFunc:  func(event.DeleteEvent) bool { return false },
	GenericFunc: func(event.GenericEvent) bool { return false },
}

// podSourcePredicate passes the Pod events that can change a document: Pods getting or losing addresses, moving
// between phases, or changing labels.
var podSourcePredicate = predicate.TypedFuncs[*corev1.Pod]{
	CreateFunc: func(e event.TypedCreateEvent[*corev1.Pod]) bool {
		return podIsSourceCandidate(e.Object)
	},
	DeleteFunc: func(e event.TypedDeleteEvent[*corev1.Pod]) bool {
		return podIsSourceCandidate(e.Object)
	},
	UpdateFunc: func(e event.TypedUpdateEvent[*corev1.Pod]) bool {
		o, n := e.ObjectOld, e.ObjectNew
		return !slices.Equal(o.Status.PodIPs, n.Status.PodIPs) ||
			o.Status.Phase != n.Status.Phase ||
			o.Spec.NodeName != n.Spec.NodeName ||
			o.Spec.HostNetwork != n.Spec.HostNetwork ||
			!maps.Equal(o.Labels, n.Labels)
	},
	GenericFunc: func(event.TypedGenericEvent[*corev1.Pod]) bool { return false },
}

// namespaceSourcePredicate passes label changes of Namespaces, which can change which Pods a namespaceSelector
// selects. Creations and deletions are covered by the Pods' own events.
var namespaceSourcePredicate = predicate.TypedFuncs[*corev1.Namespace]{
	CreateFunc: func(event.TypedCreateEvent[*corev1.Namespace]) bool { return false },
	DeleteFunc: func(event.TypedDeleteEvent[*corev1.Namespace]) bool { return false },
	UpdateFunc: func(e event.TypedUpdateEvent[*corev1.Namespace]) bool {
		return !maps.Equal(e.ObjectOld.Labels, e.ObjectNew.Labels)
	},
	GenericFunc: func(event.TypedGenericEvent[*corev1.Namespace]) bool { return false },
}

// podIsSourceCandidate reports whether a Pod can appear in a document at all.
func podIsSourceCandidate(pod *corev1.Pod) bool {
	if pod.Spec.HostNetwork || pod.Spec.NodeName == "" || len(pod.Status.PodIPs) == 0 {
		return false
	}
	return pod.Status.Phase != corev1.PodSucceeded && pod.Status.Phase != corev1.PodFailed
}

// enqueueAllWithSources returns a map function that enqueues every RouteAcceptor with spec.sources, as any of
// them may select the changed object.
func enqueueAllWithSources[object client.Object](r *SourcesReconciler) handler.TypedMapFunc[object, reconcile.Request] {
	return func(ctx context.Context, _ object) []reconcile.Request {
		var list tsapi.RouteAcceptorList
		if err := r.List(ctx, &list); err != nil {
			r.logger.Errorf("failed to list RouteAcceptors: %v", err)
			return nil
		}
		var reqs []reconcile.Request
		for _, ra := range list.Items {
			if len(ra.Spec.Sources) > 0 {
				reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{Name: ra.Name}})
			}
		}
		return reqs
	}
}

// StripPod is a cache transform that keeps only what the SourcesReconciler reads from a Pod, so that a cache of
// every Pod in the cluster stays small.
func StripPod(obj any) (any, error) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return obj, nil
	}
	return &corev1.Pod{
		TypeMeta: pod.TypeMeta,
		ObjectMeta: metav1.ObjectMeta{
			Name:              pod.Name,
			Namespace:         pod.Namespace,
			UID:               pod.UID,
			ResourceVersion:   pod.ResourceVersion,
			Labels:            pod.Labels,
			DeletionTimestamp: pod.DeletionTimestamp,
		},
		Spec: corev1.PodSpec{
			NodeName:    pod.Spec.NodeName,
			HostNetwork: pod.Spec.HostNetwork,
		},
		Status: corev1.PodStatus{
			Phase:  pod.Status.Phase,
			PodIPs: pod.Status.PodIPs,
		},
	}, nil
}

// StripNamespace is a cache transform that keeps only a Namespace's labels.
func StripNamespace(obj any) (any, error) {
	ns, ok := obj.(*corev1.Namespace)
	if !ok {
		return obj, nil
	}
	return &corev1.Namespace{
		TypeMeta: ns.TypeMeta,
		ObjectMeta: metav1.ObjectMeta{
			Name:            ns.Name,
			UID:             ns.UID,
			ResourceVersion: ns.ResourceVersion,
			Labels:          ns.Labels,
		},
	}, nil
}

// Reconcile writes the route sources document of every device of the RouteAcceptor, or removes the documents
// when spec.sources is unset.
func (r *SourcesReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	logger := r.logger.With("RouteAcceptor", req.Name)

	ra := new(tsapi.RouteAcceptor)
	err := r.Get(ctx, req.NamespacedName, ra)
	if apierrors.IsNotFound(err) {
		return reconcile.Result{}, nil
	}
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get RouteAcceptor: %w", err)
	}
	if !ra.DeletionTimestamp.IsZero() {
		return reconcile.Result{}, nil
	}

	var secrets corev1.SecretList
	if err := r.List(ctx, &secrets, client.InNamespace(r.tailscaleNamespace), client.MatchingLabels(stateSecretSelector(ra.Name))); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to list state Secrets: %w", err)
	}

	if len(ra.Spec.Sources) == 0 {
		for i := range secrets.Items {
			s := &secrets.Items[i]
			if s.Data[kubetypes.KeyRouteSources] == nil {
				continue
			}
			logger.Infof("removing route sources from state Secret %q", s.Name)
			if err := r.writeRouteSources(ctx, s, nil); err != nil {
				return reconcile.Result{}, err
			}
		}
		return reconcile.Result{}, nil
	}

	var clusterCIDRs []netip.Prefix
	for _, c := range ra.Status.ClusterCIDRs {
		if pfx, err := netip.ParsePrefix(c); err == nil {
			clusterCIDRs = append(clusterCIDRs, pfx)
		}
	}
	if len(clusterCIDRs) == 0 {
		// The RouteAcceptor reconciler reports them once it has run; its status update triggers another reconcile.
		logger.Debugf("waiting for the cluster CIDRs in the RouteAcceptor's status before writing route sources")
		return reconcile.Result{}, nil
	}

	var nodes []string
	for _, s := range secrets.Items {
		if node := s.Annotations[annotationNodeName]; node != "" {
			nodes = append(nodes, node)
		}
	}
	docs, err := r.routeSourcesByNode(ctx, ra, clusterCIDRs, nodes)
	if err != nil {
		return reconcile.Result{}, err
	}

	for i := range secrets.Items {
		s := &secrets.Items[i]
		node := s.Annotations[annotationNodeName]
		doc := docs[node]
		if doc == nil {
			doc = &routesources.Document{Version: routesources.Version, ClusterCIDRs: clusterCIDRs}
		}
		b, err := doc.Marshal()
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to encode route sources for node %q: %w", node, err)
		}
		if bytes.Equal(s.Data[kubetypes.KeyRouteSources], b) {
			continue
		}
		logger.Debugf("writing route sources for node %q: %d group(s)", node, len(doc.Groups))
		if err := r.writeRouteSources(ctx, s, b); err != nil {
			return reconcile.Result{}, err
		}
	}
	return reconcile.Result{}, nil
}

// writeRouteSources sets (or, with a nil document, removes) the route sources field of a state Secret with a
// merge patch, leaving the other fields, which containerboot writes, alone.
func (r *SourcesReconciler) writeRouteSources(ctx context.Context, s *corev1.Secret, doc []byte) error {
	var patch []byte
	var err error
	if doc == nil {
		patch, err = json.Marshal(map[string]any{"data": map[string]any{kubetypes.KeyRouteSources: nil}})
	} else {
		patch, err = json.Marshal(map[string]any{"data": map[string][]byte{kubetypes.KeyRouteSources: doc}})
	}
	if err != nil {
		return fmt.Errorf("failed to encode route sources patch: %w", err)
	}
	if err := r.Patch(ctx, s, client.RawPatch(types.MergePatchType, patch), sourcesFieldOwner); err != nil {
		return fmt.Errorf("failed to patch route sources into state Secret %q: %w", s.Name, err)
	}
	return nil
}

// compiledSource is a spec.sources entry ready for matching.
type compiledSource struct {
	pods       labels.Selector
	namespaces labels.Selector // nil selects every namespace
	routes     []netip.Prefix  // nil means every route
}

func compileSources(sources []tsapi.RouteAcceptorSource) ([]compiledSource, error) {
	out := make([]compiledSource, 0, len(sources))
	for i, src := range sources {
		var cs compiledSource
		var err error
		if src.PodSelector == nil {
			cs.pods = labels.Everything()
		} else if cs.pods, err = metav1.LabelSelectorAsSelector(src.PodSelector); err != nil {
			return nil, fmt.Errorf("spec.sources[%d].podSelector: %w", i, err)
		}
		if src.NamespaceSelector != nil {
			if cs.namespaces, err = metav1.LabelSelectorAsSelector(src.NamespaceSelector); err != nil {
				return nil, fmt.Errorf("spec.sources[%d].namespaceSelector: %w", i, err)
			}
		}
		if src.Routes != nil {
			cs.routes = []netip.Prefix{}
			for _, route := range src.Routes {
				pfx, err := netip.ParsePrefix(string(route))
				if err != nil {
					return nil, fmt.Errorf("spec.sources[%d].routes: %w", i, err)
				}
				cs.routes = append(cs.routes, pfx.Masked())
			}
		}
		out = append(out, cs)
	}
	return out, nil
}

// sourceGroup accumulates the Pod addresses of one node that share a set of routes.
type sourceGroup struct {
	routes []netip.Prefix // nil means every route
	ips    []netip.Addr
}

// routeSourcesByNode evaluates spec.sources against every Pod and returns a document per node that has Pods to
// route. In the Cilium egress gateway mode every node is a gateway for every selected Pod, so every node gets
// the whole list.
func (r *SourcesReconciler) routeSourcesByNode(ctx context.Context, ra *tsapi.RouteAcceptor, clusterCIDRs []netip.Prefix, nodes []string) (map[string]*routesources.Document, error) {
	sources, err := compileSources(ra.Spec.Sources)
	if err != nil {
		return nil, err
	}
	var pods corev1.PodList
	if err := r.pods.List(ctx, &pods); err != nil {
		return nil, fmt.Errorf("failed to list Pods: %w", err)
	}
	gateway := ciliumEgressGatewayEnabled(ra)

	nsLabels := map[string]labels.Set{}
	namespaceLabels := func(name string) (labels.Set, error) {
		if set, ok := nsLabels[name]; ok {
			return set, nil
		}
		var ns corev1.Namespace
		if err := r.pods.Get(ctx, types.NamespacedName{Name: name}, &ns); err != nil {
			if apierrors.IsNotFound(err) {
				nsLabels[name] = nil
				return nil, nil
			}
			return nil, fmt.Errorf("failed to get Namespace %q: %w", name, err)
		}
		nsLabels[name] = ns.Labels
		return ns.Labels, nil
	}

	// node -> routes key -> group
	groups := map[string]map[string]*sourceGroup{}
	addTo := func(node string, key string, routes []netip.Prefix, ips []netip.Addr) {
		byKey, ok := groups[node]
		if !ok {
			byKey = map[string]*sourceGroup{}
			groups[node] = byKey
		}
		g, ok := byKey[key]
		if !ok {
			g = &sourceGroup{routes: routes}
			byKey[key] = g
		}
		g.ips = append(g.ips, ips...)
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !podIsSourceCandidate(pod) {
			continue
		}
		matched, all := false, false
		var routes []netip.Prefix
		for _, src := range sources {
			if !src.pods.Matches(labels.Set(pod.Labels)) {
				continue
			}
			if src.namespaces != nil {
				set, err := namespaceLabels(pod.Namespace)
				if err != nil {
					return nil, err
				}
				if !src.namespaces.Matches(set) {
					continue
				}
			}
			matched = true
			if src.routes == nil {
				all = true
			} else {
				routes = append(routes, src.routes...)
			}
		}
		if !matched {
			continue
		}
		var ips []netip.Addr
		for _, ip := range pod.Status.PodIPs {
			if addr, err := netip.ParseAddr(ip.IP); err == nil {
				ips = append(ips, addr.Unmap())
			}
		}
		if len(ips) == 0 {
			continue
		}
		key := ""
		if all {
			routes = nil
		} else {
			routes = sortedPrefixes(routes)
			key = prefixesKey(routes)
		}
		if gateway {
			for _, node := range nodes {
				addTo(node, key, routes, ips)
			}
		} else {
			addTo(pod.Spec.NodeName, key, routes, ips)
		}
	}

	// Routing tables are assigned cluster-wide, in a canonical order, so that a group's table does not depend on
	// the node and stays stable while other groups come and go.
	var keys []string
	for _, byKey := range groups {
		for key := range byKey {
			if key != "" {
				keys = append(keys, key)
			}
		}
	}
	slices.Sort(keys)
	keys = slices.Compact(keys)
	tables := map[string]int{}
	taken := map[int]bool{}
	for _, key := range keys {
		routes := prefixesFromKey(key)
		table, err := routesources.TableFor(routes, taken)
		if err != nil {
			return nil, fmt.Errorf("assigning a routing table for routes %s: %w", key, err)
		}
		tables[key] = table
		taken[table] = true
	}

	docs := map[string]*routesources.Document{}
	for node, byKey := range groups {
		doc := &routesources.Document{Version: routesources.Version, ClusterCIDRs: clusterCIDRs}
		for key, g := range byKey {
			doc.Groups = append(doc.Groups, routesources.Group{Routes: g.routes, Table: tables[key], IPs: g.ips})
		}
		docs[node] = doc
	}
	return docs, nil
}

// prefixesKey is a canonical string for a set of prefixes, and prefixesFromKey its inverse.
func prefixesKey(pfxs []netip.Prefix) string {
	strs := make([]string, len(pfxs))
	for i, p := range pfxs {
		strs[i] = p.String()
	}
	return strings.Join(strs, ",")
}

func prefixesFromKey(key string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range strings.Split(key, ",") {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p)
		}
	}
	slices.SortFunc(out, func(a, b netip.Prefix) int {
		return cmp.Or(a.Addr().Compare(b.Addr()), cmp.Compare(a.Bits(), b.Bits()))
	})
	return out
}
