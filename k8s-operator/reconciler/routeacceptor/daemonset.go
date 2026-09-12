// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package routeacceptor

import (
	"context"
	"fmt"

	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"tailscale.com/ipn"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler"
	"tailscale.com/k8s-operator/reconciler/tailscaled"
	"tailscale.com/kube/kubetypes"
)

// resourceName returns the name of the DaemonSet managed for the RouteAcceptor named raName. It is also the prefix
// of the names of the Secrets managed for it.
func resourceName(raName string) string {
	return "routeacceptor-" + raName
}

// configSecretName returns the name of the config Secret shared by every device of the RouteAcceptor named raName.
func configSecretName(raName string) string {
	return resourceName(raName) + "-config"
}

// stateSecretName returns the name of the state Secret of the device of the RouteAcceptor named raName on the node
// named node.
func stateSecretName(raName, node string) string {
	return tailscaled.DaemonSetStateSecretName(resourceName(raName), node)
}

func routeAcceptorLabels(raName string) map[string]string {
	return reconciler.Labels(parentTypeRouteAcceptor, raName, "")
}

// stateSecretSelector returns the labels that select the state Secrets of the RouteAcceptor named raName.
func stateSecretSelector(raName string) map[string]string {
	l := routeAcceptorLabels(raName)
	l[kubetypes.LabelSecretType] = kubetypes.LabelSecretTypeState
	return l
}

func (r *Reconciler) tags(ra *tsapi.RouteAcceptor) []string {
	tags := ra.Spec.Tags.Stringify()
	if len(tags) == 0 {
		return r.defaultTags
	}
	return tags
}

// tailscaledConfig returns the tailscaled config shared by every device of a RouteAcceptor. As the config is shared,
// it must not contain per-device settings: the hostname is left unset so that each device takes the OS hostname,
// which in the host network namespace is the node's hostname.
func tailscaledConfig(authKey, loginServer string) ipn.ConfigVAlpha {
	conf := ipn.ConfigVAlpha{
		Version: "alpha0",
		Locked:  "false",
		// The device runs in the host network namespace; accepting the tailnet's DNS config would reconfigure
		// the node's DNS resolver.
		AcceptDNS:           "false",
		AcceptRoutes:        "true",
		NoStatefulFiltering: "true", // Explicitly enforce default value, see #14216
		AuthKey:             &authKey,
	}
	if loginServer != "" {
		conf.ServerURL = &loginServer
	}
	return conf
}

func (r *Reconciler) routeAcceptorDaemonSet(ra *tsapi.RouteAcceptor, pc *tsapi.ProxyClass) *appsv1.DaemonSet {
	ds := tailscaled.NewDaemonSet(tailscaled.DaemonSetOptions{
		Name:               resourceName(ra.Name),
		Namespace:          r.tailscaleNamespace,
		Labels:             routeAcceptorLabels(ra.Name),
		Image:              r.proxyImage,
		ServiceAccountName: serviceAccountName,
		ConfigSecretName:   configSecretName(ra.Name),
	})

	c := &ds.Spec.Template.Spec.Containers[0]
	c.Env = append(c.Env, corev1.EnvVar{Name: routeAcceptorEnvVar, Value: "true"})
	if len(ra.Spec.Sources) > 0 {
		c.Env = append(c.Env, corev1.EnvVar{Name: routeAcceptorSourcesEnvVar, Value: "true"})
	}

	ds = tailscaled.ApplyProxyClassToDaemonSet(ds, pc, managedLabelKeys, nil)
	if ds.Spec.Template.Spec.PriorityClassName == "" {
		ds.Spec.Template.Spec.PriorityClassName = r.proxyPriorityClassName
	}
	return ds
}

func (r *Reconciler) ensureDaemonSet(ctx context.Context, logger *zap.SugaredLogger, ra *tsapi.RouteAcceptor, pc *tsapi.ProxyClass) (*appsv1.DaemonSet, error) {
	desired := r.routeAcceptorDaemonSet(ra, pc)

	logger.Debugf("applying DaemonSet %q", desired.Name)
	if err := r.Patch(ctx, desired, client.Apply, fieldOwner, client.ForceOwnership); err != nil {
		return nil, fmt.Errorf("failed to apply DaemonSet: %w", err)
	}

	var current appsv1.DaemonSet
	if err := r.Get(ctx, types.NamespacedName{Namespace: desired.Namespace, Name: desired.Name}, &current); err != nil {
		return nil, fmt.Errorf("failed to get DaemonSet: %w", err)
	}

	return &current, nil
}

func (r *Reconciler) deleteDaemonSet(ctx context.Context, logger *zap.SugaredLogger, ra *tsapi.RouteAcceptor) error {
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: resourceName(ra.Name), Namespace: r.tailscaleNamespace},
	}
	logger.Debugf("deleting DaemonSet %q", ds.Name)
	if err := r.Delete(ctx, ds); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to delete DaemonSet: %w", err)
	}
	return nil
}

func (r *Reconciler) getProxyClass(ctx context.Context, ra *tsapi.RouteAcceptor) (*tsapi.ProxyClass, error) {
	if ra.Spec.ProxyClass == "" {
		return nil, nil
	}

	var pc tsapi.ProxyClass
	if err := r.Get(ctx, types.NamespacedName{Name: ra.Spec.ProxyClass}, &pc); err != nil {
		return nil, fmt.Errorf("failed to get ProxyClass %q: %w", ra.Spec.ProxyClass, err)
	}
	return &pc, nil
}

func (r *Reconciler) listNodes(ctx context.Context) ([]corev1.Node, error) {
	var list corev1.NodeList
	if err := r.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("failed to list Nodes: %w", err)
	}
	return list.Items, nil
}

// selectNodes returns the nodes that the DaemonSet's Pods are scheduled to, as far as the operator can tell: those
// matching the ProxyClass's pod.nodeSelector, if any. Affinity rules and taints are not evaluated; a node they
// exclude keeps an (empty) state Secret until it is removed from the cluster.
func selectNodes(nodes []corev1.Node, pc *tsapi.ProxyClass) []corev1.Node {
	selector := labels.Everything()
	if pc != nil && pc.Spec.StatefulSet != nil && pc.Spec.StatefulSet.Pod != nil && len(pc.Spec.StatefulSet.Pod.NodeSelector) > 0 {
		selector = labels.SelectorFromSet(pc.Spec.StatefulSet.Pod.NodeSelector)
	}

	var selected []corev1.Node
	for _, n := range nodes {
		if selector.Matches(labels.Set(n.Labels)) {
			selected = append(selected, n)
		}
	}
	return selected
}
