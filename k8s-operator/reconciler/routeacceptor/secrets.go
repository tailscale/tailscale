// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package routeacceptor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler/tailscaled"
	"tailscale.com/k8s-operator/tsclient"
	"tailscale.com/tailcfg"
	"tailscale.com/util/set"
)

const (
	// annotationAuthKeyExpires records, on the config Secret, when the reusable auth key in it expires, in RFC 3339
	// format.
	annotationAuthKeyExpires = "tailscale.com/authkey-expires"

	// authKeyExpiry is the lifetime requested for the reusable auth key. It is the longest lifetime the control
	// plane allows.
	authKeyExpiry = 90 * 24 * time.Hour

	// authKeyRotationWindow is how long before the reusable auth key expires that a new one is minted. The old key
	// stays valid until it expires, so devices that already hold it are not affected.
	authKeyRotationWindow = 14 * 24 * time.Hour
)

// ensureStateSecret pre-creates the state Secret of the device on node, stamped with the RouteAcceptor's labels and
// the node's name, so that cleanup can select state Secrets by label. The Secret's data is written by containerboot;
// a server-side apply that only manages metadata adopts a Secret containerboot created first without touching it.
func (r *Reconciler) ensureStateSecret(ctx context.Context, logger *zap.SugaredLogger, ra *tsapi.RouteAcceptor, node string) error {
	desired := tailscaled.NewStateSecret(tailscaled.StateSecretOptions{
		Name:      stateSecretName(ra.Name, node),
		Namespace: r.tailscaleNamespace,
		Labels:    routeAcceptorLabels(ra.Name),
	})
	desired.Annotations = map[string]string{annotationNodeName: node}

	logger.Debugf("applying state Secret %q", desired.Name)
	if err := r.Patch(ctx, desired, client.Apply, fieldOwner, client.ForceOwnership); err != nil {
		return fmt.Errorf("failed to apply state Secret: %w", err)
	}
	return nil
}

// listStateSecrets returns the state Secrets of the RouteAcceptor's devices.
func (r *Reconciler) listStateSecrets(ctx context.Context, ra *tsapi.RouteAcceptor) ([]corev1.Secret, error) {
	var list corev1.SecretList
	if err := r.List(ctx, &list, client.InNamespace(r.tailscaleNamespace), client.MatchingLabels(stateSecretSelector(ra.Name))); err != nil {
		return nil, fmt.Errorf("failed to list state Secrets: %w", err)
	}
	return list.Items, nil
}

// reapStaleNodes deletes the devices, and their state Secrets, of nodes that no longer exist or are no longer
// selected and no longer run a Pod of the DaemonSet.
func (r *Reconciler) reapStaleNodes(ctx context.Context, logger *zap.SugaredLogger, ra *tsapi.RouteAcceptor, allNodes, selected []corev1.Node) error {
	secrets, err := r.listStateSecrets(ctx, ra)
	if err != nil {
		return err
	}

	existing := make(set.Set[string], len(allNodes))
	for _, n := range allNodes {
		existing.Add(n.Name)
	}
	wanted := make(set.Set[string], len(selected))
	for _, n := range selected {
		wanted.Add(n.Name)
	}

	var podsByNode set.Set[string]
	tsClient, err := r.tsClients.For(ra.Spec.Tailnet)
	if err != nil {
		return fmt.Errorf("failed to resolve Tailscale API client for tailnet %q: %w", ra.Spec.Tailnet, err)
	}

	var errs []error
	for i := range secrets {
		s := &secrets[i]
		node := s.Annotations[annotationNodeName]
		if node == "" || wanted.Contains(node) {
			continue
		}
		if existing.Contains(node) {
			// The node is no longer selected, but the DaemonSet controller may not have removed its Pod yet.
			if podsByNode == nil {
				if podsByNode, err = r.podsByNode(ctx, ra); err != nil {
					return err
				}
			}
			if podsByNode.Contains(node) {
				continue
			}
		}

		logger.Infof("node %q is gone or no longer selected, deleting its device", node)
		if err := r.deleteNodeState(ctx, logger, tsClient, s); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// podsByNode returns the names of the nodes that currently run a Pod of the RouteAcceptor's DaemonSet.
func (r *Reconciler) podsByNode(ctx context.Context, ra *tsapi.RouteAcceptor) (set.Set[string], error) {
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(r.tailscaleNamespace), client.MatchingLabels(routeAcceptorLabels(ra.Name))); err != nil {
		return nil, fmt.Errorf("failed to list Pods: %w", err)
	}
	nodes := make(set.Set[string], len(pods.Items))
	for _, p := range pods.Items {
		if p.Spec.NodeName != "" {
			nodes.Add(p.Spec.NodeName)
		}
	}
	return nodes, nil
}

// deleteNodeState deletes the tailnet device whose state is held in secret, if any, and then the Secret itself.
func (r *Reconciler) deleteNodeState(ctx context.Context, logger *zap.SugaredLogger, tsClient tsclient.Client, secret *corev1.Secret) error {
	if deviceID := tailscaled.DeviceIDFromStateSecret(secret); deviceID != "" {
		if err := tailscaled.EnsureDeviceDeleted(ctx, tsClient, logger, tailcfg.StableNodeID(deviceID)); err != nil {
			return fmt.Errorf("failed to delete tailnet device %q: %w", deviceID, err)
		}
	}

	logger.Debugf("deleting state Secret %q", secret.Name)
	if err := r.Delete(ctx, secret); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to delete state Secret %q: %w", secret.Name, err)
	}
	return nil
}

// deleteAllNodeState deletes every device of the RouteAcceptor and every state Secret.
func (r *Reconciler) deleteAllNodeState(ctx context.Context, logger *zap.SugaredLogger, ra *tsapi.RouteAcceptor) error {
	if r.tsClients == nil {
		return nil
	}

	tsClient, err := r.tsClients.For(ra.Spec.Tailnet)
	if err != nil {
		return fmt.Errorf("failed to resolve Tailscale API client for tailnet %q: %w", ra.Spec.Tailnet, err)
	}

	secrets, err := r.listStateSecrets(ctx, ra)
	if err != nil {
		return err
	}

	var errs []error
	for i := range secrets {
		if err := r.deleteNodeState(ctx, logger, tsClient, &secrets[i]); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ensureConfigSecret applies the config Secret shared by every device of the RouteAcceptor, minting or rotating its
// reusable auth key as needed. It returns how long until the key should next be rotated.
func (r *Reconciler) ensureConfigSecret(ctx context.Context, logger *zap.SugaredLogger, ra *tsapi.RouteAcceptor, nodes []corev1.Node) (time.Duration, error) {
	tsClient, err := r.tsClients.For(ra.Spec.Tailnet)
	if err != nil {
		return 0, fmt.Errorf("failed to resolve Tailscale API client for tailnet %q: %w", ra.Spec.Tailnet, err)
	}

	var existing *corev1.Secret
	var cfgSecret corev1.Secret
	err = r.Get(ctx, types.NamespacedName{Namespace: r.tailscaleNamespace, Name: configSecretName(ra.Name)}, &cfgSecret)
	switch {
	case apierrors.IsNotFound(err):
	case err != nil:
		return 0, fmt.Errorf("failed to get config Secret: %w", err)
	default:
		existing = &cfgSecret
	}

	authKey, expires, err := r.ensureAuthKey(ctx, logger, tsClient, ra, existing, nodes)
	if err != nil {
		return 0, err
	}

	desired, err := tailscaled.NewConfigSecret(tailscaled.ConfigSecretOptions{
		Name:      configSecretName(ra.Name),
		Namespace: r.tailscaleNamespace,
		Labels:    routeAcceptorLabels(ra.Name),
		Config:    tailscaledConfig(authKey, tsClient.LoginURL()),
	})
	if err != nil {
		return 0, fmt.Errorf("failed to build config Secret: %w", err)
	}
	desired.Annotations = map[string]string{annotationAuthKeyExpires: expires.UTC().Format(time.RFC3339)}

	logger.Debugf("applying config Secret %q", desired.Name)
	if err = r.Patch(ctx, desired, client.Apply, fieldOwner, client.ForceOwnership); err != nil {
		return 0, fmt.Errorf("failed to apply config Secret: %w", err)
	}

	return expires.Add(-authKeyRotationWindow).Sub(r.clock.Now()), nil
}

// ensureAuthKey returns the reusable auth key to embed in the config Secret and the time it expires at. A new key is
// minted if there is none, if the current one is about to expire, or if a device has reported via its state Secret
// that the current one no longer works (for example because it was revoked). Otherwise the existing key is retained:
// unlike a single-use key, it must stay in the config so that devices on nodes joining the cluster later can use it.
func (r *Reconciler) ensureAuthKey(ctx context.Context, logger *zap.SugaredLogger, tsClient tsclient.Client, ra *tsapi.RouteAcceptor, existing *corev1.Secret, nodes []corev1.Node) (string, time.Time, error) {
	var cfgAuthKey *string
	var expires time.Time
	if existing != nil {
		cfgAuthKey = tailscaled.AuthKeyFromConfigSecret(existing)
		if v := existing.Annotations[annotationAuthKeyExpires]; v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				expires = t
			}
		}
	}

	var reason string
	switch {
	case cfgAuthKey == nil || *cfgAuthKey == "":
		reason = "no auth key in config"
	case expires.IsZero():
		reason = "unknown auth key expiry"
	case !r.clock.Now().Before(expires.Add(-authKeyRotationWindow)):
		reason = fmt.Sprintf("auth key expires at %s", expires.UTC().Format(time.RFC3339))
	default:
		// Has a device reported that the key no longer works?
		for _, n := range nodes {
			var stateSecret corev1.Secret
			err := r.Get(ctx, types.NamespacedName{Namespace: r.tailscaleNamespace, Name: stateSecretName(ra.Name, n.Name)}, &stateSecret)
			if apierrors.IsNotFound(err) {
				continue
			}
			if err != nil {
				return "", time.Time{}, fmt.Errorf("failed to get state Secret for node %q: %w", n.Name, err)
			}

			reissue, err := r.reissuer.ShouldReissue(ctx, tsClient, logger, tailscaled.ReissueInput{
				ParentName:  ra.Name,
				ReplicaName: stateSecret.Name,
				Kind:        tailscaled.KindRouteAcceptor,
				StateSecret: &stateSecret,
				CfgAuthKey:  cfgAuthKey,
			})
			if err != nil {
				return "", time.Time{}, err
			}
			if reissue {
				reason = fmt.Sprintf("device on node %q failed to authenticate with the current auth key", n.Name)
				break
			}
		}
	}

	if reason == "" {
		return *cfgAuthKey, expires, nil
	}

	logger.Infof("minting a new reusable auth key for RouteAcceptor %q: %s", ra.Name, reason)
	description := fmt.Sprintf("tailscale-operator RouteAcceptor %s", ra.Name)
	key, expires, err := tailscaled.NewReusableAuthKey(ctx, tsClient, r.tags(ra), authKeyExpiry, description)
	if err != nil {
		return "", time.Time{}, err
	}
	return key, expires, nil
}

func (r *Reconciler) deleteConfigSecret(ctx context.Context, logger *zap.SugaredLogger, ra *tsapi.RouteAcceptor) error {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: configSecretName(ra.Name), Namespace: r.tailscaleNamespace},
	}
	logger.Debugf("deleting config Secret %q", s.Name)
	if err := r.Delete(ctx, s); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to delete config Secret: %w", err)
	}
	return nil
}
