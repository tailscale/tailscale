// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package recorder

import (
	"context"
	"fmt"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler/tailscaled"
	"tailscale.com/k8s-operator/tsclient"
)

// authKeySecretKey is the data key under which a Recorder replica's auth key is stored in its auth Secret.
const authKeySecretKey = "authkey"

// recorderTags returns the tags to apply to auth keys minted for tsr's replicas.
func recorderTags(tsr *tsapi.Recorder) []string {
	if len(tsr.Spec.Tags) == 0 {
		return tsapi.Tags{"tag:k8s"}.Stringify()
	}

	return tsr.Spec.Tags.Stringify()
}

// ensureAuthSecretsCreated makes sure every replica has an auth Secret holding a usable auth key. A key is minted
// when the Secret doesn't exist yet, or when the replica has requested a reissue via its state Secret because the
// existing key can no longer authenticate it.
func (r *Reconciler) ensureAuthSecretsCreated(ctx context.Context, logger *zap.SugaredLogger, tsClient tsclient.Client, tsr *tsapi.Recorder) error {
	tags := recorderTags(tsr)

	for replica := range replicas(tsr) {
		key := types.NamespacedName{
			Namespace: r.tsNamespace,
			Name:      authSecretName(tsr.Name, replica),
		}

		existingSecret := &corev1.Secret{}
		err := r.Get(ctx, key, existingSecret)
		switch {
		case err == nil:
			stateSecret, err := r.getStateSecret(ctx, tsr.Name, replica)
			if err != nil {
				return fmt.Errorf("error getting state Secret for replica %d: %w", replica, err)
			}
			cfgAuthKey := string(existingSecret.Data[authKeySecretKey])
			reissue, err := r.reissuer.ShouldReissue(ctx, tsClient, logger, tailscaled.ReissueInput{
				ParentName:  tsr.Name,
				ReplicaName: stateSecretName(tsr.Name, replica),
				Kind:        tailscaled.KindRecorder,
				StateSecret: stateSecret,
				CfgAuthKey:  &cfgAuthKey,
			})
			if err != nil {
				return fmt.Errorf("error checking auth key reissue for replica %d: %w", replica, err)
			}
			if !reissue {
				logger.Debugf("auth Secret %q already exists, no reissue needed", key.Name)
				continue
			}
			authKey, err := tailscaled.NewAuthKey(ctx, tsClient, tags)
			if err != nil {
				return err
			}
			existingSecret.Data[authKeySecretKey] = []byte(authKey)
			if err = r.Update(ctx, existingSecret); err != nil {
				return err
			}
		case apierrors.IsNotFound(err):
			authKey, err := tailscaled.NewAuthKey(ctx, tsClient, tags)
			if err != nil {
				return err
			}
			if err = r.Create(ctx, tsrAuthSecret(tsr, r.tsNamespace, authKey, replica)); err != nil {
				return err
			}
		default:
			return fmt.Errorf("failed to get Secret %q: %w", key.Name, err)
		}
	}

	return nil
}
