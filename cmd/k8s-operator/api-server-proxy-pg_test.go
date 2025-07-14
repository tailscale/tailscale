// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"tailscale.com/internal/client/tailscale"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
)

func TestExclusiveOwnerAnnotations(t *testing.T) {
	pg := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: "pg1",
			UID:  "pg1-uid",
		},
	}
	const (
		selfOperatorID = "self-id"
		pg1Owner       = `{"ownerRefs":[{"operatorID":"self-id","resource":{"kind":"ProxyGroup","name":"pg1","uid":"pg1-uid"}}]}`
	)

	for name, tc := range map[string]struct {
		svc     *tailscale.VIPService
		wantErr string
	}{
		"no_svc": {
			svc: nil,
		},
		"empty_svc": {
			svc:     &tailscale.VIPService{},
			wantErr: "likely a resource created by something other than the Tailscale Kubernetes operator",
		},
		"already_owner": {
			svc: &tailscale.VIPService{
				Annotations: map[string]string{
					ownerAnnotation: pg1Owner,
				},
			},
		},
		"already_owner_name_updated": {
			svc: &tailscale.VIPService{
				Annotations: map[string]string{
					ownerAnnotation: `{"ownerRefs":[{"operatorID":"self-id","resource":{"kind":"ProxyGroup","name":"old-pg1-name","uid":"pg1-uid"}}]}`,
				},
			},
		},
		"preserves_existing_annotations": {
			svc: &tailscale.VIPService{
				Annotations: map[string]string{
					"existing":      "annotation",
					ownerAnnotation: pg1Owner,
				},
			},
		},
		"owned_by_another_operator": {
			svc: &tailscale.VIPService{
				Annotations: map[string]string{
					ownerAnnotation: `{"ownerRefs":[{"operatorID":"operator-2"}]}`,
				},
			},
			wantErr: "already owned by other operator(s)",
		},
		"owned_by_an_ingress": {
			svc: &tailscale.VIPService{
				Annotations: map[string]string{
					ownerAnnotation: `{"ownerRefs":[{"operatorID":"self-id"}]}`, // Ingress doesn't set Resource field (yet).
				},
			},
			wantErr: "does not reference an owning resource",
		},
		"owned_by_another_pg": {
			svc: &tailscale.VIPService{
				Annotations: map[string]string{
					ownerAnnotation: `{"ownerRefs":[{"operatorID":"self-id","resource":{"kind":"ProxyGroup","name":"pg2","uid":"pg2-uid"}}]}`,
				},
			},
			wantErr: "already owned by another resource",
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := exclusiveOwnerAnnotations(pg, "self-id", tc.svc)
			if tc.wantErr != "" {
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("exclusiveOwnerAnnotations() error = %v, wantErr %v", err, tc.wantErr)
				}
			} else if diff := cmp.Diff(pg1Owner, got[ownerAnnotation]); diff != "" {
				t.Errorf("exclusiveOwnerAnnotations() mismatch (-want +got):\n%s", diff)
			}
			if tc.svc == nil {
				return // Don't check annotations being preserved.
			}
			for k, v := range tc.svc.Annotations {
				if k == ownerAnnotation {
					continue
				}
				if got[k] != v {
					t.Errorf("exclusiveOwnerAnnotations() did not preserve annotation %q: got %q, want %q", k, got[k], v)
				}
			}
		})
	}
}
