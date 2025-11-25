// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"tailscale.com/internal/client/tailscale"
	"tailscale.com/ipn/ipnstate"
	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/k8s-proxy/conf"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/opt"
	"tailscale.com/types/ptr"
)

func TestAPIServerProxyReconciler(t *testing.T) {
	const (
		pgName        = "test-pg"
		pgUID         = "test-pg-uid"
		ns            = "operator-ns"
		defaultDomain = "test-pg.ts.net"
	)
	pg := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:       pgName,
			Generation: 1,
			UID:        pgUID,
		},
		Spec: tsapi.ProxyGroupSpec{
			Type: tsapi.ProxyGroupTypeKubernetesAPIServer,
		},
		Status: tsapi.ProxyGroupStatus{
			Conditions: []metav1.Condition{
				{
					Type:               string(tsapi.ProxyGroupAvailable),
					Status:             metav1.ConditionTrue,
					ObservedGeneration: 1,
				},
			},
		},
	}
	initialCfg := &conf.VersionedConfig{
		Version: "v1alpha1",
		ConfigV1Alpha1: &conf.ConfigV1Alpha1{
			AuthKey: ptr.To("test-key"),
			APIServerProxy: &conf.APIServerProxyConfig{
				Enabled: opt.NewBool(true),
			},
		},
	}
	expectedCfg := *initialCfg
	initialCfgB, err := json.Marshal(initialCfg)
	if err != nil {
		t.Fatalf("marshaling initial config: %v", err)
	}
	pgCfgSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pgConfigSecretName(pgName, 0),
			Namespace: ns,
			Labels:    pgSecretLabels(pgName, kubetypes.LabelSecretTypeConfig),
		},
		Data: map[string][]byte{
			// Existing config should be preserved.
			kubetypes.KubeAPIServerConfigFile: initialCfgB,
		},
	}
	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(pg, pgCfgSecret).
		WithStatusSubresource(pg).
		Build()
	expectCfg := func(c *conf.VersionedConfig) {
		t.Helper()
		cBytes, err := json.Marshal(c)
		if err != nil {
			t.Fatalf("marshaling expected config: %v", err)
		}
		pgCfgSecret.Data[kubetypes.KubeAPIServerConfigFile] = cBytes
		expectEqual(t, fc, pgCfgSecret)
	}

	ft := &fakeTSClient{}
	ingressTSSvc := &tailscale.VIPService{
		Name:    "svc:some-ingress-hostname",
		Comment: managedTSServiceComment,
		Annotations: map[string]string{
			// No resource field.
			ownerAnnotation: `{"ownerRefs":[{"operatorID":"self-id"}]}`,
		},
		Ports: []string{"tcp:443"},
		Tags:  []string{"tag:k8s"},
		Addrs: []string{"5.6.7.8"},
	}
	ft.CreateOrUpdateVIPService(t.Context(), ingressTSSvc)

	lc := &fakeLocalClient{
		status: &ipnstate.Status{
			CurrentTailnet: &ipnstate.TailnetStatus{
				MagicDNSSuffix: "ts.net",
			},
		},
	}

	r := &KubeAPIServerTSServiceReconciler{
		Client:      fc,
		tsClient:    ft,
		defaultTags: []string{"tag:k8s"},
		tsNamespace: ns,
		logger:      zap.Must(zap.NewDevelopment()).Sugar(),
		recorder:    record.NewFakeRecorder(10),
		lc:          lc,
		clock:       tstest.NewClock(tstest.ClockOpts{}),
		operatorID:  "self-id",
	}

	// Create a Tailscale Service that will conflict with the initial config.
	if err := ft.CreateOrUpdateVIPService(t.Context(), &tailscale.VIPService{
		Name: "svc:" + pgName,
	}); err != nil {
		t.Fatalf("creating initial Tailscale Service: %v", err)
	}
	expectReconciled(t, r, "", pgName)
	pg.ObjectMeta.Finalizers = []string{proxyPGFinalizerName}
	tsoperator.SetProxyGroupCondition(pg, tsapi.KubeAPIServerProxyValid, metav1.ConditionFalse, reasonKubeAPIServerProxyInvalid, "", 1, r.clock, r.logger)
	tsoperator.SetProxyGroupCondition(pg, tsapi.KubeAPIServerProxyConfigured, metav1.ConditionFalse, reasonKubeAPIServerProxyNoBackends, "", 1, r.clock, r.logger)
	expectEqual(t, fc, pg, omitPGStatusConditionMessages)
	expectMissing[corev1.Secret](t, fc, ns, defaultDomain)
	expectMissing[rbacv1.Role](t, fc, ns, defaultDomain)
	expectMissing[rbacv1.RoleBinding](t, fc, ns, defaultDomain)
	expectEqual(t, fc, pgCfgSecret) // Unchanged.

	// Delete Tailscale Service; should see Service created and valid condition updated to true.
	if err := ft.DeleteVIPService(t.Context(), "svc:"+pgName); err != nil {
		t.Fatalf("deleting initial Tailscale Service: %v", err)
	}
	expectReconciled(t, r, "", pgName)

	tsSvc, err := ft.GetVIPService(t.Context(), "svc:"+pgName)
	if err != nil {
		t.Fatalf("getting Tailscale Service: %v", err)
	}
	if tsSvc == nil {
		t.Fatalf("expected Tailscale Service to be created, but got nil")
	}
	expectedTSSvc := &tailscale.VIPService{
		Name:    "svc:" + pgName,
		Comment: managedTSServiceComment,
		Annotations: map[string]string{
			ownerAnnotation: `{"ownerRefs":[{"operatorID":"self-id","resource":{"kind":"ProxyGroup","name":"test-pg","uid":"test-pg-uid"}}]}`,
		},
		Ports: []string{"tcp:443"},
		Tags:  []string{"tag:k8s"},
		Addrs: []string{"5.6.7.8"},
	}
	if !reflect.DeepEqual(tsSvc, expectedTSSvc) {
		t.Fatalf("expected Tailscale Service to be %+v, got %+v", expectedTSSvc, tsSvc)
	}
	tsoperator.SetProxyGroupCondition(pg, tsapi.KubeAPIServerProxyValid, metav1.ConditionTrue, reasonKubeAPIServerProxyValid, "", 1, r.clock, r.logger)
	tsoperator.SetProxyGroupCondition(pg, tsapi.KubeAPIServerProxyConfigured, metav1.ConditionFalse, reasonKubeAPIServerProxyNoBackends, "", 1, r.clock, r.logger)
	expectEqual(t, fc, pg, omitPGStatusConditionMessages)

	expectedCfg.APIServerProxy.ServiceName = ptr.To(tailcfg.ServiceName("svc:" + pgName))
	expectCfg(&expectedCfg)

	expectEqual(t, fc, certSecret(pgName, ns, defaultDomain, pg))
	expectEqual(t, fc, certSecretRole(pgName, ns, defaultDomain))
	expectEqual(t, fc, certSecretRoleBinding(pg, ns, defaultDomain))

	// Simulate certs being issued; should observe AdvertiseServices config change.
	populateTLSSecret(t, fc, pgName, defaultDomain)
	expectReconciled(t, r, "", pgName)

	expectedCfg.AdvertiseServices = []string{"svc:" + pgName}
	expectCfg(&expectedCfg)

	expectEqual(t, fc, pg, omitPGStatusConditionMessages) // Unchanged status.

	// Simulate Pod prefs updated with advertised services; should see Configured condition updated to true.
	mustCreate(t, fc, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pg-0",
			Namespace: ns,
			Labels:    pgSecretLabels(pgName, kubetypes.LabelSecretTypeState),
		},
		Data: map[string][]byte{
			"_current-profile": []byte("profile-foo"),
			"profile-foo":      []byte(`{"AdvertiseServices":["svc:test-pg"],"Config":{"NodeID":"node-foo"}}`),
		},
	})
	expectReconciled(t, r, "", pgName)
	tsoperator.SetProxyGroupCondition(pg, tsapi.KubeAPIServerProxyConfigured, metav1.ConditionTrue, reasonKubeAPIServerProxyConfigured, "", 1, r.clock, r.logger)
	pg.Status.URL = "https://" + defaultDomain
	expectEqual(t, fc, pg, omitPGStatusConditionMessages)

	// Rename the Tailscale Service - old one + cert resources should be cleaned up.
	updatedServiceName := tailcfg.ServiceName("svc:test-pg-renamed")
	updatedDomain := "test-pg-renamed.ts.net"
	pg.Spec.KubeAPIServer = &tsapi.KubeAPIServerConfig{
		Hostname: updatedServiceName.WithoutPrefix(),
	}
	mustUpdate(t, fc, "", pgName, func(p *tsapi.ProxyGroup) {
		p.Spec.KubeAPIServer = pg.Spec.KubeAPIServer
	})
	expectReconciled(t, r, "", pgName)
	_, err = ft.GetVIPService(t.Context(), "svc:"+pgName)
	if !isErrorTailscaleServiceNotFound(err) {
		t.Fatalf("Expected 404, got: %v", err)
	}
	tsSvc, err = ft.GetVIPService(t.Context(), updatedServiceName)
	if err != nil {
		t.Fatalf("Expected renamed svc, got error: %v", err)
	}
	expectedTSSvc.Name = updatedServiceName
	if !reflect.DeepEqual(tsSvc, expectedTSSvc) {
		t.Fatalf("expected Tailscale Service to be %+v, got %+v", expectedTSSvc, tsSvc)
	}
	// Check cfg and status reset until TLS certs are available again.
	expectedCfg.APIServerProxy.ServiceName = ptr.To(updatedServiceName)
	expectedCfg.AdvertiseServices = nil
	expectCfg(&expectedCfg)
	tsoperator.SetProxyGroupCondition(pg, tsapi.KubeAPIServerProxyConfigured, metav1.ConditionFalse, reasonKubeAPIServerProxyNoBackends, "", 1, r.clock, r.logger)
	pg.Status.URL = ""
	expectEqual(t, fc, pg, omitPGStatusConditionMessages)

	expectEqual(t, fc, certSecret(pgName, ns, updatedDomain, pg))
	expectEqual(t, fc, certSecretRole(pgName, ns, updatedDomain))
	expectEqual(t, fc, certSecretRoleBinding(pg, ns, updatedDomain))
	expectMissing[corev1.Secret](t, fc, ns, defaultDomain)
	expectMissing[rbacv1.Role](t, fc, ns, defaultDomain)
	expectMissing[rbacv1.RoleBinding](t, fc, ns, defaultDomain)

	// Check we get the new hostname in the status once ready.
	populateTLSSecret(t, fc, pgName, updatedDomain)
	mustUpdate(t, fc, "operator-ns", "test-pg-0", func(s *corev1.Secret) {
		s.Data["profile-foo"] = []byte(`{"AdvertiseServices":["svc:test-pg"],"Config":{"NodeID":"node-foo"}}`)
	})
	expectReconciled(t, r, "", pgName)
	expectedCfg.AdvertiseServices = []string{updatedServiceName.String()}
	expectCfg(&expectedCfg)
	tsoperator.SetProxyGroupCondition(pg, tsapi.KubeAPIServerProxyConfigured, metav1.ConditionTrue, reasonKubeAPIServerProxyConfigured, "", 1, r.clock, r.logger)
	pg.Status.URL = "https://" + updatedDomain

	// Delete the ProxyGroup and verify Tailscale Service and cert resources are cleaned up.
	if err := fc.Delete(t.Context(), pg); err != nil {
		t.Fatalf("deleting ProxyGroup: %v", err)
	}
	expectReconciled(t, r, "", pgName)
	expectMissing[corev1.Secret](t, fc, ns, updatedDomain)
	expectMissing[rbacv1.Role](t, fc, ns, updatedDomain)
	expectMissing[rbacv1.RoleBinding](t, fc, ns, updatedDomain)
	_, err = ft.GetVIPService(t.Context(), updatedServiceName)
	if !isErrorTailscaleServiceNotFound(err) {
		t.Fatalf("Expected 404, got: %v", err)
	}

	// Ingress Tailscale Service should not be affected.
	svc, err := ft.GetVIPService(t.Context(), ingressTSSvc.Name)
	if err != nil {
		t.Fatalf("getting ingress Tailscale Service: %v", err)
	}
	if !reflect.DeepEqual(svc, ingressTSSvc) {
		t.Fatalf("expected ingress Tailscale Service to be unmodified %+v, got %+v", ingressTSSvc, svc)
	}
}

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

func omitPGStatusConditionMessages(p *tsapi.ProxyGroup) {
	for i := range p.Status.Conditions {
		// Don't bother validating the message.
		p.Status.Conditions[i].Message = ""
	}
}
