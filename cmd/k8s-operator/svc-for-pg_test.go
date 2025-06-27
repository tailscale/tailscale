// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"tailscale.com/ipn/ipnstate"
	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/ingressservices"
	"tailscale.com/tstest"
	"tailscale.com/types/ptr"
	"tailscale.com/util/mak"

	"tailscale.com/tailcfg"
)

func TestServicePGReconciler(t *testing.T) {
	svcPGR, stateSecret, fc, ft, _ := setupServiceTest(t)
	svcs := []*corev1.Service{}
	config := []string{}
	for i := range 4 {
		svc, _ := setupTestService(t, fmt.Sprintf("test-svc-%d", i), "", fmt.Sprintf("1.2.3.%d", i), fc, stateSecret)
		svcs = append(svcs, svc)

		// Verify initial reconciliation
		expectReconciled(t, svcPGR, "default", svc.Name)

		config = append(config, fmt.Sprintf("svc:default-%s", svc.Name))
		verifyTailscaleService(t, ft, fmt.Sprintf("svc:default-%s", svc.Name), []string{"do-not-validate"})
		verifyTailscaledConfig(t, fc, "test-pg", config)
	}

	for i, svc := range svcs {
		if err := fc.Delete(context.Background(), svc); err != nil {
			t.Fatalf("deleting Service: %v", err)
		}

		expectReconciled(t, svcPGR, "default", svc.Name)

		// Verify the ConfigMap was cleaned up
		cm := &corev1.ConfigMap{}
		if err := fc.Get(context.Background(), types.NamespacedName{
			Name:      "test-pg-ingress-config",
			Namespace: "operator-ns",
		}, cm); err != nil {
			t.Fatalf("getting ConfigMap: %v", err)
		}

		cfgs := ingressservices.Configs{}
		if err := json.Unmarshal(cm.BinaryData[ingressservices.IngressConfigKey], &cfgs); err != nil {
			t.Fatalf("unmarshaling serve config: %v", err)
		}

		if len(cfgs) > len(svcs)-(i+1) {
			t.Error("serve config not cleaned up")
		}

		config = removeEl(config, fmt.Sprintf("svc:default-%s", svc.Name))
		verifyTailscaledConfig(t, fc, "test-pg", config)
	}
}

func TestServicePGReconciler_UpdateHostname(t *testing.T) {
	svcPGR, stateSecret, fc, ft, _ := setupServiceTest(t)

	cip := "4.1.6.7"
	svc, _ := setupTestService(t, "test-service", "", cip, fc, stateSecret)

	expectReconciled(t, svcPGR, "default", svc.Name)

	verifyTailscaleService(t, ft, fmt.Sprintf("svc:default-%s", svc.Name), []string{"do-not-validate"})
	verifyTailscaledConfig(t, fc, "test-pg", []string{fmt.Sprintf("svc:default-%s", svc.Name)})

	hostname := "foobarbaz"
	mustUpdate(t, fc, svc.Namespace, svc.Name, func(s *corev1.Service) {
		mak.Set(&s.Annotations, AnnotationHostname, hostname)
	})

	// NOTE: we need to update the ingress config Secret because there is no containerboot in the fake proxy Pod
	updateIngressConfigSecret(t, fc, stateSecret, hostname, cip)
	expectReconciled(t, svcPGR, "default", svc.Name)

	verifyTailscaleService(t, ft, fmt.Sprintf("svc:%s", hostname), []string{"do-not-validate"})
	verifyTailscaledConfig(t, fc, "test-pg", []string{fmt.Sprintf("svc:%s", hostname)})

	_, err := ft.GetVIPService(context.Background(), tailcfg.ServiceName(fmt.Sprintf("svc:default-%s", svc.Name)))
	if err == nil {
		t.Fatalf("svc:default-%s not cleaned up", svc.Name)
	}
	if !isErrorTailscaleServiceNotFound(err) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func setupServiceTest(t *testing.T) (*HAServiceReconciler, *corev1.Secret, client.Client, *fakeTSClient, *tstest.Clock) {
	// Pre-create the ProxyGroup
	pg := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-pg",
			Generation: 1,
		},
		Spec: tsapi.ProxyGroupSpec{
			Type: tsapi.ProxyGroupTypeIngress,
		},
	}

	// Pre-create the ConfigMap for the ProxyGroup
	pgConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pg-ingress-config",
			Namespace: "operator-ns",
		},
		BinaryData: map[string][]byte{
			"serve-config.json": []byte(`{"Services":{}}`),
		},
	}

	// Pre-create a config Secret for the ProxyGroup
	pgCfgSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pgConfigSecretName("test-pg", 0),
			Namespace: "operator-ns",
			Labels:    pgSecretLabels("test-pg", "config"),
		},
		Data: map[string][]byte{
			tsoperator.TailscaledConfigFileName(pgMinCapabilityVersion): []byte(`{"Version":""}`),
		},
	}

	pgStateSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pg-0",
			Namespace: "operator-ns",
		},
		Data: map[string][]byte{},
	}

	pgPod := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pg-0",
			Namespace: "operator-ns",
		},
		Status: corev1.PodStatus{
			PodIPs: []corev1.PodIP{
				{
					IP: "4.3.2.1",
				},
			},
		},
	}

	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(pg, pgCfgSecret, pgConfigMap, pgPod, pgStateSecret).
		WithStatusSubresource(pg).
		WithIndex(new(corev1.Service), indexIngressProxyGroup, indexPGIngresses).
		Build()

	// Set ProxyGroup status to ready
	pg.Status.Conditions = []metav1.Condition{
		{
			Type:               string(tsapi.ProxyGroupAvailable),
			Status:             metav1.ConditionTrue,
			ObservedGeneration: 1,
		},
	}
	if err := fc.Status().Update(context.Background(), pg); err != nil {
		t.Fatal(err)
	}
	fakeTsnetServer := &fakeTSNetServer{certDomains: []string{"foo.com"}}

	ft := &fakeTSClient{}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}

	lc := &fakeLocalClient{
		status: &ipnstate.Status{
			CurrentTailnet: &ipnstate.TailnetStatus{
				MagicDNSSuffix: "ts.net",
			},
		},
	}

	cl := tstest.NewClock(tstest.ClockOpts{})
	svcPGR := &HAServiceReconciler{
		Client:      fc,
		tsClient:    ft,
		clock:       cl,
		defaultTags: []string{"tag:k8s"},
		tsNamespace: "operator-ns",
		tsnetServer: fakeTsnetServer,
		logger:      zl.Sugar(),
		recorder:    record.NewFakeRecorder(10),
		lc:          lc,
	}

	return svcPGR, pgStateSecret, fc, ft, cl
}

func TestValidateService(t *testing.T) {
	// Test that no more than one Kubernetes Service in a cluster refers to the same Tailscale Service.
	pgr, _, lc, _, cl := setupServiceTest(t)
	svc := &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-app",
			Namespace: "ns-1",
			UID:       types.UID("1234-UID"),
			Annotations: map[string]string{
				"tailscale.com/proxy-group": "test-pg",
				"tailscale.com/hostname":    "my-app",
			},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP:         "1.2.3.4",
			Type:              corev1.ServiceTypeLoadBalancer,
			LoadBalancerClass: ptr.To("tailscale"),
		},
	}
	svc2 := &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-app2",
			Namespace: "ns-2",
			UID:       types.UID("1235-UID"),
			Annotations: map[string]string{
				"tailscale.com/proxy-group": "test-pg",
				"tailscale.com/hostname":    "my-app",
			},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP:         "1.2.3.5",
			Type:              corev1.ServiceTypeLoadBalancer,
			LoadBalancerClass: ptr.To("tailscale"),
		},
	}
	wantSvc := &corev1.Service{
		ObjectMeta: svc.ObjectMeta,
		TypeMeta:   svc.TypeMeta,
		Spec:       svc.Spec,
		Status: corev1.ServiceStatus{
			Conditions: []metav1.Condition{
				{
					Type:               string(tsapi.IngressSvcValid),
					Status:             metav1.ConditionFalse,
					Reason:             reasonIngressSvcInvalid,
					LastTransitionTime: metav1.NewTime(cl.Now().Truncate(time.Second)),
					Message:            `found duplicate Service "ns-2/my-app2" for hostname "my-app" - multiple HA Services for the same hostname in the same cluster are not allowed`,
				},
			},
		},
	}

	mustCreate(t, lc, svc)
	mustCreate(t, lc, svc2)
	expectReconciled(t, pgr, svc.Namespace, svc.Name)
	expectEqual(t, lc, wantSvc)
}

func TestServicePGReconciler_MultiCluster(t *testing.T) {
	var ft *fakeTSClient
	var lc localClient
	for i := 0; i <= 10; i++ {
		pgr, stateSecret, fc, fti, _ := setupServiceTest(t)
		if i == 0 {
			ft = fti
			lc = pgr.lc
		} else {
			pgr.tsClient = ft
			pgr.lc = lc
		}

		svc, _ := setupTestService(t, "test-multi-cluster", "", "4.3.2.1", fc, stateSecret)
		expectReconciled(t, pgr, "default", svc.Name)

		tsSvcs, err := ft.ListVIPServices(context.Background())
		if err != nil {
			t.Fatalf("getting Tailscale Service: %v", err)
		}

		if len(tsSvcs) != 1 {
			t.Fatalf("unexpected number of Tailscale Services (%d)", len(tsSvcs))
		}

		for name := range tsSvcs {
			t.Logf("found Tailscale Service with name %q", name.String())
		}
	}
}

func TestIgnoreRegularService(t *testing.T) {
	pgr, _, fc, ft, _ := setupServiceTest(t)

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			// The apiserver is supposed to set the UID, but the fake client
			// doesn't. So, set it explicitly because other code later depends
			// on it being set.
			UID: types.UID("1234-UID"),
			Annotations: map[string]string{
				"tailscale.com/expose": "true",
			},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.20.30.40",
			Type:      corev1.ServiceTypeClusterIP,
		},
	}

	mustCreate(t, fc, svc)
	expectReconciled(t, pgr, "default", "test")

	verifyTailscaledConfig(t, fc, "test-pg", nil)

	tsSvcs, err := ft.ListVIPServices(context.Background())
	if err == nil {
		if len(tsSvcs) > 0 {
			t.Fatal("unexpected Tailscale Services found")
		}
	}
}

func removeEl(s []string, value string) []string {
	result := s[:0]
	for _, v := range s {
		if v != value {
			result = append(result, v)
		}
	}
	return result
}

func updateIngressConfigSecret(t *testing.T, fc client.Client, stateSecret *corev1.Secret, serviceName string, clusterIP string) {
	ingressConfig := ingressservices.Configs{
		fmt.Sprintf("svc:%s", serviceName): ingressservices.Config{
			IPv4Mapping: &ingressservices.Mapping{
				TailscaleServiceIP: netip.MustParseAddr(vipTestIP),
				ClusterIP:          netip.MustParseAddr(clusterIP),
			},
		},
	}

	ingressStatus := ingressservices.Status{
		Configs: ingressConfig,
		PodIPv4: "4.3.2.1",
	}

	icJson, err := json.Marshal(ingressStatus)
	if err != nil {
		t.Fatalf("failed to json marshal ingress config: %s", err.Error())
	}

	mustUpdate(t, fc, stateSecret.Namespace, stateSecret.Name, func(sec *corev1.Secret) {
		mak.Set(&sec.Data, ingressservices.IngressConfigKey, icJson)
	})
}

func setupTestService(t *testing.T, svcName string, hostname string, clusterIP string, fc client.Client, stateSecret *corev1.Secret) (svc *corev1.Service, eps *discoveryv1.EndpointSlice) {
	uid := rand.IntN(100)
	svc = &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      svcName,
			Namespace: "default",
			UID:       types.UID(fmt.Sprintf("%d-UID", uid)),
			Annotations: map[string]string{
				"tailscale.com/proxy-group": "test-pg",
			},
		},
		Spec: corev1.ServiceSpec{
			Type:              corev1.ServiceTypeLoadBalancer,
			LoadBalancerClass: ptr.To("tailscale"),
			ClusterIP:         clusterIP,
			ClusterIPs:        []string{clusterIP},
		},
	}

	eps = &discoveryv1.EndpointSlice{
		TypeMeta: metav1.TypeMeta{Kind: "EndpointSlice", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      svcName,
			Namespace: "default",
			Labels: map[string]string{
				discoveryv1.LabelServiceName: svcName,
			},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{
			{
				Addresses: []string{"4.3.2.1"},
				Conditions: discoveryv1.EndpointConditions{
					Ready: ptr.To(true),
				},
			},
		},
	}

	updateIngressConfigSecret(t, fc, stateSecret, fmt.Sprintf("default-%s", svcName), clusterIP)

	mustCreate(t, fc, svc)
	mustCreate(t, fc, eps)

	return svc, eps
}
