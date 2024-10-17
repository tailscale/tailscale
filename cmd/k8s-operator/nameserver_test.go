// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// tailscale-operator provides a way to expose services running in a Kubernetes
// cluster to your Tailnet and to make Tailscale nodes available to cluster
// workloads
package main

import (
	"encoding/json"
	"testing"
	"time"

	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/yaml"
	operatorutils "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/tstest"
	"tailscale.com/util/mak"
)

func TestNameserverReconciler(t *testing.T) {
	dnsCfg := &tsapi.DNSConfig{
		TypeMeta: metav1.TypeMeta{Kind: "DNSConfig", APIVersion: "tailscale.com/v1alpha1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
		},
		Spec: tsapi.DNSConfigSpec{
			Nameserver: &tsapi.Nameserver{
				Image: &tsapi.NameserverImage{
					Repo: "test",
					Tag:  "v0.0.1",
				},
			},
		},
	}

	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(dnsCfg).
		WithStatusSubresource(dnsCfg).
		Build()
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	cl := tstest.NewClock(tstest.ClockOpts{})
	nr := &NameserverReconciler{
		Client:      fc,
		clock:       cl,
		logger:      zl.Sugar(),
		tsNamespace: "tailscale",
	}
	expectReconciled(t, nr, "", "test")
	// Verify that nameserver Deployment has been created and has the expected fields.
	wantsDeploy := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "nameserver", Namespace: "tailscale"}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: appsv1.SchemeGroupVersion.Identifier()}}
	if err := yaml.Unmarshal(deployYaml, wantsDeploy); err != nil {
		t.Fatalf("unmarshalling yaml: %v", err)
	}
	dnsCfgOwnerRef := metav1.NewControllerRef(dnsCfg, tsapi.SchemeGroupVersion.WithKind("DNSConfig"))
	wantsDeploy.OwnerReferences = []metav1.OwnerReference{*dnsCfgOwnerRef}
	wantsDeploy.Spec.Template.Spec.Containers[0].Image = "test:v0.0.1"
	wantsDeploy.Namespace = "tailscale"
	labels := nameserverResourceLabels("test", "tailscale")
	wantsDeploy.ObjectMeta.Labels = labels
	expectEqual(t, fc, wantsDeploy, nil)

	// Verify that DNSConfig advertizes the nameserver's Service IP address,
	// has the ready status condition and tailscale finalizer.
	mustUpdate(t, fc, "tailscale", "nameserver", func(svc *corev1.Service) {
		svc.Spec.ClusterIP = "1.2.3.4"
	})
	expectReconciled(t, nr, "", "test")
	dnsCfg.Status.Nameserver = &tsapi.NameserverStatus{
		IP: "1.2.3.4",
	}
	dnsCfg.Finalizers = []string{FinalizerName}
	dnsCfg.Status.Conditions = append(dnsCfg.Status.Conditions, metav1.Condition{
		Type:               string(tsapi.NameserverReady),
		Status:             metav1.ConditionTrue,
		Reason:             reasonNameserverCreated,
		Message:            reasonNameserverCreated,
		LastTransitionTime: metav1.Time{Time: cl.Now().Truncate(time.Second)},
	})
	expectEqual(t, fc, dnsCfg, nil)

	// // Verify that nameserver image gets updated to match DNSConfig spec.
	mustUpdate(t, fc, "", "test", func(dnsCfg *tsapi.DNSConfig) {
		dnsCfg.Spec.Nameserver.Image.Tag = "v0.0.2"
	})
	expectReconciled(t, nr, "", "test")
	wantsDeploy.Spec.Template.Spec.Containers[0].Image = "test:v0.0.2"
	expectEqual(t, fc, wantsDeploy, nil)

	// Verify that when another actor sets ConfigMap data, it does not get
	// overwritten by nameserver reconciler.
	dnsRecords := &operatorutils.Records{Version: "v1alpha1", IP4: map[string][]string{"foo.ts.net": {"1.2.3.4"}}}
	bs, err := json.Marshal(dnsRecords)
	if err != nil {
		t.Fatalf("error marshalling ConfigMap contents: %v", err)
	}
	mustUpdate(t, fc, "tailscale", "dnsrecords", func(cm *corev1.ConfigMap) {
		mak.Set(&cm.Data, "records.json", string(bs))
	})
	expectReconciled(t, nr, "", "test")
	wantCm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "dnsrecords",
		Namespace: "tailscale", Labels: labels, OwnerReferences: []metav1.OwnerReference{*dnsCfgOwnerRef}},
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		Data:     map[string]string{"records.json": string(bs)},
	}
	expectEqual(t, fc, wantCm, nil)

	// Verify that if dnsconfig.spec.nameserver.image.{repo,tag} are unset,
	// the nameserver image defaults to tailscale/k8s-nameserver:unstable.
	mustUpdate(t, fc, "", "test", func(dnsCfg *tsapi.DNSConfig) {
		dnsCfg.Spec.Nameserver.Image = nil
	})
	expectReconciled(t, nr, "", "test")
	wantsDeploy.Spec.Template.Spec.Containers[0].Image = "tailscale/k8s-nameserver:unstable"
	expectEqual(t, fc, wantsDeploy, nil)
}
