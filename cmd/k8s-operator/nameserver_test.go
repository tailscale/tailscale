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
	"tailscale.com/types/ptr"
	"tailscale.com/util/mak"
)

func TestNameserverReconciler(t *testing.T) {
	dnsConfig := &tsapi.DNSConfig{
		TypeMeta: metav1.TypeMeta{Kind: "DNSConfig", APIVersion: "tailscale.com/v1alpha1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
		},
		Spec: tsapi.DNSConfigSpec{
			Nameserver: &tsapi.Nameserver{
				Replicas: ptr.To[int32](3),
				Image: &tsapi.NameserverImage{
					Repo: "test",
					Tag:  "v0.0.1",
				},
				Service: &tsapi.NameserverService{
					ClusterIP: "5.4.3.2",
				},
				Pod: &tsapi.NameserverPod{
					Tolerations: []corev1.Toleration{
						{
							Key:      "some-key",
							Operator: corev1.TolerationOpEqual,
							Value:    "some-value",
							Effect:   corev1.TaintEffectNoSchedule,
						},
					},
				},
			},
		},
	}

	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(dnsConfig).
		WithStatusSubresource(dnsConfig).
		Build()

	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}

	clock := tstest.NewClock(tstest.ClockOpts{})
	reconciler := &NameserverReconciler{
		Client:      fc,
		clock:       clock,
		logger:      logger.Sugar(),
		tsNamespace: tsNamespace,
	}
	expectReconciled(t, reconciler, "", "test")

	ownerReference := metav1.NewControllerRef(dnsConfig, tsapi.SchemeGroupVersion.WithKind("DNSConfig"))
	nameserverLabels := nameserverResourceLabels(dnsConfig.Name, tsNamespace)

	wantsDeploy := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "nameserver", Namespace: tsNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: appsv1.SchemeGroupVersion.Identifier()}}
	t.Run("deployment has expected fields", func(t *testing.T) {
		if err = yaml.Unmarshal(deployYaml, wantsDeploy); err != nil {
			t.Fatalf("unmarshalling yaml: %v", err)
		}
		wantsDeploy.OwnerReferences = []metav1.OwnerReference{*ownerReference}
		wantsDeploy.Spec.Template.Spec.Containers[0].Image = "test:v0.0.1"
		wantsDeploy.Spec.Replicas = ptr.To[int32](3)
		wantsDeploy.Namespace = tsNamespace
		wantsDeploy.ObjectMeta.Labels = nameserverLabels
		wantsDeploy.Spec.Template.Spec.Tolerations = []corev1.Toleration{
			{
				Key:      "some-key",
				Operator: corev1.TolerationOpEqual,
				Value:    "some-value",
				Effect:   corev1.TaintEffectNoSchedule,
			},
		}

		expectEqual(t, fc, wantsDeploy)
	})

	wantsSvc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "nameserver", Namespace: tsNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: corev1.SchemeGroupVersion.Identifier()}}
	t.Run("service has expected fields", func(t *testing.T) {
		if err = yaml.Unmarshal(svcYaml, wantsSvc); err != nil {
			t.Fatalf("unmarshalling yaml: %v", err)
		}
		wantsSvc.Spec.ClusterIP = dnsConfig.Spec.Nameserver.Service.ClusterIP
		wantsSvc.OwnerReferences = []metav1.OwnerReference{*ownerReference}
		wantsSvc.Namespace = tsNamespace
		wantsSvc.ObjectMeta.Labels = nameserverLabels
		expectEqual(t, fc, wantsSvc)
	})

	t.Run("dns config status is set", func(t *testing.T) {
		// Verify that DNSConfig advertizes the nameserver's Service IP address,
		// has the ready status condition and tailscale finalizer.
		mustUpdate(t, fc, "tailscale", "nameserver", func(svc *corev1.Service) {
			svc.Spec.ClusterIP = "1.2.3.4"
		})
		expectReconciled(t, reconciler, "", "test")

		dnsConfig.Finalizers = []string{FinalizerName}
		dnsConfig.Status.Nameserver = &tsapi.NameserverStatus{
			IP: "1.2.3.4",
		}
		dnsConfig.Status.Conditions = append(dnsConfig.Status.Conditions, metav1.Condition{
			Type:               string(tsapi.NameserverReady),
			Status:             metav1.ConditionTrue,
			Reason:             reasonNameserverCreated,
			Message:            reasonNameserverCreated,
			LastTransitionTime: metav1.Time{Time: clock.Now().Truncate(time.Second)},
		})

		expectEqual(t, fc, dnsConfig)
	})

	t.Run("nameserver image can be updated", func(t *testing.T) {
		// Verify that nameserver image gets updated to match DNSConfig spec.
		mustUpdate(t, fc, "", "test", func(dnsCfg *tsapi.DNSConfig) {
			dnsCfg.Spec.Nameserver.Image.Tag = "v0.0.2"
		})
		expectReconciled(t, reconciler, "", "test")
		wantsDeploy.Spec.Template.Spec.Containers[0].Image = "test:v0.0.2"
		expectEqual(t, fc, wantsDeploy)
	})

	t.Run("reconciler does not overwrite custom configuration", func(t *testing.T) {
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

		expectReconciled(t, reconciler, "", "test")

		wantCm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "dnsrecords",
				Namespace:       "tailscale",
				Labels:          nameserverLabels,
				OwnerReferences: []metav1.OwnerReference{*ownerReference},
			},
			TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
			Data:     map[string]string{"records.json": string(bs)},
		}

		expectEqual(t, fc, wantCm)
	})

	t.Run("uses default nameserver image", func(t *testing.T) {
		// Verify that if dnsconfig.spec.nameserver.image.{repo,tag} are unset,
		// the nameserver image defaults to tailscale/k8s-nameserver:unstable.
		mustUpdate(t, fc, "", "test", func(dnsCfg *tsapi.DNSConfig) {
			dnsCfg.Spec.Nameserver.Image = nil
		})
		expectReconciled(t, reconciler, "", "test")
		wantsDeploy.Spec.Template.Spec.Containers[0].Image = "tailscale/k8s-nameserver:unstable"
		expectEqual(t, fc, wantsDeploy)
	})
}
