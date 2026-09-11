// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package nameserver_test

import (
	_ "embed"
	"encoding/json"
	"testing"
	"time"

	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/yaml"

	operatorutils "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler"
	"tailscale.com/k8s-operator/reconciler/nameserver"
	"tailscale.com/k8s-operator/reconciler/reconcilertest"
	"tailscale.com/tstest"
	"tailscale.com/util/mak"
)

var (
	//go:embed manifests/deploy.yaml
	deployYAML []byte
	//go:embed manifests/svc.yaml
	svcYAML []byte
)

const tsNamespace = "tailscale"

func TestNameserverReconciler(t *testing.T) {
	dnsConfig := &tsapi.DNSConfig{
		TypeMeta: metav1.TypeMeta{Kind: "DNSConfig", APIVersion: "tailscale.com/v1alpha1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
		},
		Spec: tsapi.DNSConfigSpec{
			Nameserver: &tsapi.Nameserver{
				Replicas: new(int32(3)),
				Image: &tsapi.NameserverImage{
					Repo: "test",
					Tag:  "v0.0.1",
				},
				Service: &tsapi.NameserverService{
					ClusterIP: "5.4.3.2",
				},
				Pod: &tsapi.NameserverPod{
					NodeSelector: map[string]string{
						"foo": "bar",
					},
					Tolerations: []corev1.Toleration{
						{
							Key:      "some-key",
							Operator: corev1.TolerationOpEqual,
							Value:    "some-value",
							Effect:   corev1.TaintEffectNoSchedule,
						},
					},
					Affinity: &corev1.Affinity{
						NodeAffinity: &corev1.NodeAffinity{
							RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
								NodeSelectorTerms: []corev1.NodeSelectorTerm{
									{
										MatchExpressions: []corev1.NodeSelectorRequirement{
											{
												Key:      "some-key",
												Operator: corev1.NodeSelectorOpIn,
												Values:   []string{"some-value"},
											},
										},
									},
								},
							},
						},
					},
					ImagePullSecrets: []corev1.LocalObjectReference{
						{Name: "some-secret"},
					},
				},
			},
		},
	}

	fc := reconcilertest.NewClientBuilder().
		WithObjects(dnsConfig).
		WithStatusSubresource(dnsConfig).
		Build()

	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}

	clock := tstest.NewClock(tstest.ClockOpts{})
	r := nameserver.NewReconciler(nameserver.ReconcilerOptions{
		Client:             fc,
		Recorder:           record.NewFakeRecorder(10),
		TailscaleNamespace: tsNamespace,
		Logger:             logger.Sugar(),
		Clock:              clock,
	})
	reconcilertest.ExpectReconciled(t, r, "", "test")

	ownerReference := metav1.NewControllerRef(dnsConfig, tsapi.SchemeGroupVersion.WithKind("DNSConfig"))
	nameserverLabels := map[string]string{
		"tailscale.com/managed":              "true",
		"tailscale.com/parent-resource-type": "nameserver",
		"tailscale.com/parent-resource":      dnsConfig.Name,
		"tailscale.com/parent-resource-ns":   tsNamespace,
		"app.kubernetes.io/name":             "tailscale",
		"app.kubernetes.io/component":        "nameserver",
	}

	wantsDeploy := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "nameserver", Namespace: tsNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: appsv1.SchemeGroupVersion.Identifier()}}
	t.Run("deployment-expected-fields", func(t *testing.T) {
		if err = yaml.Unmarshal(deployYAML, wantsDeploy); err != nil {
			t.Fatalf("unmarshalling yaml: %v", err)
		}
		wantsDeploy.OwnerReferences = []metav1.OwnerReference{*ownerReference}
		wantsDeploy.Spec.Template.Spec.Containers[0].Image = "test:v0.0.1"
		wantsDeploy.Spec.Replicas = new(int32(3))
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
		wantsDeploy.Spec.Template.Spec.Affinity = &corev1.Affinity{
			NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{
						{
							MatchExpressions: []corev1.NodeSelectorRequirement{
								{
									Key:      "some-key",
									Operator: corev1.NodeSelectorOpIn,
									Values:   []string{"some-value"},
								},
							},
						},
					},
				},
			},
		}
		wantsDeploy.Spec.Template.Spec.NodeSelector = map[string]string{
			"foo": "bar",
		}
		wantsDeploy.Spec.Template.Spec.ImagePullSecrets = []corev1.LocalObjectReference{
			{Name: "some-secret"},
		}

		reconcilertest.ExpectEqual(t, fc, wantsDeploy)
	})

	wantsSvc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "nameserver", Namespace: tsNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: corev1.SchemeGroupVersion.Identifier()}}
	t.Run("service-expected-fields", func(t *testing.T) {
		if err = yaml.Unmarshal(svcYAML, wantsSvc); err != nil {
			t.Fatalf("unmarshalling yaml: %v", err)
		}
		wantsSvc.Spec.ClusterIP = dnsConfig.Spec.Nameserver.Service.ClusterIP
		wantsSvc.OwnerReferences = []metav1.OwnerReference{*ownerReference}
		wantsSvc.Namespace = tsNamespace
		wantsSvc.ObjectMeta.Labels = nameserverLabels
		reconcilertest.ExpectEqual(t, fc, wantsSvc)
	})

	t.Run("dns-config-status-is-set", func(t *testing.T) {
		// Verify that DNSConfig advertises the nameserver's Service IP address,
		// has the ready status condition and tailscale finalizer.
		reconcilertest.MustUpdate(t, fc, "tailscale", "nameserver", func(svc *corev1.Service) {
			svc.Spec.ClusterIP = "1.2.3.4"
		})
		reconcilertest.ExpectReconciled(t, r, "", "test")

		dnsConfig.Finalizers = []string{reconciler.Finalizer}
		dnsConfig.Status.Nameserver = &tsapi.NameserverStatus{
			IP: "1.2.3.4",
		}
		dnsConfig.Status.Conditions = append(dnsConfig.Status.Conditions, metav1.Condition{
			Type:               string(tsapi.NameserverReady),
			Status:             metav1.ConditionTrue,
			Reason:             nameserver.ReasonNameserverCreated,
			Message:            nameserver.ReasonNameserverCreated,
			LastTransitionTime: metav1.Time{Time: clock.Now().Truncate(time.Second)},
		})

		reconcilertest.ExpectEqual(t, fc, dnsConfig)
	})

	t.Run("nameserver-image-updated", func(t *testing.T) {
		// Verify that nameserver image gets updated to match DNSConfig spec.
		reconcilertest.MustUpdate(t, fc, "", "test", func(dnsCfg *tsapi.DNSConfig) {
			dnsCfg.Spec.Nameserver.Image.Tag = "v0.0.2"
		})
		reconcilertest.ExpectReconciled(t, r, "", "test")
		wantsDeploy.Spec.Template.Spec.Containers[0].Image = "test:v0.0.2"
		reconcilertest.ExpectEqual(t, fc, wantsDeploy)
	})

	t.Run("reconciler-preserves-custom-config", func(t *testing.T) {
		// Verify that when another actor sets ConfigMap data, it does not get
		// overwritten by nameserver reconciler.
		dnsRecords := &operatorutils.Records{Version: "v1alpha1", IP4: map[string][]string{"foo.ts.net": {"1.2.3.4"}}}
		bs, err := json.Marshal(dnsRecords)
		if err != nil {
			t.Fatalf("error marshalling ConfigMap contents: %v", err)
		}

		reconcilertest.MustUpdate(t, fc, "tailscale", "dnsrecords", func(cm *corev1.ConfigMap) {
			mak.Set(&cm.Data, "records.json", string(bs))
		})

		reconcilertest.ExpectReconciled(t, r, "", "test")

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

		reconcilertest.ExpectEqual(t, fc, wantCm)
	})

	t.Run("uses-default-nameserver-image", func(t *testing.T) {
		// Verify that if dnsconfig.spec.nameserver.image.{repo,tag} are unset,
		// the nameserver image defaults to tailscale/k8s-nameserver:stable.
		reconcilertest.MustUpdate(t, fc, "", "test", func(dnsCfg *tsapi.DNSConfig) {
			dnsCfg.Spec.Nameserver.Image = nil
		})
		reconcilertest.ExpectReconciled(t, r, "", "test")
		wantsDeploy.Spec.Template.Spec.Containers[0].Image = "tailscale/k8s-nameserver:stable"
		reconcilertest.ExpectEqual(t, fc, wantsDeploy)
	})
}
