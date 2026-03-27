// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package nameserver

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/yaml"

	operatorutils "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler"
	"tailscale.com/tstest"
	"tailscale.com/util/mak"
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
	r := &Reconciler{
		Client:      fc,
		clock:       clock,
		logger:      logger.Sugar(),
		tsNamespace: tsNamespace,
	}
	mustReconcile(t, r, reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}})

	ownerReference := metav1.NewControllerRef(dnsConfig, tsapi.SchemeGroupVersion.WithKind("DNSConfig"))
	nameserverLabels := nameserverResourceLabels(dnsConfig.Name, tsNamespace)

	wantsDeploy := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "nameserver", Namespace: tsNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: appsv1.SchemeGroupVersion.Identifier()}}
	t.Run("deployment has expected fields", func(t *testing.T) {
		if err = yaml.Unmarshal(deployYaml, wantsDeploy); err != nil {
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
		// Verify that DNSConfig advertises the nameserver's Service IP address,
		// has the ready status condition and tailscale finalizer.
		mustUpdate(t, fc, "tailscale", "nameserver", func(svc *corev1.Service) {
			svc.Spec.ClusterIP = "1.2.3.4"
		})
		mustReconcile(t, r, reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}})

		dnsConfig.Finalizers = []string{reconciler.FinalizerName}
		dnsConfig.Status.Nameserver = &tsapi.NameserverStatus{
			IP: "1.2.3.4",
		}
		dnsConfig.Status.Conditions = append(dnsConfig.Status.Conditions, metav1.Condition{
			Type:               string(tsapi.NameserverReady),
			Status:             metav1.ConditionTrue,
			Reason:             ReasonNameserverCreated,
			Message:            ReasonNameserverCreated,
			LastTransitionTime: metav1.Time{Time: clock.Now().Truncate(time.Second)},
		})

		expectEqual(t, fc, dnsConfig)
	})

	t.Run("nameserver image can be updated", func(t *testing.T) {
		// Verify that nameserver image gets updated to match DNSConfig spec.
		mustUpdate(t, fc, "", "test", func(dnsCfg *tsapi.DNSConfig) {
			dnsCfg.Spec.Nameserver.Image.Tag = "v0.0.2"
		})
		mustReconcile(t, r, reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}})
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

		mustReconcile(t, r, reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}})

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
		// the nameserver image defaults to tailscale/k8s-nameserver:stable.
		mustUpdate(t, fc, "", "test", func(dnsCfg *tsapi.DNSConfig) {
			dnsCfg.Spec.Nameserver.Image = nil
		})
		mustReconcile(t, r, reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}})
		wantsDeploy.Spec.Template.Spec.Containers[0].Image = "tailscale/k8s-nameserver:stable"
		expectEqual(t, fc, wantsDeploy)
	})
}

func mustReconcile(t *testing.T, r *Reconciler, req reconcile.Request) {
	t.Helper()
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("unexpected reconcile error: %v", err)
	}
}

func mustUpdate[T any, O interface {
	client.Object
	*T
}](t *testing.T, c client.Client, ns, name string, update func(O)) {
	t.Helper()
	obj := O(new(T))
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, obj); err != nil {
		t.Fatalf("getting object: %v", err)
	}
	update(obj)
	if err := c.Update(context.Background(), obj); err != nil {
		t.Fatalf("updating object: %v", err)
	}
}

func expectEqual[T any, O interface {
	client.Object
	*T
}](t *testing.T, c client.Client, want O) {
	t.Helper()
	got := O(new(T))
	if err := c.Get(context.Background(), types.NamespacedName{
		Name:      want.GetName(),
		Namespace: want.GetNamespace(),
	}, got); err != nil {
		t.Fatalf("getting %q: %v", want.GetName(), err)
	}
	// The resource version changes eagerly whenever the operator does even a
	// no-op update. Asserting a specific value leads to overly brittle tests,
	// so just remove it from both got and want.
	got.SetResourceVersion("")
	want.SetResourceVersion("")
	if diff := cmp.Diff(got, want); diff != "" {
		t.Fatalf("unexpected %s (-got +want):\n%s", reflect.TypeOf(want).Elem().Name(), diff)
	}
}
