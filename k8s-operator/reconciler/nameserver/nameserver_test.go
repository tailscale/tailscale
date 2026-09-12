// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package nameserver_test

import (
	"context"
	_ "embed"
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/yaml"

	operatorutils "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler"
	"tailscale.com/k8s-operator/reconciler/nameserver"
	"tailscale.com/k8s-operator/tailnetdns"
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
	r := nameserver.NewReconciler(nameserver.ReconcilerOptions{
		Client:             fc,
		Recorder:           record.NewFakeRecorder(10),
		TailscaleNamespace: tsNamespace,
		Logger:             logger.Sugar(),
		Clock:              clock,
	})
	mustReconcile(t, r, reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}})

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

		expectEqual(t, fc, wantsDeploy)
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
		expectEqual(t, fc, wantsSvc)
	})

	t.Run("dns-config-status-is-set", func(t *testing.T) {
		// Verify that DNSConfig advertises the nameserver's Service IP address,
		// has the ready status condition and tailscale finalizer.
		mustUpdate(t, fc, "tailscale", "nameserver", func(svc *corev1.Service) {
			svc.Spec.ClusterIP = "1.2.3.4"
		})
		mustReconcile(t, r, reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}})

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
		}, metav1.Condition{
			Type:               string(tsapi.SplitDNSReady),
			Status:             metav1.ConditionFalse,
			Reason:             nameserver.ReasonSplitDNSDisabled,
			Message:            "split DNS forwarding is not enabled",
			LastTransitionTime: metav1.Time{Time: clock.Now().Truncate(time.Second)},
		})

		expectEqual(t, fc, dnsConfig)
	})

	t.Run("nameserver-image-updated", func(t *testing.T) {
		// Verify that nameserver image gets updated to match DNSConfig spec.
		mustUpdate(t, fc, "", "test", func(dnsCfg *tsapi.DNSConfig) {
			dnsCfg.Spec.Nameserver.Image.Tag = "v0.0.2"
		})
		mustReconcile(t, r, reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}})
		wantsDeploy.Spec.Template.Spec.Containers[0].Image = "test:v0.0.2"
		expectEqual(t, fc, wantsDeploy)
	})

	t.Run("reconciler-preserves-custom-config", func(t *testing.T) {
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

	t.Run("uses-default-nameserver-image", func(t *testing.T) {
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

func mustReconcile(t *testing.T, r *nameserver.Reconciler, req reconcile.Request) {
	t.Helper()
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("unexpected reconcile error: %v", err)
	}
}

func mustUpdate[T any, O reconciler.PtrObject[T]](t *testing.T, c client.Client, ns, name string, update func(O)) {
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

func expectEqual[T any, O reconciler.PtrObject[T]](t *testing.T, c client.Client, want O) {
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
	// controller-runtime v0.20+ populates TypeMeta on objects returned by the
	// fake client. Strip it so tests can continue to build expected objects
	// without setting Kind/APIVersion explicitly.
	got.GetObjectKind().SetGroupVersionKind(schema.GroupVersionKind{})
	want.GetObjectKind().SetGroupVersionKind(schema.GroupVersionKind{})
	if diff := cmp.Diff(got, want); diff != "" {
		t.Fatalf("unexpected %s (-got +want):\n%s", reflect.TypeOf(want).Elem().Name(), diff)
	}
}

type fakeSplitDNS struct {
	routes map[string][]netip.AddrPort
	events chan event.TypedGenericEvent[tailnetdns.Change]
}

func (f *fakeSplitDNS) Routes() map[string][]netip.AddrPort { return f.routes }
func (f *fakeSplitDNS) Events() <-chan event.TypedGenericEvent[tailnetdns.Change] {
	return f.events
}

func TestNameserverReconcilerSplitDNS(t *testing.T) {
	dnsConfig := &tsapi.DNSConfig{
		TypeMeta:   metav1.TypeMeta{Kind: "DNSConfig", APIVersion: "tailscale.com/v1alpha1"},
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: tsapi.DNSConfigSpec{
			Nameserver: &tsapi.Nameserver{
				SplitDNS: &tsapi.NameserverSplitDNS{Enabled: true, Domains: []string{"Corp.Internal."}},
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
	splitDNS := &fakeSplitDNS{
		routes: map[string][]netip.AddrPort{
			"corp.internal": {netip.MustParseAddrPort("10.20.0.53:53"), netip.MustParseAddrPort("[fd7a:115c:a1e0::53]:53")},
			"eng.example":   {netip.MustParseAddrPort("10.30.0.53:53")},
		},
		events: make(chan event.TypedGenericEvent[tailnetdns.Change], 1),
	}
	recorder := record.NewFakeRecorder(10)
	r := nameserver.NewReconciler(nameserver.ReconcilerOptions{
		Client:             fc,
		Recorder:           recorder,
		TailscaleNamespace: tsNamespace,
		Logger:             logger.Sugar(),
		Clock:              tstest.NewClock(tstest.ClockOpts{}),
		SplitDNS:           splitDNS,
	})
	req := reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}}

	// The first reconcile creates the nameserver resources; the fake API server does not allocate a ClusterIP,
	// so nothing is configured until it has one.
	mustReconcile(t, r, req)
	mustUpdate(t, fc, tsNamespace, "nameserver", func(svc *corev1.Service) {
		svc.Spec.ClusterIP = "1.2.3.4"
	})
	mustReconcile(t, r, req)

	recordsCM := func(t *testing.T) operatorutils.Records {
		t.Helper()
		var cm corev1.ConfigMap
		if err := fc.Get(context.Background(), types.NamespacedName{Namespace: tsNamespace, Name: operatorutils.DNSRecordsCMName}, &cm); err != nil {
			t.Fatal(err)
		}
		var rec operatorutils.Records
		if raw := cm.Data[operatorutils.DNSRecordsCMKey]; raw != "" {
			if err := json.Unmarshal([]byte(raw), &rec); err != nil {
				t.Fatal(err)
			}
		}
		return rec
	}
	getCfg := func(t *testing.T) *tsapi.DNSConfig {
		t.Helper()
		var cfg tsapi.DNSConfig
		if err := fc.Get(context.Background(), types.NamespacedName{Name: "test"}, &cfg); err != nil {
			t.Fatal(err)
		}
		return &cfg
	}
	condition := func(cfg *tsapi.DNSConfig, typ tsapi.ConditionType) *metav1.Condition {
		for i := range cfg.Status.Conditions {
			if cfg.Status.Conditions[i].Type == string(typ) {
				return &cfg.Status.Conditions[i]
			}
		}
		return nil
	}

	t.Run("forwards-configured-for-selected-domains", func(t *testing.T) {
		rec := recordsCM(t)
		want := map[string][]string{"corp.internal": {"10.20.0.53:53", "[fd7a:115c:a1e0::53]:53"}}
		if !reflect.DeepEqual(rec.Forwards, want) {
			t.Errorf("Forwards = %v, want %v (eng.example is not in spec.nameserver.splitDNS.domains)", rec.Forwards, want)
		}
		cfg := getCfg(t)
		if !reflect.DeepEqual(cfg.Status.SplitDNSDomains, []string{"corp.internal"}) {
			t.Errorf("SplitDNSDomains = %v, want [corp.internal]", cfg.Status.SplitDNSDomains)
		}
		if c := condition(cfg, tsapi.SplitDNSReady); c == nil || c.Status != metav1.ConditionTrue || c.Reason != nameserver.ReasonSplitDNSConfigured {
			t.Errorf("SplitDNSReady = %+v, want True/%s", c, nameserver.ReasonSplitDNSConfigured)
		}
		// No RouteAcceptor exists, so the user is warned once.
		select {
		case ev := <-recorder.Events:
			if !strings.Contains(ev, "NoRouteAcceptor") {
				t.Errorf("event = %q, want a NoRouteAcceptor warning", ev)
			}
		default:
			t.Error("no NoRouteAcceptor event recorded")
		}
	})

	t.Run("other-writers-records-are-kept", func(t *testing.T) {
		// The dnsrecords reconciler shares the ConfigMap.
		if err := operatorutils.UpdateDNSRecords(context.Background(), fc, tsNamespace, func(rec *operatorutils.Records) {
			rec.IP4["foo.ts.net"] = []string{"100.64.0.1"}
		}); err != nil {
			t.Fatal(err)
		}
		mustReconcile(t, r, req)
		rec := recordsCM(t)
		if rec.IP4["foo.ts.net"] == nil || rec.Forwards["corp.internal"] == nil {
			t.Errorf("records = %+v, want both the ts.net record and the forwards", rec)
		}
	})

	t.Run("no-matching-domains", func(t *testing.T) {
		mustUpdate(t, fc, "", "test", func(cfg *tsapi.DNSConfig) {
			cfg.Spec.Nameserver.SplitDNS.Domains = []string{"other.example"}
		})
		mustReconcile(t, r, req)
		if rec := recordsCM(t); len(rec.Forwards) != 0 {
			t.Errorf("Forwards = %v, want none", rec.Forwards)
		}
		cfg := getCfg(t)
		if c := condition(cfg, tsapi.SplitDNSReady); c == nil || c.Status != metav1.ConditionFalse || c.Reason != nameserver.ReasonNoSplitDNSDomains {
			t.Errorf("SplitDNSReady = %+v, want False/%s", c, nameserver.ReasonNoSplitDNSDomains)
		}
		if len(cfg.Status.SplitDNSDomains) != 0 {
			t.Errorf("SplitDNSDomains = %v, want none", cfg.Status.SplitDNSDomains)
		}
	})

	t.Run("all-domains-when-unrestricted", func(t *testing.T) {
		mustUpdate(t, fc, "", "test", func(cfg *tsapi.DNSConfig) {
			cfg.Spec.Nameserver.SplitDNS.Domains = nil
		})
		mustReconcile(t, r, req)
		if got := getCfg(t).Status.SplitDNSDomains; !reflect.DeepEqual(got, []string{"corp.internal", "eng.example"}) {
			t.Errorf("SplitDNSDomains = %v, want both domains, sorted", got)
		}
	})

	t.Run("disabled-clears-forwards", func(t *testing.T) {
		mustUpdate(t, fc, "", "test", func(cfg *tsapi.DNSConfig) {
			cfg.Spec.Nameserver.SplitDNS.Enabled = false
		})
		mustReconcile(t, r, req)
		if rec := recordsCM(t); len(rec.Forwards) != 0 {
			t.Errorf("Forwards = %v after disabling, want none", rec.Forwards)
		}
		cfg := getCfg(t)
		if c := condition(cfg, tsapi.SplitDNSReady); c == nil || c.Status != metav1.ConditionFalse || c.Reason != nameserver.ReasonSplitDNSDisabled {
			t.Errorf("SplitDNSReady = %+v, want False/%s", c, nameserver.ReasonSplitDNSDisabled)
		}
	})
}

func TestNameserverReconcilerSplitDNSUnavailable(t *testing.T) {
	dnsConfig := &tsapi.DNSConfig{
		TypeMeta:   metav1.TypeMeta{Kind: "DNSConfig", APIVersion: "tailscale.com/v1alpha1"},
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: tsapi.DNSConfigSpec{
			Nameserver: &tsapi.Nameserver{SplitDNS: &tsapi.NameserverSplitDNS{Enabled: true}},
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
	// No SplitDNS source: the operator cannot read the tailnet's DNS configuration.
	r := nameserver.NewReconciler(nameserver.ReconcilerOptions{
		Client:             fc,
		Recorder:           record.NewFakeRecorder(10),
		TailscaleNamespace: tsNamespace,
		Logger:             logger.Sugar(),
		Clock:              tstest.NewClock(tstest.ClockOpts{}),
	})
	req := reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}}
	mustReconcile(t, r, req)
	mustUpdate(t, fc, tsNamespace, "nameserver", func(svc *corev1.Service) {
		svc.Spec.ClusterIP = "1.2.3.4"
	})
	mustReconcile(t, r, req)

	var cfg tsapi.DNSConfig
	if err := fc.Get(context.Background(), types.NamespacedName{Name: "test"}, &cfg); err != nil {
		t.Fatal(err)
	}
	for _, c := range cfg.Status.Conditions {
		if c.Type == string(tsapi.SplitDNSReady) {
			if c.Status != metav1.ConditionFalse || c.Reason != nameserver.ReasonSplitDNSUnavailable {
				t.Errorf("SplitDNSReady = %+v, want False/%s", c, nameserver.ReasonSplitDNSUnavailable)
			}
			return
		}
	}
	t.Error("SplitDNSReady condition not set")
}
