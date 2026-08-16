// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package recorder_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tailscaleclient "tailscale.com/client/tailscale/v2"

	"tailscale.com/ipn"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler/reconcilertest"
	"tailscale.com/k8s-operator/reconciler/recorder"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tstest"
	"tailscale.com/types/key"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/mak"
	"tailscale.com/version"
)

const (
	tsNamespace   = "tailscale"
	tsLoginServer = "example.tailscale.com"
)

func TestRecorder(t *testing.T) {
	tsr := &tsapi.Recorder{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test",
			Finalizers: []string{"tailscale.com/finalizer"},
		},
		Spec: tsapi.RecorderSpec{
			Replicas: new(int32(3)),
		},
	}

	fc := reconcilertest.NewClientBuilder().
		WithObjects(tsr).
		WithStatusSubresource(tsr).
		Build()
	tsClient := reconcilertest.NewFakeClient(reconcilertest.WithLoginURL(tsLoginServer))
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	fr := record.NewFakeRecorder(2)
	r := recorder.NewReconciler(recorder.ReconcilerOptions{
		Client:             fc,
		Recorder:           fr,
		TailscaleNamespace: tsNamespace,
		Clients:            reconcilertest.NewFakeClientProvider(tsClient),
		Logger:             zl.Sugar(),
		Clock:              tstest.NewClock(tstest.ClockOpts{}),
	})

	t.Run("invalid_spec_gives_an_error_condition", func(t *testing.T) {
		reconcilertest.ExpectReconciled(t, r, "", tsr.Name)

		expectReadyCondition(t, fc, tsr.Name, metav1.ConditionFalse, "RecorderInvalid",
			"Recorder is invalid: must either enable UI or use S3 storage to ensure recordings are accessible")
		expectManagedCount(t, 0)
		expectRecorderResources(t, fc, tsr, false)

		reconcilertest.ExpectEvents(t, fr, []string{"Warning RecorderInvalid Recorder is invalid: must either enable UI or use S3 storage to ensure recordings are accessible"})

		tsr.Spec.EnableUI = true
		tsr.Spec.StatefulSet.Pod.ServiceAccount.Annotations = map[string]string{
			"invalid space characters": "test",
		}
		reconcilertest.MustUpdate(t, fc, "", "test", func(o *tsapi.Recorder) {
			o.Spec = tsr.Spec
		})
		reconcilertest.ExpectReconciled(t, r, "", tsr.Name)

		reconcilertest.ExpectEvents(t, fr, []string{"Warning RecorderInvalid Recorder is invalid: must use S3 storage when using multiple replicas to ensure recordings are accessible"})

		tsr.Spec.Storage.S3 = &tsapi.S3{}
		reconcilertest.MustUpdate(t, fc, "", "test", func(o *tsapi.Recorder) {
			o.Spec = tsr.Spec
		})
		reconcilertest.ExpectReconciled(t, r, "", tsr.Name)

		// Only check part of this error message, because it's defined in an
		// external package and may change.
		got := &tsapi.Recorder{}
		reconcilertest.MustGet(t, fc, "", tsr.Name, got)
		reconcilertest.ExpectConditionStatus(t, got.Status.Conditions, tsapi.RecorderReady, metav1.ConditionFalse, "RecorderInvalid")
		cond := reconcilertest.Condition(t, got.Status.Conditions, tsapi.RecorderReady)
		for _, msg := range []string{cond.Message, <-fr.Events} {
			if !strings.Contains(msg, `"invalid space characters"`) {
				t.Fatalf("expected invalid annotation key in error message, got %q", msg)
			}
		}
	})

	t.Run("conflicting_service_account_config_marked_as_invalid", func(t *testing.T) {
		reconcilertest.MustCreate(t, fc, &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pre-existing-sa",
				Namespace: tsNamespace,
			},
		})

		tsr.Spec.StatefulSet.Pod.ServiceAccount.Annotations = nil
		tsr.Spec.StatefulSet.Pod.ServiceAccount.Name = "pre-existing-sa"
		reconcilertest.MustUpdate(t, fc, "", "test", func(o *tsapi.Recorder) {
			o.Spec = tsr.Spec
		})

		reconcilertest.ExpectReconciled(t, r, "", tsr.Name)

		msg := `Recorder is invalid: custom ServiceAccount name "pre-existing-sa" specified but conflicts with a pre-existing ServiceAccount in the tailscale namespace`
		expectReadyCondition(t, fc, tsr.Name, metav1.ConditionFalse, "RecorderInvalid", msg)
		expectManagedCount(t, 0)

		reconcilertest.ExpectEvents(t, fr, []string{"Warning RecorderInvalid " + msg})
	})

	t.Run("observe_Ready_true_status_condition_for_a_valid_spec", func(t *testing.T) {
		tsr.Spec.StatefulSet.Pod.ServiceAccount.Name = ""
		reconcilertest.MustUpdate(t, fc, "", "test", func(o *tsapi.Recorder) {
			o.Spec = tsr.Spec
		})

		reconcilertest.ExpectReconciled(t, r, "", tsr.Name)

		// The reason is part of the CRD's observable status, so assert it as a literal: a rename of the constant
		// should fail here.
		expectReadyCondition(t, fc, tsr.Name, metav1.ConditionTrue, "RecorderCreated", "RecorderCreated")
		expectManagedCount(t, 1)
		expectRecorderResources(t, fc, tsr, true)

		// Every replica's auth key was minted with the default tag, and its
		// StatefulSet is pointed at the login server of its tailnet.
		if got := len(tsClient.CreateAuthKeyCalls()); got != int(*tsr.Spec.Replicas) {
			t.Fatalf("expected %d auth keys to be created, got %d", *tsr.Spec.Replicas, got)
		}
		for _, req := range tsClient.CreateAuthKeyCalls() {
			if diff := cmp.Diff(req.Capabilities.Devices.Create.Tags, []string{"tag:k8s"}); diff != "" {
				t.Errorf("unexpected auth key tags (-got +want):\n%s", diff)
			}
		}

		ss := &appsv1.StatefulSet{}
		reconcilertest.MustGet(t, fc, tsNamespace, tsr.Name, ss)
		if got := envValue(ss, "TSRECORDER_LOGIN_SERVER"); got != tsLoginServer {
			t.Errorf("unexpected login server env value: got %q, want %q", got, tsLoginServer)
		}
	})

	t.Run("valid_service_account_config", func(t *testing.T) {
		tsr.Spec.StatefulSet.Pod.ServiceAccount.Name = "test-sa"
		tsr.Spec.StatefulSet.Pod.ServiceAccount.Annotations = map[string]string{
			"test": "test",
		}
		reconcilertest.MustUpdate(t, fc, "", "test", func(o *tsapi.Recorder) {
			o.Spec = tsr.Spec
		})

		reconcilertest.ExpectReconciled(t, r, "", tsr.Name)

		expectManagedCount(t, 1)
		expectRecorderResources(t, fc, tsr, true)

		// Get the service account and check the annotations.
		sa := &corev1.ServiceAccount{}
		reconcilertest.MustGet(t, fc, tsNamespace, "test-sa", sa)
		if diff := cmp.Diff(sa.Annotations, tsr.Spec.StatefulSet.Pod.ServiceAccount.Annotations); diff != "" {
			t.Fatalf("unexpected service account annotations (-got +want):\n%s", diff)
		}

		// The ServiceAccount named after the Recorder is no longer referenced,
		// so it should have been cleaned up.
		reconcilertest.ExpectMissing[corev1.ServiceAccount](t, fc, tsNamespace, tsr.Name)
	})

	t.Run("populate_node_info_in_state_secret_and_see_it_appear_in_status", func(t *testing.T) {
		for replica := range *tsr.Spec.Replicas {
			seedStateSecret(t, fc, fmt.Sprintf("test-%d", replica), fmt.Sprintf("node-%d", replica), fmt.Sprintf("test-%d.example.ts.net", replica))
		}

		tsClient.SetDevices(
			tailscaleclient.Device{
				ID:        "node-0",
				Hostname:  "hostname-node-0",
				Addresses: []string{"1.2.3.4", "::1"},
			},
			tailscaleclient.Device{
				ID:        "node-1",
				Hostname:  "hostname-node-1",
				Addresses: []string{"1.2.3.4", "::1"},
			},
			tailscaleclient.Device{
				ID:        "node-2",
				Hostname:  "hostname-node-2",
				Addresses: []string{"1.2.3.4", "::1"},
			},
		)

		reconcilertest.ExpectReconciled(t, r, "", tsr.Name)

		want := []tsapi.RecorderTailnetDevice{
			{
				Hostname:   "hostname-node-0",
				TailnetIPs: []string{"1.2.3.4", "::1"},
				URL:        "https://test-0.example.ts.net",
			},
			{
				Hostname:   "hostname-node-1",
				TailnetIPs: []string{"1.2.3.4", "::1"},
				URL:        "https://test-1.example.ts.net",
			},
			{
				Hostname:   "hostname-node-2",
				TailnetIPs: []string{"1.2.3.4", "::1"},
				URL:        "https://test-2.example.ts.net",
			},
		}

		got := &tsapi.Recorder{}
		reconcilertest.MustGet(t, fc, "", tsr.Name, got)
		if diff := cmp.Diff(got.Status.Devices, want); diff != "" {
			t.Fatalf("unexpected devices in status (-got +want):\n%s", diff)
		}
	})

	t.Run("scale_down_deletes_dangling_replica_secrets_and_devices", func(t *testing.T) {
		tsr.Spec.Replicas = new(int32(1))
		reconcilertest.MustUpdate(t, fc, "", "test", func(o *tsapi.Recorder) {
			o.Spec = tsr.Spec
		})

		reconcilertest.ExpectReconciled(t, r, "", tsr.Name)

		// Replicas 1 and 2 are gone from the cluster and from the tailnet;
		// replica 0 is untouched.
		for _, name := range []string{"test-1", "test-auth-1", "test-2", "test-auth-2"} {
			reconcilertest.ExpectMissing[corev1.Secret](t, fc, tsNamespace, name)
		}
		reconcilertest.MustGet(t, fc, tsNamespace, "test-0", &corev1.Secret{})
		if diff := cmp.Diff(tsClient.DeviceDeletes(), []string{"node-1", "node-2"}); diff != "" {
			t.Fatalf("unexpected deleted devices (-got +want):\n%s", diff)
		}

		// The Role should no longer grant access to the scaled-down replicas'
		// Secrets.
		role := &rbacv1.Role{}
		reconcilertest.MustGet(t, fc, tsNamespace, tsr.Name, role)
		if diff := cmp.Diff(role.Rules[0].ResourceNames, []string{"test-0", "test-auth-0"}); diff != "" {
			t.Fatalf("unexpected Role resource names (-got +want):\n%s", diff)
		}
	})

	t.Run("delete_the_Recorder_and_observe_cleanup", func(t *testing.T) {
		reconcilertest.MustDeleteAll(t, fc, tsr)

		reconcilertest.ExpectReconciled(t, r, "", tsr.Name)

		reconcilertest.ExpectMissing[tsapi.Recorder](t, fc, "", tsr.Name)
		expectManagedCount(t, 0)
		if diff := cmp.Diff(tsClient.DeviceDeletes(), []string{"node-1", "node-2", "node-0"}); diff != "" {
			t.Fatalf("unexpected deleted devices (-got +want):\n%s", diff)
		}
		// The fake client does not clean up objects whose owner has been
		// deleted, so we can't test for the owned resources getting deleted.
	})
}

func TestRecorderTailnetUnavailable(t *testing.T) {
	tsr := &tsapi.Recorder{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec:       tsapi.RecorderSpec{EnableUI: true, Tailnet: "missing"},
	}

	fc := reconcilertest.NewClientBuilder().
		WithObjects(tsr).
		WithStatusSubresource(tsr).
		Build()
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	r := recorder.NewReconciler(recorder.ReconcilerOptions{
		Client:             fc,
		Recorder:           record.NewFakeRecorder(1),
		TailscaleNamespace: tsNamespace,
		Clients:            reconcilertest.NewFailingClientProvider(errors.New(`tailnet "missing" not found`)),
		Logger:             zl.Sugar(),
		Clock:              tstest.NewClock(tstest.ClockOpts{}),
	})

	reconcilertest.ExpectReconciled(t, r, "", tsr.Name)

	got := &tsapi.Recorder{}
	reconcilertest.MustGet(t, fc, "", tsr.Name, got)
	reconcilertest.ExpectCondition(t, got.Status.Conditions, tsapi.RecorderReady,
		metav1.ConditionFalse, "RecorderTailnetUnavailable", `tailnet "missing" not found`)

	// No resources should have been created for a Recorder we can't mint keys
	// for, and no finalizer should have been added.
	reconcilertest.ExpectMissing[appsv1.StatefulSet](t, fc, tsNamespace, tsr.Name)
	if len(got.Finalizers) > 0 {
		t.Fatalf("expected no finalizers, got %v", got.Finalizers)
	}
}

func TestRecorderCleanupContinuesPastUnreportedDevice(t *testing.T) {
	tsr := &tsapi.Recorder{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test",
			Finalizers:        []string{"tailscale.com/finalizer"},
			DeletionTimestamp: new(metav1.Now()),
		},
		Spec: tsapi.RecorderSpec{
			Replicas: new(int32(3)),
			Storage:  tsapi.Storage{S3: &tsapi.S3{}},
		},
	}

	fc := reconcilertest.NewClientBuilder().
		WithObjects(
			tsr,
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "test-0", Namespace: tsNamespace}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "test-1", Namespace: tsNamespace}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "test-2", Namespace: tsNamespace}},
		).
		WithStatusSubresource(tsr).
		Build()
	tsClient := reconcilertest.NewFakeClient(reconcilertest.WithLoginURL(tsLoginServer))
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	r := recorder.NewReconciler(recorder.ReconcilerOptions{
		Client:             fc,
		Recorder:           record.NewFakeRecorder(1),
		TailscaleNamespace: tsNamespace,
		Clients:            reconcilertest.NewFakeClientProvider(tsClient),
		Logger:             zl.Sugar(),
		Clock:              tstest.NewClock(tstest.ClockOpts{}),
	})

	// Replica 0 registered with control but never reported its device ID. It comes first, so it must not end cleanup
	// early.
	mk := key.NewMachine()
	mkText, err := mk.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	reconcilertest.MustUpdate(t, fc, tsNamespace, "test-0", func(s *corev1.Secret) {
		s.Data = map[string][]byte{string(ipn.MachineKeyStateKey): mkText}
	})
	seedStateSecret(t, fc, "test-1", "node-1", "test-1.example.ts.net")
	seedStateSecret(t, fc, "test-2", "node-2", "test-2.example.ts.net")
	tsClient.SetDevices(
		tailscaleclient.Device{NodeID: "unreported-0", MachineKey: mk.Public().String()},
		tailscaleclient.Device{NodeID: "other", MachineKey: key.NewMachine().Public().String()},
	)

	reconcilertest.ExpectReconciled(t, r, "", tsr.Name)

	reconcilertest.ExpectMissing[tsapi.Recorder](t, fc, "", tsr.Name)
	if diff := cmp.Diff(tsClient.DeviceDeletes(), []string{"unreported-0", "node-1", "node-2"}); diff != "" {
		t.Fatalf("unexpected deleted devices (-got +want):\n%s", diff)
	}
}

func TestRecorderStatefulSetSpec(t *testing.T) {
	tsr := &tsapi.Recorder{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
		},
		Spec: tsapi.RecorderSpec{
			Replicas: new(int32(3)),
			EnableUI: true,
			Storage: tsapi.Storage{
				S3: &tsapi.S3{
					Endpoint: "s3.example.com",
					Bucket:   "recordings",
					Credentials: tsapi.S3Credentials{
						Secret: tsapi.S3Secret{Name: "s3-creds"},
					},
				},
			},
			StatefulSet: tsapi.RecorderStatefulSet{
				Labels: map[string]string{
					"ss-label-key": "ss-label-value",
				},
				Annotations: map[string]string{
					"ss-annotation-key": "ss-annotation-value",
				},
				Pod: tsapi.RecorderPod{
					Labels: map[string]string{
						"pod-label-key": "pod-label-value",
					},
					Annotations: map[string]string{
						"pod-annotation-key": "pod-annotation-value",
					},
					Affinity: &corev1.Affinity{
						PodAffinity: &corev1.PodAffinity{
							RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{{
								LabelSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"match-label": "match-value",
									},
								}},
							},
						},
					},
					SecurityContext: &corev1.PodSecurityContext{
						RunAsUser: new(int64(1000)),
					},
					ImagePullSecrets: []corev1.LocalObjectReference{{
						Name: "img-pull",
					}},
					NodeSelector: map[string]string{
						"some-node": "selector",
					},
					Tolerations: []corev1.Toleration{{
						Key:               "key",
						Value:             "value",
						TolerationSeconds: new(int64(60)),
					}},
					ServiceAccount: tsapi.RecorderServiceAccount{
						Name: "custom-sa",
					},
					Container: tsapi.RecorderContainer{
						Env: []tsapi.Env{{
							Name:  "some_env",
							Value: "env_value",
						}},
						Image:           "custom-image",
						ImagePullPolicy: corev1.PullAlways,
						SecurityContext: &corev1.SecurityContext{
							Capabilities: &corev1.Capabilities{
								Add: []corev1.Capability{
									"NET_ADMIN",
								},
							},
						},
						Resources: corev1.ResourceRequirements{
							Limits: corev1.ResourceList{
								corev1.ResourceCPU: resource.MustParse("100m"),
							},
							Requests: corev1.ResourceList{
								corev1.ResourceCPU: resource.MustParse("50m"),
							},
						},
					},
				},
			},
		},
	}

	fc := reconcilertest.NewClientBuilder().
		WithObjects(tsr).
		WithStatusSubresource(tsr).
		Build()
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	r := recorder.NewReconciler(recorder.ReconcilerOptions{
		Client:             fc,
		Recorder:           record.NewFakeRecorder(1),
		TailscaleNamespace: tsNamespace,
		Clients:            reconcilertest.NewFakeClientProvider(reconcilertest.NewFakeClient(reconcilertest.WithLoginURL(tsLoginServer))),
		Logger:             zl.Sugar(),
		Clock:              tstest.NewClock(tstest.ClockOpts{}),
	})

	reconcilertest.ExpectReconciled(t, r, "", tsr.Name)

	// Every field that the spec passes through ends up on the Recorder's children.
	expectRecorderResources(t, fc, tsr, true)
}

// expectRecorderResources asserts that the full set of resources for each of tsr's replicas either exists or is
// absent. The test builds each expected child itself, without the reconciler's spec builders, so a change to what the
// reconciler writes fails here.
func expectRecorderResources(t *testing.T, fc client.Client, tsr *tsapi.Recorder, shouldExist bool) {
	t.Helper()

	// The owner references carry the UID of the stored Recorder.
	stored := &tsapi.Recorder{}
	reconcilertest.MustGet(t, fc, "", tsr.Name, stored)
	stored.Spec = tsr.Spec

	role := wantRole(stored)
	roleBinding := wantRoleBinding(stored)
	serviceAccount := wantServiceAccount(stored)
	statefulSet := wantStatefulSet(stored)

	if !shouldExist {
		reconcilertest.ExpectMissing[rbacv1.Role](t, fc, role.Namespace, role.Name)
		reconcilertest.ExpectMissing[rbacv1.RoleBinding](t, fc, roleBinding.Namespace, roleBinding.Name)
		reconcilertest.ExpectMissing[corev1.ServiceAccount](t, fc, serviceAccount.Namespace, serviceAccount.Name)
		reconcilertest.ExpectMissing[appsv1.StatefulSet](t, fc, statefulSet.Namespace, statefulSet.Name)
		for replica := range replicaCount(stored) {
			reconcilertest.ExpectMissing[corev1.Secret](t, fc, tsNamespace, authSecretName(stored, replica))
			reconcilertest.ExpectMissing[corev1.Secret](t, fc, tsNamespace, stateSecretName(stored, replica))
		}
		return
	}

	reconcilertest.ExpectEqual(t, fc, role)
	reconcilertest.ExpectEqual(t, fc, roleBinding)
	reconcilertest.ExpectEqual(t, fc, serviceAccount)
	reconcilertest.ExpectEqual(t, fc, statefulSet)

	for replica := range replicaCount(stored) {
		auth := &corev1.Secret{}
		reconcilertest.MustGet(t, fc, tsNamespace, authSecretName(stored, replica), auth)
		if auth.StringData["authkey"] == "" {
			t.Errorf("auth Secret %q has no auth key", auth.Name)
		}

		// The fake Tailscale client generates each auth key, so leave the key out of the comparison.
		reconcilertest.ExpectEqual(t, fc, wantSecret(stored, authSecretName(stored, replica)), func(s *corev1.Secret) {
			s.StringData = nil
		})
		reconcilertest.ExpectEqual(t, fc, wantSecret(stored, stateSecretName(stored, replica)))
	}
}

func replicaCount(tsr *tsapi.Recorder) int32 {
	if tsr.Spec.Replicas == nil {
		return 1
	}
	return *tsr.Spec.Replicas
}

func authSecretName(tsr *tsapi.Recorder, replica int32) string {
	return fmt.Sprintf("%s-auth-%d", tsr.Name, replica)
}

func stateSecretName(tsr *tsapi.Recorder, replica int32) string {
	return fmt.Sprintf("%s-%d", tsr.Name, replica)
}

func wantServiceAccountName(tsr *tsapi.Recorder) string {
	if name := tsr.Spec.StatefulSet.Pod.ServiceAccount.Name; name != "" {
		return name
	}
	return tsr.Name
}

func wantLabels(tsr *tsapi.Recorder, custom map[string]string) map[string]string {
	labels := maps.Clone(custom)
	mak.Set(&labels, "app.kubernetes.io/name", "recorder")
	mak.Set(&labels, "app.kubernetes.io/instance", tsr.Name)
	mak.Set(&labels, "app.kubernetes.io/managed-by", "tailscale-operator")
	return labels
}

func wantObjectMeta(tsr *tsapi.Recorder, name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name:      name,
		Namespace: tsNamespace,
		Labels:    wantLabels(tsr, nil),
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion:         "tailscale.com/v1alpha1",
			Kind:               "Recorder",
			Name:               tsr.Name,
			UID:                tsr.UID,
			Controller:         new(true),
			BlockOwnerDeletion: new(true),
		}},
	}
}

func wantSecret(tsr *tsapi.Recorder, name string) *corev1.Secret {
	return &corev1.Secret{ObjectMeta: wantObjectMeta(tsr, name)}
}

func wantServiceAccount(tsr *tsapi.Recorder) *corev1.ServiceAccount {
	sa := &corev1.ServiceAccount{ObjectMeta: wantObjectMeta(tsr, wantServiceAccountName(tsr))}
	sa.Annotations = tsr.Spec.StatefulSet.Pod.ServiceAccount.Annotations
	return sa
}

func wantRole(tsr *tsapi.Recorder) *rbacv1.Role {
	var secrets []string
	for replica := range replicaCount(tsr) {
		secrets = append(secrets, stateSecretName(tsr, replica), authSecretName(tsr, replica))
	}

	return &rbacv1.Role{
		ObjectMeta: wantObjectMeta(tsr, tsr.Name),
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups:     []string{""},
				Resources:     []string{"secrets"},
				Verbs:         []string{"get", "patch", "update"},
				ResourceNames: secrets,
			},
			{
				APIGroups: []string{""},
				Resources: []string{"events"},
				Verbs:     []string{"get", "create", "patch"},
			},
		},
	}
}

func wantRoleBinding(tsr *tsapi.Recorder) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		ObjectMeta: wantObjectMeta(tsr, tsr.Name),
		Subjects: []rbacv1.Subject{{
			Kind:      "ServiceAccount",
			Name:      wantServiceAccountName(tsr),
			Namespace: tsNamespace,
		}},
		RoleRef: rbacv1.RoleRef{
			Kind: "Role",
			Name: tsr.Name,
		},
	}
}

func wantStatefulSet(tsr *tsapi.Recorder) *appsv1.StatefulSet {
	pod := tsr.Spec.StatefulSet.Pod

	image := pod.Container.Image
	if image == "" {
		meta := version.GetMeta()
		prefix := ""
		if meta.UnstableBranch {
			prefix = "unstable-"
		}
		image = fmt.Sprintf("tailscale/tsrecorder:%sv%s", prefix, meta.MajorMinorPatch)
	}

	env := []corev1.EnvVar{
		{Name: "POD_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"}}},
		{Name: "POD_UID", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.uid"}}},
		{Name: "TS_AUTHKEY_FILE", Value: "/etc/tailscaled/$(POD_NAME)/authkey"},
		{Name: "TS_STATE", Value: "kube:$(POD_NAME)"},
		{Name: "TSRECORDER_HOSTNAME", Value: "$(POD_NAME)"},
		{Name: "TSRECORDER_LOGIN_SERVER", Value: tsLoginServer},
	}
	for _, e := range pod.Container.Env {
		env = append(env, corev1.EnvVar{Name: string(e.Name), Value: e.Value})
	}

	var envFrom []corev1.EnvFromSource
	if s3 := tsr.Spec.Storage.S3; s3 != nil {
		env = append(env,
			corev1.EnvVar{Name: "TSRECORDER_DST", Value: "s3://" + s3.Endpoint},
			corev1.EnvVar{Name: "TSRECORDER_BUCKET", Value: s3.Bucket},
		)
		if s3.Credentials.Secret.Name != "" {
			envFrom = []corev1.EnvFromSource{{
				SecretRef: &corev1.SecretEnvSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: s3.Credentials.Secret.Name},
				},
			}}
		}
	} else {
		env = append(env, corev1.EnvVar{Name: "TSRECORDER_DST", Value: "/data/recordings"})
	}
	if tsr.Spec.EnableUI {
		env = append(env, corev1.EnvVar{Name: "TSRECORDER_UI", Value: "true"})
	}

	mounts := []corev1.VolumeMount{{Name: "data", MountPath: "/data"}}
	volumes := []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}}
	for replica := range replicaCount(tsr) {
		name := fmt.Sprintf("authkey-%d", replica)
		mounts = append(mounts, corev1.VolumeMount{
			Name:      name,
			ReadOnly:  true,
			MountPath: "/etc/tailscaled/" + stateSecretName(tsr, replica),
		})
		volumes = append(volumes, corev1.Volume{
			Name: name,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: authSecretName(tsr, replica),
					Items:      []corev1.KeyToPath{{Key: "authkey", Path: "authkey"}},
				},
			},
		})
	}

	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:            tsr.Name,
			Namespace:       tsNamespace,
			Labels:          wantLabels(tsr, tsr.Spec.StatefulSet.Labels),
			Annotations:     tsr.Spec.StatefulSet.Annotations,
			OwnerReferences: wantObjectMeta(tsr, tsr.Name).OwnerReferences,
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: new(replicaCount(tsr)),
			Selector: &metav1.LabelSelector{MatchLabels: wantLabels(tsr, pod.Labels)},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:        tsr.Name,
					Namespace:   tsNamespace,
					Labels:      wantLabels(tsr, pod.Labels),
					Annotations: pod.Annotations,
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: wantServiceAccountName(tsr),
					Affinity:           pod.Affinity,
					SecurityContext:    pod.SecurityContext,
					ImagePullSecrets:   pod.ImagePullSecrets,
					NodeSelector:       pod.NodeSelector,
					Tolerations:        pod.Tolerations,
					Containers: []corev1.Container{{
						Name:            "recorder",
						Image:           image,
						ImagePullPolicy: pod.Container.ImagePullPolicy,
						Resources:       pod.Container.Resources,
						SecurityContext: pod.Container.SecurityContext,
						Env:             env,
						EnvFrom:         envFrom,
						Command:         []string{"/tsrecorder"},
						VolumeMounts:    mounts,
					}},
					Volumes: volumes,
				},
			},
		},
	}
}

// expectReadyCondition asserts the Recorder's RecorderReady condition.
func expectReadyCondition(t *testing.T, fc client.Client, name string, status metav1.ConditionStatus, reason, message string) {
	t.Helper()
	tsr := &tsapi.Recorder{}
	reconcilertest.MustGet(t, fc, "", name, tsr)
	reconcilertest.ExpectCondition(t, tsr.Status.Conditions, tsapi.RecorderReady, status, reason, message)
}

// expectManagedCount asserts the number of Recorders the reconciler reports as managed via its clientmetric gauge.
func expectManagedCount(t *testing.T, want int64) {
	t.Helper()
	for _, m := range clientmetric.Metrics() {
		if m.Name() == kubetypes.MetricRecorderCount {
			if got := m.Value(); got != want {
				t.Fatalf("expected %d recorders, got %d", want, got)
			}
			return
		}
	}
	t.Fatalf("metric %q not found", kubetypes.MetricRecorderCount)
}

// seedStateSecret writes the profile data that tailscaled would have written to a replica's state Secret once it has
// authenticated.
func seedStateSecret(t *testing.T, fc client.Client, name, nodeID, loginName string) {
	t.Helper()
	const key = "profile-abc"

	body, err := json.Marshal(map[string]any{
		"Config": map[string]any{
			"NodeID": nodeID,
			"UserProfile": map[string]any{
				"LoginName": loginName,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	reconcilertest.MustUpdate(t, fc, tsNamespace, name, func(s *corev1.Secret) {
		s.Data = map[string][]byte{
			string(ipn.CurrentProfileStateKey): []byte(key),
			key:                                body,
		}
	})
}

func envValue(ss *appsv1.StatefulSet, name string) string {
	for _, env := range ss.Spec.Template.Spec.Containers[0].Env {
		if env.Name == name {
			return env.Value
		}
	}
	return ""
}
