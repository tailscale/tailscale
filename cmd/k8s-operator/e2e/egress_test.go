// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	kube "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/tstest"
)

const egressPort = 80

// See [TestMain] for test requirements.
func TestEgress(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestEgress requires a working tailnet client")
	}
	t.Parallel()

	t.Run("IPv4", func(t *testing.T) {
		if !clusterIPv4Support {
			t.Skip("cluster does not support IPv4")
		}
		svc := egressService(generateName("test-egress"), map[string]string{
			"tailscale.com/tailnet-ip": tnTarget.ipv4,
		})
		createAndCleanup(t, kubeClient, svc)
		waitForEgress(t, svc.Name, kube.SvcIsReady)
		testEgressIsReachable(t, ns, svc.Name)
	})

	t.Run("IPv6", func(t *testing.T) {
		if !clusterIPv6Support {
			t.Skip("cluster does not support IPv6")
		}
		svc := egressService(generateName("test-egress"), map[string]string{
			"tailscale.com/tailnet-ip": tnTarget.ipv6,
		})
		createAndCleanup(t, kubeClient, svc)
		waitForEgress(t, svc.Name, kube.SvcIsReady)
		testEgressIsReachable(t, ns, svc.Name)
	})

	t.Run("FQDN", func(t *testing.T) {
		svc := egressService(generateName("test-egress"), map[string]string{
			"tailscale.com/tailnet-fqdn": tnTarget.fqdn,
		})
		createAndCleanup(t, kubeClient, svc)
		waitForEgress(t, svc.Name, kube.SvcIsReady)
		testEgressIsReachable(t, ns, svc.Name)
	})
}

// See [TestMain] for test requirements.
func TestHAEgress(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestHAEgress requires a working tailnet client")
	}
	t.Parallel()

	pg := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: generateName("egress"),
		},
		Spec: tsapi.ProxyGroupSpec{
			Type: tsapi.ProxyGroupTypeEgress,
		},
	}
	createAndCleanup(t, kubeClient, pg)

	t.Run("IPv4", func(t *testing.T) {
		if !clusterIPv4Support {
			t.Skip("cluster does not support IPv4")
		}
		svc := egressService(generateName("test-egress"), map[string]string{
			"tailscale.com/tailnet-ip":  tnTarget.ipv4,
			"tailscale.com/proxy-group": pg.Name,
		})
		createAndCleanup(t, kubeClient, svc)
		waitForEgress(t, svc.Name, pgEgressReady)
		testEgressIsReachable(t, ns, svc.Name)
	})

	t.Run("IPv6", func(t *testing.T) {
		if !clusterIPv6Support {
			t.Skip("cluster does not support IPv6")
		}
		svc := egressService(generateName("test-egress"), map[string]string{
			"tailscale.com/tailnet-ip":  tnTarget.ipv6,
			"tailscale.com/proxy-group": pg.Name,
		})
		createAndCleanup(t, kubeClient, svc)
		waitForEgress(t, svc.Name, pgEgressReady)
		testEgressIsReachable(t, ns, svc.Name)
	})

	t.Run("FQDN", func(t *testing.T) {
		svc := egressService(generateName("test-egress"), map[string]string{
			"tailscale.com/tailnet-fqdn": tnTarget.fqdn,
			"tailscale.com/proxy-group":  pg.Name,
		})
		createAndCleanup(t, kubeClient, svc)
		waitForEgress(t, svc.Name, pgEgressReady)
		testEgressIsReachable(t, ns, svc.Name)
	})
}

// See [TestMain] for test requirements.
func TestHAEgressMultiTailnet(t *testing.T) {
	if tnClient == nil || secondTNClient == nil {
		t.Skip("TestHAEgressMultiTailnet requires a working tailnet client for a first and second tailnet")
	}
	t.Parallel()

	pg := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: generateName("egress"),
		},
		Spec: tsapi.ProxyGroupSpec{
			Type:    tsapi.ProxyGroupTypeEgress,
			Tailnet: "second-tailnet",
		},
	}
	createAndCleanup(t, kubeClient, pg)
	if err := verifyProxyGroupTailnet(t, pg, secondTNClient); err != nil {
		t.Fatalf("verifying ProxyGroup %s is registered to the correct tailnet: %v", pg.Name, err)
	}

	svc := egressService(generateName("test-egress"), map[string]string{
		"tailscale.com/tailnet-fqdn": secondTNTarget.fqdn,
		"tailscale.com/proxy-group":  pg.Name,
	})
	createAndCleanup(t, kubeClient, svc)
	waitForEgress(t, svc.Name, pgEgressReady)
	testEgressIsReachable(t, ns, svc.Name)
}

func egressService(name string, annotations map[string]string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   ns,
			Annotations: annotations,
		},
		Spec: corev1.ServiceSpec{
			ExternalName: "placeholder",
			Type:         corev1.ServiceTypeExternalName,
			Ports: []corev1.ServicePort{
				{
					Name:     "http",
					Protocol: corev1.ProtocolTCP,
					Port:     egressPort,
				},
			},
		},
	}
}

func pgEgressReady(svc *corev1.Service) bool {
	cond := kube.GetServiceCondition(svc, tsapi.EgressSvcReady)
	return cond != nil && cond.Status == metav1.ConditionTrue
}

func waitForEgress(t *testing.T, svcName string, ready func(*corev1.Service) bool) {
	t.Helper()
	if err := tstest.WaitFor(5*time.Minute, func() error {
		svc := &corev1.Service{ObjectMeta: objectMeta(ns, svcName)}
		if err := get(t.Context(), kubeClient, svc); err != nil {
			return err
		}
		if ready(svc) {
			t.Logf("Service %s is ready", svcName)
			return nil
		}
		return fmt.Errorf("Service %s is not ready yet", svcName)
	}); err != nil {
		t.Fatalf("error waiting for Service %s to become ready: %v", svcName, err)
	}
}

func testEgressIsReachable(t *testing.T, namespace, svcName string) {
	t.Helper()
	url := fmt.Sprintf("http://%s.%s.svc.cluster.local:%d", svcName, namespace, egressPort)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      generateName("curl"),
			Namespace: namespace,
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{
				{
					Name:  "curl",
					Image: "curlimages/curl",
					Command: []string{"sh", "-c", fmt.Sprintf(
						`for i in $(seq 1 10); do `+
							`code=$(curl -s -o /dev/null -w "%%{http_code}" --max-time 5 %q); `+
							`[ "$code" = "200" ] && exit 0; sleep 2; done; exit 1`, url)},
				},
			},
		},
	}
	createAndCleanup(t, kubeClient, pod)

	if err := tstest.WaitFor(2*time.Minute, func() error {
		p := &corev1.Pod{ObjectMeta: objectMeta(namespace, pod.Name)}
		if err := get(t.Context(), kubeClient, p); err != nil {
			return err
		}
		if p.Status.Phase == corev1.PodSucceeded {
			t.Logf("curl pod %s succeeded", pod.Name)
			return nil
		}
		return fmt.Errorf("curl pod %s phase: %s", pod.Name, p.Status.Phase)
	}); err != nil {
		t.Fatalf("egress service %s/%s not reachable: %v",
			namespace, svcName, err)
	}
}
