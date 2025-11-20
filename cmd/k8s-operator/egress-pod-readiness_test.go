// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tstest"
	"tailscale.com/types/ptr"
)

func TestEgressPodReadiness(t *testing.T) {
	// We need to pass a Pod object to WithStatusSubresource because of some quirks in how the fake client
	// works. Without this code we would not be able to update Pod's status further down.
	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithStatusSubresource(&corev1.Pod{}).
		Build()
	zl, _ := zap.NewDevelopment()
	cl := tstest.NewClock(tstest.ClockOpts{})
	rec := &egressPodsReconciler{
		tsNamespace: "operator-ns",
		Client:      fc,
		logger:      zl.Sugar(),
		clock:       cl,
	}
	pg := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: "dev",
		},
		Spec: tsapi.ProxyGroupSpec{
			Type:     "egress",
			Replicas: ptr.To(int32(3)),
		},
	}
	mustCreate(t, fc, pg)
	podIP := "10.0.0.2"
	podTemplate := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "operator-ns",
			Name:      "pod",
			Labels: map[string]string{
				LabelParentType: "proxygroup",
				LabelParentName: "dev",
			},
		},
		Spec: corev1.PodSpec{
			ReadinessGates: []corev1.PodReadinessGate{{
				ConditionType: tsEgressReadinessGate,
			}},
			Containers: []corev1.Container{{
				Name: "tailscale",
				Env: []corev1.EnvVar{{
					Name:  "TS_ENABLE_HEALTH_CHECK",
					Value: "true",
				}},
			}},
		},
		Status: corev1.PodStatus{
			PodIPs: []corev1.PodIP{{IP: podIP}},
		},
	}

	t.Run("no_egress_services", func(t *testing.T) {
		pod := podTemplate.DeepCopy()
		mustCreate(t, fc, pod)
		expectReconciled(t, rec, "operator-ns", pod.Name)

		// Pod should have readiness gate condition set.
		podSetReady(pod, cl)
		expectEqual(t, fc, pod)
		mustDeleteAll(t, fc, pod)
	})
	t.Run("one_svc_already_routed_to", func(t *testing.T) {
		pod := podTemplate.DeepCopy()

		svc, hep := newSvc("svc", 9002)
		mustCreateAll(t, fc, svc, pod)
		resp := readyResps(podIP, 1)
		httpCl := fakeHTTPClient{
			t:     t,
			state: map[string][]fakeResponse{hep: resp},
		}
		rec.httpClient = &httpCl
		expectReconciled(t, rec, "operator-ns", pod.Name)

		// Pod should have readiness gate condition set.
		podSetReady(pod, cl)
		expectEqual(t, fc, pod)

		// A subsequent reconcile should not change the Pod.
		expectReconciled(t, rec, "operator-ns", pod.Name)
		expectEqual(t, fc, pod)

		mustDeleteAll(t, fc, pod, svc)
	})
	t.Run("one_svc_many_backends_eventually_routed_to", func(t *testing.T) {
		pod := podTemplate.DeepCopy()

		svc, hep := newSvc("svc", 9002)
		mustCreateAll(t, fc, svc, pod)
		// For a 3 replica ProxyGroup the healthcheck endpoint should be called 9 times, make the 9th time only
		// return with the right Pod IP.
		resps := append(readyResps("10.0.0.3", 4), append(readyResps("10.0.0.4", 4), readyResps(podIP, 1)...)...)
		httpCl := fakeHTTPClient{
			t:     t,
			state: map[string][]fakeResponse{hep: resps},
		}
		rec.httpClient = &httpCl
		expectReconciled(t, rec, "operator-ns", pod.Name)

		// Pod should have readiness gate condition set.
		podSetReady(pod, cl)
		expectEqual(t, fc, pod)
		mustDeleteAll(t, fc, pod, svc)
	})
	t.Run("one_svc_one_backend_eventually_healthy", func(t *testing.T) {
		pod := podTemplate.DeepCopy()

		svc, hep := newSvc("svc", 9002)
		mustCreateAll(t, fc, svc, pod)
		// For a 3 replica ProxyGroup the healthcheck endpoint should be called 9 times, make the 9th time only
		// return with 200 status code.
		resps := append(unreadyResps(podIP, 8), readyResps(podIP, 1)...)
		httpCl := fakeHTTPClient{
			t:     t,
			state: map[string][]fakeResponse{hep: resps},
		}
		rec.httpClient = &httpCl
		expectReconciled(t, rec, "operator-ns", pod.Name)

		// Pod should have readiness gate condition set.
		podSetReady(pod, cl)
		expectEqual(t, fc, pod)
		mustDeleteAll(t, fc, pod, svc)
	})
	t.Run("one_svc_one_backend_never_routable", func(t *testing.T) {
		pod := podTemplate.DeepCopy()

		svc, hep := newSvc("svc", 9002)
		mustCreateAll(t, fc, svc, pod)
		// For a 3 replica ProxyGroup the healthcheck endpoint should be called 9 times and Pod should be
		// requeued if neither of those succeed.
		resps := readyResps("10.0.0.3", 9)
		httpCl := fakeHTTPClient{
			t:     t,
			state: map[string][]fakeResponse{hep: resps},
		}
		rec.httpClient = &httpCl
		expectRequeue(t, rec, "operator-ns", pod.Name)

		// Pod should not have readiness gate condition set.
		expectEqual(t, fc, pod)
		mustDeleteAll(t, fc, pod, svc)
	})
	t.Run("one_svc_many_backends_already_routable", func(t *testing.T) {
		pod := podTemplate.DeepCopy()

		svc, hep := newSvc("svc", 9002)
		svc2, hep2 := newSvc("svc-2", 9002)
		svc3, hep3 := newSvc("svc-3", 9002)
		mustCreateAll(t, fc, svc, svc2, svc3, pod)
		resps := readyResps(podIP, 1)
		httpCl := fakeHTTPClient{
			t: t,
			state: map[string][]fakeResponse{
				hep:  resps,
				hep2: resps,
				hep3: resps,
			},
		}
		rec.httpClient = &httpCl
		expectReconciled(t, rec, "operator-ns", pod.Name)

		// Pod should not have readiness gate condition set.
		podSetReady(pod, cl)
		expectEqual(t, fc, pod)
		mustDeleteAll(t, fc, pod, svc, svc2, svc3)
	})
	t.Run("one_svc_many_backends_eventually_routable_and_healthy", func(t *testing.T) {
		pod := podTemplate.DeepCopy()
		svc, hep := newSvc("svc", 9002)
		svc2, hep2 := newSvc("svc-2", 9002)
		svc3, hep3 := newSvc("svc-3", 9002)
		mustCreateAll(t, fc, svc, svc2, svc3, pod)
		resps := append(readyResps("10.0.0.3", 7), readyResps(podIP, 1)...)
		resps2 := append(readyResps("10.0.0.3", 5), readyResps(podIP, 1)...)
		resps3 := append(unreadyResps(podIP, 4), readyResps(podIP, 1)...)
		httpCl := fakeHTTPClient{
			t: t,
			state: map[string][]fakeResponse{
				hep:  resps,
				hep2: resps2,
				hep3: resps3,
			},
		}
		rec.httpClient = &httpCl
		expectReconciled(t, rec, "operator-ns", pod.Name)

		// Pod should have readiness gate condition set.
		podSetReady(pod, cl)
		expectEqual(t, fc, pod)
		mustDeleteAll(t, fc, pod, svc, svc2, svc3)
	})
	t.Run("one_svc_many_backends_never_routable_and_healthy", func(t *testing.T) {
		pod := podTemplate.DeepCopy()

		svc, hep := newSvc("svc", 9002)
		svc2, hep2 := newSvc("svc-2", 9002)
		svc3, hep3 := newSvc("svc-3", 9002)
		mustCreateAll(t, fc, svc, svc2, svc3, pod)
		// For a ProxyGroup with 3 replicas, each Service's health endpoint will be tried 9 times and the Pod
		// will be requeued if neither succeeds.
		resps := readyResps("10.0.0.3", 9)
		resps2 := append(readyResps("10.0.0.3", 5), readyResps("10.0.0.4", 4)...)
		resps3 := unreadyResps(podIP, 9)
		httpCl := fakeHTTPClient{
			t: t,
			state: map[string][]fakeResponse{
				hep:  resps,
				hep2: resps2,
				hep3: resps3,
			},
		}
		rec.httpClient = &httpCl
		expectRequeue(t, rec, "operator-ns", pod.Name)

		// Pod should not have readiness gate condition set.
		expectEqual(t, fc, pod)
		mustDeleteAll(t, fc, pod, svc, svc2, svc3)
	})
	t.Run("one_svc_many_backends_one_never_routable", func(t *testing.T) {
		pod := podTemplate.DeepCopy()

		svc, hep := newSvc("svc", 9002)
		svc2, hep2 := newSvc("svc-2", 9002)
		svc3, hep3 := newSvc("svc-3", 9002)
		mustCreateAll(t, fc, svc, svc2, svc3, pod)
		// For a ProxyGroup with 3 replicas, each Service's health endpoint will be tried 9 times and the Pod
		// will be requeued if any one never succeeds.
		resps := readyResps(podIP, 9)
		resps2 := readyResps(podIP, 9)
		resps3 := append(readyResps("10.0.0.3", 5), readyResps("10.0.0.4", 4)...)
		httpCl := fakeHTTPClient{
			t: t,
			state: map[string][]fakeResponse{
				hep:  resps,
				hep2: resps2,
				hep3: resps3,
			},
		}
		rec.httpClient = &httpCl
		expectRequeue(t, rec, "operator-ns", pod.Name)

		// Pod should not have readiness gate condition set.
		expectEqual(t, fc, pod)
		mustDeleteAll(t, fc, pod, svc, svc2, svc3)
	})
	t.Run("one_svc_many_backends_one_never_healthy", func(t *testing.T) {
		pod := podTemplate.DeepCopy()

		svc, hep := newSvc("svc", 9002)
		svc2, hep2 := newSvc("svc-2", 9002)
		svc3, hep3 := newSvc("svc-3", 9002)
		mustCreateAll(t, fc, svc, svc2, svc3, pod)
		// For a ProxyGroup with 3 replicas, each Service's health endpoint will be tried 9 times and the Pod
		// will be requeued if any one never succeeds.
		resps := readyResps(podIP, 9)
		resps2 := unreadyResps(podIP, 9)
		resps3 := readyResps(podIP, 9)
		httpCl := fakeHTTPClient{
			t: t,
			state: map[string][]fakeResponse{
				hep:  resps,
				hep2: resps2,
				hep3: resps3,
			},
		}
		rec.httpClient = &httpCl
		expectRequeue(t, rec, "operator-ns", pod.Name)

		// Pod should not have readiness gate condition set.
		expectEqual(t, fc, pod)
		mustDeleteAll(t, fc, pod, svc, svc2, svc3)
	})
	t.Run("one_svc_many_backends_different_ports_eventually_healthy_and_routable", func(t *testing.T) {
		pod := podTemplate.DeepCopy()

		svc, hep := newSvc("svc", 9003)
		svc2, hep2 := newSvc("svc-2", 9004)
		svc3, hep3 := newSvc("svc-3", 9010)
		mustCreateAll(t, fc, svc, svc2, svc3, pod)
		// For a ProxyGroup with 3 replicas, each Service's health endpoint will be tried up to 9 times and
		// marked as success as soon as one try succeeds.
		resps := append(readyResps("10.0.0.3", 7), readyResps(podIP, 1)...)
		resps2 := append(readyResps("10.0.0.3", 5), readyResps(podIP, 1)...)
		resps3 := append(unreadyResps(podIP, 4), readyResps(podIP, 1)...)
		httpCl := fakeHTTPClient{
			t: t,
			state: map[string][]fakeResponse{
				hep:  resps,
				hep2: resps2,
				hep3: resps3,
			},
		}
		rec.httpClient = &httpCl
		expectReconciled(t, rec, "operator-ns", pod.Name)

		// Pod should have readiness gate condition set.
		podSetReady(pod, cl)
		expectEqual(t, fc, pod)
		mustDeleteAll(t, fc, pod, svc, svc2, svc3)
	})
	// Proxies of 1.78 and earlier did not set the Pod IP header.
	t.Run("pod_does_not_return_ip_header", func(t *testing.T) {
		pod := podTemplate.DeepCopy()
		pod.Name = "foo-bar"

		svc, hep := newSvc("foo-bar", 9002)
		mustCreateAll(t, fc, svc, pod)
		// If a response does not contain Pod IP header, we assume that this is an earlier proxy version,
		// readiness cannot be verified so the readiness gate is just set to true.
		resps := unreadyResps("", 1)
		httpCl := fakeHTTPClient{
			t: t,
			state: map[string][]fakeResponse{
				hep: resps,
			},
		}
		rec.httpClient = &httpCl
		expectReconciled(t, rec, "operator-ns", pod.Name)

		// Pod should have readiness gate condition set.
		podSetReady(pod, cl)
		expectEqual(t, fc, pod)
		mustDeleteAll(t, fc, pod, svc)
	})
	t.Run("one_svc_one_backend_eventually_healthy_and_routable", func(t *testing.T) {
		pod := podTemplate.DeepCopy()

		svc, hep := newSvc("svc", 9002)
		mustCreateAll(t, fc, svc, pod)
		// If a response errors, it is probably because the Pod is not yet properly running, so retry.
		resps := append(erroredResps(8), readyResps(podIP, 1)...)
		httpCl := fakeHTTPClient{
			t: t,
			state: map[string][]fakeResponse{
				hep: resps,
			},
		}
		rec.httpClient = &httpCl
		expectReconciled(t, rec, "operator-ns", pod.Name)

		// Pod should have readiness gate condition set.
		podSetReady(pod, cl)
		expectEqual(t, fc, pod)
		mustDeleteAll(t, fc, pod, svc)
	})
	t.Run("one_svc_one_backend_svc_does_not_have_health_port", func(t *testing.T) {
		pod := podTemplate.DeepCopy()

		// If a Service does not have health port set, we assume that it is not possible to determine Pod's
		// readiness and set it to ready.
		svc, _ := newSvc("svc", -1)
		mustCreateAll(t, fc, svc, pod)
		rec.httpClient = nil
		expectReconciled(t, rec, "operator-ns", pod.Name)

		// Pod should have readiness gate condition set.
		podSetReady(pod, cl)
		expectEqual(t, fc, pod)
		mustDeleteAll(t, fc, pod, svc)
	})
	t.Run("error_setting_up_healthcheck", func(t *testing.T) {
		pod := podTemplate.DeepCopy()
		// This is not a realistic reason for error, but we are just testing the behaviour of a healthcheck
		// lookup failing.
		pod.Status.PodIPs = []corev1.PodIP{{IP: "not-an-ip"}}

		svc, _ := newSvc("svc", 9002)
		svc2, _ := newSvc("svc-2", 9002)
		svc3, _ := newSvc("svc-3", 9002)
		mustCreateAll(t, fc, svc, svc2, svc3, pod)
		rec.httpClient = nil
		expectError(t, rec, "operator-ns", pod.Name)

		// Pod should not have readiness gate condition set.
		expectEqual(t, fc, pod)
		mustDeleteAll(t, fc, pod, svc, svc2, svc3)
	})
	t.Run("pod_does_not_have_an_ip_address", func(t *testing.T) {
		pod := podTemplate.DeepCopy()
		pod.Status.PodIPs = nil

		svc, _ := newSvc("svc", 9002)
		svc2, _ := newSvc("svc-2", 9002)
		svc3, _ := newSvc("svc-3", 9002)
		mustCreateAll(t, fc, svc, svc2, svc3, pod)
		rec.httpClient = nil
		expectRequeue(t, rec, "operator-ns", pod.Name)

		// Pod should not have readiness gate condition set.
		expectEqual(t, fc, pod)
		mustDeleteAll(t, fc, pod, svc, svc2, svc3)
	})
}

func readyResps(ip string, num int) (resps []fakeResponse) {
	for range num {
		resps = append(resps, fakeResponse{statusCode: 200, podIP: ip})
	}
	return resps
}

func unreadyResps(ip string, num int) (resps []fakeResponse) {
	for range num {
		resps = append(resps, fakeResponse{statusCode: 503, podIP: ip})
	}
	return resps
}

func erroredResps(num int) (resps []fakeResponse) {
	for range num {
		resps = append(resps, fakeResponse{err: errors.New("timeout")})
	}
	return resps
}

func newSvc(name string, port int32) (*corev1.Service, string) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "operator-ns",
			Name:      name,
			Labels: map[string]string{
				kubetypes.LabelManaged: "true",
				labelProxyGroup:        "dev",
				labelSvcType:           typeEgress,
			},
		},
		Spec: corev1.ServiceSpec{},
	}
	if port != -1 {
		svc.Spec.Ports = []corev1.ServicePort{
			{
				Name:       tsHealthCheckPortName,
				Port:       port,
				TargetPort: intstr.FromInt(9002),
				Protocol:   "TCP",
			},
		}
	}
	return svc, fmt.Sprintf("http://%s.operator-ns.svc.cluster.local:%d/healthz", name, port)
}

func podSetReady(pod *corev1.Pod, cl *tstest.Clock) {
	pod.Status.Conditions = append(pod.Status.Conditions, corev1.PodCondition{
		Type:               tsEgressReadinessGate,
		Status:             corev1.ConditionTrue,
		LastTransitionTime: metav1.Time{Time: cl.Now().Truncate(time.Second)},
	})
}

// fakeHTTPClient is a mock HTTP client with a preset map of request URLs to list of responses. When it receives a
// request for a specific URL, it returns the preset response for that URL. It errors if an unexpected request is
// received.
type fakeHTTPClient struct {
	t     *testing.T
	mu    sync.Mutex // protects following
	state map[string][]fakeResponse
}

func (f *fakeHTTPClient) Do(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	resps := f.state[req.URL.String()]
	if len(resps) == 0 {
		f.mu.Unlock()
		log.Printf("\n\n\nURL %q\n\n\n", req.URL)
		f.t.Fatalf("fakeHTTPClient received an unexpected request for %q", req.URL)
	}
	defer func() {
		if len(resps) == 1 {
			delete(f.state, req.URL.String())
			f.mu.Unlock()
			return
		}
		f.state[req.URL.String()] = f.state[req.URL.String()][1:]
		f.mu.Unlock()
	}()

	resp := resps[0]
	if resp.err != nil {
		return nil, resp.err
	}
	r := http.Response{
		StatusCode: resp.statusCode,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader([]byte{})),
	}
	r.Header.Add(kubetypes.PodIPv4Header, resp.podIP)
	return &r, nil
}

type fakeResponse struct {
	err        error
	statusCode int
	podIP      string // for the Pod IP header
}
