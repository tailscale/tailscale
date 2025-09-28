// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	xslices "golang.org/x/exp/slices"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tstime"
	"tailscale.com/util/backoff"
	"tailscale.com/util/httpm"
)

const tsEgressReadinessGate = "tailscale.com/egress-services"

// egressPodsReconciler is responsible for setting tailscale.com/egress-services condition on egress ProxyGroup Pods.
// The condition is used as a readiness gate for the Pod, meaning that kubelet will not mark the Pod as ready before the
// condition is set. The ProxyGroup StatefulSet updates are rolled out in such a way that no Pod is restarted, before
// the previous Pod is marked as ready, so ensuring that the Pod does not get marked as ready when it is not yet able to
// route traffic for egress service prevents downtime during restarts caused by no available endpoints left because
// every Pod has been recreated and is not yet added to endpoints.
// https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#pod-readiness-gate
type egressPodsReconciler struct {
	client.Client
	logger      *zap.SugaredLogger
	tsNamespace string
	clock       tstime.Clock
	httpClient  doer          // http client that can be set to a mock client in tests
	maxBackoff  time.Duration // max backoff period between health check calls
}

// Reconcile reconciles an egress ProxyGroup Pods on changes to those Pods and ProxyGroup EndpointSlices. It ensures
// that for each Pod who is ready to route traffic to all egress services for the ProxyGroup, the Pod has a
// tailscale.com/egress-services condition to set, so that kubelet will mark the Pod as ready.
//
// For the Pod to be ready
// to route traffic to the egress service, the kube proxy needs to have set up the Pod's IP as an endpoint for the
// ClusterIP Service corresponding to the egress service.
//
// Note that the endpoints for the ClusterIP Service are configured by the operator itself using custom
// EndpointSlices(egress-eps-reconciler), so the routing is not blocked on Pod's readiness.
//
// Each egress service has a corresponding ClusterIP Service, that exposes all user configured
// tailnet ports, as well as a health check port for the proxy.
//
// The reconciler calls the health check endpoint of each Service up to N number of times, where N is the number of
// replicas for the ProxyGroup x 3, and checks if the received response is healthy response from the Pod being reconciled.
//
// The health check response contains a header with the
// Pod's IP address- this is used to determine whether the response is received from this Pod.
//
// If the Pod does not appear to be serving the health check endpoint (pre-v1.80 proxies), the reconciler just sets the
// readiness condition for backwards compatibility reasons.
func (er *egressPodsReconciler) Reconcile(ctx context.Context, req reconcile.Request) (res reconcile.Result, err error) {
	l := er.logger.With("Pod", req.NamespacedName)
	l.Debugf("starting reconcile")
	defer l.Debugf("reconcile finished")

	pod := new(corev1.Pod)
	err = er.Get(ctx, req.NamespacedName, pod)
	if apierrors.IsNotFound(err) {
		return reconcile.Result{}, nil
	}
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get Pod: %w", err)
	}
	if !pod.DeletionTimestamp.IsZero() {
		l.Debugf("Pod is being deleted, do nothing")
		return res, nil
	}
	if pod.Labels[LabelParentType] != proxyTypeProxyGroup {
		l.Infof("[unexpected] reconciler called for a Pod that is not a ProxyGroup Pod")
		return res, nil
	}

	// If the Pod does not have the readiness gate set, there is no need to add the readiness condition. In practice
	// this will happen if the user has configured custom TS_LOCAL_ADDR_PORT, thus disabling the graceful failover.
	if !slices.ContainsFunc(pod.Spec.ReadinessGates, func(r corev1.PodReadinessGate) bool {
		return r.ConditionType == tsEgressReadinessGate
	}) {
		l.Debug("Pod does not have egress readiness gate set, skipping")
		return res, nil
	}

	proxyGroupName := pod.Labels[LabelParentName]
	pg := new(tsapi.ProxyGroup)
	if err := er.Get(ctx, types.NamespacedName{Name: proxyGroupName}, pg); err != nil {
		return res, fmt.Errorf("error getting ProxyGroup %q: %w", proxyGroupName, err)
	}
	if pg.Spec.Type != typeEgress {
		l.Infof("[unexpected] reconciler called for %q ProxyGroup Pod", pg.Spec.Type)
		return res, nil
	}
	// Get all ClusterIP Services for all egress targets exposed to cluster via this ProxyGroup.
	lbls := map[string]string{
		kubetypes.LabelManaged: "true",
		labelProxyGroup:        proxyGroupName,
		labelSvcType:           typeEgress,
	}
	svcs := &corev1.ServiceList{}
	if err := er.List(ctx, svcs, client.InNamespace(er.tsNamespace), client.MatchingLabels(lbls)); err != nil {
		return res, fmt.Errorf("error listing ClusterIP Services")
	}

	idx := xslices.IndexFunc(pod.Status.Conditions, func(c corev1.PodCondition) bool {
		return c.Type == tsEgressReadinessGate
	})
	if idx != -1 {
		l.Debugf("Pod is already ready, do nothing")
		return res, nil
	}

	var routesMissing atomic.Bool
	errChan := make(chan error, len(svcs.Items))
	for _, svc := range svcs.Items {
		s := svc
		go func() {
			ll := l.With("service_name", s.Name)
			d := retrieveClusterDomain(er.tsNamespace, ll)
			healthCheckAddr := healthCheckForSvc(&s, d)
			if healthCheckAddr == "" {
				ll.Debugf("ClusterIP Service does not expose a health check endpoint, unable to verify if routing is set up")
				errChan <- nil
				return
			}

			var routesSetup bool
			bo := backoff.NewBackoff(s.Name, ll.Infof, er.maxBackoff)
			for range numCalls(pgReplicas(pg)) {
				if ctx.Err() != nil {
					errChan <- nil
					return
				}
				state, err := er.lookupPodRouteViaSvc(ctx, pod, healthCheckAddr, ll)
				if err != nil {
					errChan <- fmt.Errorf("error validating if routing has been set up for Pod: %w", err)
					return
				}
				if state == healthy || state == cannotVerify {
					routesSetup = true
					break
				}
				if state == unreachable || state == unhealthy || state == podNotReady {
					bo.BackOff(ctx, errors.New("backoff"))
				}
			}
			if !routesSetup {
				ll.Debugf("Pod is not yet configured as Service endpoint")
				routesMissing.Store(true)
			}
			errChan <- nil
		}()
	}
	for range len(svcs.Items) {
		e := <-errChan
		err = errors.Join(err, e)
	}
	if err != nil {
		return res, fmt.Errorf("error verifying conectivity: %w", err)
	}
	if rm := routesMissing.Load(); rm {
		l.Info("Pod is not yet added as an endpoint for all egress targets, waiting...")
		return reconcile.Result{RequeueAfter: shortRequeue}, nil
	}
	if err := er.setPodReady(ctx, pod, l); err != nil {
		return res, fmt.Errorf("error setting Pod as ready: %w", err)
	}
	return res, nil
}

func (er *egressPodsReconciler) setPodReady(ctx context.Context, pod *corev1.Pod, l *zap.SugaredLogger) error {
	if slices.ContainsFunc(pod.Status.Conditions, func(c corev1.PodCondition) bool {
		return c.Type == tsEgressReadinessGate
	}) {
		return nil
	}
	l.Infof("Pod is ready to route traffic to all egress targets")
	pod.Status.Conditions = append(pod.Status.Conditions, corev1.PodCondition{
		Type:               tsEgressReadinessGate,
		Status:             corev1.ConditionTrue,
		LastTransitionTime: metav1.Time{Time: er.clock.Now()},
	})
	return er.Status().Update(ctx, pod)
}

// healthCheckState is the result of a single request to an egress Service health check endpoint with a goal to hit a
// specific backend Pod.
type healthCheckState int8

const (
	cannotVerify healthCheckState = iota // not verifiable for this setup (i.e earlier proxy version)
	unreachable                          // no backends or another network error
	notFound                             // hit another backend
	unhealthy                            // not 200
	podNotReady                          // Pod is not ready, i.e does not have an IP address yet
	healthy                              // 200
)

// lookupPodRouteViaSvc attempts to reach a Pod using a health check endpoint served by a Service and returns the state of the health check.
func (er *egressPodsReconciler) lookupPodRouteViaSvc(ctx context.Context, pod *corev1.Pod, healthCheckAddr string, l *zap.SugaredLogger) (healthCheckState, error) {
	if !slices.ContainsFunc(pod.Spec.Containers[0].Env, func(e corev1.EnvVar) bool {
		return e.Name == "TS_ENABLE_HEALTH_CHECK" && e.Value == "true"
	}) {
		l.Debugf("Pod does not have health check enabled, unable to verify if it is currently routable via Service")
		return cannotVerify, nil
	}
	wantsIP, err := podIPv4(pod)
	if err != nil {
		return -1, fmt.Errorf("error determining Pod's IP address: %w", err)
	}
	if wantsIP == "" {
		return podNotReady, nil
	}

	ctx, cancel := context.WithTimeout(ctx, time.Second*3)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, httpm.GET, healthCheckAddr, nil)
	if err != nil {
		return -1, fmt.Errorf("error creating new HTTP request: %w", err)
	}
	// Do not re-use the same connection for the next request so to maximize the chance of hitting all backends equally.
	req.Close = true
	resp, err := er.httpClient.Do(req)
	if err != nil {
		// This is most likely because this is the first Pod and is not yet added to Service endoints. Other
		// error types are possible, but checking for those would likely make the system too fragile.
		return unreachable, nil
	}
	defer resp.Body.Close()
	gotIP := resp.Header.Get(kubetypes.PodIPv4Header)
	if gotIP == "" {
		l.Debugf("Health check does not return Pod's IP header, unable to verify if Pod is currently routable via Service")
		return cannotVerify, nil
	}
	if !strings.EqualFold(wantsIP, gotIP) {
		return notFound, nil
	}
	if resp.StatusCode != http.StatusOK {
		return unhealthy, nil
	}
	return healthy, nil
}

// numCalls return the number of times an endpoint on a ProxyGroup Service should be called till it can be safely
// assumed that, if none of the responses came back from a specific Pod then traffic for the Service is currently not
// being routed to that Pod. This assumes that traffic for the Service is routed via round robin, so
// InternalTrafficPolicy must be 'Cluster' and session affinity must be None.
func numCalls(replicas int32) int32 {
	return replicas * 3
}

// doer is an interface for HTTP client that can be set to a mock client in tests.
type doer interface {
	Do(*http.Request) (*http.Response, error)
}
