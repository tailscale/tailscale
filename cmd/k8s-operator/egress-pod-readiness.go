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
	"tailscale.com/logtail/backoff"
	"tailscale.com/tstime"
	"tailscale.com/util/httpm"
)

const tsEgressReadinessGate = "tailscale.com/egress-services"

// egressPodsReconciler is responsible for setting tailscale.com/egress-services condition on egress ProxyGroup Pods.
type egressPodsReconciler struct {
	client.Client
	logger      *zap.SugaredLogger
	tsNamespace string
	clock       tstime.Clock
	httpClient  doer
}

func (er *egressPodsReconciler) Reconcile(ctx context.Context, req reconcile.Request) (res reconcile.Result, err error) {
	l := er.logger.With("Pod", req.NamespacedName)
	l.Debugf("starting reconcile")
	defer l.Debugf("reconcile finished")

	pod := new(corev1.Pod)
	err = er.Get(ctx, req.NamespacedName, pod)
	if apierrors.IsNotFound(err) {
		l.Debugf("Pod not found")
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
		LabelManaged:    "true",
		labelProxyGroup: proxyGroupName,
		labelSvcType:    typeEgress,
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
	errChan := make(chan error)
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
			bo := backoff.NewBackoff(s.Name, ll.Infof, time.Second*2)
			for range numCalls(int(*pg.Spec.Replicas)) {
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
				select {
				case <-ctx.Done():
					errChan <- nil
					return
				default:
					continue
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

	l.Infof("Pod is ready to route traffic to all egress targets")
	pod.Status.Conditions = append(pod.Status.Conditions, corev1.PodCondition{
		Type:               tsEgressReadinessGate,
		Status:             corev1.ConditionTrue,
		LastTransitionTime: metav1.Time{Time: er.clock.Now()},
	})
	if err := er.Status().Update(ctx, pod); err != nil {
		return res, fmt.Errorf("error setting Pod's status conditions: %w", err)
	}
	return res, nil
}

// healthCheckState is the result of a single request to an egress Service health check endpoint with a goal to hit a
// specific backend Pod.
type healthCheckState int8

const (
	cannotVerify healthCheckState = iota // not verifiable for this setup (i.e earlier proxy version)
	unreachable                          // no backends or another network error
	notFound                             // hit another backend
	unhealthy                            // not 200
	podNotReady
	healthy // 200
)

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

// healthCheckForSvc return the URL of the containerboot's health check endpoint served by this Service or empty string.
func healthCheckForSvc(svc *corev1.Service, clusterDomain string) string {
	// This version of the operator always sets health check port on the egress Services. However, it is possible
	// that this reconcile loops runs during a proxy upgrade from a version that did not set the health check port
	// and parses a Service that does not have the port set yet.
	i := slices.IndexFunc(svc.Spec.Ports, func(port corev1.ServicePort) bool {
		return port.Name == tsHealthCheckPortName
	})
	if i == -1 {
		return ""
	}
	return fmt.Sprintf("http://%s.%s.svc.%s:%d/healthz", svc.Name, svc.Namespace, clusterDomain, svc.Spec.Ports[i].Port)
}

// numCalls return the number of times an endpoint on a ProxyGroup Service should be called till it can be safely
// assumed that, if none of the responses came back from a specific Pod then traffic for the Service is currently not
// being routed to that Pod. This assumes that traffic for the Service is routed via round robin, so
// InternalTrafficPolicy must be 'Cluster' and session affinity must be None.
func numCalls(replicas int) int {
	return replicas * 3
}

// doer is an interface for HTTP client that can be set to a mock client in tests.
type doer interface {
	Do(*http.Request) (*http.Response, error)
}
