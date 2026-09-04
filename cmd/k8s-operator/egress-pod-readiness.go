// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
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

type egressPodsReconciler struct {
	client.Client
	logger      *zap.SugaredLogger
	tsNamespace string
	clock       tstime.Clock
	httpClient  doer
	maxBackoff  time.Duration
}

func (er *egressPodsReconciler) Reconcile(ctx context.Context, req reconcile.Request) (res reconcile.Result, err error) {
	lg := er.logger.With("Pod", req.NamespacedName)
	lg.Debugf("starting reconcile")
	defer lg.Debugf("reconcile finished")

	pod := new(corev1.Pod)
	err = er.Get(ctx, req.NamespacedName, pod)
	if apierrors.IsNotFound(err) {
		return reconcile.Result{}, nil
	}
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get Pod: %w", err)
	}
	if !pod.DeletionTimestamp.IsZero() {
		lg.Debugf("Pod is being deleted, do nothing")
		return res, nil
	}

	if pod.Labels[LabelParentType] != proxyTypeProxyGroup {
		lg.Warn("reconciler called for a Pod that is not a ProxyGroup Pod")
		return res, nil
	}

	if !slices.ContainsFunc(pod.Spec.ReadinessGates, func(r corev1.PodReadinessGate) bool {
		return r.ConditionType == tsEgressReadinessGate
	}) {
		lg.Debug("Pod does not have egress readiness gate set, skipping")
		return res, nil
	}

	proxyGroupName := pod.Labels[LabelParentName]
	pg := new(tsapi.ProxyGroup)
	if err := er.Get(ctx, types.NamespacedName{Name: proxyGroupName}, pg); err != nil {
		return res, fmt.Errorf("error getting ProxyGroup %q: %w", proxyGroupName, err)
	}

	if pg.Spec.Type != typeEgress {
		lg.Warnf("reconciler called for %q ProxyGroup Pod", pg.Spec.Type)
		return res, nil
	}

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
		lg.Debugf("Pod is already ready, do nothing")
		return res, nil
	}

	var routesMissing atomic.Bool
	errChan := make(chan error, len(svcs.Items))
	for _, svc := range svcs.Items {
		s := svc
		go func() {
			ll := lg.With("service_name", s.Name)
			d := retrieveClusterDomain(er.tsNamespace, ll)
			targets := healthCheckTargetsForReadiness(&s, d)
			if len(targets) == 0 {
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

				allFamiliesHealthy := true
				for _, target := range targets {
					state, err := er.lookupPodRouteViaSvc(ctx, pod, target.addr, target.podIP, ll)
					if err != nil {
						errChan <- fmt.Errorf("error validating if routing has been set up for Pod: %w", err)
						return
					}
					if state == cannotVerify {
						routesSetup = true
						allFamiliesHealthy = true
						break
					}
					if state != healthy {
						allFamiliesHealthy = false
						break
					}
				}
				if allFamiliesHealthy {
					routesSetup = true
					break
				}
				bo.BackOff(ctx, errors.New("backoff"))
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
		return res, fmt.Errorf("error verifying connectivity: %w", err)
	}
	if rm := routesMissing.Load(); rm {
		lg.Info("Pod is not yet added as an endpoint for all egress targets, waiting...")
		return reconcile.Result{RequeueAfter: shortRequeue}, nil
	}
	if err := er.setPodReady(ctx, pod, lg); err != nil {
		return res, fmt.Errorf("error setting Pod as ready: %w", err)
	}
	return res, nil
}

func (er *egressPodsReconciler) setPodReady(ctx context.Context, pod *corev1.Pod, lg *zap.SugaredLogger) error {
	if slices.ContainsFunc(pod.Status.Conditions, func(c corev1.PodCondition) bool {
		return c.Type == tsEgressReadinessGate
	}) {
		return nil
	}
	lg.Infof("Pod is ready to route traffic to all egress targets")
	pod.Status.Conditions = append(pod.Status.Conditions, corev1.PodCondition{
		Type:               tsEgressReadinessGate,
		Status:             corev1.ConditionTrue,
		LastTransitionTime: metav1.Time{Time: er.clock.Now()},
	})
	return er.Status().Update(ctx, pod)
}

type healthCheckState int8

const (
	cannotVerify healthCheckState = iota
	unreachable
	notFound
	unhealthy
	podNotReady
	healthy
)

type healthCheckTarget struct {
	addr  string
	podIP string
}

// healthCheckTargetsForReadiness returns one health-check target per Service
// ClusterIP. Targeting ClusterIPs directly pins the request to an address
// family, which is necessary for dual-stack Services: DNS does not guarantee
// which family the HTTP client will select.
func healthCheckTargetsForReadiness(svc *corev1.Service, clusterDomain string) []healthCheckTarget {
	i := slices.IndexFunc(svc.Spec.Ports, func(port corev1.ServicePort) bool {
		return port.Name == tsHealthCheckPortName
	})
	if i == -1 {
		return nil
	}

	port := uint16(svc.Spec.Ports[i].Port)
	targets := make([]healthCheckTarget, 0, len(svc.Spec.ClusterIPs))
	for _, clusterIP := range svc.Spec.ClusterIPs {
		ip, err := netip.ParseAddr(clusterIP)
		if err != nil {
			continue
		}
		targets = append(targets, healthCheckTarget{
			addr:  fmt.Sprintf("http://%s/healthz", netip.AddrPortFrom(ip, port)),
			podIP: "",
		})
	}

	if len(targets) == 0 {
		// During an upgrade there can briefly be a Service object without
		// ClusterIPs. Keep the existing DNS behavior as a compatibility fallback.
		if clusterDomain == "" {
			return nil
		}
		return []healthCheckTarget{{
			addr:  healthCheckForSvc(svc, clusterDomain),
			podIP: "",
		}}
	}
	return targets
}

func podIPForHealthCheckFamily(pod *corev1.Pod, targetAddr string) (string, bool) {
	host, _, err := netip.ParseAddrPort(strings.TrimPrefix(strings.TrimSuffix(targetAddr, "/healthz"), "http://"))
	if err != nil {
		return "", false
	}
	for _, podIP := range pod.Status.PodIPs {
		ip, err := netip.ParseAddr(podIP.IP)
		if err == nil && ip.Is6() == host.Is6() {
			return podIP.IP, true
		}
	}
	return "", false
}

func (er *egressPodsReconciler) lookupPodRouteViaSvc(ctx context.Context, pod *corev1.Pod, healthCheckAddr, wantsIP string, lg *zap.SugaredLogger) (healthCheckState, error) {
	if !slices.ContainsFunc(pod.Spec.Containers[0].Env, func(e corev1.EnvVar) bool {
		return e.Name == "TS_ENABLE_HEALTH_CHECK" && e.Value == "true"
	}) {
		lg.Debugf("Pod does not have health check enabled, unable to verify if it is currently routable via Service")
		return cannotVerify, nil
	}

	if wantsIP == "" {
		var ok bool
		wantsIP, ok = podIPForHealthCheckFamily(pod, healthCheckAddr)
		if !ok {
			return podNotReady, nil
		}
	}
	parsed, err := netip.ParseAddr(wantsIP)
	if err != nil {
		return -1, fmt.Errorf("error parsing Pod IP %q: %w", wantsIP, err)
	}
	header := kubetypes.PodIPv4Header
	if parsed.Is6() {
		header = kubetypes.PodIPv6Header
	}

	ctx, cancel := context.WithTimeout(ctx, time.Second*3)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, httpm.GET, healthCheckAddr, nil)
	if err != nil {
		return -1, fmt.Errorf("error creating new HTTP request: %w", err)
	}
	req.Close = true
	resp, err := er.httpClient.Do(req)
	if err != nil {
		return unreachable, nil
	}
	defer resp.Body.Close()
	gotIP := resp.Header.Get(header)
	if gotIP == "" {
		lg.Debugf("Health check does not return Pod's IP header, unable to verify if Pod is currently routable via Service")
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

func numCalls(replicas int32) int32 {
	return replicas * 3
}

type doer interface {
	Do(*http.Request) (*http.Response, error)
}
