//go:build !plan9

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// reconciles egress proxy state secret.
type EgressSvcConfigReconciler struct {
	client.Client
	logger *zap.SugaredLogger
}

// For this prototype only (make it determine what has change more intelligently later):
// on any state Secret change:
//   - read the service status hints
//   - for each status hint:
//   - get all Pods for that Service
//   - get EndpointSlice for that Service
//   - if the status hint suggests that this proxy routes from fwegress Pods to backend, ensure endpoint addresses contain it
//   - apply any changes to EndpointSlice
//   - TODO: add finalizer to the proxy Secret to ensure cleanup when proxy deleted
func (er *EgressSvcConfigReconciler) Reconcile(ctx context.Context, req reconcile.Request) (res reconcile.Result, err error) {
	logger := er.logger.With("secret-ns", req.Namespace, "secret-name", req.Name)
	logger.Debugf("starting reconcile")
	defer logger.Debugf("reconcile finished")

	// request should be for a state Secret
	s := new(corev1.Secret)
	err = er.Get(ctx, req.NamespacedName, s)
	if apierrors.IsNotFound(err) {
		// Request object not found, could have been deleted after reconcile request.
		logger.Debugf("service not found, assuming it was deleted")
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get Secret: %w", err)
	}
	if !s.DeletionTimestamp.IsZero() {
		logger.Debugf("Secret is being deleted")
		return
	}

	// For now - we reconcile all Secrets in tailscale namespace and ignore those without statusHint
	// get status hint
	if _, ok := s.Data["statusHint"]; !ok {
		logger.Debugf("secret does not have a statusHint field, ignore %+#v", s.Data)
		return
	}

	statusHint := make(map[string][]string)
	if err := json.Unmarshal(s.Data["statusHint"], &statusHint); err != nil {
		return res, fmt.Errorf("error unmarshalling status hint: %w\n status hint is %q", err, s.Data["statusHint"])
	}
	if len(statusHint) == 0 {
		logger.Debugf("no status hint")
		return
	}
	// get the associated Pod
	proxyPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name:      s.Name,
		Namespace: "tailscale",
	}}
	err = er.Get(ctx, client.ObjectKeyFromObject(proxyPod), proxyPod)
	if apierrors.IsNotFound(err) {
		logger.Debugf("Pod %s does not yet exist", s.Name)
		return
	}
	if err != nil {
		return res, fmt.Errorf("error retrieving Pod %s: %w", s.Name, err)
	}
	// for each of the services in status hint
	for svcName, clusterSources := range statusHint {
		eps := &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      svcName,
				Namespace: "tailscale",
			},
		}
		err := er.Get(ctx, client.ObjectKeyFromObject(eps), eps)
		if apierrors.IsNotFound(err) {
			logger.Debugf("EndpointSlice %s not found", svcName)
			return res, nil
		}
		if err != nil {
			return res, fmt.Errorf("error retrieving EndpointSlice %s: %w", svcName, err)
		}
		fweEgressPods := &corev1.PodList{}
		if err := er.List(ctx, fweEgressPods, client.InNamespace("tailscale"), client.MatchingLabels(map[string]string{"app": svcName})); err != nil {
			return res, fmt.Errorf("error listing fwegress Pods for %s", svcName)
		}
		if len(fweEgressPods.Items) == 0 {
			logger.Debugf("no fwegress pods for %s yet", svcName)
		}
		oldEps := eps.DeepCopy()
		for _, pod := range fweEgressPods.Items {
			podIP := pod.Status.PodIP
			podUID := pod.UID
			var ep *discoveryv1.Endpoint
			for _, maybeEP := range eps.Endpoints {
				if strings.EqualFold(string(podUID), *maybeEP.Hostname) {
					ep = &maybeEP
					break
				}
			}
			if ep == nil {
				logger.Debugf("no endpoint created for Pod with uid %s yet", podUID)
				break
			}
			hasIP := false
			for _, ip := range clusterSources {
				if strings.EqualFold(ip, podIP) {
					hasIP = true
					break
				}
			}
			if !hasIP {
				logger.Debugf("proxy has NOT set up route from Pod %s, do nothing", podUID)
				break
			}
			logger.Debugf("proxy has set up route from Pod %s, ensuring this is refected in EndpointSlice", podUID)
			hasProxyPodIP := false
			for _, addr := range ep.Addresses {
				if strings.EqualFold(addr, proxyPod.Status.PodIP) {
					hasProxyPodIP = true
					break
				}
			}
			if hasProxyPodIP {
				logger.Debugf("proxy IP already present in EndpointSlice endpoint %s", proxyPod.Status.PodIP, podUID)
				break
			}
			logger.Debugf("proxy IP not yet present in EndpointSlice endpoint %s", proxyPod.Status.PodIP, podUID)
			ep.Addresses = append(ep.Addresses, proxyPod.Status.PodIP)
		}
		if !reflect.DeepEqual(oldEps, eps) {
			if err := er.Update(ctx, eps); err != nil {
				return res, fmt.Errorf("error updating EndpointSlice")
			}
		}
	}
	return
}
