// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	xslices "golang.org/x/exp/slices"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	kzap "sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/util/linuxfw"
)

func main() {
	var opts []kzap.Opts
	opts = append(opts, kzap.UseDevMode(true), kzap.Level(zapcore.DebugLevel))
	zlog := kzap.NewRaw(opts...).Sugar()
	logf.SetLogger(zapr.NewLogger(zlog.Desugar()))
	restConfig := config.GetConfigOrDie()
	// One EndpointSlice marked by egress service name for the Service
	egressSvc := os.Getenv("TS_EGRESS_SVC")
	if egressSvc == "" {
		zlog.Fatalf("empty egress service name")
	}

	podIP := os.Getenv("POD_IP")
	if podIP == "" {
		zlog.Fatalf("empty POD_IP")
	}
	podUID := os.Getenv("POD_UID")
	if podUID == "" {
		zlog.Fatalf("empty Pod UID")
	}
	labelReq, err := labels.NewRequirement("tailscale.com/fwegress", selection.Equals, []string{egressSvc})
	if err != nil {
		zlog.Fatalf("error creating a label requirement: %v", err)
	}
	labelFilter := cache.ByObject{
		Label: labels.NewSelector().Add(*labelReq),
	}
	nsFilter := cache.ByObject{
		Namespaces: map[string]cache.Config{"tailscale": {LabelSelector: labelFilter.Label}},
	}
	nsFilter1 := cache.ByObject{
		Field: client.InNamespace("tailscale").AsSelector(),
	}
	mgr, err := manager.New(restConfig, manager.Options{Scheme: tsapi.GlobalScheme,
		Cache: cache.Options{
			ByObject: map[client.Object]cache.ByObject{
				&discoveryv1.EndpointSlice{}: nsFilter,
				&corev1.Pod{}:                nsFilter1,
			},
		}})
	if err != nil {
		zlog.Fatalf("could not create manager: %v", err)
	}
	// TODO: does this result in setting up unnecessary default firewall
	// rules for tailscale?
	nfRunner, err := linuxfw.New(zlog.Debugf, "")
	if err != nil {
		zlog.Fatalf("could not create netfilter runner: %v", err)
	}
	podName := os.Getenv("POD_NAME")
	if podName == "" {
		zlog.Fatal("empty Pod name")
	}
	err = builder.
		ControllerManagedBy(mgr).
		For(&discoveryv1.EndpointSlice{}). // label filter
		Complete(&FWEgressReconciler{
			Client:    mgr.GetClient(),
			logger:    zlog.Named("FWEgress-reconciler"),
			nfRunner:  nfRunner,
			podIP:     netip.MustParseAddr(podIP),
			podName:   podName,
			podUID:    podUID,
			state:     &state{routes: make([]netip.Addr, 0)},
			egressSvc: egressSvc,
		})
	if err != nil {
		zlog.Fatalf("error creating FWEgress reconciler: %v", err)
	}
	if mgr.Start(signals.SetupSignalHandler()); err != nil {
		zlog.Fatalf("error starting controller manager: %v", err)
	}
}

type FWEgressReconciler struct {
	client.Client
	state     *state
	logger    *zap.SugaredLogger
	nfRunner  linuxfw.NetfilterRunner
	podIP     netip.Addr
	podName   string
	podUID    string
	egressSvc string
}

// The operator creates the EndpointSlice as that makes it easier to co-ordinate the IP family thing.
func (r *FWEgressReconciler) Reconcile(ctx context.Context, req reconcile.Request) (res reconcile.Result, err error) {
	r.logger.Debugf("starting reconcile")
	defer r.logger.Debugf("reconcile finished")
	newRoutes := make([]netip.Addr, 0)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.podName,
			Namespace: "tailscale",
		},
	}
	if err := r.Get(ctx, client.ObjectKeyFromObject(pod), pod); err != nil {
		return res, err
	}
	ready := corev1.ConditionFalse
	defer func() {
		r.logger.Debugf("setting  new routes %v", newRoutes)
		r.state.set(newRoutes)
		oldPodStatus := pod.Status.DeepCopy()
		podSetTailscaleReady(ready, pod)
		if !apiequality.Semantic.DeepEqual(pod.Status, oldPodStatus) {
			r.logger.Debugf("updating Pod status", newRoutes)
			if updateErr := r.Status().Update(ctx, pod); updateErr != nil {
				err = errors.Join(err, fmt.Errorf("error updating proxy headless Service metadata: %w", err))
			}
		}
		// custom pod status condition is only used for readiness check, it is not reliable for internal use because it is possible that container restarted and we lost routes, but pod status is still the same
	}()
	eps := new(discoveryv1.EndpointSlice)
	err = r.Get(ctx, req.NamespacedName, eps)
	if apierrors.IsNotFound(err) {
		r.logger.Debugf("EndpointSlice not found, assuming it was deleted")
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get EndpointSlice: %w", err)
	}
	egressSvc := eps.Labels["tailscale.com/fwegress"]
	if !strings.EqualFold(egressSvc, r.egressSvc) {
		r.logger.Debugf("got EndpointSlice for service %s interested in %s", egressSvc, r.egressSvc)
		return res, nil
	}

	// TODO: this is round robin for iptables, but not nftables- must fix
	// nftables
	addrs := make([]netip.Addr, 0)
	for _, ep := range eps.Endpoints {
		if !strings.EqualFold(*ep.Hostname, r.podUID) {
			r.logger.Debugf("skip endpoint for fwegress Pod %s", *ep.Hostname)
			break
		}
		for _, addrS := range ep.Addresses {
			addr, err := netip.ParseAddr(addrS)
			if err != nil {
				return res, fmt.Errorf("error parsing EndpointSlice address %s: %v", addrS, err)
			}
			// duplicates aren't expected
			addrs = append(addrs, addr)
		}
	}
	if !r.state.routesNeedUpdate(addrs) {
		r.logger.Debugf("routes don't need update")
		ready = corev1.ConditionTrue
		return
	}
	r.logger.Debugf("routes need update, new routes are %v", addrs)

	// TODO: also add a mark
	// we could mark packets for this service so don't have to reconfigure as these Pods go up and down
	if err := r.nfRunner.DNATWithLoadBalancer(r.podIP, addrs); err != nil {
		r.logger.Errorf("error updating routes: %v", err)
		return res, fmt.Errorf("error setting up load balancer rules: %v", err)
	}
	for _, addr := range addrs {
		if err := r.nfRunner.AddSNATRuleForDst(r.podIP, addr); err != nil {
			return res, fmt.Errorf("error setting up SNAT rules %w", err)
		}
	}

	newRoutes = addrs
	ready = corev1.ConditionTrue
	return res, nil
}

type state struct {
	sync.RWMutex
	routes []netip.Addr
}

func (s *state) routesNeedUpdate(newRoutes []netip.Addr) bool {
	s.Lock()
	defer s.Unlock()
	if len(newRoutes) != len(s.routes) {
		return true
	}
	// TODO: bart.Table would be more efficient maybe
	// Routes should be sorted
	for i, r := range s.routes {
		if newRoutes[i].Compare(r) != 0 {
			return true
		}
	}
	return false
}

// we need to store routes internally - they can be lost during container
// restarts and container restarts can happen in a way that cannot be tied to
// resource garbage collection etc
func (s *state) set(routes []netip.Addr) {
	s.Lock()
	s.routes = routes
	s.Unlock()
}

func podSetTailscaleReady(status corev1.ConditionStatus, pod *corev1.Pod) {
	newCondition := corev1.PodCondition{
		Type:   corev1.PodConditionType("TailscaleRoutesReady"),
		Status: status,
	}

	idx := xslices.IndexFunc(pod.Status.Conditions, func(cond corev1.PodCondition) bool {
		return cond.Type == corev1.PodConditionType("TailscaleRoutesReady")
	})
	if idx == -1 {
		pod.Status.Conditions = append(pod.Status.Conditions, newCondition)
		return
	}
	pod.Status.Conditions[idx] = newCondition
}
