package main

import (
	"context"
	"fmt"

	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
)

type proxiesReconciler struct {
	client.Client
	logger *zap.SugaredLogger

	recorder record.EventRecorder
	ssr      *tailscaleSTSReconciler

	tsNamespace string
}

func (pr *proxiesReconciler) Reconcile(ctx context.Context, req reconcile.Request) (_ reconcile.Result, err error) {
	logger := pr.logger.With("ClusterConfig", req.Name)
	logger.Debugf("starting reconcile")
	defer logger.Debugf("reconcile finished")

	cc := new(tsapi.ClusterConfig)
	err = pr.Get(ctx, req.NamespacedName, cc)
	if apierrors.IsNotFound(err) {
		// Request object not found, could have been deleted after reconcile request.
		logger.Debugf("ClusterConfig not found, assuming it was deleted")
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get ClusterConfig: %w", err)
	}
	ownerRef := metav1.NewControllerRef(cc, tsapi.SchemeGroupVersion.WithKind("ClusterConfig"))

	// For this prototype the number of proxy nodes is hardcoded to 4,
	// Service CIDR range hardcoded to 100.64.2.0/24
	// https://www.davidc.net/sites/default/subnets/subnets.html
	cidrs := []string{"100.64.2.0/26", "100.64.2.64/26", "100.64.2.128/26", "100.64.2.192/26"}
	stsCfg := &tailscaleSTSConfig{
		name:                cc.Name,
		serviceCIDRs:        cidrs,
		clusterConfOwnerRef: ownerRef,
	}
	if err = pr.ssr.Provision(ctx, logger, stsCfg); err != nil {
		return reconcile.Result{}, fmt.Errorf("error provision proxy: %w", err)
	}
	// logger.Debugf("finished reconciling index %d ", i)
	// Now watch for Secret changes, pull out device info and update cluster config status
	return reconcile.Result{}, nil

	// // build opts
	// stsCfg := &tailscaleSTSConfig{
	// 	Tags:             []string{"tag:k8s"},
	// 	HostnameTemplate: class.Name,
	// 	serviceClass:     class.Name,
	// 	dnsAddr:          cidr.Addr(),
	// 	serviceCIDR:      []netip.Prefix{cidr},
	// 	numProxies:       class.NumProxies,
	// }
	// defaultClassCIDR = []netip.Prefix{cidr}

	// // write DNS addr to the ServiceRecords ConfigMap
	// cm := &corev1.ConfigMap{}
	// if err := pr.Get(ctx, types.NamespacedName{Namespace: pr.tsNamespace, Name: "servicerecords"}, cm); err != nil {
	// 	return reconcile.Result{}, fmt.Errorf("error getting serviceRecords ConfigMap: %w", err)
	// }

	// var serviceRecords *kube.Records
	// if serviceRecordsB := cm.BinaryData["serviceRecords"]; len(serviceRecordsB) == 0 {
	// 	serviceRecords = &kube.Records{Version: kube.Alpha1Version}
	// } else {
	// 	if err := json.Unmarshal(cm.BinaryData["serviceRecords"], serviceRecords); err != nil {
	// 		return reconcile.Result{}, fmt.Errorf("error unmarshalling service records: %w", err)
	// 	}
	// }
	// // Remove, this will only get passed as env var to the proxies
	// if dnsAddr := serviceRecords.DNSAddr; dnsAddr != "" {
	// 	logger.Info("DNS addr already set to %s", dnsAddr)
	// 	return reconcile.Result{}, nil
	// }
	// dnsAddr := defaultClassCIDR[0].Addr()
	// serviceRecords.DNSAddr = dnsAddr.String()
	// serviceRecordsB, err := json.Marshal(serviceRecords)
	// cm.BinaryData["serviceRecords"] = serviceRecordsB

	// return reconcile.Result{}, pr.Update(ctx, cm)
}
