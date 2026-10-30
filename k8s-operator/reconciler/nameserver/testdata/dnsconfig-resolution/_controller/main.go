// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Standalone driver for the production nameserver controller in an isolated cluster.
package main

import (
	"log"

	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"k8s.io/client-go/rest"
	klog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler/nameserver"
)

func main() {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		log.Fatal(err)
	}
	mgr, err := manager.New(cfg, manager.Options{Scheme: tsapi.GlobalScheme, Metrics: metricsserver.Options{BindAddress: "0"}})
	if err != nil {
		log.Fatal(err)
	}
	logger, err := zap.NewDevelopment()
	if err != nil {
		log.Fatal(err)
	}
	klog.SetLogger(zapr.NewLogger(logger))
	r := nameserver.NewReconciler(nameserver.ReconcilerOptions{
		Client: mgr.GetClient(), Recorder: mgr.GetEventRecorderFor("dnsconfig-reproduction"),
		TailscaleNamespace: "tailscale", Logger: logger.Sugar(),
	})
	if err := r.Register(mgr); err != nil {
		log.Fatal(err)
	}
	if err := mgr.Start(signals.SetupSignalHandler()); err != nil {
		log.Fatal(err)
	}
}
